import 'dart:convert';
import 'dart:math';

import 'package:dotenv/dotenv.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf_router/shelf_router.dart';
import 'package:supabase/supabase.dart';
import 'package:http/http.dart' as http;
import 'package:crypto/crypto.dart';
import 'package:uuid/uuid.dart';

import 'error_service.dart';

class Api {
  /// .env
  final env = DotEnv(includePlatformEnvironment: true)..load();

  /// generate random salt to hash
  String generateRandomString(int len) {
    var r = Random.secure();
    const chars =
        'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz1234567890';
    return List.generate(len, (index) => chars[r.nextInt(chars.length)]).join();
  }

  /// create SupabaseClient with given schema
  SupabaseClient createSupabaseClient(String schema) {
    return SupabaseClient(
      env['SUPABASE_URL']!,
      env['SECRET_ROLE']!,
      schema: schema,
    );
  }

  /// check and create domain client
  Future<SupabaseClient> getDomainClient(String domain) async {
    // create supabase_client for sys schema
    final supabaseClient = createSupabaseClient('sys');
    // get db_schemas
    final resDbSchemas = await supabaseClient.rpc('get_db_schemas').execute();
    final dbSchemas = resDbSchemas.data.split('=')[1];
    // check whether domain exist or not
    if (!dbSchemas.contains(domain)) throw DomainNotExistError.message();
    // create SupabaseClient for new schema
    final domainClient = createSupabaseClient(domain);
    return domainClient;
  }

  Map<String, dynamic> verifyJwt(String? header, String jwtSecret) {
    final token = getJwt(header);
    final jwt = JWT.verify(token, SecretKey(jwtSecret));
    return jwt.payload;
  }

  /// extract jwt from header
  /// ex: 'Bearer abc.def.ghi' => abc.def.ghi
  String getJwt(String? header) {
    if (header == null) throw Exception('header is null');
    final ls = header.split(' ');
    if (ls.length < 2) throw Exception('header lenght invalid');
    final token = ls[1];
    return token;
  }

  Handler get handler {
    final router = Router();

    final nextJsUrl = env['NEXTJS_URL']!;
    final emailjs = {
      'url': env['EMAILJS_URL']!,
      'service-id': env['EMAILJS_SERVICE_ID']!,
      'template-id': env['EMAILJS_TEMPLATE_ID']!,
      'user-id': env['EMAILJS_USER_ID']!,
      'secret-key': env['EMAILJS_SECRET_KEY']!,
    };
    final verifyEmailSecret = env['VERIFY_EMAIL_SECRET_KEY']!;
    const verifyEmailDuration = Duration(minutes: 5);
    final verifyDomainSecret = env['VERIFY_DOMAIN_SECRET_KEY']!;
    const verifyDomainDuration = Duration(days: 180);

    /// ====================== NEXTJS ==============================

    /// Send email to verify
    Future<bool> sendVerifiedEmail({
      required String username,
      required String email,
      required String token,
    }) async {
      final uri = Uri.parse(emailjs['url']!);
      final verifiedLink = '$nextJsUrl/verify-email?token=$token';
      final verifiedRes = await http.post(
        uri,
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'service_id': emailjs['service-id'],
          'template_id': emailjs['template-id'],
          'user_id': emailjs['user-id'],
          'accessToken': emailjs['secret-key'],
          'template_params': {
            'to_name': username,
            'to_email': email,
            'link': verifiedLink,
          },
        }),
      );
      if (verifiedRes.statusCode == 200) return true;
      return false;
    }

    /// Sign up
    router.post('/v1/register', (Request request) async {
      final payload =
          jsonDecode(await request.readAsString()) as Map<String, dynamic>;
      final username = payload['username'];
      final email = payload['email'];
      final password = payload['password'];
      // hash password with salt
      final salt = generateRandomString(6);
      final bytes = utf8.encode(password + salt);
      final hash = sha256.convert(bytes).toString();
      // create verified hash to confirm email
      final verifiedSalt = utf8.encode(generateRandomString(18));
      final verifiedHash = sha256.convert(verifiedSalt).toString();
      // create supabase_client for sys schema
      final supabaseClient = createSupabaseClient('sys');
      // insert new user info
      final res = await supabaseClient.from('customer').insert({
        'email': email,
        'username': username,
        'salt': salt,
        'hash': hash,
        'email_verified': false,
        'verified_hash': verifiedHash,
      }).execute();
      if (res.hasError) {
        return EmailHasBeenUsedError.message();
      }
      // create jwt token to confirm
      final jwt = JWT({'email': email, 'verified_hash': verifiedHash});
      final token = jwt.sign(
        SecretKey(verifyEmailSecret),
        expiresIn: verifyEmailDuration,
      );
      // send confirm email
      final sendEmailSuccess = await sendVerifiedEmail(
        email: email,
        username: username,
        token: token,
      );
      if (sendEmailSuccess) {
        return Response.ok(null);
      } else {
        return SMTPServiceError.message();
      }
    });

    /// Resend verify email
    router.post('/v1/resend-verify', (Request request) async {
      final payload =
          jsonDecode(await request.readAsString()) as Map<String, dynamic>;
      final email = payload['email'];
      // create verified hash to confirm email
      final verifiedSalt = utf8.encode(generateRandomString(18));
      final verifiedHash = sha256.convert(verifiedSalt).toString();
      // create supabase_client for sys schema
      final supabaseClient = createSupabaseClient('sys');
      // select customer row
      final res = await supabaseClient
          .from('customer')
          .select()
          .match({'email': email})
          .single()
          .execute();
      if (res.hasError) {
        return EmailHasNotRegisterError.message();
      }
      final username = res.data['username'];
      final emailVerified = res.data['email_verified'];
      if (emailVerified) {
        return Response.badRequest(
            body: jsonEncode({'message': 'Email has verified'}));
      }
      // update verified_hash
      final updateRes = await supabaseClient
          .from('customer')
          .update({'verified_hash': verifiedHash})
          .match({'email': email})
          .single()
          .execute();
      if (updateRes.hasError) {
        return EmailHasNotRegisterError.message();
      }
      // create jwt token to confirm
      final jwt = JWT({'email': email, 'verified_hash': verifiedHash});
      final token = jwt.sign(
        SecretKey(verifyEmailSecret),
        expiresIn: verifyEmailDuration,
      );
      // send confirm email
      final sendEmailSuccess = await sendVerifiedEmail(
        email: email,
        username: username,
        token: token,
      );
      if (sendEmailSuccess) {
        return Response.ok(null);
      } else {
        return SMTPServiceError.message();
      }
    });

    /// Verify email
    router.post('/v1/verify-email', (Request request) async {
      final payload =
          jsonDecode(await request.readAsString()) as Map<String, dynamic>;
      final token = payload['token'];
      try {
        final jwt = JWT.verify(token, SecretKey(verifyEmailSecret));
        final email = jwt.payload['email'];
        final verifiedHash = jwt.payload['verified_hash'];
        // create supabase_client for sys schema
        final supabaseClient = createSupabaseClient('sys');
        final res = await supabaseClient
            .from('customer')
            .select()
            .match({'email': email})
            .single()
            .execute();
        if (res.hasError) {
          return EmailHasNotRegisterError.message();
        }
        final emailVerified = res.data['email_verified'];
        if (emailVerified) {
          return EmailHasBeenVerifiedError.message();
        }
        // update verify status
        final updateRes = await supabaseClient
            .from('customer')
            .update({'email_verified': true})
            .match({'email': email, 'verified_hash': verifiedHash})
            .single()
            .execute();
        if (updateRes.hasError) {
          return VerifyTokenWasObsoleteError.message();
        }
        return Response.ok(jsonEncode({'data': 'Verify email successfully'}));
      } on JWTExpiredError {
        return VerifyTokenWasExpiredError.message();
      } on JWTError {
        return VerifyTokenIsInvalidsError.message();
      }
    });

    /// Log in
    router.post('/v1/login', (Request request) async {
      final payload =
          jsonDecode(await request.readAsString()) as Map<String, dynamic>;
      final email = payload['email'];
      final password = payload['password'];
      // create supabase_client for sys schema
      final supabaseClient = createSupabaseClient('sys');
      // hash password with salt
      final res = await supabaseClient
          .from('customer')
          .select()
          .match({'email': email})
          .single()
          .execute();
      if (res.hasError) {
        return EmailHasNotRegisterError.message();
      }

      final salt = res.data['salt'];
      final hashDB = res.data['hash'];
      final emailVerified = res.data['email_verified'];

      final bytes = utf8.encode(password + salt);
      final hash = sha256.convert(bytes).toString();
      if (hash == hashDB) {
        if (emailVerified) {
          // create session token
          final id = Uuid().v4();
          final sessionRes = await supabaseClient
              .from('session')
              .insert({'id': id, 'email': email}).execute();
          if (sessionRes.hasError) {
            return EmailHasNotRegisterError.message();
          }
          return Response.ok(jsonEncode({'authToken': id}));
        } else {
          return EmailHasNotBeenVerifiedError.message();
        }
      } else {
        return EmailOrPasswordNotMatchedError.message();
      }
    });

    /// Log out
    router.get('/v1/logout', (Request request) async {
      final authToken = request.headers['auth-token'];
      if (authToken == null) {
        return UnauthorizedError.message();
      }
      // create supabase_client for sys schema
      final supabaseClient = createSupabaseClient('sys');
      await supabaseClient
          .from('session')
          .delete()
          .match({'id': authToken}).execute();
      return Response.ok(null);
    });

    /// Get account info
    router.get('/v1/account', (Request request) async {
      final authToken = request.headers['auth-token'];
      if (authToken == null) {
        return UnauthorizedError.message();
      }
      // create supabase_client for sys schema
      final supabaseClient = createSupabaseClient('sys');
      final res = await supabaseClient
          .from('session')
          .select()
          .match({'id': authToken})
          .single()
          .execute();
      if (res.hasError) {
        return UnauthorizedError.message();
      }
      final email = res.data['email'];
      return Response.ok(jsonEncode({'email': email}));
    });

    /// Create domain
    router.post('/v1/domain', (Request request) async {
      final authToken = request.headers['auth-token'];
      if (authToken == null) {
        return UnauthorizedError.message();
      }
      // create supabase_client for sys schema
      final supabaseClient = createSupabaseClient('sys');
      // check whether auth-token is valid or not
      final resSession = await supabaseClient
          .from('session')
          .select()
          .match({'id': authToken})
          .single()
          .execute();
      if (resSession.hasError) return UnauthorizedError.message();
      // get customer data
      final email = resSession.data['email'];
      final resCustomer = await supabaseClient
          .from('customer')
          .select()
          .match({'email': email})
          .single()
          .execute();
      if (resCustomer.hasError) return UnauthorizedError.message();
      final salt = resCustomer.data['salt'];
      final hash = resCustomer.data['hash'];
      // get domain name
      final payload =
          jsonDecode(await request.readAsString()) as Map<String, dynamic>;
      final domain = payload['domain'];
      // get db_schemas
      final resDbSchemas = await supabaseClient.rpc('get_db_schemas').execute();
      final dbSchemas = resDbSchemas.data.split('=')[1];
      if (dbSchemas.contains(domain)) {
        print(resDbSchemas.data);
        return DomainHasBeenUsedError.message();
      } else {
        // add new schema to tenant
        final resTenant = await supabaseClient.from('tenant').insert({
          'id': Uuid().v4(),
          'email': email,
          'domain': domain,
        }).execute();
        if (resTenant.hasError) {
          return DomainHasBeenUsedError.message();
        }
        // add domain to schemas list
      }
      // call rpc to create new schema
      final resSchema = await supabaseClient
          .rpc('create_schema', params: {'s_name': domain}).execute();
      if (resSchema.hasError) return DatabaseError.message();
      // call rpc to create expose schema to service_role
      final resExpose = await supabaseClient.rpc('change_postgrest_db_schemas',
          params: {'schemas': '$dbSchemas, $domain'}).execute();
      if (resExpose.hasError) return DatabaseError.message();
      // CREATE TABLE
      // USER
      final resUser = await supabaseClient
          .rpc('create_user', params: {'s_name': domain}).execute();
      if (resUser.hasError) return DatabaseError.message();
      // PROJECT
      final resProject = await supabaseClient
          .rpc('create_project', params: {'s_name': domain}).execute();
      if (resProject.hasError) return DatabaseError.message();
      // GROUP
      final resGroup = await supabaseClient
          .rpc('create_group', params: {'s_name': domain}).execute();
      if (resGroup.hasError) return DatabaseError.message();
      // BROKER
      final resBroker = await supabaseClient
          .rpc('create_broker', params: {'s_name': domain}).execute();
      if (resBroker.hasError) return DatabaseError.message();
      // DEVICE
      final resDevice = await supabaseClient
          .rpc('create_device', params: {'s_name': domain}).execute();
      if (resDevice.hasError) return DatabaseError.message();
      // ATTRIBUTE
      final resAttribute = await supabaseClient
          .rpc('create_attribute', params: {'s_name': domain}).execute();
      if (resAttribute.hasError) return DatabaseError.message();
      // create SupabaseClient for new schema
      final domainClient = createSupabaseClient(domain);
      // add customer info to user table
      final resAddUser = await domainClient.from('user').insert({
        'email': email,
        'salt': salt,
        'hash': hash,
        'is_admin': true
      }).execute();
      if (resAddUser.hasError) {
        print(resAddUser.error);
        return DatabaseError.message();
      }

      return Response.ok(null);
    });

    /// delete domain
    router.delete('/v1/domain', (Request request) async {
      final authToken = request.headers['auth-token'];
      if (authToken == null) {
        return UnauthorizedError.message();
      }
      // create supabase_client for sys schema
      final supabaseClient = createSupabaseClient('sys');
      // check whether auth-token is valid or not
      final resSession = await supabaseClient
          .from('session')
          .select()
          .match({'id': authToken})
          .single()
          .execute();
      if (resSession.hasError) return UnauthorizedError.message();
      final payload =
          jsonDecode(await request.readAsString()) as Map<String, dynamic>;
      final domain = payload['domain'];
      // call rpc to create delete schema
      final resDel = await supabaseClient
          .rpc('delete_schema', params: {'s_name': domain}).execute();
      if (resDel.hasError) return DatabaseError.message();
      // delete row in tenant
      final resTenant = await supabaseClient
          .from('tenant')
          .delete()
          .match({'domain': domain}).execute();
      if (resTenant.hasError) return DatabaseError.message();
      // get db_schemas
      final resDbSchemas = await supabaseClient.rpc('get_db_schemas').execute();
      final dbSchemas = resDbSchemas.data.split('=')[1];
      // check whether domain exist or not
      if (!dbSchemas.contains(domain)) return DomainNotExistError.message();
      final schemas = dbSchemas.split(', ')..remove(domain);
      final dbSchemasUpdate = schemas.join(', ');
      final resExpose = await supabaseClient.rpc('change_postgrest_db_schemas',
          params: {'schemas': dbSchemasUpdate}).execute();
      if (resExpose.hasError) return DatabaseError.message();

      return Response.ok(null);
    });

    /// ====================== MOBILE ==============================

    /// Log in tenant
    router.post('/v1/domain/login', (Request request) async {
      final payload =
          jsonDecode(await request.readAsString()) as Map<String, dynamic>;
      final domain = payload['domain'];
      final email = payload['email'];
      final password = payload['password'];
      // create supabase_client for sys schema
      final supabaseClient = createSupabaseClient('sys');
      // get db_schemas
      final resDbSchemas = await supabaseClient.rpc('get_db_schemas').execute();
      final dbSchemas = resDbSchemas.data.split('=')[1];
      // check whether domain exist or not
      if (!dbSchemas.contains(domain)) return DomainNotExistError.message();
      // create SupabaseClient for new schema
      final domainClient = createSupabaseClient(domain);
      // hash password with salt
      final res = await domainClient
          .from('user')
          .select()
          .match({'email': email})
          .single()
          .execute();
      if (res.hasError) return UserNotExistError.message();

      final salt = res.data['salt'];
      final hashDB = res.data['hash'];

      final bytes = utf8.encode(password + salt);
      final hash = sha256.convert(bytes).toString();
      if (hash == hashDB) {
        // create jwt token to confirm
        final jwt = JWT({'email': email, 'domain': domain});
        final token = jwt.sign(
          SecretKey(verifyDomainSecret),
          expiresIn: verifyDomainDuration,
        );
        return Response.ok(jsonEncode({'token': token}));
      } else {
        return EmailOrPasswordNotMatchedError.message();
      }
    });

    /// Check whether auth-token is valid
    router.get('/v1/domain/account', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final email = jwtPayload['email'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient
            .from('user')
            .select()
            .match({'email': email})
            .single()
            .execute();
        if (res.hasError) {
          return UnauthorizedError.message();
        }
        final isAdmin = res.data['is_admin'];
        return Response.ok(jsonEncode({'email': email, 'isAdmin': isAdmin}));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // < PROJECT REST API >
    // POST: tạo mới một dự án
    router.post('/v1/domain/projects', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // decode request payload
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final id = payload['id'];
        final name = payload['name'];
        final res = await domainClient
            .from('project')
            .insert({'id': id, 'name': name}).execute();
        if (res.hasError) return DatabaseError.message();
        return Response.ok(jsonEncode({'id': id, 'name': name}));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // GET: lấy danh sách dự án
    router.get('/v1/domain/projects', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // get name of project
        final res = await domainClient.from('project').select().execute();
        if (res.hasError) return DatabaseError.message();
        return Response.ok(jsonEncode({'projects': res.data}));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // GET: lấy chi tiết dự án với id cụ thể
    router.get('/v1/domain/projects/<project_id>',
        (Request request, String projectID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // get name of project
        final res = await domainClient
            .from('project')
            .select()
            .match({'id': projectID})
            .single()
            .execute();
        if (res.hasError) return ProjectNotExistError.message();
        return Response.ok(jsonEncode(res.data));
      } catch (e) {
        print(e);
        return UnknownError.message();
      }
    });

    // PUT: cập nhật dự án với id cụ thể
    router.put('/v1/domain/projects/<project_id>',
        (Request request, String projectID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // decode request payload
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final name = payload['name'];
        final res = await domainClient
            .from('project')
            .update({'name': name}).match({'id': projectID}).execute();
        if (res.hasError) return ProjectNotExistError.message();
        return Response.ok(jsonEncode({'id': projectID, 'name': name}));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // DELETE: xóa dự án với id cụ thể
    router.delete('/v1/domain/projects/<project_id>',
        (Request request, String projectID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient
            .from('project')
            .delete()
            .match({'id': projectID}).execute();
        if (res.hasError) return ProjectNotExistError.message();
        return Response.ok(null);
      } catch (e) {
        return UnknownError.message();
      }
    });
    // </ PROJECT REST API >

    // < GROUP REST API >
    // POST: tạo mới một nhóm
    router.post('/v1/domain/groups', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // decode request payload
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final id = payload['id'];
        final projectID = payload['project_id'];
        final groupID = payload['group_id'];
        final name = payload['name'];
        final res = await domainClient.from('group').insert({
          'id': id,
          'project_id': projectID,
          'group_id': groupID,
          'name': name,
        }).execute();
        if (res.hasError) return DatabaseError.message();
        return Response.ok(jsonEncode({
          'id': id,
          'project_id': projectID,
          'group_id': groupID,
          'name': name,
        }));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // GET: lấy danh sách nhóm
    router.get('/v1/domain/groups', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient.from('group').select().execute();
        if (res.hasError) return DatabaseError.message();
        return Response.ok(jsonEncode({'groups': res.data}));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // GET: lấy chi tiết nhóm với id cụ thể
    router.get('/v1/domain/groups/<group_id>',
        (Request request, String groupID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient
            .from('group')
            .select()
            .match({'id': groupID})
            .single()
            .execute();
        if (res.hasError) return GroupNotExistError.message();
        return Response.ok(jsonEncode(res.data));
      } catch (e) {
        print(e);
        return UnknownError.message();
      }
    });

    // PUT: cập nhật nhóm với id cụ thể
    router.put('/v1/domain/groups/<group_id>',
        (Request request, String id) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // decode request payload
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final projectID = payload['project_id'];
        final groupID = payload['group_id'];
        final name = payload['name'];
        final res = await domainClient.from('group').update({
          'project_id': projectID,
          'group_id': groupID,
          'name': name,
        }).match({'id': id}).execute();
        if (res.hasError) return GroupNotExistError.message();
        return Response.ok(jsonEncode({
          'id': id,
          'project_id': projectID,
          'group_id': groupID,
          'name': name,
        }));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // DELETE: xóa nhóm với id cụ thể
    router.delete('/v1/domain/groups/<group_id>',
        (Request request, String groupID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient
            .from('group')
            .delete()
            .match({'id': groupID}).execute();
        if (res.hasError) return GroupNotExistError.message();
        return Response.ok(null);
      } catch (e) {
        return UnknownError.message();
      }
    });
    // </ GROUP REST API >

    // < BROKER REST API >

    // POST: tạo mới một thiết bị
    router.post('/v1/domain/brokers', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // decode request payload
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final id = payload['id'];
        final groupID = payload['group_id'];
        final brokerID = payload['broker_id'];
        final name = payload['name'];
        final topic = payload['topic'];
        final jsonEnable = payload['json_enable'];
        final res = await domainClient.from('device').insert({
          'id': id,
          'group_id': groupID,
          'broker_id': brokerID,
          'name': name,
          'topic': topic,
          'json_enable': jsonEnable,
        }).execute();
        if (res.hasError) return DatabaseError.message();
        return Response.ok(jsonEncode({
          'id': id,
          'group_id': groupID,
          'broker_id': brokerID,
          'name': name,
          'topic': topic,
          'json_enable': jsonEnable,
        }));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // GET: lấy danh sách thiết bị
    router.get('/v1/domain/devices', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient.from('device').select().execute();
        if (res.hasError) {
          return DatabaseError.message();
        }
        return Response.ok(jsonEncode({'devices': res.data}));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // GET: lấy chi tiết thiết bị với id cụ thể
    router.get('/v1/domain/devices/<device_id>',
        (Request request, String deviceID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient
            .from('device')
            .select()
            .match({'id': deviceID})
            .single()
            .execute();
        if (res.hasError) return DeviceNotExistError.message();
        return Response.ok(jsonEncode(res.data));
      } catch (e) {
        print(e);
        return UnknownError.message();
      }
    });

    // PUT: cập nhật thiết bị với id cụ thể
    router.put('/v1/domain/devices/<device_id>',
        (Request request, String deviceID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // decode request payload
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final groupID = payload['group_id'];
        final brokerID = payload['broker_id'];
        final name = payload['name'];
        final topic = payload['topic'];
        final jsonEnable = payload['json_enable'];
        final res = await domainClient.from('device').update({
          'group_id': groupID,
          'broker_id': brokerID,
          'name': name,
          'topic': topic,
          'json_enable': jsonEnable,
        }).match({'id': deviceID}).execute();
        if (res.hasError) return DeviceNotExistError.message();
        return Response.ok(jsonEncode({
          'id': deviceID,
          'group_id': groupID,
          'broker_id': brokerID,
          'name': name,
          'topic': topic,
          'json_enable': jsonEnable,
        }));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // DELETE: xóa thiết bị với id cụ thể
    router.delete('/v1/domain/devices/<device_id>',
        (Request request, String deviceID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient
            .from('device')
            .delete()
            .match({'id': deviceID}).execute();
        if (res.hasError) return DeviceNotExistError.message();
        return Response.ok(null);
      } catch (e) {
        return UnknownError.message();
      }
    });
    // </ BROKER REST API >

    // /// Get all project
    // router.get('/api/projects', (Request request) async {
    //   final response = await client.from('project').select().execute();

    //   return Response.ok(jsonEncode({'success': true, 'data': response.data}),
    //       headers: {'Content-type': 'application/json'});
    // });

    // /// Create project
    // router.post('/api/projects', (Request request) async {
    //   try {
    //     final payload =
    //         jsonDecode(await request.readAsString()) as Map<String, dynamic>;
    //     print(payload);
    //     final id = payload['id'];
    //     final key = payload['key'];
    //     final name = payload['name'];
    //     final description = payload['description'];
    //     final userId = payload['user_id'];

    //     final body = {
    //       'key': key,
    //       'name': name,
    //     };
    //     if (description != null) {
    //       body['description'] = description;
    //     }
    //     final response = await httpClient.post(
    //       Uri.http(kBaseURL, '/api/v2/$username/groups'),
    //       body: body,
    //       headers: {
    //         'X-AIO-Key': ioKey,
    //       },
    //     );
    //     if (response.statusCode == 201) {
    //       try {
    //         final adafruitBody =
    //             jsonDecode(response.body) as Map<String, dynamic>;
    //         final supabaseInstance = {
    //           'id': id as String,
    //           'name': name as String,
    //           'key': key as String,
    //           'description': description as String?,
    //           'created_at': adafruitBody['created_at'] as String,
    //           'updated_at': adafruitBody['updated_at'] as String,
    //           'created_by': userId as String,
    //           'updated_by': userId,
    //         };
    //         print(supabaseInstance);
    //         final supaReponse =
    //             await client.from('project').insert(supabaseInstance).execute();
    //         final result = supaReponse.data as List;
    //         return Response.ok(
    //           jsonEncode({'success': true, 'data': result.first}),
    //           headers: {'Content-type': 'application/json'},
    //         );
    //       } catch (e) {
    //         print(e);
    //         return Response.badRequest(body: jsonEncode({'success': false}));
    //       }
    //     } else {
    //       return Response.badRequest(body: jsonEncode({'success': false}));
    //     }
    //   } catch (e) {
    //     print(e);
    //     return Response.badRequest(body: jsonEncode({'success': false}));
    //   }
    // });

    // /// Update project
    // router.put('/api/projects/<old_key>',
    //     (Request request, String oldKey) async {
    //   try {
    //     final payload =
    //         jsonDecode(await request.readAsString()) as Map<String, dynamic>;
    //     final id = payload['id'];
    //     final key = payload['key'];
    //     final name = payload['name'];
    //     final description = payload['description'];
    //     final createBy = payload['create_by'];
    //     final userId = payload['user_id'];
    //     final body = {
    //       'key': key,
    //       'name': name,
    //     };
    //     if (description != null) {
    //       body['description'] = description;
    //     }
    //     final response = await httpClient.put(
    //       Uri.http(kBaseURL, '/api/v2/$username/groups/$oldKey'),
    //       body: body,
    //       headers: {
    //         'X-AIO-Key': ioKey,
    //       },
    //     );
    //     if (response.statusCode == 200) {
    //       final adafruitBody =
    //           jsonDecode(response.body) as Map<String, dynamic>;
    //       final supabaseInstance = {
    //         'name': name as String,
    //         'key': key as String,
    //         'description': description as String?,
    //         'created_at': adafruitBody['created_at'] as String,
    //         'updated_at': adafruitBody['updated_at'] as String,
    //         'created_by': createBy as String,
    //         'updated_by': userId as String,
    //       };

    //       final supaReponse = await client
    //           .from('project')
    //           .update(supabaseInstance)
    //           .match({'id': id}).execute();
    //       final result = supaReponse.data as List;
    //       return Response.ok(
    //         jsonEncode({'success': true, 'data': result.first}),
    //         headers: {'Content-type': 'application/json'},
    //       );
    //     } else {
    //       return Response.badRequest(body: jsonEncode({'success': false}));
    //     }
    //   } catch (e) {
    //     return Response.badRequest(body: jsonEncode({'success': false}));
    //   }
    // });

    // /// Get specific project
    // router.get('/api/projects/<id>', (Request request, String id) async {
    //   final response =
    //       await client.from('projects').select().match({'id': id}).execute();
    //   return Response.ok(jsonEncode({'success': true, 'data': response.data}),
    //       headers: {'Content-type': 'application/json'});
    // });

    // router.delete('/api/projects/<id>', (Request request, String id) async {
    //   final response =
    //       await client.from('projects').delete().match({'id': id}).execute();

    //   return Response.ok(
    //     jsonEncode({'success': true, 'data': response.data}),
    //     headers: {'Content-type': 'application/json'},
    //   );
    // });

    // router.get('/api/schema', (Request request) async {
    //   final response = await client.rpc('get_projects').execute();
    //   return Response.ok(jsonEncode({'success': true, 'data': response.data}),
    //       headers: {'Content-type': 'application/json'});
    // });

    // ///
    // /// ================================================
    // ///

    // /// Get all devices
    // router.get('/api/devices', (Request request) async {
    //   final response = await client.from('device').select().execute();

    //   final devicesFull = <dynamic>[];
    //   for (final device in (response.data as List<dynamic>)) {
    //     final deviceFull = Map<String, dynamic>.from(device);
    //     final json = await client
    //         .from('json_variable')
    //         .select()
    //         .match({'device_id': device['id']}).execute();
    //     deviceFull['json_variables'] = json.data ?? [];
    //     devicesFull.add(deviceFull);
    //   }

    //   return Response.ok(jsonEncode({'success': true, 'data': devicesFull}),
    //       headers: {'Content-type': 'application/json'});
    // });

    // /// Create device
    // router.post('/api/devices', (Request request) async {
    //   try {
    //     final payload =
    //         jsonDecode(await request.readAsString()) as Map<String, dynamic>;
    //     final id = payload['id'];
    //     final projectId = payload['project_id'];
    //     final projectKey = payload['project_key'];
    //     final name = payload['name'];
    //     final key = payload['key'];
    //     final description = payload['description'];
    //     final jsonEnable = payload['json_enable'];
    //     final jsonVariables = payload['json_variables'] as List<dynamic>;
    //     final userID = payload['user_id'];
    //     final body = {
    //       'feed': {
    //         'name': name,
    //         'key': key,
    //         'description': description,
    //       }
    //     };
    //     final response = await httpClient.post(
    //       Uri.http(kBaseURL, '/api/v2/$username/groups/$projectKey/feeds'),
    //       body: jsonEncode(body),
    //       headers: {
    //         'Content-Type': 'application/json',
    //         'X-AIO-Key': ioKey,
    //       },
    //     );
    //     if (response.statusCode == 201) {
    //       final adafruitBody =
    //           jsonDecode(response.body) as Map<String, dynamic>;
    //       // add to device table
    //       final supabaseInstance = {
    //         'id': id as String,
    //         'project_id': projectId as String,
    //         'name': name as String,
    //         'key': key as String,
    //         'description': description as String?,
    //         'json_enable': jsonEnable as bool,
    //         'created_at': adafruitBody['created_at'] as String,
    //         'updated_at': adafruitBody['updated_at'] as String,
    //         'created_by': userID as String,
    //         'updated_by': userID,
    //       };
    //       final supaReponse =
    //           await client.from('device').insert(supabaseInstance).execute();
    //       // add to json_variable table
    //       final jsonVariablesJson = <dynamic>[];
    //       for (final jsonVariable in jsonVariables) {
    //         final json = await client
    //             .from('json_variable')
    //             .insert(jsonVariable)
    //             .execute();
    //         jsonVariablesJson.add((json.data as List<dynamic>).first);
    //       }
    //       final deviceJson =
    //           Map<String, dynamic>.from((supaReponse.data as List).first);
    //       deviceJson["json_variables"] = jsonVariablesJson;
    //       return Response.ok(
    //         jsonEncode({'success': true, 'data': deviceJson}),
    //         headers: {'Content-type': 'application/json'},
    //       );
    //     } else {
    //       return Response.badRequest(body: jsonEncode({'success': false}));
    //     }
    //   } catch (e) {
    //     return Response.badRequest(body: jsonEncode({'success': false}));
    //   }
    // });

    // /// Update device
    // router.put('/api/devices/<old_key>',
    //     (Request request, String oldKey) async {
    //   try {
    //     final payload =
    //         jsonDecode(await request.readAsString()) as Map<String, dynamic>;
    //     final id = payload['id'];
    //     final projectId = payload['project_id'];
    //     final projectKey = payload['project_key'];
    //     final name = payload['name'];
    //     final key = payload['key'];
    //     final description = payload['description'];
    //     final jsonEnable = payload['json_enable'];
    //     final jsonVariables = payload['json_variables'] as List<dynamic>;
    //     final userID = payload['user_id'];
    //     final body = {
    //       'feed': {
    //         'name': name,
    //         'key': key,
    //       }
    //     };
    //     if (description != null) {
    //       body['feed']!['description'] = description;
    //     }
    //     final response = await httpClient.put(
    //       Uri.http(kBaseURL, '/api/v2/$username/feeds/$projectKey.$oldKey'),
    //       body: jsonEncode(body),
    //       headers: {
    //         'Content-Type': 'application/json',
    //         'X-AIO-Key': ioKey,
    //       },
    //     );
    //     if (response.statusCode == 200) {
    //       final adafruitBody =
    //           jsonDecode(response.body) as Map<String, dynamic>;
    //       final supabaseInstance = {
    //         'id': id as String,
    //         'project_id': projectId as String,
    //         'name': name as String,
    //         'key': key as String,
    //         'description': description as String?,
    //         'json_enable': jsonEnable as bool,
    //         'created_at': adafruitBody['created_at'] as String,
    //         'updated_at': adafruitBody['updated_at'] as String,
    //         'created_by': userID as String,
    //         'updated_by': userID,
    //       };
    //       final supaReponse = await client
    //           .from('device')
    //           .update(supabaseInstance)
    //           .match({'id': id}).execute();

    //       final jsonVariablesJson = <dynamic>[];
    //       for (final jsonVariable in jsonVariables) {
    //         final json = await client
    //             .from('json_variable')
    //             .upsert(jsonVariable)
    //             .execute();
    //         jsonVariablesJson.add((json.data as List<dynamic>).first);
    //       }
    //       final deviceJson =
    //           Map<String, dynamic>.from((supaReponse.data as List).first);
    //       deviceJson["json_variables"] = jsonVariablesJson;
    //       return Response.ok(
    //         jsonEncode({'success': true, 'data': deviceJson}),
    //         headers: {'Content-type': 'application/json'},
    //       );
    //     } else {
    //       return Response.badRequest(body: jsonEncode({'success': false}));
    //     }
    //   } catch (e) {
    //     return Response.badRequest(body: jsonEncode({'success': false}));
    //   }
    // });

    // ///
    // /// =============================  Tile Config =================================
    // /// Get all tile configs
    // router.get('/api/tile-configs', (Request request) async {
    //   final response = await client.from('tile_config').select().execute();

    //   final tileConfigs = <dynamic>[];
    //   for (final tileConfig in response.data) {
    //     final id = tileConfig['id'];
    //     final tileType = tileConfig['tile_type'];
    //     switch (tileType) {
    //       case 0:
    //         final tileDataResponse = await client
    //             .from('toggle_tile_data')
    //             .select()
    //             .match({'id': id})
    //             .single()
    //             .execute();
    //         final toggleTileData =
    //             tileDataResponse.data as Map<String, dynamic>;
    //         toggleTileData.remove('id');
    //         toggleTileData['tile_type'] = 0;
    //         final completeTileData = Map<String, dynamic>.from(tileConfig);
    //         completeTileData['tile_data'] = toggleTileData;
    //         tileConfigs.add(completeTileData);
    //         break;
    //       case 1:
    //         final tileDataResponse = await client
    //             .from('text_tile_data')
    //             .select()
    //             .match({'id': id})
    //             .single()
    //             .execute();
    //         final textTileData = tileDataResponse.data as Map<String, dynamic>;
    //         textTileData.remove('id');
    //         textTileData['tile_type'] = 1;
    //         final completeTileData = Map<String, dynamic>.from(tileConfig);
    //         completeTileData['tile_data'] = textTileData;
    //         tileConfigs.add(completeTileData);
    //         break;
    //       default:
    //     }
    //   }

    //   return Response.ok(jsonEncode({'success': true, 'data': tileConfigs}),
    //       headers: {'Content-type': 'application/json'});
    // });

    // /// Create tile config
    // router.post('/api/tile-configs', (Request request) async {
    //   try {
    //     final payload =
    //         jsonDecode(await request.readAsString()) as Map<String, dynamic>;
    //     final id = payload['id'];
    //     final name = payload['name'];
    //     final tileType = payload['tile_type'] as int;
    //     final deviceId = payload['device_id'];
    //     final tileData = payload['tile_data'];
    //     final supabaseInstance = {
    //       'id': id as String,
    //       'device_id': deviceId as String,
    //       'name': name as String,
    //       'tile_type': tileType,
    //     };
    //     final supaReponse =
    //         await client.from('tile_config').insert(supabaseInstance).execute();
    //     final tileDataJson =
    //         Map<String, dynamic>.from((supaReponse.data as List).first);
    //     switch (tileType) {
    //       case 0:
    //         final onLabel = tileData['on_label'] as String?;
    //         final onValue = tileData['on_value'] as String;
    //         final offLabel = tileData['off_label'] as String?;
    //         final offValue = tileData['off_value'] as String;
    //         final jsonVariableId = tileData['json_variable_id'] as String?;
    //         final tileDataResponse =
    //             await client.from('toggle_tile_data').insert({
    //           'id': id,
    //           'on_label': onLabel,
    //           'on_value': onValue,
    //           'off_label': offLabel,
    //           'off_value': offValue,
    //           'json_variable_id': jsonVariableId,
    //         }).execute();
    //         final toggleTileData =
    //             (tileDataResponse.data as List).first as Map<String, dynamic>;
    //         toggleTileData.remove('id');
    //         toggleTileData['tile_type'] = 0;
    //         tileDataJson['tile_data'] = toggleTileData;
    //         break;
    //       case 1:
    //         final prefix = tileData['prefix'] as String?;
    //         final postfix = tileData['postfix'] as String?;
    //         final jsonVariableId = tileData['json_variable_id'] as String?;
    //         final tileDataResponse =
    //             await client.from('text_tile_data').insert({
    //           'id': id,
    //           'prefix': prefix,
    //           'postfix': postfix,
    //           'json_variable_id': jsonVariableId,
    //         }).execute();
    //         final textTileData =
    //             (tileDataResponse.data as List).first as Map<String, dynamic>;
    //         textTileData.remove('id');
    //         textTileData['tile_type'] = 1;
    //         tileDataJson['tile_data'] = textTileData;
    //         break;
    //     }
    //     return Response.ok(
    //       jsonEncode({'success': true, 'data': tileDataJson}),
    //       headers: {'Content-type': 'application/json'},
    //     );
    //   } catch (e) {
    //     return Response.badRequest(body: jsonEncode({'success': false}));
    //   }
    // });

    // /// Update tile config
    // router.put('/api/tile-configs', (Request request) async {
    //   try {
    //     final payload =
    //         jsonDecode(await request.readAsString()) as Map<String, dynamic>;
    //     final id = payload['id'];
    //     final name = payload['name'];
    //     final tileType = payload['tile_type'] as int;
    //     final deviceId = payload['device_id'];
    //     final tileData = payload['tile_data'];
    //     final supabaseInstance = {
    //       'id': id as String,
    //       'device_id': deviceId as String,
    //       'name': name as String,
    //       'tile_type': tileType,
    //     };
    //     final supaReponse =
    //         await client.from('tile_config').upsert(supabaseInstance).execute();
    //     final tileDataJson =
    //         Map<String, dynamic>.from((supaReponse.data as List).first);
    //     switch (tileType) {
    //       case 0:
    //         final onLabel = tileData['on_label'] as String?;
    //         final onValue = tileData['on_value'] as String;
    //         final offLabel = tileData['off_label'] as String?;
    //         final offValue = tileData['off_value'] as String;
    //         final jsonVariableId = tileData['json_variable_id'] as String?;
    //         final inserValue = {
    //           'id': id,
    //           'on_label': onLabel,
    //           'on_value': onValue,
    //           'off_label': offLabel,
    //           'off_value': offValue,
    //           'json_variable_id': jsonVariableId,
    //         };
    //         final tileDataResponse = await client
    //             .from('toggle_tile_data')
    //             .upsert(inserValue)
    //             .execute();
    //         final toggleTileData =
    //             (tileDataResponse.data as List).first as Map<String, dynamic>;
    //         toggleTileData.remove('id');
    //         toggleTileData['tile_type'] = 0;
    //         tileDataJson['tile_data'] = toggleTileData;
    //         break;
    //       case 1:
    //         final prefix = tileData['prefix'] as String?;
    //         final postfix = tileData['postfix'] as String?;
    //         final jsonVariableId = tileData['json_variable_id'] as String?;
    //         final tileDataResponse =
    //             await client.from('text_tile_data').upsert({
    //           'id': id,
    //           'prefix': prefix,
    //           'postfix': postfix,
    //           'json_variable_id': jsonVariableId,
    //         }).execute();
    //         final textTileData =
    //             (tileDataResponse.data as List).first as Map<String, dynamic>;
    //         textTileData.remove('id');
    //         textTileData['tile_type'] = 1;
    //         tileDataJson['tile_data'] = textTileData;
    //         break;
    //     }
    //     return Response.ok(
    //       jsonEncode({'success': true, 'data': tileDataJson}),
    //       headers: {'Content-type': 'application/json'},
    //     );
    //   } catch (e) {
    //     return Response.badRequest(body: jsonEncode({'success': false}));
    //   }
    // });

    // /// Delete tile config
    // router.delete('/api/tile-configs', (Request request) async {
    //   try {
    //     final payload =
    //         jsonDecode(await request.readAsString()) as Map<String, dynamic>;
    //     final id = payload['id'];
    //     await client
    //         .from('text_tile_data')
    //         .delete()
    //         .match({'id': id}).execute();
    //     await client
    //         .from('toggle_tile_data')
    //         .delete()
    //         .match({'id': id}).execute();
    //     final supaReponse = await client
    //         .from('tile_config')
    //         .delete()
    //         .match({'id': id}).execute();
    //     if (supaReponse.hasError) {
    //       return Response.ok(
    //         jsonEncode({'success': false}),
    //         headers: {'Content-type': 'application/json'},
    //       );
    //     } else {
    //       return Response.ok(
    //         jsonEncode({'success': true}),
    //         headers: {'Content-type': 'application/json'},
    //       );
    //     }
    //   } catch (e) {
    //     return Response.badRequest(body: jsonEncode({'success': false}));
    //   }
    // });
    return router;
  }
}
