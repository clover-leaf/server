import 'dart:convert';
import 'dart:math';

import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:dotenv/dotenv.dart';
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

  bool isUserJwt(Map<String, dynamic> payload) =>
      payload.containsKey('username');

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
      // ADMIN
      final resAdmin = await supabaseClient
          .rpc('create_admin', params: {'s_name': domain}).execute();
      if (resAdmin.hasError) return DatabaseError.message();
      // USER
      final resUser = await supabaseClient
          .rpc('create_user', params: {'s_name': domain}).execute();
      if (resUser.hasError) return DatabaseError.message();
      // PROJECT
      final resProject = await supabaseClient
          .rpc('create_project', params: {'s_name': domain}).execute();
      if (resProject.hasError) return DatabaseError.message();
      // USER-PROJECT
      final resUserProject = await supabaseClient
          .rpc('create_user_project', params: {'s_name': domain}).execute();
      if (resUserProject.hasError) return DatabaseError.message();
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
      if (resDevice.hasError) {
        print(resDevice.error);
        return DatabaseError.message();
      }
      // ATTRIBUTE
      final resAttribute = await supabaseClient
          .rpc('create_attribute', params: {'s_name': domain}).execute();
      if (resAttribute.hasError) {
        print(resAttribute.error);
        return DatabaseError.message();
      }
      // DASHBOARD
      final resDashboard = await supabaseClient
          .rpc('create_dashboard', params: {'s_name': domain}).execute();
      if (resDashboard.hasError) {
        print(resDashboard.error);
        return DatabaseError.message();
      }
      // TILE
      final resTile = await supabaseClient
          .rpc('create_tile', params: {'s_name': domain}).execute();
      if (resTile.hasError) {
        print(resTile.error);
        return DatabaseError.message();
      }
      // STORAGE
      final resStorage = await supabaseClient
          .rpc('create_storage', params: {'s_name': domain}).execute();
      if (resStorage.hasError) {
        print(resStorage.error);
        return DatabaseError.message();
      }
      // create SupabaseClient for new schema
      final domainClient = createSupabaseClient(domain);
      // add customer info to user table
      final resAddUser = await domainClient
          .from('admin')
          .insert({'email': email, 'salt': salt, 'hash': hash}).execute();
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

    /// POST: đăng nhập vào domain
    /// trả về jwt
    router.post('/v1/domain/login', (Request request) async {
      final payload =
          jsonDecode(await request.readAsString()) as Map<String, dynamic>;
      final domain = payload['domain'];
      final username = payload['username'];
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
      final resAdmin = await domainClient
          .from('admin')
          .select()
          .match({'email': username})
          .single()
          .execute();
      // account is admin
      if (!resAdmin.hasError) {
        // hash password with salt
        final salt = resAdmin.data['salt'];
        final bytes = utf8.encode(password + salt);
        final hash = sha256.convert(bytes).toString();
        final hashDB = resAdmin.data['hash'];
        // check password is matched
        if (hash == hashDB) {
          // jwt contain email
          final jwt = JWT({'email': username, 'domain': domain});
          final token = jwt.sign(
            SecretKey(verifyDomainSecret),
            expiresIn: verifyDomainDuration,
          );
          return Response.ok(jsonEncode({'token': token, 'isAdmin': true}));
        }
      }
      // account is user
      final resUser = await domainClient
          .from('user')
          .select()
          .match({'username': username})
          .single()
          .execute();
      if (resUser.hasError) return UserNotExistError.message();
      final passwordDB = resUser.data['password'];
      final id = resUser.data['id'];
      if (password == passwordDB) {
        // jwt contain username
        final jwt = JWT({'id': id, 'username': username, 'domain': domain});
        final token = jwt.sign(
          SecretKey(verifyDomainSecret),
          expiresIn: verifyDomainDuration,
        );
        return Response.ok(jsonEncode({'token': token, 'isAdmin': false}));
      } else {
        return EmailOrPasswordNotMatchedError.message();
      }
    });

    /// GET: lấy thông tin tài khoản của JWT
    router.get('/v1/domain/user', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        if (isUserJwt(jwtPayload)) {
          final username = jwtPayload['username'];
          final id = jwtPayload['id'];
          final res = await domainClient
              .from('user')
              .select()
              .match({'id': id})
              .single()
              .execute();
          if (res.hasError) return UnauthorizedError.message();
          return Response.ok(
              jsonEncode({'username': username, 'isAdmin': false}));
        } else {
          final email = jwtPayload['email'];
          final res = await domainClient
              .from('admin')
              .select()
              .match({'email': email})
              .single()
              .execute();
          if (res.hasError) return UnauthorizedError.message();
          return Response.ok(jsonEncode({'username': email, 'isAdmin': true}));
        }
      } catch (e) {
        return UnknownError.message();
      }
    });

    /// Lấy toàn bộ dữ liệu của schema
    router.get('/v1/domain/initial', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient.from('project').select().execute();
        if (res.hasError) return DatabaseError.message();
        // get project rows
        final resProject =
            await domainClient.from('project').select().execute();
        if (resProject.hasError) return DatabaseError.message();
        // get group rows
        final resGroup = await domainClient.from('group').select().execute();
        if (resGroup.hasError) return DatabaseError.message();
        // get broker rows
        final resBroker = await domainClient.from('broker').select().execute();
        if (resBroker.hasError) return DatabaseError.message();
        // get device rows
        final resDevice = await domainClient.from('device').select().execute();
        if (resDevice.hasError) return DatabaseError.message();
        // get attribute rows
        final resAttribute =
            await domainClient.from('attribute').select().execute();
        if (resAttribute.hasError) return DatabaseError.message();
        // get dashboard rows
        final resDashboard =
            await domainClient.from('dashboard').select().execute();
        if (resDashboard.hasError) return DatabaseError.message();
        // get tile rows
        final resTile = await domainClient.from('tile').select().execute();
        if (resTile.hasError) return DatabaseError.message();
        // get alert rows
        final resAlert = await domainClient.from('alert').select().execute();
        if (resAlert.hasError) return DatabaseError.message();
        // get condition rows
        final resCondition =
            await domainClient.from('condition').select().execute();
        if (resCondition.hasError) return DatabaseError.message();
        // get action rows
        final resAction = await domainClient.from('action').select().execute();
        if (resAction.hasError) return DatabaseError.message();
        if (isUserJwt(jwtPayload)) {
          final sysDomain = createSupabaseClient('sys');
          // is user
          final resJoin = await sysDomain
              .rpc('join_user_project', params: {'s_name': domain}).execute();
          if (resJoin.hasError) {
            print(resJoin.error);
            return DatabaseError.message();
          }
          final joinTable = resJoin.data as List<dynamic>;
          final userID = jwtPayload['id'];
          // filter by projects which user can access
          final showProjectJoins =
              joinTable.where((row) => row['user_id'] == userID).toList();
          final showProjectIDs = showProjectJoins
              .map((pr) => (pr as Map<String, dynamic>)['project_id'] as String)
              .toList();
          final projects = resProject.data as List<dynamic>;
          final showProject = projects.where((pr) {
            final prAsMap = pr as Map<String, dynamic>;
            final prID = prAsMap['id'] as String;
            return showProjectIDs.contains(prID);
          }).toList();
          // Broker
          final brokers = resBroker.data as List<dynamic>;
          final showBroker = brokers.where((br) {
            final brAsMap = br as Map<String, dynamic>;
            final brPrID = brAsMap['project_id'] as String;
            return showProjectIDs.contains(brPrID);
          }).toList();
          // Device
          final showBrokerIDs = showBroker
              .map((br) => (br as Map<String, dynamic>)['id'] as String)
              .toList();
          final devices = resDevice.data as List<dynamic>;
          final showDevice = devices.where((dv) {
            final dvAsMap = dv as Map<String, dynamic>;
            final dvBrID = dvAsMap['broker_id'] as String;
            return showBrokerIDs.contains(dvBrID);
          }).toList();
          // Attribute
          final showDeviceIDs = showDevice
              .map((dv) => (dv as Map<String, dynamic>)['id'] as String)
              .toList();
          final attributes = resAttribute.data as List<dynamic>;
          final showAttribute = attributes.where((att) {
            final attAsMap = att as Map<String, dynamic>;
            final attDvID = attAsMap['device_id'] as String;
            return showDeviceIDs.contains(attDvID);
          }).toList();
          // Dashboard
          final dashboards = resDashboard.data as List<dynamic>;
          final showDashboard = dashboards.where((db) {
            final dbAsMap = db as Map<String, dynamic>;
            final dbPrID = dbAsMap['project_id'] as String;
            return showProjectIDs.contains(dbPrID);
          }).toList();
          // Tile
          final showDashboardIDs = showDashboard
              .map((db) => (db as Map<String, dynamic>)['id'] as String)
              .toList();
          final tiles = resTile.data as List<dynamic>;
          final showTile = tiles.where((tl) {
            final tlAsMap = tl as Map<String, dynamic>;
            final tlDbID = tlAsMap['dashboard_id'] as String;
            return showDashboardIDs.contains(tlDbID);
          }).toList();
          // Alert
          final alerts = resAlert.data as List<dynamic>;
          final showAlert = alerts.where((al) {
            final alAsMap = al as Map<String, dynamic>;
            final alDvID = alAsMap['device_id'] as String;
            return showDeviceIDs.contains(alDvID);
          }).toList();
          // Condition
          final showAlertIDs = showAlert
              .map((al) => (al as Map<String, dynamic>)['id'] as String)
              .toList();
          final conditions = resCondition.data as List<dynamic>;
          final showCondition = conditions.where((cd) {
            final cdAsMap = cd as Map<String, dynamic>;
            final cdAlID = cdAsMap['alert_id'] as String;
            return showAlertIDs.contains(cdAlID);
          }).toList();
          // Action
          final actions = resAction.data as List<dynamic>;
          final showAction = actions.where((ac) {
            final acAsMap = ac as Map<String, dynamic>;
            final acAlID = acAsMap['alert_id'] as String;
            return showAlertIDs.contains(acAlID);
          }).toList();
          return Response.ok(jsonEncode({
            'projects': showProject,
            'brokers': showBroker,
            'groups': resGroup.data,
            'devices': showDevice,
            'attributes': showAttribute,
            'dashboards': showDashboard,
            'tiles': showTile,
            'alerts': showAlert,
            'conditions': showCondition,
            'actions': showAction,
          }));
        } else {
          // is admin then we query data from table user and user_project
          // get user rows
          final resUser = await domainClient.from('user').select().execute();
          if (resUser.hasError) return DatabaseError.message();
          // get user_project rows
          final resUserProject =
              await domainClient.from('user_project').select().execute();
          if (resUserProject.hasError) return DatabaseError.message();
          return Response.ok(jsonEncode({
            'projects': resProject.data,
            'users': resUser.data,
            'user-projects': resUserProject.data,
            'brokers': resBroker.data,
            'groups': resGroup.data,
            'devices': resDevice.data,
            'attributes': resAttribute.data,
            'dashboards': resDashboard.data,
            'tiles': resTile.data,
            'alerts': resAlert.data,
            'conditions': resCondition.data,
            'actions': resAction.data,
          }));
        }
      } catch (e) {
        print(e.toString());
        return UnknownError.message();
      }
    });

    // ================== USER REST API ========================
    /// POST: tạo mới một tài khoản người dùng
    /// admin: ok
    /// user: cấm
    router.post('/v1/domain/users', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        if (isUserJwt(jwtPayload)) return ForbiddenError.message();
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // decode request payload
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final id = payload['id'];
        final username = payload['username'];
        final password = payload['password'];
        final res = await domainClient.from('user').insert({
          'id': id,
          'username': username,
          'password': password,
        }).execute();
        if (res.hasError) return DatabaseError.message();
        return Response.ok(jsonEncode({
          'id': id,
          'username': username,
          'password': password,
        }));
      } catch (e) {
        print(e);
        return UnknownError.message();
      }
    });

    /// GET: lấy danh sách tài khoản người dùng
    /// admin: ok
    /// user: cấm
    router.get('/v1/domain/users', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        if (isUserJwt(jwtPayload)) return ForbiddenError.message();
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient.from('user').select().execute();
        if (res.hasError) return DatabaseError.message();
        return Response.ok(jsonEncode({'users': res.data}));
      } catch (e) {
        return UnknownError.message();
      }
    });

    /// GET: lấy chi tiết tài khoản người dùng với id cụ thể
    /// admin: ok
    /// user: cấm
    router.get('/v1/domain/users/<user_id>',
        (Request request, String userID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        if (isUserJwt(jwtPayload)) return ForbiddenError.message();
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient
            .from('user')
            .select()
            .match({'id': userID})
            .single()
            .execute();
        if (res.hasError) return ProjectNotExistError.message();
        return Response.ok(jsonEncode(res.data));
      } catch (e) {
        print(e);
        return UnknownError.message();
      }
    });

    /// PUT: cập nhật tài khoản người dùng với id cụ thể
    /// admin: ok
    /// user: cấm
    router.put('/v1/domain/users/<user_id>',
        (Request request, String userID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        if (isUserJwt(jwtPayload)) return ForbiddenError.message();
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // decode request payload
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final username = payload['username'];
        final password = payload['password'];
        final res = await domainClient.from('user').update({
          'username': username,
          'password': password,
        }).match({'id': userID}).execute();
        if (res.hasError) return ProjectNotExistError.message();
        return Response.ok(jsonEncode({
          'id': userID,
          'username': username,
          'password': password,
        }));
      } catch (e) {
        return UnknownError.message();
      }
    });

    /// DELETE: xóa tài khoản người dùng với id cụ thể
    /// admin: ok
    /// user: cấm
    router.delete('/v1/domain/users/<user_id>',
        (Request request, String userID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        if (isUserJwt(jwtPayload)) return ForbiddenError.message();
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient
            .from('user')
            .delete()
            .match({'id': userID}).execute();
        if (res.hasError) return ProjectNotExistError.message();
        return Response.ok(null);
      } catch (e) {
        return UnknownError.message();
      }
    });
    // ================== USER REST API ========================

    // ================== USER-PROJECT REST API ========================
    /// POST: cho phép một người dùng truy cập 1 dự án
    /// admin: ok
    /// user: cấm
    router.post('/v1/domain/users-projects', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        if (isUserJwt(jwtPayload)) return ForbiddenError.message();
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // decode request payload
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final id = payload['id'];
        final userID = payload['user_id'];
        final projectID = payload['project_id'];
        final res = await domainClient.from('user_project').insert({
          'id': id,
          'user_id': userID,
          'project_id': projectID,
        }).execute();
        if (res.hasError) return DatabaseError.message();
        return Response.ok(jsonEncode({
          'id': id,
          'user_id': userID,
          'project_id': projectID,
        }));
      } catch (e) {
        return UnknownError.message();
      }
    });

    /// GET: lấy danh sách người dùng được truy cập vào dự án
    /// admin: ok
    /// user: cấm
    router.get('/v1/domain/users-projects', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        if (isUserJwt(jwtPayload)) return ForbiddenError.message();
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient.from('user_project').select().execute();
        if (res.hasError) return DatabaseError.message();
        return Response.ok(jsonEncode({'users-projects': res.data}));
      } catch (e) {
        return UnknownError.message();
      }
    });

    /// GET: lấy danh sách người dùng được truy cập vào
    /// dự án với id cụ thể
    /// admin: ok
    /// user: cấm
    router.get('/v1/domain/users-projects/<id>',
        (Request request, String id) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        if (isUserJwt(jwtPayload)) return ForbiddenError.message();
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient
            .from('user_project')
            .select()
            .match({'id': id}).execute();
        if (res.hasError) return DatabaseError.message();
        return Response.ok(jsonEncode({'users-projects': res.data}));
      } catch (e) {
        return UnknownError.message();
      }
    });

    /// PUT: cập nhật một record người dùng có thể truy cập dự án
    /// admin: ok
    /// user: cấm
    router.put('/v1/domain/users-projects/<id>',
        (Request request, String id) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        if (isUserJwt(jwtPayload)) return ForbiddenError.message();
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // decode request payload
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final userID = payload['user_id'];
        final projectID = payload['project_id'];
        final res = await domainClient.from('user_project').update({
          'user_id': userID,
          'project_id': projectID,
        }).match({'id': id}).execute();
        if (res.hasError) return ProjectNotExistError.message();
        return Response.ok(jsonEncode({
          'id': id,
          'user_id': userID,
          'project_id': projectID,
        }));
      } catch (e) {
        return UnknownError.message();
      }
    });

    /// DELETE: xóa quyền truy cập của người dùng vào dự án
    /// admin: ok
    /// user: cấm
    router.delete('/v1/domain/users-projects/<id>',
        (Request request, String id) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        if (isUserJwt(jwtPayload)) return ForbiddenError.message();
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient
            .from('user_project')
            .delete()
            .match({'id': id}).execute();
        if (res.hasError) {
          print(res.error);
          return UserProjectNotExistError.message();
        }
        return Response.ok(null);
      } catch (e) {
        return UnknownError.message();
      }
    });
    // ================== USER-PROJECT REST API ========================

    // ================== PROJECT REST API ========================
    /// POST: tạo mới một dự án
    /// admin: ok
    /// user: cấm
    router.post('/v1/domain/projects', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        if (isUserJwt(jwtPayload)) return ForbiddenError.message();
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

    /// GET: lấy danh sách dự án
    /// admin: ok
    /// user: chỉ trả về các project mà user được cho phép truy cập
    router.get('/v1/domain/projects', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        if (isUserJwt(jwtPayload)) {
          // is user
          final resJoin = await domainClient
              .rpc('join_user_project', params: {'s_name': domain}).execute();
          if (resJoin.hasError) return DatabaseError.message();
          final joinTable = resJoin.data as List<dynamic>;
          final userID = jwtPayload['id'];
          final showProject =
              joinTable.where((row) => row['user_id'] == userID).toList();
          return Response.ok(jsonEncode({'projects': showProject}));
        } else {
          // is admin
          final res = await domainClient.from('project').select().execute();
          if (res.hasError) return DatabaseError.message();
          return Response.ok(jsonEncode({'projects': res.data}));
        }
      } catch (e) {
        return UnknownError.message();
      }
    });

    // GET: lấy chi tiết dự án với id cụ thể
    /// admin: ok
    /// user: cấm
    router.get('/v1/domain/projects/<project_id>',
        (Request request, String projectID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        if (isUserJwt(jwtPayload)) return ForbiddenError();
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
    /// admin: ok
    /// user: cấm
    router.put('/v1/domain/projects/<project_id>',
        (Request request, String projectID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        if (isUserJwt(jwtPayload)) return ForbiddenError();
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
    /// admin: ok
    /// user: cấm
    router.delete('/v1/domain/projects/<project_id>',
        (Request request, String projectID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        if (isUserJwt(jwtPayload)) return ForbiddenError();
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
    // ================== PROJECT REST API ========================

    // ================== GROUP REST API ========================
    // POST: tạo mới một nhóm
    // admin: ok
    // user: cấm
    router.post('/v1/domain/groups', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        if (isUserJwt(jwtPayload)) return ForbiddenError();
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
    // admin: ok
    // user: chỉ trả về group người dùng đc phép truy cập
    router.get('/v1/domain/groups', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient.from('group').select().execute();
        if (res.hasError) return DatabaseError.message();
        if (isUserJwt(jwtPayload)) {
          // is user
          // final userID = jwtPayload['id'];
          // final resUsPr = await domainClient
          //     .from('user_project')
          //     .select('project_id')
          //     .match({'user_id': userID}).execute();
          // if (resUsPr.hasError) return DatabaseError.message();
          return Response.ok(jsonEncode({'groups': res.data}));
        } else {
          // is admin
          return Response.ok(jsonEncode({'groups': res.data}));
        }
      } catch (e) {
        return UnknownError.message();
      }
    });

    // GET: lấy chi tiết nhóm với id cụ thể
    // admin: ok
    // user: cấm
    router.get('/v1/domain/groups/<group_id>',
        (Request request, String groupID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        if (isUserJwt(jwtPayload)) return ForbiddenError();
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
    // admin: ok
    // user: cấm
    router.put('/v1/domain/groups/<group_id>',
        (Request request, String id) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        if (isUserJwt(jwtPayload)) return ForbiddenError();
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
    // admin: ok
    // user: cấm
    router.delete('/v1/domain/groups/<group_id>',
        (Request request, String groupID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        if (isUserJwt(jwtPayload)) return ForbiddenError();
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
    // ================== GROUP REST API ========================

    // ================== DEVICE REST API ========================
    // POST: tạo mới một thiết bị
    router.post('/v1/domain/devices', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        if (isUserJwt(jwtPayload)) return ForbiddenError.message();
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
        final res = await domainClient.from('device').insert({
          'id': id,
          'group_id': groupID,
          'broker_id': brokerID,
          'name': name,
          'topic': topic
        }).execute();
        if (res.hasError) return DatabaseError.message();
        return Response.ok(jsonEncode({
          'id': id,
          'group_id': groupID,
          'broker_id': brokerID,
          'name': name,
          'topic': topic,
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
        final res = await domainClient.from('device').update({
          'group_id': groupID,
          'broker_id': brokerID,
          'name': name,
          'topic': topic,
        }).match({'id': deviceID}).execute();
        if (res.hasError) return DeviceNotExistError.message();
        return Response.ok(jsonEncode({
          'id': deviceID,
          'group_id': groupID,
          'broker_id': brokerID,
          'name': name,
          'topic': topic,
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
    // ================== DEVICE REST API ========================

    // ================== BROKER REST API ========================
    // POST: tạo mới một diểm giao
    router.post('/v1/domain/brokers', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        if (isUserJwt(jwtPayload)) return ForbiddenError.message();
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // decode request payload
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final id = payload['id'];
        final projectID = payload['project_id'];
        final name = payload['name'];
        final url = payload['url'];
        final port = payload['port'];
        final account = payload['account'];
        final password = payload['password'];
        final res = await domainClient.from('broker').insert({
          'id': id,
          'project_id': projectID,
          'name': name,
          'url': url,
          'port': port,
          'account': account,
          'password': password,
        }).execute();
        if (res.hasError) {
          print(res.error);
          return DatabaseError.message();
        }
        return Response.ok(jsonEncode({
          'id': id,
          'project_id': projectID,
          'name': name,
          'url': url,
          'port': port,
          'account': account,
          'password': password,
        }));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // GET: lấy danh sách điểm giao
    router.get('/v1/domain/brokers', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient.from('broker').select().execute();
        if (res.hasError) {
          return DatabaseError.message();
        }
        return Response.ok(jsonEncode({'brokers': res.data}));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // GET: lấy chi tiết điểm giao với id cụ thể
    router.get('/v1/domain/brokers/<broker_id>',
        (Request request, String brokerID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient
            .from('broker')
            .select()
            .match({'id': brokerID})
            .single()
            .execute();
        if (res.hasError) return DeviceNotExistError.message();
        return Response.ok(jsonEncode(res.data));
      } catch (e) {
        print(e);
        return UnknownError.message();
      }
    });

    // PUT: cập nhật điểm giao với id cụ thể
    router.put('/v1/domain/brokers/<broker_id>',
        (Request request, String brokerID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // decode request payload
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final projectID = payload['project_id'];
        final name = payload['name'];
        final url = payload['url'];
        final port = payload['port'];
        final account = payload['account'];
        final password = payload['password'];
        final res = await domainClient.from('broker').update({
          'project_id': projectID,
          'name': name,
          'url': url,
          'port': port,
          'account': account,
          'password': password,
        }).match({'id': brokerID}).execute();
        if (res.hasError) return BrokerNotExistError.message();
        return Response.ok(jsonEncode({
          'id': brokerID,
          'project_id': projectID,
          'name': name,
          'url': url,
          'port': port,
          'account': account,
          'password': password,
        }));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // DELETE: xóa điểm giao với id cụ thể
    router.delete('/v1/domain/brokers/<broker_id>',
        (Request request, String brokerID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient
            .from('broker')
            .delete()
            .match({'id': brokerID}).execute();
        if (res.hasError) return BrokerNotExistError.message();
        return Response.ok(null);
      } catch (e) {
        return UnknownError.message();
      }
    });
    // ================== BROKER REST API ========================

    // ================== ATTRIBUTE REST API ========================
    // POST: tạo mới một thuộc tính
    router.post('/v1/domain/attributes', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        if (isUserJwt(jwtPayload)) return ForbiddenError.message();
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // decode request payload
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final id = payload['id'];
        final deviceID = payload['device_id'];
        final name = payload['name'];
        final jsonPath = payload['json_path'];
        final unit = payload['unit'];
        final res = await domainClient.from('attribute').insert({
          'id': id,
          'device_id': deviceID,
          'name': name,
          'json_path': jsonPath,
          'unit': unit,
        }).execute();
        if (res.hasError) return DatabaseError.message();
        return Response.ok(jsonEncode({
          'id': id,
          'device_id': deviceID,
          'name': name,
          'json_path': jsonPath,
          'unit': unit,
        }));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // GET: lấy danh sách thuộc tính
    router.get('/v1/domain/attributes', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient.from('attribute').select().execute();
        if (res.hasError) {
          return DatabaseError.message();
        }
        return Response.ok(jsonEncode({'attributes': res.data}));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // GET: lấy chi tiết thuộc tính với id cụ thể
    router.get('/v1/domain/attributes/<attribute_id>',
        (Request request, String attributeID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient
            .from('attribute')
            .select()
            .match({'id': attributeID})
            .single()
            .execute();
        if (res.hasError) return DeviceNotExistError.message();
        return Response.ok(jsonEncode(res.data));
      } catch (e) {
        print(e);
        return UnknownError.message();
      }
    });

    // PUT: cập nhật thuộc tính với id cụ thể
    router.put('/v1/domain/attributes/<attribute_id>',
        (Request request, String attributeID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // decode request payload
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final deviceID = payload['device_id'];
        final name = payload['name'];
        final jsonPath = payload['json_path'];
        final unit = payload['unit'];
        final res = await domainClient.from('attribute').update({
          'device_id': deviceID,
          'name': name,
          'json_path': jsonPath,
          'unit': unit,
        }).match({'id': attributeID}).execute();
        if (res.hasError) return DeviceNotExistError.message();
        return Response.ok(jsonEncode({
          'id': attributeID,
          'device_id': deviceID,
          'name': name,
          'json_path': jsonPath,
          'unit': unit,
        }));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // DELETE: xóa thuộc tính với id cụ thể
    router.delete('/v1/domain/attributes/<attribute_id>',
        (Request request, String attributeID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient
            .from('attribute')
            .delete()
            .match({'id': attributeID}).execute();
        if (res.hasError) return AttributeNotExistError.message();
        return Response.ok(null);
      } catch (e) {
        return UnknownError.message();
      }
    });
    // ================== ATTRIBUTE REST API ========================

    // ================== DASHBOARD REST API ========================
    // POST: tạo mới một bảng theo dõi
    router.post('/v1/domain/dashboards', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        if (isUserJwt(jwtPayload)) return ForbiddenError.message();
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // decode request payload
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final id = payload['id'];
        final projectID = payload['project_id'];
        final name = payload['name'];
        final res = await domainClient.from('dashboard').insert({
          'id': id,
          'project_id': projectID,
          'name': name,
        }).execute();
        if (res.hasError) return DatabaseError.message();
        return Response.ok(jsonEncode({
          'id': id,
          'project_id': projectID,
          'name': name,
        }));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // GET: lấy danh sách bảng theo dõi
    router.get('/v1/domain/dashboards', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient.from('dashboard').select().execute();
        if (res.hasError) {
          return DatabaseError.message();
        }
        return Response.ok(jsonEncode({'dashboards': res.data}));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // GET: lấy chi tiết bảng theo dõi với id cụ thể
    router.get('/v1/domain/dashboards/<dashboard_id>',
        (Request request, String dashboardID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient
            .from('dashboard')
            .select()
            .match({'id': dashboardID})
            .single()
            .execute();
        if (res.hasError) return DeviceNotExistError.message();
        return Response.ok(jsonEncode(res.data));
      } catch (e) {
        print(e);
        return UnknownError.message();
      }
    });

    // PUT: cập nhật bảng theo dõi với id cụ thể
    router.put('/v1/domain/dashboards/<dashboard_id>',
        (Request request, String dashboardID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // decode request payload
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final projectID = payload['project_id'];
        final name = payload['name'];
        final res = await domainClient.from('dashboard').update({
          'project_id': projectID,
          'name': name,
        }).match({'id': dashboardID}).execute();
        if (res.hasError) return DeviceNotExistError.message();
        return Response.ok(jsonEncode({
          'id': dashboardID,
          'project_id': projectID,
          'name': name,
        }));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // DELETE: xóa bảng theo dõi với id cụ thể
    router.delete('/v1/domain/dashboards/<dashboard_id>',
        (Request request, String dashboardID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient
            .from('dashboard')
            .delete()
            .match({'id': dashboardID}).execute();
        if (res.hasError) return AttributeNotExistError.message();
        return Response.ok(null);
      } catch (e) {
        return UnknownError.message();
      }
    });
    // ================== DASHBOARD REST API ========================

    // ================== TILE REST API ========================
    // POST: tạo mới một ô theo dõi
    router.post('/v1/domain/tiles', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        if (isUserJwt(jwtPayload)) return ForbiddenError.message();
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // decode request payload
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final id = payload['id'];
        final dashboardID = payload['dashboard_id'];
        final deviceID = payload['device_id'];
        final attributeID = payload['attribute_id'];
        final name = payload['name'];
        final type = payload['type'];
        final lob = payload['lob'];
        final color = payload['color'];
        final icon = payload['icon'];
        final res = await domainClient.from('tile').insert({
          'id': id,
          'dashboard_id': dashboardID,
          'device_id': deviceID,
          'attribute_id': attributeID,
          'name': name,
          'type': type,
          'lob': lob,
          'color': color,
          'icon': icon,
        }).execute();
        if (res.hasError) return DatabaseError.message();
        return Response.ok(jsonEncode({
          'id': id,
          'dashboard_id': dashboardID,
          'device_id': deviceID,
          'attribute_id': attributeID,
          'name': name,
          'type': type,
          'lob': lob,
          'color': color,
          'icon': icon,
        }));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // GET: lấy danh sách ô theo dõi
    router.get('/v1/domain/tiles', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient.from('tile').select().execute();
        if (res.hasError) {
          return DatabaseError.message();
        }
        return Response.ok(jsonEncode({'tiles': res.data}));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // GET: lấy chi tiết ô theo dõi với id cụ thể
    router.get('/v1/domain/tiles/<tile_id>',
        (Request request, String tileID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient
            .from('tile')
            .select()
            .match({'id': tileID})
            .single()
            .execute();
        if (res.hasError) return DeviceNotExistError.message();
        return Response.ok(jsonEncode(res.data));
      } catch (e) {
        print(e);
        return UnknownError.message();
      }
    });

    // PUT: cập nhật ô theo dõi với id cụ thể
    router.put('/v1/domain/tiles/<tile_id>',
        (Request request, String tileID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // decode request payload
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final dashboardID = payload['dashboard_id'];
        final deviceID = payload['device_id'];
        final attributeID = payload['attribute_id'];
        final name = payload['name'];
        final type = payload['type'];
        final lob = payload['lob'];
        final color = payload['color'];
        final icon = payload['icon'];
        final res = await domainClient.from('tile').update({
          'dashboard_id': dashboardID,
          'device_id': deviceID,
          'attribute_id': attributeID,
          'name': name,
          'type': type,
          'lob': lob,
          'color': color,
          'icon': icon,
        }).match({'id': tileID}).execute();
        if (res.hasError) return DeviceNotExistError.message();
        return Response.ok(jsonEncode({
          'id': tileID,
          'dashboard_id': dashboardID,
          'device_id': deviceID,
          'attribute_id': attributeID,
          'name': name,
          'type': type,
          'lob': lob,
          'color': color,
          'icon': icon,
        }));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // DELETE: xóa ô theo dõi với id cụ thể
    router.delete('/v1/domain/tiles/<tile_id>',
        (Request request, String tileID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient
            .from('tile')
            .delete()
            .match({'id': tileID}).execute();
        if (res.hasError) return AttributeNotExistError.message();
        return Response.ok(null);
      } catch (e) {
        return UnknownError.message();
      }
    });
    // ================== TILE REST API ========================

    // ================== ALERT REST API ========================
    // POST: tạo mới một ô theo dõi
    router.post('/v1/domain/alerts', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        if (isUserJwt(jwtPayload)) return ForbiddenError.message();
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // decode request payload
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final id = payload['id'];
        final deviceID = payload['device_id'];
        final name = payload['name'];
        final res = await domainClient.from('alert').insert({
          'id': id,
          'device_id': deviceID,
          'name': name,
        }).execute();
        if (res.hasError) return DatabaseError.message();
        return Response.ok(jsonEncode({
          'id': id,
          'device_id': deviceID,
          'name': name,
        }));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // GET: lấy danh sách ô theo dõi
    router.get('/v1/domain/alerts', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient.from('alert').select().execute();
        if (res.hasError) {
          return DatabaseError.message();
        }
        return Response.ok(jsonEncode({'alerts': res.data}));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // GET: lấy chi tiết ô theo dõi với id cụ thể
    router.get('/v1/domain/alerts/<alert_id>',
        (Request request, String alertID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient
            .from('alert')
            .select()
            .match({'id': alertID})
            .single()
            .execute();
        if (res.hasError) return DeviceNotExistError.message();
        return Response.ok(jsonEncode(res.data));
      } catch (e) {
        print(e);
        return UnknownError.message();
      }
    });

    // PUT: cập nhật ô theo dõi với id cụ thể
    router.put('/v1/domain/alerts/<alert_id>',
        (Request request, String alertID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // decode request payload
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final deviceID = payload['device_id'];
        final name = payload['name'];
        final res = await domainClient.from('alert').update({
          'device_id': deviceID,
          'name': name,
        }).match({'id': alertID}).execute();
        if (res.hasError) return DeviceNotExistError.message();
        return Response.ok(jsonEncode({
          'id': alertID,
          'device_id': deviceID,
          'name': name,
        }));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // DELETE: xóa ô theo dõi với id cụ thể
    router.delete('/v1/domain/alerts/<alert_id>',
        (Request request, String alertID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient
            .from('alert')
            .delete()
            .match({'id': alertID}).execute();
        if (res.hasError) return AttributeNotExistError.message();
        return Response.ok(null);
      } catch (e) {
        return UnknownError.message();
      }
    });
    // ================== ALERT REST API ========================

    // ================== CONDITION REST API ========================
    // POST: tạo mới một ô theo dõi
    router.post('/v1/domain/conditions', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        if (isUserJwt(jwtPayload)) return ForbiddenError.message();
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // decode request payload
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final id = payload['id'];
        final alertID = payload['alert_id'];
        final attributeID = payload['attribute_id'];
        final comparison = payload['comparison'];
        final value = payload['value'];
        final res = await domainClient.from('condition').insert({
          'id': id,
          'alert_id': alertID,
          'attribute_id': attributeID,
          'comparison': comparison,
          'value': value,
        }).execute();
        if (res.hasError) return DatabaseError.message();
        return Response.ok(jsonEncode({
          'id': id,
          'alert_id': alertID,
          'attribute_id': attributeID,
          'comparison': comparison,
          'value': value,
        }));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // GET: lấy danh sách ô theo dõi
    router.get('/v1/domain/conditions', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient.from('condition').select().execute();
        if (res.hasError) {
          return DatabaseError.message();
        }
        return Response.ok(jsonEncode({'conditions': res.data}));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // GET: lấy chi tiết ô theo dõi với id cụ thể
    router.get('/v1/domain/conditions/<condition_id>',
        (Request request, String conditionID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient
            .from('condition')
            .select()
            .match({'id': conditionID})
            .single()
            .execute();
        if (res.hasError) return DeviceNotExistError.message();
        return Response.ok(jsonEncode(res.data));
      } catch (e) {
        print(e);
        return UnknownError.message();
      }
    });

    // PUT: cập nhật ô theo dõi với id cụ thể
    router.put('/v1/domain/conditions/<condition_id>',
        (Request request, String conditionID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // decode request payload
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final alertID = payload['alert_id'];
        final attributeID = payload['attribute_id'];
        final comparison = payload['comparison'];
        final value = payload['value'];
        final res = await domainClient.from('condition').update({
          'alert_id': alertID,
          'attribute_id': attributeID,
          'comparison': comparison,
          'value': value,
        }).match({'id': conditionID}).execute();
        if (res.hasError) return DeviceNotExistError.message();
        return Response.ok(jsonEncode({
          'id': conditionID,
          'alert_id': alertID,
          'attribute_id': attributeID,
          'comparison': comparison,
          'value': value,
        }));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // DELETE: xóa ô theo dõi với id cụ thể
    router.delete('/v1/domain/conditions/<condition_id>',
        (Request request, String conditionID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient
            .from('condition')
            .delete()
            .match({'id': conditionID}).execute();
        if (res.hasError) return AttributeNotExistError.message();
        return Response.ok(null);
      } catch (e) {
        return UnknownError.message();
      }
    });
    // ================== CONDITION REST API ========================

    // ================== ACTION REST API ========================
    // POST: tạo mới một ô theo dõi
    router.post('/v1/domain/actions', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        if (isUserJwt(jwtPayload)) return ForbiddenError.message();
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // decode request payload
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final id = payload['id'];
        final alertID = payload['alert_id'];
        final deviceID = payload['device_id'];
        final attributeID = payload['attribute_id'];
        final value = payload['value'];
        final res = await domainClient.from('action').insert({
          'id': id,
          'alert_id': alertID,
          'device_id': deviceID,
          'attribute_id': attributeID,
          'value': value,
        }).execute();
        if (res.hasError) return DatabaseError.message();
        return Response.ok(jsonEncode({
          'id': id,
          'alert_id': alertID,
          'device_id': deviceID,
          'attribute_id': attributeID,
          'value': value,
        }));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // GET: lấy danh sách ô theo dõi
    router.get('/v1/domain/actions', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient.from('action').select().execute();
        if (res.hasError) {
          return DatabaseError.message();
        }
        return Response.ok(jsonEncode({'actions': res.data}));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // GET: lấy chi tiết ô theo dõi với id cụ thể
    router.get('/v1/domain/actions/<action_id>',
        (Request request, String actionID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient
            .from('action')
            .select()
            .match({'id': actionID})
            .single()
            .execute();
        if (res.hasError) return DeviceNotExistError.message();
        return Response.ok(jsonEncode(res.data));
      } catch (e) {
        print(e);
        return UnknownError.message();
      }
    });

    // PUT: cập nhật ô theo dõi với id cụ thể
    router.put('/v1/domain/actions/<action_id>',
        (Request request, String actionID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // decode request payload
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final alertID = payload['alert_id'];
        final deviceID = payload['device_id'];
        final attributeID = payload['attribute_id'];
        final value = payload['value'];
        final res = await domainClient.from('action').update({
          'alert_id': alertID,
          'device_id': deviceID,
          'attribute_id': attributeID,
          'value': value,
        }).match({'id': actionID}).execute();
        if (res.hasError) return DeviceNotExistError.message();
        return Response.ok(jsonEncode({
          'id': actionID,
          'alert_id': alertID,
          'device_id': deviceID,
          'attribute_id': attributeID,
          'value': value,
        }));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // DELETE: xóa ô theo dõi với id cụ thể
    router.delete('/v1/domain/actions/<action_id>',
        (Request request, String actionID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient
            .from('action')
            .delete()
            .match({'id': actionID}).execute();
        if (res.hasError) return AttributeNotExistError.message();
        return Response.ok(null);
      } catch (e) {
        return UnknownError.message();
      }
    });
    // ================== ACTION REST API ========================

    // ================== LOG REST API ========================
    // POST: tạo mới một ô theo dõi
    router.post('/v1/domain/logs', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        if (isUserJwt(jwtPayload)) return ForbiddenError.message();
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // decode request payload
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final id = payload['id'];
        final alertID = payload['alert_id'];
        final time = payload['time'];
        final res = await domainClient.from('log').insert({
          'id': id,
          'alert_id': alertID,
          'time': time,
        }).execute();
        if (res.hasError) return DatabaseError.message();
        return Response.ok(jsonEncode({
          'id': id,
          'alert_id': alertID,
          'time': time,
        }));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // GET: lấy danh sách ô theo dõi
    router.get('/v1/domain/logs', (Request request) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient.from('log').select().execute();
        if (res.hasError) {
          return DatabaseError.message();
        }
        return Response.ok(jsonEncode({'logs': res.data}));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // GET: lấy chi tiết ô theo dõi với id cụ thể
    router.get('/v1/domain/logs/<log_id>',
        (Request request, String logID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient
            .from('log')
            .select()
            .match({'id': logID})
            .single()
            .execute();
        if (res.hasError) return DeviceNotExistError.message();
        return Response.ok(jsonEncode(res.data));
      } catch (e) {
        print(e);
        return UnknownError.message();
      }
    });

    // PUT: cập nhật ô theo dõi với id cụ thể
    router.put('/v1/domain/logs/<log_id>',
        (Request request, String logID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        // decode request payload
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final alertID = payload['alert_id'];
        final time = payload['time'];
        final res = await domainClient.from('log').update({
          'alert_id': alertID,
          'time': time,
        }).match({'id': logID}).execute();
        if (res.hasError) return DeviceNotExistError.message();
        return Response.ok(jsonEncode({
          'id': logID,
          'alert_id': alertID,
          'time': time,
        }));
      } catch (e) {
        return UnknownError.message();
      }
    });

    // DELETE: xóa ô theo dõi với id cụ thể
    router.delete('/v1/domain/logs/<log_id>',
        (Request request, String logID) async {
      final header = request.headers['Authorization'];
      try {
        final jwtPayload = verifyJwt(header, verifyDomainSecret);
        final domain = jwtPayload['domain'];
        final domainClient = await getDomainClient(domain);
        final res = await domainClient
            .from('log')
            .delete()
            .match({'id': logID}).execute();
        if (res.hasError) return AttributeNotExistError.message();
        return Response.ok(null);
      } catch (e) {
        return UnknownError.message();
      }
    });
    // ================== LOG REST API ========================
    return router;
  }
}
