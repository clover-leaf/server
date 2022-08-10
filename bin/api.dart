import 'dart:convert';
import 'dart:math';

import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf_router/shelf_router.dart';
import 'package:supabase/supabase.dart';
import 'package:http/http.dart' as http;
import 'package:crypto/crypto.dart';
import 'package:uuid/uuid.dart';

class Api {
  String generateRandomString(int len) {
    var r = Random.secure();
    const chars =
        'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz1234567890';
    return List.generate(len, (index) => chars[r.nextInt(chars.length)]).join();
  }

  Handler get handler {
    final router = Router();
    final httpClient = http.Client();
    final client = SupabaseClient(
      'https://mwwncvkpflyreaofpapd.supabase.co',
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.'
          'eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im13d25jdmtwZmx5cmVhb2ZwYXBkIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTY1OTE3NjQ3MywiZXhwIjoxOTc0NzUyNDczfQ.'
          'rmqW5s0jSY_1f4NPdIdnuBW9pR1nEJRcMdJWqgB7Ekc',
      schema: 'sys',
    );

    const kBaseURL = 'io.adafruit.com';
    const ioKey = 'aio_TanT84FMKkLpM2wYCrOIbOMUCwmW';
    const username = 'thangnguyen106';
    const serviceID = 'service_ug3gq7y';
    const templateID = 'template_gwu7agv';
    const userID = 'PnSycmtlbZDY8Knrw';
    const secretKey = 'VfyVZu_FdIUwQgmsOulUg';
    const verifyEmailSecret = 'thitthanxiumai';
    const verifyEmailDuration = Duration(minutes: 5);

    /// ====================== AUTH ==============================

    /// Send email to verify
    Future<Response> sendVerifiedEmail({
      required String name,
      required String email,
      required String verifiedLink,
    }) async {
      final uri = Uri.parse('https://api.emailjs.com/api/v1.0/email/send');
      final verifiedRes = await http.post(
        uri,
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode({
          'service_id': serviceID,
          'template_id': templateID,
          'user_id': userID,
          'accessToken': secretKey,
          'template_params': {
            'to_name': name,
            'to_email': email,
            'link': verifiedLink,
          },
        }),
      );
      if (verifiedRes.statusCode == 200) {
        return Response.ok(jsonEncode(
          {
            'data':
                'Check link in email to verify. The link will expire in 5 minutes'
          },
        ));
      } else {
        return Response.badRequest(
            body: jsonEncode(
          {'error': 'There is a error in SMTP service has happened'},
        ));
      }
    }

    /// Sign up
    router.post('/api/register', (Request request) async {
      final payload =
          jsonDecode(await request.readAsString()) as Map<String, dynamic>;
      final name = payload['name'];
      final email = payload['email'];
      final password = payload['password'];
      // create uuid  
      final id = Uuid().v4();
      // hash password with salt
      final salt = generateRandomString(6);
      final bytes = utf8.encode(password + salt);
      final hash = sha256.convert(bytes).toString();
      // create verified hash to confirm email
      final verifiedSalt = utf8.encode(generateRandomString(18));
      final verifiedHash = sha256.convert(verifiedSalt).toString();
      // insert new user info
      final res = await client.from('customer').insert({
        'id': id,
        'email': email,
        'name': name,
        'salt': salt,
        'hash': hash,
        'email_verified': false,
        'verified_hash': verifiedHash,
      }).execute();
      if (res.hasError) {
        print(res.error);
        return Response.badRequest(
            body: jsonEncode(
          {'error': 'This email has been used'},
        ));
      }
      // create jwt token to confirm
      final jwt = JWT({'email': email, 'verified_hash': verifiedHash});
      final token = jwt.sign(
        SecretKey(verifyEmailSecret),
        expiresIn: verifyEmailDuration,
      );
      final verifiedLink = '0.0.0.0:8080/api/verify-email/$token';
      // send confirm email
      return sendVerifiedEmail(
        email: email,
        name: name,
        verifiedLink: verifiedLink,
      );
    });

    /// Resend verify email
    router.post('/api/resend-verify', (Request request) async {
      final payload =
          jsonDecode(await request.readAsString()) as Map<String, dynamic>;
      final sessionToken = payload['session_token'];
      // create verified hash to confirm email
      final verifiedSalt = utf8.encode(generateRandomString(18));
      final verifiedHash = sha256.convert(verifiedSalt).toString();
      // select customer row
      final res = await client
          .from('customer')
          .select()
          .match({'id': sessionToken})
          .single()
          .execute();
      if (res.hasError) {
        return Response.badRequest(body: jsonEncode({'error': 'Unauthorized'}));
      }
      final email = res.data['email'];
      final name = res.data['name'];
      final emailVerified = res.data['email_verified'];
      if (emailVerified) {
        return Response.badRequest(
            body: jsonEncode({'error': 'Email has verified'}));
      }
      // update verified_hash
      final updateRes = await client
          .from('customer')
          .update({'verified_hash': verifiedHash})
          .match({'id': sessionToken})
          .single()
          .execute();
      if (updateRes.hasError) {
        return Response.badRequest(body: jsonEncode({'error': 'Unauthorized'}));
      }
      // create jwt token to confirm
      final jwt = JWT({'email': email, 'verified_hash': verifiedHash});
      final token = jwt.sign(
        SecretKey(verifyEmailSecret),
        expiresIn: verifyEmailDuration,
      );
      final verifiedLink = '0.0.0.0:8080/api/verify-email/$token';
      // send confirm email
      return sendVerifiedEmail(
        email: email,
        name: name,
        verifiedLink: verifiedLink,
      );
    });

    /// Verify email
    router.get('/api/verify-email/<token>',
        (Request request, String token) async {
      try {
        final jwt = JWT.verify(token, SecretKey(verifyEmailSecret));
        final email = jwt.payload['email'];
        final verifiedHash = jwt.payload['verified_hash'];
        final res = await client
            .from('customer')
            .select()
            .match({'email': email})
            .single()
            .execute();
        if (res.hasError) {
          return Response.badRequest(
              body: jsonEncode(
            {'error': 'Unauthorized'},
          ));
        }
        final emailVerified = res.data['email_verified'];
        if (emailVerified) {
          return Response.badRequest(
              body: jsonEncode(
            {'error': 'This email has verified'},
          ));
        }
        // update verify status
        final updateRes = await client
            .from('customer')
            .update({'email_verified': true})
            .match({'email': email, 'verified_hash': verifiedHash})
            .single()
            .execute();
        if (updateRes.hasError) {
          return Response.badRequest(
              body: jsonEncode(
            {'error': 'This link is old, use latest link to verify'},
          ));
        }
        return Response.ok(jsonEncode({'data': 'Verify email successfully'}));
      } on JWTExpiredError {
        return Response.badRequest(
            body: jsonEncode(
          {'error': 'Verified link has expired'},
        ));
      } on JWTError {
        return Response.badRequest(
            body: jsonEncode(
          {'error': 'Invalid signature'},
        ));
      }
    });

    /// Sign in
    router.post('/api/user-sessions', (Request request) async {
      final payload =
          jsonDecode(await request.readAsString()) as Map<String, dynamic>;
      final email = payload['email'];
      final password = payload['password'];
      // hash password with salt
      final res = await client
          .from('customer')
          .select()
          .match({'email': email})
          .single()
          .execute();
      if (res.hasError) {
        return Response.badRequest(
            body: jsonEncode({'error': 'This email has not yet signed up'}));
      }

      final salt = res.data['salt'];
      final hashDB = res.data['hash'];
      final token = res.data['id'];
      final emailVerified = res.data['email_verified'];

      final bytes = utf8.encode(password + salt);
      final hash = sha256.convert(bytes).toString();
      if (hash == hashDB) {
        if (emailVerified) {
          return Response.ok(jsonEncode({'session_token': token}));
        } else {
          return Response.badRequest(
              body: jsonEncode({
            'error': 'Has not yet verify email',
            'session_token': token,
          }));
        }
      } else {
        return Response.badRequest(
            body: jsonEncode({'error': 'Email or password not matched'}));
      }
    });

    /// ====================== TENANT ==============================

    /// Create tenant
    router.post('/api/tenants', (Request request) async {
      final payload =
          jsonDecode(await request.readAsString()) as Map<String, dynamic>;
      final name = payload['name'];

      // call rpc to create new schema
      final resSchema =
          await client.rpc('create_schema', params: {'s_name': name}).execute();
      if (resSchema.hasError) return Response.badRequest();

      // call rpc to create new project table in new schema
      final resProject = await client
          .rpc('create_project', params: {'s_name': name}).execute();
      if (resProject.hasError) return Response.badRequest();

      return Response.ok(null);
    });

    /// ====================== PROJECT ==============================

    /// Get all project
    router.get('/api/projects', (Request request) async {
      final response = await client.from('project').select().execute();

      return Response.ok(jsonEncode({'success': true, 'data': response.data}),
          headers: {'Content-type': 'application/json'});
    });

    /// Create project
    router.post('/api/projects', (Request request) async {
      try {
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        print(payload);
        final id = payload['id'];
        final key = payload['key'];
        final name = payload['name'];
        final description = payload['description'];
        final userId = payload['user_id'];

        final body = {
          'key': key,
          'name': name,
        };
        if (description != null) {
          body['description'] = description;
        }
        final response = await httpClient.post(
          Uri.http(kBaseURL, '/api/v2/$username/groups'),
          body: body,
          headers: {
            'X-AIO-Key': ioKey,
          },
        );
        if (response.statusCode == 201) {
          try {
            final adafruitBody =
                jsonDecode(response.body) as Map<String, dynamic>;
            final supabaseInstance = {
              'id': id as String,
              'name': name as String,
              'key': key as String,
              'description': description as String?,
              'created_at': adafruitBody['created_at'] as String,
              'updated_at': adafruitBody['updated_at'] as String,
              'created_by': userId as String,
              'updated_by': userId,
            };
            print(supabaseInstance);
            final supaReponse =
                await client.from('project').insert(supabaseInstance).execute();
            final result = supaReponse.data as List;
            return Response.ok(
              jsonEncode({'success': true, 'data': result.first}),
              headers: {'Content-type': 'application/json'},
            );
          } catch (e) {
            print(e);
            return Response.badRequest(body: jsonEncode({'success': false}));
          }
        } else {
          return Response.badRequest(body: jsonEncode({'success': false}));
        }
      } catch (e) {
        print(e);
        return Response.badRequest(body: jsonEncode({'success': false}));
      }
    });

    /// Update project
    router.put('/api/projects/<old_key>',
        (Request request, String oldKey) async {
      try {
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final id = payload['id'];
        final key = payload['key'];
        final name = payload['name'];
        final description = payload['description'];
        final createBy = payload['create_by'];
        final userId = payload['user_id'];
        final body = {
          'key': key,
          'name': name,
        };
        if (description != null) {
          body['description'] = description;
        }
        final response = await httpClient.put(
          Uri.http(kBaseURL, '/api/v2/$username/groups/$oldKey'),
          body: body,
          headers: {
            'X-AIO-Key': ioKey,
          },
        );
        if (response.statusCode == 200) {
          final adafruitBody =
              jsonDecode(response.body) as Map<String, dynamic>;
          final supabaseInstance = {
            'name': name as String,
            'key': key as String,
            'description': description as String?,
            'created_at': adafruitBody['created_at'] as String,
            'updated_at': adafruitBody['updated_at'] as String,
            'created_by': createBy as String,
            'updated_by': userId as String,
          };

          final supaReponse = await client
              .from('project')
              .update(supabaseInstance)
              .match({'id': id}).execute();
          final result = supaReponse.data as List;
          return Response.ok(
            jsonEncode({'success': true, 'data': result.first}),
            headers: {'Content-type': 'application/json'},
          );
        } else {
          return Response.badRequest(body: jsonEncode({'success': false}));
        }
      } catch (e) {
        return Response.badRequest(body: jsonEncode({'success': false}));
      }
    });

    /// Get specific project
    router.get('/api/projects/<id>', (Request request, String id) async {
      final response =
          await client.from('projects').select().match({'id': id}).execute();
      return Response.ok(jsonEncode({'success': true, 'data': response.data}),
          headers: {'Content-type': 'application/json'});
    });

    router.delete('/api/projects/<id>', (Request request, String id) async {
      final response =
          await client.from('projects').delete().match({'id': id}).execute();

      return Response.ok(
        jsonEncode({'success': true, 'data': response.data}),
        headers: {'Content-type': 'application/json'},
      );
    });

    router.get('/api/schema', (Request request) async {
      final response = await client.rpc('get_projects').execute();
      return Response.ok(jsonEncode({'success': true, 'data': response.data}),
          headers: {'Content-type': 'application/json'});
    });

    ///
    /// ================================================
    ///

    /// Get all devices
    router.get('/api/devices', (Request request) async {
      final response = await client.from('device').select().execute();

      final devicesFull = <dynamic>[];
      for (final device in (response.data as List<dynamic>)) {
        final deviceFull = Map<String, dynamic>.from(device);
        final json = await client
            .from('json_variable')
            .select()
            .match({'device_id': device['id']}).execute();
        deviceFull['json_variables'] = json.data ?? [];
        devicesFull.add(deviceFull);
      }

      return Response.ok(jsonEncode({'success': true, 'data': devicesFull}),
          headers: {'Content-type': 'application/json'});
    });

    /// Create device
    router.post('/api/devices', (Request request) async {
      try {
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final id = payload['id'];
        final projectId = payload['project_id'];
        final projectKey = payload['project_key'];
        final name = payload['name'];
        final key = payload['key'];
        final description = payload['description'];
        final jsonEnable = payload['json_enable'];
        final jsonVariables = payload['json_variables'] as List<dynamic>;
        final userID = payload['user_id'];
        final body = {
          'feed': {
            'name': name,
            'key': key,
            'description': description,
          }
        };
        final response = await httpClient.post(
          Uri.http(kBaseURL, '/api/v2/$username/groups/$projectKey/feeds'),
          body: jsonEncode(body),
          headers: {
            'Content-Type': 'application/json',
            'X-AIO-Key': ioKey,
          },
        );
        if (response.statusCode == 201) {
          final adafruitBody =
              jsonDecode(response.body) as Map<String, dynamic>;
          // add to device table
          final supabaseInstance = {
            'id': id as String,
            'project_id': projectId as String,
            'name': name as String,
            'key': key as String,
            'description': description as String?,
            'json_enable': jsonEnable as bool,
            'created_at': adafruitBody['created_at'] as String,
            'updated_at': adafruitBody['updated_at'] as String,
            'created_by': userID as String,
            'updated_by': userID,
          };
          final supaReponse =
              await client.from('device').insert(supabaseInstance).execute();
          // add to json_variable table
          final jsonVariablesJson = <dynamic>[];
          for (final jsonVariable in jsonVariables) {
            final json = await client
                .from('json_variable')
                .insert(jsonVariable)
                .execute();
            jsonVariablesJson.add((json.data as List<dynamic>).first);
          }
          final deviceJson =
              Map<String, dynamic>.from((supaReponse.data as List).first);
          deviceJson["json_variables"] = jsonVariablesJson;
          return Response.ok(
            jsonEncode({'success': true, 'data': deviceJson}),
            headers: {'Content-type': 'application/json'},
          );
        } else {
          return Response.badRequest(body: jsonEncode({'success': false}));
        }
      } catch (e) {
        return Response.badRequest(body: jsonEncode({'success': false}));
      }
    });

    /// Update device
    router.put('/api/devices/<old_key>',
        (Request request, String oldKey) async {
      try {
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final id = payload['id'];
        final projectId = payload['project_id'];
        final projectKey = payload['project_key'];
        final name = payload['name'];
        final key = payload['key'];
        final description = payload['description'];
        final jsonEnable = payload['json_enable'];
        final jsonVariables = payload['json_variables'] as List<dynamic>;
        final userID = payload['user_id'];
        final body = {
          'feed': {
            'name': name,
            'key': key,
          }
        };
        if (description != null) {
          body['feed']!['description'] = description;
        }
        final response = await httpClient.put(
          Uri.http(kBaseURL, '/api/v2/$username/feeds/$projectKey.$oldKey'),
          body: jsonEncode(body),
          headers: {
            'Content-Type': 'application/json',
            'X-AIO-Key': ioKey,
          },
        );
        if (response.statusCode == 200) {
          final adafruitBody =
              jsonDecode(response.body) as Map<String, dynamic>;
          final supabaseInstance = {
            'id': id as String,
            'project_id': projectId as String,
            'name': name as String,
            'key': key as String,
            'description': description as String?,
            'json_enable': jsonEnable as bool,
            'created_at': adafruitBody['created_at'] as String,
            'updated_at': adafruitBody['updated_at'] as String,
            'created_by': userID as String,
            'updated_by': userID,
          };
          final supaReponse = await client
              .from('device')
              .update(supabaseInstance)
              .match({'id': id}).execute();

          final jsonVariablesJson = <dynamic>[];
          for (final jsonVariable in jsonVariables) {
            final json = await client
                .from('json_variable')
                .upsert(jsonVariable)
                .execute();
            jsonVariablesJson.add((json.data as List<dynamic>).first);
          }
          final deviceJson =
              Map<String, dynamic>.from((supaReponse.data as List).first);
          deviceJson["json_variables"] = jsonVariablesJson;
          return Response.ok(
            jsonEncode({'success': true, 'data': deviceJson}),
            headers: {'Content-type': 'application/json'},
          );
        } else {
          return Response.badRequest(body: jsonEncode({'success': false}));
        }
      } catch (e) {
        return Response.badRequest(body: jsonEncode({'success': false}));
      }
    });

    ///
    /// =============================  Tile Config =================================
    /// Get all tile configs
    router.get('/api/tile-configs', (Request request) async {
      final response = await client.from('tile_config').select().execute();

      final tileConfigs = <dynamic>[];
      for (final tileConfig in response.data) {
        final id = tileConfig['id'];
        final tileType = tileConfig['tile_type'];
        switch (tileType) {
          case 0:
            final tileDataResponse = await client
                .from('toggle_tile_data')
                .select()
                .match({'id': id})
                .single()
                .execute();
            final toggleTileData =
                tileDataResponse.data as Map<String, dynamic>;
            toggleTileData.remove('id');
            toggleTileData['tile_type'] = 0;
            final completeTileData = Map<String, dynamic>.from(tileConfig);
            completeTileData['tile_data'] = toggleTileData;
            tileConfigs.add(completeTileData);
            break;
          case 1:
            final tileDataResponse = await client
                .from('text_tile_data')
                .select()
                .match({'id': id})
                .single()
                .execute();
            final textTileData = tileDataResponse.data as Map<String, dynamic>;
            textTileData.remove('id');
            textTileData['tile_type'] = 1;
            final completeTileData = Map<String, dynamic>.from(tileConfig);
            completeTileData['tile_data'] = textTileData;
            tileConfigs.add(completeTileData);
            break;
          default:
        }
      }

      return Response.ok(jsonEncode({'success': true, 'data': tileConfigs}),
          headers: {'Content-type': 'application/json'});
    });

    /// Create tile config
    router.post('/api/tile-configs', (Request request) async {
      try {
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final id = payload['id'];
        final name = payload['name'];
        final tileType = payload['tile_type'] as int;
        final deviceId = payload['device_id'];
        final tileData = payload['tile_data'];
        final supabaseInstance = {
          'id': id as String,
          'device_id': deviceId as String,
          'name': name as String,
          'tile_type': tileType,
        };
        final supaReponse =
            await client.from('tile_config').insert(supabaseInstance).execute();
        final tileDataJson =
            Map<String, dynamic>.from((supaReponse.data as List).first);
        switch (tileType) {
          case 0:
            final onLabel = tileData['on_label'] as String?;
            final onValue = tileData['on_value'] as String;
            final offLabel = tileData['off_label'] as String?;
            final offValue = tileData['off_value'] as String;
            final jsonVariableId = tileData['json_variable_id'] as String?;
            final tileDataResponse =
                await client.from('toggle_tile_data').insert({
              'id': id,
              'on_label': onLabel,
              'on_value': onValue,
              'off_label': offLabel,
              'off_value': offValue,
              'json_variable_id': jsonVariableId,
            }).execute();
            final toggleTileData =
                (tileDataResponse.data as List).first as Map<String, dynamic>;
            toggleTileData.remove('id');
            toggleTileData['tile_type'] = 0;
            tileDataJson['tile_data'] = toggleTileData;
            break;
          case 1:
            final prefix = tileData['prefix'] as String?;
            final postfix = tileData['postfix'] as String?;
            final jsonVariableId = tileData['json_variable_id'] as String?;
            final tileDataResponse =
                await client.from('text_tile_data').insert({
              'id': id,
              'prefix': prefix,
              'postfix': postfix,
              'json_variable_id': jsonVariableId,
            }).execute();
            final textTileData =
                (tileDataResponse.data as List).first as Map<String, dynamic>;
            textTileData.remove('id');
            textTileData['tile_type'] = 1;
            tileDataJson['tile_data'] = textTileData;
            break;
        }
        return Response.ok(
          jsonEncode({'success': true, 'data': tileDataJson}),
          headers: {'Content-type': 'application/json'},
        );
      } catch (e) {
        return Response.badRequest(body: jsonEncode({'success': false}));
      }
    });

    /// Update tile config
    router.put('/api/tile-configs', (Request request) async {
      try {
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final id = payload['id'];
        final name = payload['name'];
        final tileType = payload['tile_type'] as int;
        final deviceId = payload['device_id'];
        final tileData = payload['tile_data'];
        final supabaseInstance = {
          'id': id as String,
          'device_id': deviceId as String,
          'name': name as String,
          'tile_type': tileType,
        };
        final supaReponse =
            await client.from('tile_config').upsert(supabaseInstance).execute();
        final tileDataJson =
            Map<String, dynamic>.from((supaReponse.data as List).first);
        switch (tileType) {
          case 0:
            final onLabel = tileData['on_label'] as String?;
            final onValue = tileData['on_value'] as String;
            final offLabel = tileData['off_label'] as String?;
            final offValue = tileData['off_value'] as String;
            final jsonVariableId = tileData['json_variable_id'] as String?;
            final inserValue = {
              'id': id,
              'on_label': onLabel,
              'on_value': onValue,
              'off_label': offLabel,
              'off_value': offValue,
              'json_variable_id': jsonVariableId,
            };
            final tileDataResponse = await client
                .from('toggle_tile_data')
                .upsert(inserValue)
                .execute();
            final toggleTileData =
                (tileDataResponse.data as List).first as Map<String, dynamic>;
            toggleTileData.remove('id');
            toggleTileData['tile_type'] = 0;
            tileDataJson['tile_data'] = toggleTileData;
            break;
          case 1:
            final prefix = tileData['prefix'] as String?;
            final postfix = tileData['postfix'] as String?;
            final jsonVariableId = tileData['json_variable_id'] as String?;
            final tileDataResponse =
                await client.from('text_tile_data').upsert({
              'id': id,
              'prefix': prefix,
              'postfix': postfix,
              'json_variable_id': jsonVariableId,
            }).execute();
            final textTileData =
                (tileDataResponse.data as List).first as Map<String, dynamic>;
            textTileData.remove('id');
            textTileData['tile_type'] = 1;
            tileDataJson['tile_data'] = textTileData;
            break;
        }
        return Response.ok(
          jsonEncode({'success': true, 'data': tileDataJson}),
          headers: {'Content-type': 'application/json'},
        );
      } catch (e) {
        return Response.badRequest(body: jsonEncode({'success': false}));
      }
    });

    /// Delete tile config
    router.delete('/api/tile-configs', (Request request) async {
      try {
        final payload =
            jsonDecode(await request.readAsString()) as Map<String, dynamic>;
        final id = payload['id'];
        await client
            .from('text_tile_data')
            .delete()
            .match({'id': id}).execute();
        await client
            .from('toggle_tile_data')
            .delete()
            .match({'id': id}).execute();
        final supaReponse = await client
            .from('tile_config')
            .delete()
            .match({'id': id}).execute();
        if (supaReponse.hasError) {
          return Response.ok(
            jsonEncode({'success': false}),
            headers: {'Content-type': 'application/json'},
          );
        } else {
          return Response.ok(
            jsonEncode({'success': true}),
            headers: {'Content-type': 'application/json'},
          );
        }
      } catch (e) {
        return Response.badRequest(body: jsonEncode({'success': false}));
      }
    });
    return router;
  }
}
