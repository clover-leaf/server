import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:args/args.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as io;
import 'package:supabase/supabase.dart';

import 'api.dart';

// For Google Cloud Run, set _hostname to '0.0.0.0'.
// const _hostname = '0.0.0.0';
const _hostname = 'localhost';

void main(List<String> args) async {
  final parser = ArgParser()..addOption('port', abbr: 'p');
  final result = parser.parse(args);

  // For Google Cloud Run, we respect the PORT environment variable
  final portStr = result['port'] ?? Platform.environment['PORT'] ?? '8080';
  final port = int.tryParse(portStr);

  if (port == null) {
    stdout.writeln('Could not parse port value "$portStr" into a number.');
    // 64: command line usage error
    exitCode = 64;
    return;
  }
  const corsHeaders = {
    "Access-Control-Allow-Origin": "http://localhost:3000",
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers":
        "Authorization, Origin, X-Requested-With, Content-Type, Accept",
  };

  Response? _options(Request request) => (request.method == "OPTIONS")
      ? Response.ok(null, headers: corsHeaders)
      : null;

  Response _cors(Response response) => response.change(headers: corsHeaders);
  final fixCORS =
      createMiddleware(requestHandler: _options, responseHandler: _cors);

  // final handler =
      // const Pipeline().addMiddleware(logRequests()).addHandler(_echoRequest);
  final handler = const Pipeline()
      .addMiddleware(fixCORS)
      .addMiddleware(logRequests())
      .addHandler(Api().handler);

  final server = await io.serve(handler, _hostname, port);
  print('Serving at http://${server.address.host}:${server.port}');
}

Future<Response> _echoRequest(Request request) async {
  // return shelf.Response.ok('Request for $request');
  switch (request.url.toString()) {
    case 'users':
      return await _echoUsers(request);
    default:
      return Response.ok('Invalid url');
  }
}

class Ticker {
  const Ticker();
  Stream<int> tick({required int ticks}) {
    return Stream.periodic(const Duration(seconds: 1), (x) => ticks - x - 1)
        .take(ticks);
  }
}

StreamSubscription<int>? _tickerSubscription;

Future<Response> _echoBroker(Request request) async {
  final payload =
      jsonDecode(await request.readAsString()) as Map<String, dynamic>;
  _tickerSubscription?.cancel();
  _tickerSubscription = Ticker()
      .tick(ticks: payload['duration'])
      .listen((duration) => print(duration));
  return Response.ok(null);
}

Future<Response> _echoUsers(Request request) async {
  final client = SupabaseClient('https://mwwncvkpflyreaofpapd.supabase.co',
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im13d25jdmtwZmx5cmVhb2ZwYXBkIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTY1OTE3NjQ3MywiZXhwIjoxOTc0NzUyNDczfQ.rmqW5s0jSY_1f4NPdIdnuBW9pR1nEJRcMdJWqgB7Ekc');

  // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im13d25jdmtwZmx5cmVhb2ZwYXBkIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTY1OTE3NjQ3MywiZXhwIjoxOTc0NzUyNDczfQ.rmqW5s0jSY_1f4NPdIdnuBW9pR1nEJRcMdJWqgB7Ekc

  // eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im13d25jdmtwZmx5cmVhb2ZwYXBkIiwicm9sZSI6ImFub24iLCJpYXQiOjE2NTkxNzY0NzMsImV4cCI6MTk3NDc1MjQ3M30.ocRvvDEt5zaZUETnGIrexN_OgewsfEh3Ufceh3wniv4

  // final createSchemaRes = await client
  //     .rpc('create_schema', params: {'s_name': 'progress'}).execute();
  // print(createSchemaRes.error);
  // print(createSchemaRes.data);
  // print(createSchemaRes.status);
  // final getSchemaRes = await client
  //     .rpc('get_db_schemas').execute();
  // print(getSchemaRes.error);
  // print(getSchemaRes.data);
  // print(getSchemaRes.status);
  // final response_ = await client.rpc('change_postgrest_db_schemas',
  //     params: {"schemas": "public, storage, bee, sys"}).execute();
  // print(response_.error);
  // print(response_.data);
  // print(response_.status);
  final resProject =
      await client.rpc('create_project', params: {'s_name': 'bee'}).execute();
  print(resProject.error);
  print(resProject.data);
  print(resProject.status);

  return Response.ok(jsonEncode({
    'status': 'success',
  }));
}
