import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:args/args.dart';
import 'package:shelf/shelf.dart';
import 'package:shelf/shelf_io.dart' as io;

import 'api.dart';

// For Google Cloud Run, set _hostname to '0.0.0.0'.
const _hostname = '0.0.0.0';
// const _hostname = 'localhost';

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
  final fixCORS = createMiddleware(
    requestHandler: _options,
    responseHandler: _cors,
  );

  // final handler =
  // const Pipeline().addMiddleware(logRequests()).addHandler(_echoRequest);
  final handler = const Pipeline()
      .addMiddleware(fixCORS)
      .addMiddleware(logRequests())
      .addHandler(Api().handler);
  final server = await io.serve(handler, _hostname, port);
  print('Serving at http://${server.address.host}:${server.port}');
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
