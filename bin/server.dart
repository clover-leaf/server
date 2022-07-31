import 'dart:convert';
import 'dart:io';

import 'package:args/args.dart';
import 'package:shelf/shelf.dart' as shelf;
import 'package:shelf/shelf_io.dart' as io;
import 'package:supabase/supabase.dart';

// For Google Cloud Run, set _hostname to '0.0.0.0'.
const _hostname = '0.0.0.0';

void main(List<String> args) async {
  var parser = ArgParser()..addOption('port', abbr: 'p');
  var result = parser.parse(args);

  // For Google Cloud Run, we respect the PORT environment variable
  var portStr = result['port'] ?? Platform.environment['PORT'] ?? '8080';
  var port = int.tryParse(portStr);

  if (port == null) {
    stdout.writeln('Could not parse port value "$portStr" into a number.');
    // 64: command line usage error
    exitCode = 64;
    return;
  }

  var handler = const shelf.Pipeline()
      .addMiddleware(shelf.logRequests())
      .addHandler(_echoRequest);

  var server = await io.serve(handler, _hostname, port);
  print('Serving at http://${server.address.host}:${server.port}');
}

Future<shelf.Response> _echoRequest(shelf.Request request) async {
  // return shelf.Response.ok('Request for $request');
  switch (request.url.toString()) {
    case 'users':
      return await _echoUsers(request);
    default:
      return shelf.Response.ok('Invalid url');
  }
}

Future<shelf.Response> _echoUsers(shelf.Request request) async {
  final client = SupabaseClient('https://mwwncvkpflyreaofpapd.supabase.co',
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im13d25jdmtwZmx5cmVhb2ZwYXBkIiwicm9sZSI6ImFub24iLCJpYXQiOjE2NTkxNzY0NzMsImV4cCI6MTk3NDc1MjQ3M30.ocRvvDEt5zaZUETnGIrexN_OgewsfEh3Ufceh3wniv4');

  // // Retrieve data from 'users' table
  // final response = await client.from('projects').select().execute();
  // final response = await client.from('projects').insert({
  //   'id': 'ce81c472-5007-4d6e-b664-71cde7030468',
  //   'name': 'fuck',
  // }).execute();
  // final response = await client
  //     .from('projects')
  //     .select()
  //     .match({'name': 'thit_than'}).execute();
  final response = await client.from('projects').update({'name': 'pls'}).match(
      {'id': 'ce81c472-5007-4d6e-b664-71cde7030468'}).execute();

  var map = {'users': response.data};

  return shelf.Response.ok(jsonEncode(map));
}
