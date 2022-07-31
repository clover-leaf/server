import 'package:supabase/supabase.dart';

void main(List<String> args) async {
  final client = SupabaseClient('https://mwwncvkpflyreaofpapd.supabase.co',
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im13d25jdmtwZmx5cmVhb2ZwYXBkIiwicm9sZSI6ImFub24iLCJpYXQiOjE2NTkxNzY0NzMsImV4cCI6MTk3NDc1MjQ3M30.ocRvvDEt5zaZUETnGIrexN_OgewsfEh3Ufceh3wniv4');
  final supabaseInstance = {
    'id': "e60aff55-6bba-493c-9ced-30289bd26861",
    'project_id': 'd7cfd791-5d7d-4c80-b313-9b5991cdc35f',
    'name': 'why',
    'key': 'why',
    'description': null,
    'json_enable': false,
    'created_at': '2022-07-31T08:14:08',
    'updated_at': '2022-07-31T08:14:08',
    'created_by': '8e9668a4-c08d-4622-b3b0-0b5f8fea95c1',
    'updated_by': '8e9668a4-c08d-4622-b3b0-0b5f8fea95c1',
  };
  final supaReponse =
      await client.from('device').insert(supabaseInstance).execute();
  print(supaReponse.data);
}
