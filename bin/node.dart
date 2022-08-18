void main(List<String> args) {
  // final records = <Map<String, String?>>[
  //   {
  //     "id": "73468f2c-360c-423f-8cb5-cb0d8418f541",
  //     "project_id": null,
  //     "group_id": "7b424eb6-264a-4813-8464-acbcc68a10ec",
  //     "name": "rr"
  //   },
  //   {
  //     "id": "7b424eb6-264a-4813-8464-acbcc68a10ec",
  //     "project_id": null,
  //     "group_id": "3c6b3b83-cb63-482b-9ca5-4c92ed2c69ff",
  //     "name": "uu"
  //   },
  //   {
  //     "id": "3c6b3b83-cb63-482b-9ca5-4c92ed2c69ff",
  //     "project_id": "e95efb05-5a6e-4a96-88e6-e8cf9b3d1171",
  //     "group_id": null,
  //     "name": "kk"
  //   },
  //   {
  //     "id": "eaa63420-2063-4cb2-bc58-5da2ed56ac16",
  //     "project_id": "364ad94f-5a01-4978-8c9e-7b67c403151a",
  //     "group_id": null,
  //     "name": "yy"
  //   },
  //   {
  //     "id": "7715a33b-d46b-4468-889f-04e3b9d2bc26",
  //     "project_id": "1b80209d-fe03-4657-8157-fd0de4d0da75",
  //     "group_id": null,
  //     "name": "december"
  //   },
  // ];
  // final roots = buildForestAndGetRoots(records);
  // print(roots.map((e) => e.toString()));
}

List<String> buildForestAndGetRoots(List<Map<String, String?>> records) {
  final roots = <String>[];
  final hashTable = <String, Node>{};
  for (final record in records) {
    final childNode = findOrCreate(record['id']!, hashTable);
    if (record['group_id'] != null) {
      final parentNode = findOrCreate(record['group_id']!, hashTable);

      childNode.parentNode = parentNode;
      parentNode.children = [...parentNode.children, childNode];

      hashTable[childNode.id] = childNode;
      hashTable[parentNode.id] = parentNode;

      if (parentNode.parentNode == null && !roots.contains(parentNode.id)) {
        roots.add(parentNode.id);
        print('Add: ${parentNode.id}');
      }
      if (roots.contains(childNode.id)) {
        roots.remove(childNode.id);
        print('Remove: ${childNode.id}');
      }
    } else if (!roots.contains(childNode.id)) {
      roots.add(childNode.id);
      print('Add else: ${childNode.id}');
      hashTable[childNode.id] = childNode;
      // print(hashTable);
    }
    // print('Roots: ${roots.map((e) => e.id)}');
  }
  return roots;
}

Node findOrCreate(String id, Map<String, Node> hashTable) {
  if (hashTable.containsKey(id)) {
    return hashTable[id]!;
  } else {
    final node = Node(id: id);
    return node;
  }
}

// List<String> getRootsAndChildrenID(List<String> ids, List<Node> roots) {
//   final nodes = <Node>[];
//   for (final id in ids) {
//     for (final root in roots) {
//       if (root.id == id) {

//       }
//     }
//   }
// }

List<Node> travel(Node root) {
  final nodes = <Node>[];
  for (final node in root.children) {
    nodes.addAll(travel(node));
  }
  return [root, ...nodes];
}

class Node {
  Node({
    required this.id,
    this.children = const [],
    this.parentNode,
  });

  final String id;

  Node? parentNode;

  List<Node> children;

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Node && runtimeType == other.runtimeType && id == other.id;

  @override
  int get hashCode => id.hashCode;
}
