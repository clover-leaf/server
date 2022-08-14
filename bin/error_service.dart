import 'dart:convert';
import 'package:shelf/shelf.dart';

class EmailHasNotRegisterError {
  static Response message() {
    return Response(404,
        body: jsonEncode({'message': 'This email has not yet signed up'}));
  }
}

class EmailHasBeenUsedError {
  static Response message() {
    return Response(404,
        body: jsonEncode({'message': 'This email has been used'}));
  }
}

class EmailHasBeenVerifiedError {
  static Response message() {
    return Response(404,
        body: jsonEncode({'message': 'This email has been verified'}));
  }
}

class EmailHasNotBeenVerifiedError {
  static Response message() {
    return Response.badRequest(
        body: jsonEncode({'message': 'This email has not been verified'}));
  }
}

class EmailOrPasswordNotMatchedError {
  static Response message() {
    return Response(404,
        body: jsonEncode({'message': 'Email or password not correct'}));
  }
}

class VerifyTokenWasObsoleteError {
  static Response message() {
    return Response(404,
        body: jsonEncode(
            {'message': 'This link was obsolete, use latest link to verify'}));
  }
}

class VerifyTokenWasExpiredError {
  static Response message() {
    return Response(404,
        body: jsonEncode({
          'message': 'This link was expired, please request to resend new link'
        }));
  }
}

class VerifyTokenIsInvalidsError {
  static Response message() {
    return Response(404, body: jsonEncode({'message': 'This link is invalid'}));
  }
}

class SMTPServiceError {
  static Response message() {
    return Response(400,
        body: jsonEncode({
          'message': 'There is something wrong happened with SMTP service'
        }));
  }
}

class UnauthorizedError {
  static Response message() {
    return Response(403, body: jsonEncode({'message': 'Unauthorized'}));
  }
}

class UserNotExistError {
  static Response message() {
    return Response(401,
        body: jsonEncode({'message': 'This account not exist'}));
  }
}

class DomainNotExistError {
  static Response message() {
    return Response(404,
        body: jsonEncode({'message': 'This domain not exist'}));
  }
}

class DomainHasBeenUsedError {
  static Response message() {
    return Response(404,
        body: jsonEncode({'message': 'This domain name has been used'}));
  }
}

class ProjectNotExistError {
  static Response message() {
    return Response(404,
        body: jsonEncode({'message': 'This project not exist'}));
  }
}

class DatabaseError {
  static Response message() {
    return Response(404,
        body: jsonEncode(
            {'message': 'There is something wrong happened with Database'}));
  }
}
