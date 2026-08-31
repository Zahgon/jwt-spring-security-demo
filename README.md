# JWT Spring Security Demo

![Screenshot from running application](etc/screenshot-jwt-spring-security-demo.png?raw=true "Screenshot JWT Spring Security Demo")

## About
This is a demo for using **[JWT (JSON Web Token)](https://jwt.io)** with **[Go](https://go.dev)**. It is a port of the original
Spring Security / Spring Boot demo, which was itself based on the code base from the [JHipster Project](https://www.jhipster.tech/).
The port keeps the HTTP surface, the token format, the seeded accounts and the error messages of the original, so a token issued
by either implementation is accepted by the other.

[![Build Status](https://travis-ci.org/szerhusenBC/jwt-spring-security-demo.svg?branch=master)](https://travis-ci.org/szerhusenBC/jwt-spring-security-demo)

## Requirements
This demo is built with Go 1.25. There is nothing else to install: the configuration, the seed data and the
static client are embedded in the binary, and the database is in-process.

## Usage
Start the application with `go run .`, or build it first with `go build -o jwtdemo` and run `./jwtdemo`. The application is
running at [http://localhost:8080](http://localhost:8080).

Run the tests with `go test ./...`, and the checks CI runs with `gofmt -l .` and `go vet ./...`.

## Backend
There are three user accounts present to demonstrate the different levels of access to the endpoints in
the API and the different authorization exceptions:
```
Admin - admin:admin
User - user:password
Disabled - disabled:password (this user is deactivated)
```

There are four endpoints that are reasonable for the demo:
```
/api/authenticate - authentication endpoint with unrestricted access
/api/user - returns detail information for an authenticated user (a valid JWT token must be present in the request header)
/api/person - an example endpoint that is restricted to authorized users with the authority 'ROLE_USER' (a valid JWT token must be present in the request header)
/api/hiddenmessage - an example endpoint that is restricted to authorized users with the authority 'ROLE_ADMIN' (a valid JWT token must be present in the request header)
```

## Frontend
I've written a small Javascript client and put some comments in the code that hopefully makes this demo understandable.
You can find it at [/src/main/resources/static/js/client.js](/src/main/resources/static/js/client.js).

### Generating password hashes for new users

I'm using [bcrypt](https://en.wikipedia.org/wiki/Bcrypt) to encode passwords. Your can generate your hashes with this simple 
tool: [Bcrypt Generator](https://www.bcrypt-generator.com)

### Configuration

The token settings live in *config/application.yml* and are embedded into the binary at build time:

```
jwt:
  header: Authorization
  # must be base64-encoded; the decoded bytes are the HMAC key
  base64-secret: ...
  token-validity-in-seconds: 86400
  token-validity-in-seconds-for-remember-me: 108000
```

### Using another database

This demo uses an in-process SQLite database, created and seeded at startup from *resources/import.sql*. To point it
at another database, change the driver and DSN in *internal/db/db.go* and adjust the DDL there to your dialect —
the schema is three tables, `USER`, `AUTHORITY` and `USER_AUTHORITY`.

## Docker
The `Dockerfile` at the repository root builds a static binary and copies it into a minimal image:

```
docker build -t jwt-spring-security-demo .
docker run -p 8080:8080 jwt-spring-security-demo
```

## Questions
If you have project related questions please take a look at the [past questions](https://github.com/szerhusenBC/jwt-spring-security-demo/issues?utf8=%E2%9C%93&q=is%3Aissue%20is%3Aopen%2Cclosed%20label%3Aquestion%20) or create a new ticket with your question.

*If you have questions that are not directly related to this project (e.g. common questions to the Spring Framework or Spring Security etc.) please search the web or look at [Stackoverflow](http://www.stackoverflow.com).*

Sorry for that but I'm very busy right now and don't have much time.

## Interesting projects

* [golang-jwt](https://github.com/golang-jwt/jwt) a general-purpose JWT library for Go
* For more complex microservice environments take a look here: [Using JWT with Spring Security OAuth](http://www.baeldung.com/spring-security-oauth-jwt)

## Author

**Stephan Zerhusen**

* https://twitter.com/stzerhus
* https://github.com/szerhusenBC

## Copyright and license

The code is released under the [MIT license](LICENSE?raw=true).

---------------------------------------

Please feel free to send me some feedback or questions!
