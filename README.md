# Gouncer

A high speed auth server written in go

## Installation

```shell
  go get github.com/npolar/gouncer
```

#### Dependencies

```shell
  go get github.com/bradfitz/gomemcache/memcache
  go get github.com/rs/cors
  go get github.com/codegangsta/cli
```

#### Compilation

- **Staticlly linked**

```shell
  go install && CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-s' main/gouncer.go
```
**NOTE!**:change the GOOS= variable to match your platform

- **Dynamically linked**

```shell
  go install && go build main/gouncer.go
```

### Run

#### Cli configuration
```shell
  ./gouncer -h # for flag info
  ./gouncer --db http://localhost:5984 -c my-ssl/certificate.crt -k my-ssl/keyfile.key -m my.cache.com:11211
```

#### Config file
Gouncer supports configuration through a [TOML v0.4.0](https://github.com/toml-lang/toml/blob/master/versions/en/toml-v0.4.0.md) file.
```shell
  ./gouncer --config myconf.toml
```

**Example Config**

```toml
  # Gouncer Configuration Example

  # Essential server configuration
  [core]
  hostname = ""      # Server name eg. example.com
  port     = ":8950" # Server port written as string prependend with ':'
  jsonp    = true    # Enable JSONP support
  log      = "/var/log/gouncer/error.log"

  [ssl]
  certificate = "my-certs/certificate.crt" # SSL Certificate
  key         = "my-keys/keyfile.key"      # SSL key

  [backend]
  couchdb  = "https://localhost:5984" # Address to a couchdb instance
  userdb   = "users"                  # Name of the user database
  groupdb  = "groups"                 # Name of the groups database
  memcache = ["localhost:11211"]      # List of memcache instances
  smtp     = "my-smtp.com:25"         # Address to the SMTP server you want to use to send notifications

  [token]
  algorithm  = "HS512" # Supported JWT algorithms [none, HS256, HS384, HS512]
  expiration = 10800  # Token expiration time in seconds

  [registrations]

    # Default group settings for mail addresses containing the @example.com domain

    [registrations.example]
    domain = "example.com"
    groups = ["exampleGroup"]

    # Default group settings for all email domains not defined

    [registrations.default]
    domain = "default"
    groups = ["globalGroup"]

  [mail_config]
  sender               = "noreply@example.com"                                    # Email address to use when sending notifications
  link_timeout         = 1200                                                     # Time a confirmation link will stay active
  confirmation_subject = "Account confirmation"                                   # Confirmation mail subject
  confirmation_message = "Thanks dude! Click for awesomeness: {{link}}"           # Confirmation mail message. Use the {{link}} pattern to inject the link into the message
  cancel_subject       = "Cancellation confirmation"                              # Cancellation mail subject
  cancel_message       = "Bummer dude! Click to cancel the awesomeness: {{link}}" # Cancellation mail message. Use the {{link}} pattern to inject the link into the message

```

### Usage

#### Authentication

- **Basic**

```shell
  curl -k -XGET https://username:password@localhost:8950/authenticate
  # OR
  curl -k -XGET https://localhost:8950/authenticate -H "Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ="
```

Gouncer will then respond with a json object

```json
  {
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
  }
```

- **Revalidation**

```shell
  curl -k -XGET https://localhost:8950/authenticate -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
```

Gouncer will then respond with a new token

```json
  {
    "token": "eyJhbG...",
  }
```

#### Authorization

To check if we have access to https://example.com/info we send our token in the authorization header and pass the system we want to get authorization for as body

```shell
  curl -XPOST https://localhost:8950/authorize -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RM" -d '{"system": "https://example.com/info"}'
```

Gouncer will respond with a list of access rights or with an http 401 error.

```json
  {
    "rights":[
      "create",
      "read",
      "update",
      "delete"
    ]
  }
```

#### Account Registration

To create a new account you can send a request to the /register path. **NOTE**: an smtp address must be register for this feature to work.

```shell
  curl -k -XPOST https://localhost:8950/register -d '{"email":"my-mail@example.com", "name":"myname", "password":"some-secret"}'
```

If successfull you will get a mail at the email address you tried to register. Use the code inside to complete account creation. If an account for the mail address already exist you will get an error.
To complete the registration run the following command. For <code> insert the value received in the email.
```shell
  curl -k -XGET https://localhost:8950/confirm/<code>
```

#### Account Cancellation

To cancel your account you can send a request to the /unregister path with valid credentials (basic || token)

```shell
  curl -k -XDELETE https://localhost:8950/unregister
```

If you sent the request with valid credentials you'll receive an email on the accounts email address with a code to complete the cancellation process.
To complete cancallation run the following command. For <code> inser the value received in the email.

```shell
  curl -k -XGET https://localhost:8950/cancel/<code>
```

## Example Notice

Note that the curl commands in the provided examples ignore self signed SSL certificates. To check certificate validity remove the **-k** flag from the commands.

## Notice

Gouncer is still under development. API and formats change as we go! Use in poduction systems is not recommended.
