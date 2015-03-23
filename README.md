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
  go install && go build -a -tags netgo -installsuffix netgo main/gouncer.go
```

- **Dynamically linked**

```shell
  go install && go build main/gouncer.go
```

### Run

```shell
  ./gouncer -h # for flag info
  ./gouncer --db http://localhost:5984 -c my-ssl/certificate.crt -k my-ssl/keyfile.key -m my.cache.com:11211
```

## Notice

Gouncer is still under development. API and formats change as we go! Use in poduction systems is not recommended.
