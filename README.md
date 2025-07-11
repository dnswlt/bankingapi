# bankingapi

Go implementation of banking APIs.

## Overview

This library provides Go bindings for the comdirect REST API. You can use it 
to retrieve your account balances, depot positions, and more.

NOTE: All operations provided by this library are read-only. This library does
not support trading or other transactions.

## Try it

This repository contains a small [CLI tool](./cmd/cli/main.go) that you can use
for testing and as an example for how to use the library.

### Activate the API and set credentials

Before you can use the comdirect REST API, you need to enable it and get your credentials.
This is well documented at <https://www.comdirect.de/cms/kontakt-zugaenge-api.html>.

Create a `.bankingapi_credentials` file in the root directory of the cloned repository
and edit it to configure your credentials:

```bash
cat > ./.bankingapi_credentials <<EOF
{
  "client_id": "YOUR_CLIENT_ID",
  "client_secret": "YOUR_CLIENT_SECRET",
  "username": "YOUR_USERNAME",
  "password": ""
}
EOF
```

The `username` is typically an 8-digit number.
Leave the `password` empty to get prompted for it each time you run the example CLI.

### Run the CLI

In the root directory of this repository, run

```bash
go run ./cmd/cli/
```

The CLI will ask you for your password (unless you have configured it in `.bankingapi_credentials`).
It will then request a session TAN, so you will typically receive a notification on
your phone, asking you for a photoTAN. Grant this request and **ONLY THEN** proceed in the CLI.

The tool will print your account balances and recent transactions to stdout.

## Data model

The model classes for the REST API were generated from the Swagger schema
provided by comdirect (see [./comdirect/swagger](./comdirect/swagger/)).

```bash
openapi-generator generate \                                      
  -i comdirect/swagger/comdirect_rest_api_swagger.json \
  -g go \
  -o ./comdirect --api-package comdirect
```

Some adaptations were necessary to make things work. All modified model files have an
associated `_test.go` file.
