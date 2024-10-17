#!/bin/bash

if [ -z "$1" ]; then
  echo "Error: No port provided. Please provide a port number."
  exit 1
fi

PORT=$1

echo "Starting neqo server on port $PORT"

export LD_LIBRARY_PATH="$(dirname "$(find . -name libssl3.so -print | head -1)")"
export PATH="${PATH}:/neqo/bin"

DB=./neqo/db
CERT=cert
P12CERT=$(mktemp)
mkdir -p "$DB"
certutil -N -d "sql:$DB" --empty-password
openssl pkcs12 -export -nodes -in ./ssl_cert.pem -inkey ./ssl_key.pem \
	-name "$CERT" -passout pass: -out "$P12CERT"
pk12util -d "sql:$DB" -i "$P12CERT" -W ''
certutil -L -d "sql:$DB" -n "$CERT"


./neqo/target/debug/neqo-server 0.0.0.0:$PORT -d "$DB" -k "$CERT" -v --qns-test http3