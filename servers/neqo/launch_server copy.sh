#!/bin/bash

if [ -z "$1" ]; then
  echo "Error: No port provided. Please provide a port number."
  exit 1
fi

PORT=$1

echo "Starting neqo server on port $PORT"

export LD_LIBRARY_PATH="$(dirname "$(find . -name libssl3.so -print | head -1)")"
export PATH="${PATH}:/neqo/bin"

echo $PATH

cp /neqo/target/release/neqo-server /neqo/bin/
pwd
ls /
#DB=/neqo/db
#CERT=cert
#P12CERT=$(mktemp)
#mkdir -p "$DB"
#certutil -N -d "sql:$DB" --empty-password
#openssl pkcs12 -export -nodes -in /certs/cert.pem -inkey /certs/priv.key -name "$CERT" -passout pass: -out "$P12CERT"
#pk12util -d "sql:$DB" -i "$P12CERT" -W ''
#certutil -L -d "sql:$DB" -n "$CERT"
#RUST_LOG=debug RUST_BACKTRACE=1 neqo-server --cc cubic --qns-test "$TESTCASE" --qlog-dir "$QLOGDIR" -d "$DB" -k "$CERT" '[::]:443' 2> >(tee -i -a "/logs/$ROLE.log" >&2)

DB=/neqo/db
CERT=cert
P12CERT=$(mktemp)
mkdir -p "$DB"
certutil -N -d "sql:$DB" --empty-password
openssl pkcs12 -export -nodes -in /ssl_cert.pem -inkey /ssl_key.pem \
	-name "$CERT" -passout pass: -out "$P12CERT"
pk12util -d "sql:$DB" -i "$P12CERT" -W ''
certutil -L -d "sql:$DB" -n "$CERT"

RUST_BACKTRACE=1 ./neqo/target/debug/neqo-server 0.0.0.0:$PORT -d "$DB" -k "$CERT"
#RUST_LOG=debug RUST_BACKTRACE=1 ./neqo/bin/neqo-server 0.0.0.0:$PORT -d "$DB" -k "$CERT"
