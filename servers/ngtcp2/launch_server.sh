#!/bin/bash

if [ -z "$1" ]; then
  echo "Error: No port provided. Please provide a port number."
  exit 1
fi

PORT=$1

echo "Starting ngtcp server on port $PORT"

./examples/wsslserver 0.0.0.0 $PORT ./ssl_key.pem ./ssl_cert.pem -d ./root