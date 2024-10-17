#!/bin/bash
if [ -z "$1" ]; then
  echo "Error: No port provided. Please provide a port number."
  exit 1
fi

PORT=$1
largefile_size=$2

echo "Starting aioquic server on port $PORT"

python3 examples/http3_server.py --certificate tests/ssl_cert.pem --private-key tests/ssl_key.pem --host 0.0.0.0 --port $PORT
	