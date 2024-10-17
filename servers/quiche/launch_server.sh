#!/bin/bash

if [ -z "$1" ]; then
  echo "Error: No port provided. Please provide a port number."
  exit 1
fi

PORT=$1

echo "Starting quiche server on port $PORT"

cargo run --bin quiche-server -- --cert apps/src/bin/ssl_cert.pem --key apps/src/bin/ssl_key.pem --listen 0.0.0.0:$PORT --root apps/src/bin/root/ --name www.example.com --no-retry --max-active-cids 999
apps/src/bin/root/