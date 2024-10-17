#!/bin/bash

if [ -z "$1" ]; then
  echo "Error: No port provided. Please provide a port number."
  exit 1
fi

PORT=$1

echo "Starting quicly server on port $PORT"

ls

./cli -c ssl_cert.pem -k ssl_key.pem 0.0.0.0 $PORT