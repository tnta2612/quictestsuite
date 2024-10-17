#!/bin/bash

if [ -z "$1" ]; then
  echo "Error: No port provided. Please provide a port number."
  exit 1
fi

PORT=$1

echo "Starting picoquic server on port $PORT"

./picoquicdemo -p $PORT -w root -k ssl_key.pem -c ssl_cert.pem