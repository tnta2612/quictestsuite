#!/bin/bash

if [ -z "$1" ]; then
  echo "Error: No port provided. Please provide a port number."
  exit 1
fi

PORT=$1
echo "Starting msquic server on port $PORT"

# The server only server http 0.9/1.1 => use --legacy-http for aioquic client
./quicinteropserver -listen:0.0.0.0 -port:$PORT -root:root -file:ssl_cert.pem -key:ssl_key.pem -name:www.example.com -noexit
