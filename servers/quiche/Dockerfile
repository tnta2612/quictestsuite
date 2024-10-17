FROM ubuntu:24.04

# Install necessary system packages
RUN apt-get update && apt-get install -y git cmake cargo g++ \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Clone the specific version of quic-go
RUN git clone --recursive https://github.com/cloudflare/quiche \
    && cd /quiche \
    && git checkout tags/0.22.0 \
    && cargo build --examples

WORKDIR /quiche

# Copy the necessary files
RUN mkdir -p apps/src/bin/root
COPY index.html apps/src/bin/root/index.html
COPY index.html apps/src/bin/root/test.html
COPY largeFile.html apps/src/bin/root/largeFile.html
COPY launch_server.sh .
COPY ssl_cert.pem apps/src/bin/
COPY ssl_key.pem apps/src/bin/

# Make the shell script executable
RUN chmod +x launch_server.sh

# Set the entrypoint to launch the server
ENTRYPOINT [ "./launch_server.sh" ]
