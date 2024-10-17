FROM ubuntu:24.04

# Install necessary system packages
RUN apt-get update && apt-get install -y build-essential git cmake software-properties-common openssl libssl-dev pkg-config clang \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Clone the specific version of quic-go
RUN git clone https://github.com/private-octopus/picoquic.git \
    && cd /picoquic \
    && cmake -DPICOQUIC_FETCH_PTLS=Y . && make

WORKDIR /picoquic

# Copy the necessary files
RUN mkdir -p root
COPY index.html root/index.html
COPY index.html root/test.html
COPY largeFile.html root/largeFile.html
COPY launch_server.sh .
COPY ssl_cert.pem .
COPY ssl_key.pem .

# Make the shell script executable
RUN chmod +x launch_server.sh

# Set the entrypoint to launch the server
ENTRYPOINT [ "./launch_server.sh" ]
