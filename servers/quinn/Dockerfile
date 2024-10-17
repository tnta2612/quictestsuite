FROM ubuntu:24.04

# Install necessary system packages
RUN apt-get update && apt-get install -y git cmake cargo g++ \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Clone the specific version of quic-go
RUN git clone --recursive https://github.com/quinn-rs/quinn.git \
    && cd /quinn \
    && git checkout tags/quinn-udp-0.5.5
#    && cargo build --examples

WORKDIR /quinn

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
