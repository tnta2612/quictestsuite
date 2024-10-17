FROM ubuntu:24.04

# Install necessary system packages
RUN apt-get update && apt-get install -y wget tar git net-tools \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN wget https://go.dev/dl/go1.22.6.linux-amd64.tar.gz && \
    rm -rf /usr/local/go && tar -C /usr/local -xzf go1.22.6.linux-amd64.tar.gz && \
    rm go1.22.6.linux-amd64.tar.gz

ENV PATH="$PATH:/usr/local/go/bin"

# Clone the specific version of quic-go
RUN git clone https://github.com/quic-go/quic-go.git \
    && cd /quic-go \
    && git checkout tags/v0.46.0

WORKDIR /quic-go

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
