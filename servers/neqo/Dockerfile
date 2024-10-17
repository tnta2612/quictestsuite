FROM ubuntu:24.04

# Install necessary system packages
RUN apt-get update && apt-get install -y curl git make mercurial gyp ninja-build python-is-python3 g++ zlib1g-dev libclang-dev ca-certificates coreutils libnss3-tools \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

ENV NSS_DIR=/nss
ENV NSPR_DIR=/nspr

RUN hg clone https://hg.mozilla.org/projects/nss "$NSS_DIR" && \
    hg clone https://hg.mozilla.org/projects/nspr "$NSPR_DIR"

RUN cd /nss && ./build.sh

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="$PATH:/root/.cargo/bin"

# Clone the specific version of quic-go
RUN git clone --recursive https://github.com/mozilla/neqo.git \
    && cd /neqo \
    && git checkout tags/v0.9.0 \
    && cargo build

# Copy the necessary files
RUN mkdir /www
RUN chmod 777 /www
COPY index.html /www/index.html
COPY index.html /www/test.html
COPY largeFile.html /www/largeFile.html
COPY launch_server.sh .
COPY ssl_cert.pem /
COPY ssl_key.pem /

# Make the shell script executable
RUN chmod +x launch_server.sh

# Set the entrypoint to launch the server
ENTRYPOINT [ "./launch_server.sh" ]
