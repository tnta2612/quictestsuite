FROM ubuntu:24.04

# Install necessary system packages
RUN apt-get update && apt-get install -y g++ \
    build-essential \
    autoconf \
    libtool \
    pkg-config \
    git \
    wget \
    curl \
    automake \
    ca-certificates \
    libev-dev \
    zlib1g-dev \
    libssl-dev \
    libnghttp2-dev \
    python3 \
    python3-pip \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV WOLFSSL_VERSION=v5.7.2-stable

# Clone and build wolfSSL
RUN git clone --depth 1 -b $WOLFSSL_VERSION https://github.com/wolfSSL/wolfssl && \
    cd wolfssl && \
    autoreconf -i && \
    ./configure --prefix=$PWD/build --enable-all --enable-aesni --enable-harden --enable-keylog-export --disable-ech && \
    make -j$(nproc) && \
    make install

# Clone and build nghttp3
RUN git clone --recursive https://github.com/ngtcp2/nghttp3 && \
    cd nghttp3 && \
    git checkout tags/v1.5.0 && \
    autoreconf -i && \
    ./configure --prefix=$PWD/build --enable-lib-only && \
    make -j$(nproc) check && \
    make install

# Clone and build ngtcp2
RUN git clone --recursive https://github.com/ngtcp2/ngtcp2 && \
    cd ngtcp2 && \
    git checkout tags/v1.7.0 && \
    autoreconf -i && \
    ./configure PKG_CONFIG_PATH=$PWD/../wolfssl/build/lib/pkgconfig:$PWD/../nghttp3/build/lib/pkgconfig --with-wolfssl && \
    make -j$(nproc) check


# Set the working directory
WORKDIR /ngtcp2

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


