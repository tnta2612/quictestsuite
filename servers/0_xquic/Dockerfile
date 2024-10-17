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

# Clone and build specific version of xquic and boringssl
RUN git clone git@github.com:alibaba/xquic.git /xquic \
    && cd /xquic \
    && git checkout tags/v1.8.0

WORKDIR /xquic

RUN git clone https://github.com/google/boringssl.git ./third_party/boringssl \
    && cd ./third_party/boringssl \
    && mkdir -p build && cd build \
    && cmake -DBUILD_SHARED_LIBS=0 -DCMAKE_C_FLAGS="-fPIC" -DCMAKE_CXX_FLAGS="-fPIC" .. \
    && make ssl crypto

ENV SSL_TYPE_STR=boringssl
ENV SSL_PATH_STR=/xquic/third_party/boringssl

RUN git submodule update --init --recursive \
    && mkdir -p build && cd build \
    && cmake -DGCOV=on \
    -DCMAKE_BUILD_TYPE=Debug \
    -DXQC_ENABLE_TESTING=1 \
    -DXQC_SUPPORT_SENDMMSG_BUILD=1 \
    -DXQC_ENABLE_EVENT_LOG=1 \
    -DXQC_ENABLE_BBR2=1 \
    -DXQC_ENABLE_RENO=1 \
    -DSSL_TYPE=boringssl \
    -DSSL_PATH=/xquic/third_party/boringssl .. \
    && make -j

# Set working directory to xquic
WORKDIR /xquic/build

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
