FROM ubuntu:24.04

# Install necessary system packages
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    cmake \
    software-properties-common \
    zlib1g-dev \
    libevent-dev \
    golang \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Clone the BoringSSL repository and navigate to its directory
RUN git clone https://boringssl.googlesource.com/boringssl /boringssl

WORKDIR /boringssl

# Check out a specific commit and modify CMakeLists.txt
RUN git checkout 9fc1c33e9c21439ce5f87855a6591a9324e569fd \
    && sed -i '/^cmake_minimum_required/ a add_compile_options(-Wno-ignored-attributes)' CMakeLists.txt \
    || sed -i '/^project/ a add_compile_options(-Wno-ignored-attributes)' CMakeLists.txt \
    && cmake . \
    && make

# Define an environment variable for BoringSSL directory
ENV BORINGSSL=/boringssl

# Clone the specific version of lsquic and build it
RUN git clone https://github.com/litespeedtech/lsquic.git /lsquic \
    && cd /lsquic \
    && git checkout tags/v4.0.9 \
    && git submodule update --init \
    && cmake -DBORINGSSL_DIR=$BORINGSSL . \
    && make

# Set working directory for the final application
WORKDIR /lsquic/bin

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
