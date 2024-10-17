FROM ubuntu:24.04

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive

# Install necessary system packages
RUN apt-get update && apt-get install -y git curl wget python3 python3-pip lsb-release sudo file \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Clone depot_tools and add to PATH
RUN git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git /opt/depot_tools
ENV PATH="/opt/depot_tools:${PATH}"

# Create chromium directory and fetch code (without history for faster build)
RUN mkdir -p /home/chromium && \
    cd /home/chromium && \
    fetch --nohooks --no-history chromium

# Switch to src directory
WORKDIR /home/chromium/src

# Install additional build dependencies (Ubuntu specific)
RUN ./build/install-build-deps.sh

# Run hooks to set up environment
RUN gclient runhooks

# Generate build files using GN
RUN gn gen out/Debug && ninja -C out/Debug quic_server quic_client

RUN cd net/tools/quic/certs && ./generate-certs.sh

# Copy the necessary files
RUN mkdir -p root
COPY index.html root/index.html
COPY test.html root/test.html
COPY largeFile.html root/largeFile.html
COPY launch_server.sh .

# Make the shell script executable
RUN chmod +x launch_server.sh

# Set the entrypoint to launch the server
ENTRYPOINT [ "./launch_server.sh" ]
