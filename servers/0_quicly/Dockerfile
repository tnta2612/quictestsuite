FROM ubuntu:24.04

# Install necessary system packages
RUN apt-get update && apt-get install -y libssl-dev \
    build-essential \
    git \
    cmake \
    software-properties-common \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Clone the specific version of lsquic and build it
RUN git clone https://github.com/h2o/quicly.git /quicly \
    && cd /quicly \
    && git submodule update --init --recursive \
    && cmake . \
    && make

# Set working directory for the final application
WORKDIR /quicly

# Copy the necessary files
RUN mkdir -p /www
COPY index.html /www/index.html
COPY index.html /www/test.html
COPY largeFile.html /www/largeFile.html
COPY launch_server.sh .
COPY ssl_cert.pem .
COPY ssl_key.pem .

# Make the shell script executable
RUN chmod +x launch_server.sh

# Set the entrypoint to launch the server
ENTRYPOINT [ "./launch_server.sh" ]
