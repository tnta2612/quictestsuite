FROM ubuntu:24.04

ENV     DEBIAN_FRONTEND=noninteractive

# Install necessary system packages
RUN apt-get update && apt-get install -y gradle openjdk-11-jdk wget \
    build-essential \
    git \
    cmake \
    software-properties-common \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Clone the specific version of kwik and build it
RUN git clone https://github.com/ptrd/kwik.git

WORKDIR /kwik

RUN git checkout tags/0.8.13
RUN	git submodule update --init --recursive && ./gradlew assemble
    
        
    COPY --from=build /kwik/build/libs/kwik.jar .
    COPY --from=build /git_version.txt /git_version.txt
    

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
