FROM ubuntu:24.04

# Install necessary system packages
RUN apt-get update && apt-get install -y git cmake wget sudo software-properties-common \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y dotnet-sdk-8.0 aspnetcore-runtime-8.0 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*


# Clone the specific version of msquic
RUN git clone https://github.com/microsoft/msquic.git \
    && cd /msquic \
    && git checkout tags/v2.3.6 \
    && git submodule update --init --recursive

WORKDIR /msquic

# Install PowerShell

RUN wget https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb && \
    dpkg -i packages-microsoft-prod.deb && \
    apt-get update && \
    apt-get install -y apt-transport-https && \
    apt-get update && \
    dotnet tool install -g powershell && \
    mkdir nuget./

ENV PATH="$PATH:/root/.dotnet/tools"

RUN pwsh -Command ./scripts/prepare-machine.ps1 \
    && pwsh -Command ./scripts/build.ps1

WORKDIR /msquic/artifacts/bin/linux/x64_Debug_openssl3

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
