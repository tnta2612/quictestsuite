FROM ubuntu:24.04

# Install necessary system packages
RUN apt-get update && apt-get install -y \
    libssl-dev \
    python3-dev \
    python3-pip \
    python3-venv \
    git && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Clone the specific version of aioquic
RUN git clone https://github.com/aiortc/aioquic && \
    cd /aioquic && git checkout tags/1.2.0

WORKDIR /aioquic

# Create and activate a Python virtual environment
RUN python3 -m venv venv
ENV PATH="/aioquic/venv/bin:$PATH"

# Install aioquic and dependencies in editable mode using the virtual environment
RUN pip install --upgrade pip && pip install -e . aiofiles asgiref httpbin starlette wsproto werkzeug

# Copy the necessary files
COPY index.html examples/htdocs/index.html
COPY index.html examples/htdocs/test.html
COPY largeFile.html examples/htdocs/largeFile.html
COPY launch_server.sh .

# Make the shell script executable
RUN chmod +x launch_server.sh

# Set the entrypoint to launch the server
ENTRYPOINT [ "./launch_server.sh" ]
