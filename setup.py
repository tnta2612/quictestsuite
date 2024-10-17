import subprocess
import sys
import time
import os
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# initially implemented for picoquic, not necessary anymore
def set_sslkeylogfile_path():
    """
    Set the SSLKEYLOGFILE environment variable path in ~/.bashrc.
    """
    sslkeylog_line = "export SSLKEYLOGFILE=$HOME/testsuitegit/sslkey.log"
    bashrc_path = os.path.expanduser("~/.bashrc")
    
    try:
        # Check if the line already exists in ~/.bashrc
        with open(bashrc_path, 'r') as bashrc_file:
            if sslkeylog_line in bashrc_file.read():
                logging.info("The SSLKEYLOGFILE path is already set in ~/.bashrc.")
            else:
                # Append the line to ~/.bashrc
                with open(bashrc_path, 'a') as bashrc_file_append:
                    bashrc_file_append.write(f"\n{sslkeylog_line}\n")
                logging.info("The SSLKEYLOGFILE path has been added to ~/.bashrc.")
                logging.info("Please run 'source ~/.bashrc' or restart your terminal to apply the changes.")
    except Exception as e:
        logging.error(f"Failed to set SSLKEYLOGFILE path: {e}")
        sys.exit(1)
# initially implemented for picoquic, not necessary anymore
def check_and_build_picoquic():
    """
    Check if picoquic is available in the current repo.
    If not, clone and build picoquic.
    """
    picoquic_path = "./picoquic"
    
    if os.path.isdir(picoquic_path):
        logging.info("picoquic is already available in the current repository.")
    else:
        logging.info("picoquic not found. Cloning and building picoquic...")
        try:
            subprocess.run("git clone https://github.com/private-octopus/picoquic.git", shell=True, check=True)
            os.chdir(picoquic_path)
            subprocess.run("cmake -DPICOQUIC_FETCH_PTLS=Y . && make", shell=True, check=True)
            os.chdir("..")
            logging.info("picoquic cloned and built successfully.")
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to clone and build picoquic: {e}")
            sys.exit(1)

def check_and_build_aioquic():
    """
    Check if aioquic is available in the current repo.
    If not, clone and build aioquic.
    """
    aioquic_path = "./aioquic"
    
    if os.path.isdir(aioquic_path):
        logging.info("aioquic is already available in the current repository.")
    else:
        logging.info("aioquic not found. Cloning and building picoquic...")
        try:
            subprocess.run("git clone https://github.com/aiortc/aioquic", shell=True, check=True)
            os.chdir(aioquic_path)
            subprocess.run("git checkout tags/1.2.0", shell=True, check=True)
            subprocess.run(f"git apply ../client.patch", shell=True, check=True)
            subprocess.run("python3 -m venv venv", shell=True, check=True)
            os.environ["PATH"] = f"{os.path.abspath('venv/bin')}:{os.environ['PATH']}"
            subprocess.run("pip install --upgrade pip", shell=True, check=True)
            subprocess.run("pip install -e . aiofiles asgiref httpbin starlette wsproto werkzeug pyshark", shell=True, check=True)
            logging.info("aioquic cloned, built, and dependencies installed successfully.")
            os.makedirs("log", exist_ok=True)
            os.makedirs("output", exist_ok=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Failed to clone and build aioquic: {e}")
            sys.exit(1)

def run_docker_server(server, port):
    """
    Run the server Docker image with the given port.
    """
    try:
        logging.info(f"Starting server: {server} on port: {port}")
        docker_command = f"sudo docker run --name {server} -p {port}:{port}/udp --rm -d {server} {port}"
        subprocess.run(docker_command, shell=True, check=True)
        logging.info(f"Server {server} started successfully on port {port}.")
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to start server {server} on port {port}: {e}")
        sys.exit(1)

def main(server_ports):
    """
    Main function to start the Docker servers and ensure aioquic is set up.
    """
    # Ensure aioquic is available
    check_and_build_aioquic()

    for sp in server_ports:
        server, port = sp.split(':')
        port = int(port)
        # Run the server
        run_docker_server(server, port)
        # Wait a moment for the server to be ready
        time.sleep(5)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Example Usage: python3 setup.py 'aioquic:6001,lsquic:6002'")
        sys.exit(1)

    server_ports = sys.argv[1].split(',')
    main(server_ports)
