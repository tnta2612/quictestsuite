import subprocess
import sys
import os
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def stop_docker_server(server):
    """
    Stop the running Docker server.
    """
    try:
        stop_command = f"sudo docker stop {server}"
        subprocess.run(stop_command, shell=True, check=True)
        logging.info(f"Server {server} stopped successfully.")
    except subprocess.CalledProcessError as e:
        logging.info(f"Failed to stop server {server}: {e}")


def remove_file(file_path):
    """
    Remove a specific file.
    
    :param file_path: Path to the file to be deleted
    """
    if not os.path.exists(file_path):
        logging.info(f"File {file_path} does not exist.")
        return
    
    try:
        if os.path.isfile(file_path):
            os.remove(file_path)
            logging.info(f"Removed file: {file_path}")
        else:
            logging.info(f"{file_path} is not a file.")
    except Exception as e:
        logging.info(f"Failed to remove file {file_path}: {e}")
        sys.exit(1)


def remove_log_files(logs_path='./aioquic/log'):
    """
    Remove files from the .aioquic/log directory.
    
    :param logs_path: Path to the log directory
    """
    if not os.path.exists(logs_path):
        logging.info(f"Directory {logs_path} does not exist.")
        return
    
    for filename in os.listdir(logs_path):
        file_path = os.path.join(logs_path, filename)
        remove_file(file_path)


def main(server_ports):
    """
    Main function to stop Docker servers and clean up files in the logs directory.
    """
    for sp in server_ports:
        server, _ = sp.split(':')
        # Stop the server
        stop_docker_server(server)
    
    # Remove all files
    remove_log_files()
    remove_file('./aioquic/session')
    remove_file('./aioquic/session_old')


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Example Usage: python3 cleanup.py 'aioquic:6001,lsquic:6002'")
        sys.exit(1)
    server_ports = sys.argv[1].split(',')
    main(server_ports)
