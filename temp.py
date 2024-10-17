import subprocess
import logging
import time
import sys
import pyshark
tshark_sniff_command = [
    'tshark', '-i', 'lo', '-f', 'udp port 5555', '-w', './capture.pcap'
]
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

results_string = ""

def append_to_results(result):
    global results_string
    results_string += result + "\n"

def run_test_case_new_token_support(server, port, http3=True):
    logging.info(f"Running test case new_token_support against {server} on port {port}.")
    client_command_h0 = [
        "python3", "aioquic/examples/http3_client.py",
        "--ca-certs", "aioquic/tests/pycacert.pem",
        "--secrets-log", "aioquic/secrets.log",
        "--session-ticket", "aioquic/session",
        "--insecure",
        "--output-dir", "aioquic/output",
        "--quic-log", "aioquic/log",
        "--verbose",
        "--legacy-http",
        "--server-name", "www.example.com",
        "--local-port", "5555",
        f"https://localhost:{str(port)}/test.html"
    ]
    client_command_h3 = [
        "python3", "aioquic/examples/http3_client.py",
        "--ca-certs", "aioquic/tests/pycacert.pem",
        "--secrets-log", "aioquic/secrets.log",
        "--session-ticket", "aioquic/session",
        "--insecure",
        "--output-dir", "aioquic/output",
        "--quic-log", "aioquic/log",
        "--verbose",
        "--server-name", "www.example.com",
        "--local-port", "5555",
        f"https://localhost:{str(port)}/test.html"
    ]
    if http3:
        client_command = client_command_h3
    else:
        client_command = client_command_h0

    try:
        logging.info(f"Executing client command: {' '.join(client_command)}")
        subprocess.run(client_command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
    except subprocess.CalledProcessError as e:
        logging.error(f"Failed to run HTTP/3 client script against {server} on port {port}: {e}")
        logging.info(f"Trying again with HTTP/0.9...")
        return run_test_case_new_token_support(server, port, http3=False)


if __name__ == "__main__":
    server = "chromium"
    port = 6002
    run_test_case_new_token_support(server, port)
