# QUIC Server Testing Framework

This repository provides tools for validating protection mechanisms of QUIC servers regarding secrutiy considerations in RFC 9000. 
Docker servers can be run with Docker images whose Dockerfiles are provided.


Test suite need sudo previlidge because of network traffic sniffing and iptables

Switch to sudo user: sudo -i

Create a Python virtual environment

## Prerequisites

Ensure the following are installed on your system before starting:

sudo apt update
sudo apt install build-essential libnetfilter-queue-dev

- Python 3.x
- Docker (with `sudo` privileges)
- tshark

### Setup Wireshark for Traffic Capture

To capture traffic with `tshark`, add your user to the Wireshark group:

```bash
sudo dpkg-reconfigure wireshark-common 
sudo usermod -a -G wireshark $USER
gnome-session-quit --logout --no-prompt
```

### Install Dependencies

Install the required Python packages via pip:

```bash
sudo pip install -r requirements.txt
```

### Applying Patch Files

You can create and apply patch files using the following commands:

- To create a patch:  
  ```bash
  git diff > patch_file.patch
  ```
- To apply a patch:  
  ```bash
  git apply patch_file.patch
  ```
- To revert a patch:  
  ```bash
  git apply -R <patch>
  ```

## Project Structure

- **`build_docker_images.sh`**: Script to build Docker images for the QUIC servers.
- **`setup.py`**: Starts Docker containers running QUIC servers.
- **`testsuite.py`**: Runs test cases (e.g., amplification attack) and analyzes `.qlog` files.
- **`cleanup.py`**: Stops the running Docker containers.

## Sample Usage

### 1. Start QUIC Servers

To start the QUIC servers in Docker containers, run:

```bash
python3 setup.py 'aioquic:6001,lsquic:6002'
```

- Replace `'aioquic:6001,lsquic:6002'` with your server and port combinations.
- This will launch Docker containers with the specified servers listening on the given ports.

### 2. Activate the Virtual Environment

Activate the virtual environment for `aioquic`:

```bash
source aioquic/venv/bin/activate
```

### 3. Run Test Cases

With the servers running, execute the test cases and analyze the `.qlog` files using:

```bash
python3 testsuite.py 'aioquic:6001,lsquic:6002'
```

- This script will connect to each server, execute amplification attack tests, and analyze `.qlog` files for vulnerabilities.

### 4. Stop QUIC Servers

After testing, stop the QUIC servers by running:

```bash
python3 cleanup.py 'aioquic:6001,lsquic:6002'
```

- This will stop the specified Docker containers.

## Customization

### Adding New Test Cases

- To introduce additional test cases, modify the `testsuite.py` script. Define new functions and include them in the `main()` function.
- Ensure that any necessary setup or cleanup actions are handled within these functions.

### Log Analysis

- The existing log analysis in `testsuite.py` is basic. Customize the `analyze_qlog()` function to include specific logic for analyzing `.qlog` file contents.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for more information.

## Contributions

Contributions are welcome! Feel free to submit a pull request or open an issue to discuss improvements or new features.

---

This version improves readability, makes instructions more consistent, and removes redundant wording.