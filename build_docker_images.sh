# Record start time
SECONDS=0

cd servers/aioquic
sudo docker build -t aioquic .
cd ../lsquic
sudo docker build -t lsquic .
cd ../mvfst
sudo docker build -t mvfst .
cd ../picoquic
sudo docker build -t picoquic .
cd ../quic-go
sudo docker build -t quic-go .
cd ../quiche
sudo docker build -t quiche .
cd ../msquic
sudo docker build -t msquic .
cd ../quinn
sudo docker build -t quinn .
cd ../neqo
sudo docker build -t neqo .
cd ../ngtcp2
sudo docker build -t ngtcp2 .
cd ../chromium
sudo docker build -t chromium .


echo "Script runtime: $SECONDS seconds"

