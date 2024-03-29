# IoTShieldClientApp
Attack Detection in IoT &amp; IIoT Device Networks Using Machine Learning

Create AWS Linux 2 Server
Step for run the app
sudo yum update -y
sudo yum install git
sudo yum install wireshark
sudo yum install gcc openssl-devel bzip2-devel libffi-devel -y
wget https://www.python.org/ftp/python/3.9.0/Python-3.9.0.tgz
tar xzf Python-3.9.0.tgz

cd Python-3.9.0
./configure --enable-optimizations
sudo make altinstall


python3.9 --version

sudo alternatives --set python /usr/bin/python3.9

sudo update-alternatives --install /usr/bin/python3 python3 /usr/local/bin/python3.9 1

python3 --version

sudo pip3 install -r requirements.txt
sudo pip3 install urllib3==1.26.7
sudo python3 -m streamlit run app.py
