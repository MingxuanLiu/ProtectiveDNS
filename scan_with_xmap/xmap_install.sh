#!/bin/bash
###
# Detailed description of installing Xmap in https://github.com/idealeer/xmap/blob/master/INSTALL.md
###
clear
# wget https://github.com/idealeer/xmap/releases/download/1.0.0/xmap-1.0.0.tar.gz
# tar -xzf xmap-1.0.0.tar.gz
cd xmapx-master
sudo yum -y install tmux htop jq
sudo yum -y install libarchive cmake gmp-devel gengetopt flex byacc json-c-devel
sudo dnf --enablerepo=powertools -y install libpcap-devel
sudo dnf --enablerepo=powertools -y install libunistring-devel
cmake .
make -j4
sudo make install