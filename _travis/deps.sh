#!/bin/sh

git clone https://github.com/aquynh/capstone.git --branch 4.0.2 --single-branch
cd capstone
make
sudo make install
cd ..
