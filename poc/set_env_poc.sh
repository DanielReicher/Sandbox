#!/bin/bash

#install gcc for compiling the seccomp code
#and seccomp tools library.

echo
echo "Setup started"

sudo apt update
sudo apt install gcc libseccomp-dev

#give execution premition to the isolated process code.
chmod +x create_isolated_env_poc.sh

gcc seccomp-poc.c -o seccomp-poc -lseccomp

#compile malware file.
gcc maleware.c -o maleware

echo
echo "Setup completed."
