#!/bin/bash

#if a command fails the script will keep running
set -e

echo "downloading and updating busybox command if needed-"
echo ""

#download commands for isolated system.
sudo apt update && sudo apt install -y busybox-static

#absorb file to run in the isolated enviorment.
echo "Enter the path of the file to run in the isolated environment:"
read filePath

#check if file exists.
if [ ! -f "$filePath" ]; then
    echo "Error: File not found!"
    exit 1
fi

# Get the absolute path of our current directory
BASE="$(pwd)"
SANDBOX_DIR="$BASE/sandbox"

#create basic folders for isolated enviorment.
mkdir -p "$SANDBOX_DIR/bin"
mkdir -p "$SANDBOX_DIR/old_root"

#copy the file to run into the isolated enviorment.
cp "$filePath" "$SANDBOX_DIR/"
FILENAME=$(basename "$filePath")

#give running premissions to file.
chmod +x "$SANDBOX_DIR/$FILENAME"

#append minimal commands for isolated system.
cp /bin/busybox "$SANDBOX_DIR/bin/"
ln -sf busybox "$SANDBOX_DIR/bin/sh"
ln -sf busybox "$SANDBOX_DIR/bin/ls"
ln -sf busybox "$SANDBOX_DIR/bin/echo"

#find pivot_root
PIVOT_ROOT=$(command -v pivot_root || true)

if [ -z "$PIVOT_ROOT" ]; then
    echo "pivot_root not found. Installing util-linux..."
    sudo apt update
    sudo apt install -y util-linux-extra
    PIVOT_ROOT=$(command -v pivot_root || true)
fi

if [ -z "$PIVOT_ROOT" ]; then
    echo "Error: pivot_root was not found after installation."
    exit 1
fi

echo "pivot_root found at: $PIVOT_ROOT"

echo "Entering new namespaces..."

#sudo- root privileges
#unshare- creates new Linux namespaces for the process
#--mount-  creates a new mount namespace
#--pid- creates a new PID namespace
#--fork — creates a child process so that the child becomes the first process in the new PID namespace
#--mount-proc- mounts a new /proc filesystem 
#uts - sets up the hostname and domain name, without to effecting the rest of the system.
#enter a new bash shell, running in a new UTS namespace.
#env- creates an environment named "BASE"
#bash -c- starts bash and execute the commands in the ''

#--mape-root-user - map UID 0 (root) inside the namespace to UID 1000 on the host system


sudo unshare --mount --pid --uts --net --user --map-root-user --fork --mount-proc \
    env BASE="$BASE" FILENAME="$FILENAME" PIVOT_ROOT="$PIVOT_ROOT" \
    bash -c '

        echo "Inside namespaces:"
        echo "PID: $$"

        #change hostname and domain.

        hostname sandbox-hila-daniel
        domainname -b sandbox-hila-daniel-domain


        echo "After changing the UTS:"
        lsns -t uts -o NS,PID,USER
        echo

        #for loopback/localhost communication
        ip link set lo up

        #move sandbox folder into the isolated file system.
        mount --bind "$BASE/sandbox" "$BASE/sandbox"

        #prevent mount from "hurting" the host
        mount --make-private "$BASE/sandbox"


        #move into sandbox directory.
        cd "$BASE/sandbox"    


        #change root of the file system.

        if ! "$PIVOT_ROOT" . old_root; then
            echo "Error: pivot_root failed"
            exit 1
        fi

        #move to the new root
        cd /

        #update path for commands.
        export PATH=/bin

        echo "New root filesystem:"
        ls /

        echo "Testing loopback:"
        busybox ping -c 1 127.0.0.1

        echo "Testing external network:"
        if busybox ping -c 1 -W 2 1.1.1.1; then
            echo "error: External network is reachable"
        else
            echo "External network is unreachable"
        fi

        echo "Executing the file in the isolated environment:"
        #run file in isolated enviroment with busybox.
        sh /"$FILENAME"

        echo
        echo "Namespace test complete"

    '

