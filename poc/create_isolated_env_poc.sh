#!/bin/bash

#if a command fails the script will keep running
set -e

echo "Creating bookstore filesystem"

# Get the absolute path of our current directory
BASE="$(pwd)"

# Create directory structure
mkdir -p "$BASE/bookstore/books"
mkdir -p "$BASE/bookstore/checkout"
mkdir -p "$BASE/bookstore/lounge"
mkdir -p "$BASE/bookstore/old_root"

# Create sample file
echo "Fiction novels" > "$BASE/bookstore/books/inventory.txt"

#copy maleware file and seccomp file to the isolated env.
cp seccomp-poc "$BASE/bookstore/"
cp maleware "$BASE/bookstore/"

echo "Entering new namespaces"

#sudo- root privileges
#unshare- creates new Linux namespaces for the process
#--mount-  creates a new mount namespace
#--pid- creates a new PID namespace
#--fork — creates a child process so that the child becomes the first process in the new PID namespace
#--mount-proc- mounts a new /proc filesystem 
#env- creates an environment named "BASE"
#bash -c- starts bash and execute the commands in the ''

sudo unshare --mount --pid --fork --mount-proc \
    env BASE="$BASE" \
    bash -c '

        echo "Inside namespace"
        echo "PID: $$"

        # moved booksore dirc into the isolated file system (Make bookstore a mount point)
        mount --bind "$BASE/bookstore" "$BASE/bookstore"

        # Prevent mount from "hurting" the host
        mount --make-private "$BASE/bookstore"

        # Move into the bookstore dict
        cd "$BASE/bookstore"

        echo "Before pivot_root:"
        pwd

        # Change root and move the old root into the dirc "old_root"
        #make bookstore the new /
        pivot_root . old_root

        # Move to the new root
        cd /

        echo
        echo "New root filesystem"
        ls /

        echo
        echo "Reading inventory"
        cat /books/inventory.txt

        echo
        echo "Namespace test complete"

        echo
        echo "Running maleware with seccomp limitations"

        #
        ./seccomp-poc ./malware
    '