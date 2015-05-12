#!/bin/sh
# This script is an example of the script
# responsible for launching AlfCSNode

while [ true ]; do
    python3 -m AlfCSNode <server_ip> --cert server.pem
    if [ $? -ne 1 ]; then
        break
    fi
    echo Relaunching Alf CrashStash Node
    echo
    sleep 1
done
