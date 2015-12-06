#!/bin/sh
mkdir mnt
. venv/bin/activate
pip3 install -e .
env PYTHONUNBUFFERED=1 venv/bin/secfs-server server.sock > server.log &

# Load user-1001-key.pem below, for testing group permissions.
sudo env PYTHONUNBUFFERED=1 venv/bin/secfs-fuse PYRO:secfs@./u:server.sock mnt/ root.pub user-0-key.pem "user-$(id -u)-key.pem" "user-1001-key.pem" > client.log &
