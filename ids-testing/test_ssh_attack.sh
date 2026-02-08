#!/bin/bash

# Add fake SSH failed login attempts to auth.log
echo "Adding fake SSH brute force attempts..."

FAKE_IP="203.0.113.50"
TIMESTAMP=$(date '+%b %d %H:%M:%S')

# Append 10 failed login attempts
for i in {1..10}; do
    echo "$TIMESTAMP $(hostname) sshd[12345]: Failed password for invalid user admin from $FAKE_IP port 54321 ssh2" | sudo tee -a /var/log/auth.log > /dev/null
    echo "Added attempt $i"
    sleep 0.5
done

echo "Done! Check your IDS - it should detect $FAKE_IP"
