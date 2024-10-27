#!/bin/bash

# NOTE:
# This will not be runnable via launchctl in macOS until /bin/bash has been
# given Full Disk Access permission. To do this, open Security & Privacy settings,
# choose 'Full Disk Access', click the lock to make changes and enter your password.
# Then click the + button. Then hit cmd+shift+G, type `/bin/bash` and hit Enter.
# See: https://stackoverflow.com/questions/58442951/how-to-fix-operation-not-permitted-when-i-use-launchctl-in-macos-catalina

echo "Starting IPFS"
launchctl load $IPFS_LAUNCHD

echo "Starting MongoDB"
launchctl load $MONGODB_LAUNCHD

echo "Starting Bitcoind"
launchctl load $BITCOIN_LAUNCHD

echo "Starting ION bitcoin microservice"
launchctl load $ION_BITCOIN_LAUNCHD

echo "Starting ION core microservice"
launchctl load $ION_CORE_LAUNCHD
