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

# TODO: start bitcoind and ION microservices.
