#!/bin/bash

# Check OS.
os=$(uname)
if [ "$os" != "Darwin" ]; then
  echo "This is not macOS"
  exit 1
fi

# Check the $ION_CONFIG env variable is set.
if [ -z $ION_CONFIG ]; then
  echo "ION_CONFIG is unset";
  exit 1
fi

# Check the $BITCOIN_DATA env variable is set.
if [ -z $BITCOIN_DATA ]; then
  echo "BITCOIN_DATA is unset";
  exit 1
fi

# Check the $ION_REPO env variable is set.
if [ -z $ION_REPO ]; then
  echo "ION_REPO is unset";
  exit 1
fi

# Check the $ION_BITCOIN_CONFIG_FILE_PATH env variable is set.
if [ -z $ION_BITCOIN_CONFIG_FILE_PATH ]; then
  echo "ION_BITCOIN_CONFIG_FILE_PATH is unset";
  exit 1
fi

# Check the $ION_BITCOIN_VERSIONING_CONFIG_FILE_PATH env variable is set.
if [ -z $ION_BITCOIN_VERSIONING_CONFIG_FILE_PATH ]; then
  echo "ION_BITCOIN_VERSIONING_CONFIG_FILE_PATH is unset";
  exit 1
fi

# Check the $ION_CORE_CONFIG_FILE_PATH env variable is set.
if [ -z $ION_CORE_CONFIG_FILE_PATH ]; then
  echo "ION_CORE_CONFIG_FILE_PATH is unset";
  exit 1
fi

# Check the $ION_CORE_VERSIONING_CONFIG_FILE_PATH env variable is set.
if [ -z $ION_CORE_VERSIONING_CONFIG_FILE_PATH ]; then
  echo "ION_CORE_VERSIONING_CONFIG_FILE_PATH is unset";
  exit 1
fi

# Get the directory containing this script.
src_dir=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )

# Get the User Agents (plist) directory.
plist_dir="$HOME/Library/LaunchAgents"
mkdir -p "$plist_dir"

###
### Edit the IPFS plist file and write it to the plist directory.
###
ipfs_plist=tech.ipfs.daemon.plist
ipfs_launchd="$plist_dir/$ipfs_plist"
escaped_ipfs_launchd=$(echo $ipfs_launchd|sed 's/\//\\\//g')

# Discover IPFS path and binary.
IPFS_PATH="${IPFS_PATH:-$HOME/.ipfs}"
escaped_ipfs_path=$(echo $IPFS_PATH|sed 's/\//\\\//g')

IPFS_BIN=$(which ipfs || echo ipfs)
escaped_ipfs_bin=$(echo $IPFS_BIN|sed 's/\//\\\//g')

# Replace tokens in the plist file and write to the plist directory.
sed -e 's/{{IPFS_PATH}}/'"$escaped_ipfs_path"'/g' \
  -e 's/{{IPFS_BIN}}/'"$escaped_ipfs_bin"'/g' \
  "$src_dir/$ipfs_plist" \
  > "$ipfs_launchd"

###
### Refer to the MongoDB plist file already created by Homebrew.
###
mongodb_plist=homebrew.mxcl.mongodb-community.plist
mongodb_launchd="$plist_dir/$mongodb_plist"

###
### Edit the Bitcoin plist file and write it to the plist directory.
###
bitcoin_plist=org.bitcoin.daemon.plist
bitcoin_launchd="$plist_dir/$bitcoin_plist"

# Discover bitcoind path and binary.
BITCOIN_BIN=$(find /Applications/bitcoin-*/bin -name "bitcoind")
if [ -z $BITCOIN_BIN ]; then
  echo "Error: failed to find bitcoind";
  exit 1
fi
escaped_bitcoin_bin=$(echo $BITCOIN_BIN|sed 's/\//\\\//g')

BITCOIN_CONF="$BITCOIN_DATA/bitcoin.conf"
escaped_bitcoin_conf=$(echo $BITCOIN_CONF|sed 's/\//\\\//g')

# Replace tokens in the plist file and write to the plist directory.
sed -e 's/{{BITCOIN_BIN}}/'"$escaped_bitcoin_bin"'/g' \
  -e 's/{{BITCOIN_CONF}}/'"$escaped_bitcoin_conf"'/g' \
  "$src_dir/$bitcoin_plist" \
  > "$bitcoin_launchd"

###
### Edit the ION plist files and write them to the plist directory.
###
ion_bitcoin_plist=foundation.identity.ion.bitcoin.plist
ion_core_plist=foundation.identity.ion.core.plist
ion_bitcoin_launchd="$plist_dir/$ion_bitcoin_plist"
ion_core_launchd="$plist_dir/$ion_core_plist"

# Discover npm path and binary.
NODE_BIN=$(which node || echo node)
escaped_node_bin=$(echo $NODE_BIN|sed 's/\//\\\//g')

escaped_ion_repo=$(echo $ION_REPO|sed 's/\//\\\//g')

ion_log_dir="$ION_CONFIG/log"
escaped_ion_log_dir=$(echo $ion_log_dir|sed 's/\//\\\//g')

mkdir -p "$ion_log_dir"

escaped_ion_bitcoin_config=$(echo $ION_BITCOIN_CONFIG_FILE_PATH|sed 's/\//\\\//g')
escaped_ion_bitcoin_versioning_config=$(echo $ION_BITCOIN_VERSIONING_CONFIG_FILE_PATH|sed 's/\//\\\//g')

escaped_ion_core_config=$(echo $ION_CORE_CONFIG_FILE_PATH|sed 's/\//\\\//g')
escaped_ion_core_versioning_config=$(echo $ION_CORE_VERSIONING_CONFIG_FILE_PATH|sed 's/\//\\\//g')

# Replace tokens in the plist files and write to the plist directory.
sed -e 's/{{NODE_BIN}}/'"$escaped_node_bin"'/g' \
  -e 's/{{ION_REPO}}/'"$escaped_ion_repo"'/g' \
  -e 's/{{ION_LOG_DIR}}/'"$escaped_ion_log_dir"'/g' \
  -e 's/{{ION_BITCOIN_CONFIG_FILE_PATH}}/'"$escaped_ion_bitcoin_config"'/g' \
  -e 's/{{ION_BITCOIN_VERSIONING_CONFIG_FILE_PATH}}/'"$escaped_ion_bitcoin_versioning_config"'/g' \
  "$src_dir/$ion_bitcoin_plist" \
  > "$ion_bitcoin_launchd"

sed -e 's/{{NODE_BIN}}/'"$escaped_node_bin"'/g' \
  -e 's/{{ION_REPO}}/'"$escaped_ion_repo"'/g' \
  -e 's/{{ION_LOG_DIR}}/'"$escaped_ion_log_dir"'/g' \
  -e 's/{{ION_CORE_CONFIG_FILE_PATH}}/'"$escaped_ion_core_config"'/g' \
  -e 's/{{ION_CORE_VERSIONING_CONFIG_FILE_PATH}}/'"$escaped_ion_core_versioning_config"'/g' \
  "$src_dir/$ion_core_plist" \
  > "$ion_core_launchd"

###
### Load the user agents.
###

# NOTE:
# These launchctl commands will take effect in macOS only if /bin/bash has been
# given Full Disk Access permission. To do this, open Security & Privacy settings,
# choose 'Full Disk Access', click the lock to make changes and enter your password.
# Then click the + button. Then hit cmd+shift+G, type `/bin/bash` and hit Enter.
# See: https://stackoverflow.com/questions/58442951/how-to-fix-operation-not-permitted-when-i-use-launchctl-in-macos-catalina

launchctl load $ipfs_launchd
launchctl load $mongodb_launchd
launchctl load $bitcoin_launchd
launchctl load $ion_bitcoin_launchd
launchctl load $ion_core_launchd

# Make the `stop_ion.sh` script executable.
chmod u+x "$src_dir/stop_ion.sh"

echo "Installed & loaded ION User Agents in: $plist_dir"
echo "ION logs will be written to: $ion_log_dir"
