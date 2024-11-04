#!/bin/bash

# Check OS.
os=$(uname)
if [ "$os" != "Linux" ]; then
  echo "This is not Linux"
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

# Get the systemd directory for `--user` services.
systemd_dir="$HOME/.config/systemd/user/"
mkdir -p "$systemd_dir"

###
### Edit the IPFS service file and write it to the systemd directory.
###

escaped_home_dir=$(echo $HOME|sed 's/\//\\\//g')

# Replace tokens in the ipfs.service file and write to the systemd directory.
sed -e 's/{{HOME}}/'"$escaped_home_dir"'/g' \
  "$src_dir/ipfs.service" \
  > "$systemd_dir/ipfs.service"

###
### Edit the bitcoind.service file and write it to the systemd directory.
###
escaped_bitcoin_data=$(echo $BITCOIN_DATA|sed 's/\//\\\//g')

# Replace tokens in the bitcoind.service file and write to the systemd directory.
sed -e 's/{{BITCOIN_DATA}}/'"$escaped_bitcoin_data"'/g' \
  "$src_dir/bitcoind.service" \
  > "$systemd_dir/bitcoind.service"

###
### Edit the ION service files and write them to the systemd directory.
###
escaped_ion_repo=$(echo $ION_REPO|sed 's/\//\\\//g')

escaped_ion_bitcoin_config=$(echo $ION_BITCOIN_CONFIG_FILE_PATH|sed 's/\//\\\//g')
escaped_ion_bitcoin_versioning_config=$(echo $ION_BITCOIN_VERSIONING_CONFIG_FILE_PATH|sed 's/\//\\\//g')

escaped_ion_core_config=$(echo $ION_CORE_CONFIG_FILE_PATH|sed 's/\//\\\//g')
escaped_ion_core_versioning_config=$(echo $ION_CORE_VERSIONING_CONFIG_FILE_PATH|sed 's/\//\\\//g')

ion_log_dir="$ION_CONFIG/log"
escaped_ion_log_dir=$(echo $ion_log_dir|sed 's/\//\\\//g')

mkdir -p "$ion_log_dir"

# Replace tokens in the service files and write to the systemd directory.
sed -e 's/{{ION_REPO}}/'"$escaped_ion_repo"'/g' \
  -e 's/{{ION_BITCOIN_CONFIG_FILE_PATH}}/'"$escaped_ion_bitcoin_config"'/g' \
  -e 's/{{ION_BITCOIN_VERSIONING_CONFIG_FILE_PATH}}/'"$escaped_ion_bitcoin_versioning_config"'/g' \
  -e 's/{{ION_LOG_DIR}}/'"$escaped_ion_log_dir"'/g' \
  "$src_dir/ion.bitcoin.service" \
  > "$systemd_dir/ion.bitcoin.service"

sed -e 's/{{ION_REPO}}/'"$escaped_ion_repo"'/g' \
  -e 's/{{ION_CORE_CONFIG_FILE_PATH}}/'"$escaped_ion_core_config"'/g' \
  -e 's/{{ION_CORE_VERSIONING_CONFIG_FILE_PATH}}/'"$escaped_ion_core_versioning_config"'/g' \
  -e 's/{{ION_LOG_DIR}}/'"$escaped_ion_log_dir"'/g' \
  "$src_dir/ion.core.service" \
  > "$systemd_dir/ion.core.service"

###
### Start and enable the services.
###
systemctl --user start ipfs
systemctl --user start mongod
systemctl --user start bitcoind
systemctl --user start ion.bitcoin
systemctl --user start ion.core

systemctl --user enable ipfs
systemctl --user enable mongod
systemctl --user enable bitcoind
systemctl --user enable ion.bitcoin
systemctl --user enable ion.core

# Make the `stop_ion.sh` script executable.
chmod u+x "$src_dir/stop_ion.sh"

echo "Installed & enabled ION services in: $systemd_dir"
echo "ION logs will be written to: $ion_log_dir"
