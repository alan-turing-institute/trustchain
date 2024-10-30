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
escaped_src_dir=$(echo $src_dir|sed 's/\//\\\//g')

systemd_dir="/etc/systemd/system/"
escaped_systemd_dir=$(echo $systemd_dir|sed 's/\//\\\//g')

escaped_home_dir=$(echo $HOME|sed 's/\//\\\//g')

###
### Edit the IPFS service file and write it to the systemd directory.
###

# Replace tokens in the ipfs.service file and write to the systemd directory.
sed -e 's/{{HOME}}/'"$escaped_home_dir"'/g' \
  -e 's/{{USER}}/'"$USER"'/g' \
  "$src_dir/ipfs.service" \
  > "$escaped_systemd_dir/ipfs.service"

###
### Edit the bitcoind.service file and write it to the systemd directory.
###
escaped_bitcoin_data=$(echo $BITCOIN_DATA|sed 's/\//\\\//g')

# Replace tokens in the bitcoind.service file and write to the systemd directory.
sed -e 's/{{BITCOIN_DATA}}/'"$escaped_bitcoin_data"'/g' \
  -e 's/{{USER}}/'"$USER"'/g' \
  "$src_dir/bitcoind.service" \
  > "$escaped_systemd_dir/bitcoind.service"

###
### Edit the ION service files and write them to the systemd directory.
###
escaped_ion_repo=$(echo $ION_REPO|sed 's/\//\\\//g')

ion_log_dir="$ION_CONFIG/log"
escaped_ion_log_dir=$(echo $ion_log_dir|sed 's/\//\\\//g')

mkdir -p "$ion_log_dir"

escaped_ion_bitcoin_config=$(echo $ION_BITCOIN_CONFIG_FILE_PATH|sed 's/\//\\\//g')
escaped_ion_bitcoin_versioning_config=$(echo $ION_BITCOIN_VERSIONING_CONFIG_FILE_PATH|sed 's/\//\\\//g')

escaped_ion_core_config=$(echo $ION_CORE_CONFIG_FILE_PATH|sed 's/\//\\\//g')
escaped_ion_core_versioning_config=$(echo $ION_CORE_VERSIONING_CONFIG_FILE_PATH|sed 's/\//\\\//g')

# Replace tokens in the service files and write to the systemd directory.
sed -e 's/{{USER}}/'"$USER"'/g' \
  -e 's/{{ION_REPO}}/'"$escaped_ion_repo"'/g' \
  -e 's/{{ION_LOG_DIR}}/'"$escaped_ion_log_dir"'/g' \
  -e 's/{{ION_BITCOIN_CONFIG_FILE_PATH}}/'"$escaped_ion_bitcoin_config"'/g' \
  -e 's/{{ION_BITCOIN_VERSIONING_CONFIG_FILE_PATH}}/'"$escaped_ion_bitcoin_versioning_config"'/g' \
  "$src_dir/ion.bitcoin.service" \
  > "$escaped_systemd_dir/ion.bitcoin.service"

sed -e 's/{{USER}}/'"$USER"'/g' \
  -e 's/{{ION_REPO}}/'"$escaped_ion_repo"'/g' \
  -e 's/{{ION_LOG_DIR}}/'"$escaped_ion_log_dir"'/g' \
  -e 's/{{ION_CORE_CONFIG_FILE_PATH}}/'"$escaped_ion_core_config"'/g' \
  -e 's/{{ION_CORE_VERSIONING_CONFIG_FILE_PATH}}/'"$escaped_ion_core_versioning_config"'/g' \
  "$src_dir/ion.core.service" \
  > "$escaped_systemd_dir/ion.core.service"

###
### Start and enable the services.
###
systemctl start ipfs.service
systemctl start mongod.service
systemctl start bitcoind.service
systemctl start ion.bitcoin.service
systemctl start ion.core.service

systemctl enable ipfs.service
systemctl enable mongod.service
systemctl enable bitcoind.service
systemctl enable ion.bitcoin.service
systemctl enable ion.core.service

# Make the `stop_ion.sh` script executable.
chmod u+x "$src_dir/stop_ion.sh"

echo "Installed & enabled ION services in: $systemd_dir"
echo "ION logs will be written to: $ion_log_dir"
