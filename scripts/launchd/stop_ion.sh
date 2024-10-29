#!/bin/bash

# Get the User Agents (plist) directory.
plist_dir="$HOME/Library/LaunchAgents"

ipfs_plist=tech.ipfs.daemon.plist
ipfs_launchd="$plist_dir/$ipfs_plist"

mongodb_plist=homebrew.mxcl.mongodb-community.plist
mongodb_launchd="$plist_dir/$mongodb_plist"

bitcoin_plist=org.bitcoin.daemon.plist
bitcoin_launchd="$plist_dir/$bitcoin_plist"

ion_bitcoin_plist=foundation.identity.ion.bitcoin.plist
ion_bitcoin_launchd="$plist_dir/$ion_bitcoin_plist"

ion_core_plist=foundation.identity.ion.core.plist
ion_core_launchd="$plist_dir/$ion_core_plist"

launchctl unload $ipfs_launchd
launchctl unload $mongodb_launchd
launchctl unload $bitcoin_launchd
launchctl unload $ion_bitcoin_launchd
launchctl unload $ion_core_launchd
