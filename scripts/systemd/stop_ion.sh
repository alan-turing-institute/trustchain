#!/bin/bash

systemctl --user stop ipfs
systemctl --user stop mongod
systemctl --user stop bitcoind
systemctl --user stop ion.bitcoin
systemctl --user stop ion.core

systemctl --user disable ipfs
systemctl --user disable mongod
systemctl --user disable bitcoind
systemctl --user disable ion.bitcoin
systemctl --user disable ion.core
