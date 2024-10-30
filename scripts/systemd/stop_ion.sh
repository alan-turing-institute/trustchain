#!/bin/bash

systemctl stop ipfs.service
systemctl stop mongodb.service
systemctl stop bitcoind.service
systemctl stop ion.bitcoin.service
systemctl stop ion.core.service

systemctl disable ipfs.service
systemctl disable mongodb.service
systemctl disable bitcoind.service
systemctl disable ion.bitcoin.service
systemctl disable ion.core.service
