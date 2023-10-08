#!/bin/sh
# DO NOT release this file, this is literally security by obscurity

cp server.py /tmp/
cp shellcancer /tmp/
cp 5ac38c9dbd2cff2892cb085953144cfbcf891c05/flag.txt /tmp/

cd /tmp && python3 server.py && ./shellcancer
