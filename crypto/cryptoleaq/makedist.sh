#!/bin/sh

cp src/server.py dist/
cp src/README.md dist/
cp src/program.subleq dist/
cp -r src/vm dist/

zip -r dist.zip dist
