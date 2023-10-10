#!/bin/sh

until nc -z -v -w30 $DBHOST 3306
do
  echo "Waiting for database connection..."
  sleep 5
done

node index.js