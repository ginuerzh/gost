#!/bin/bash
set -x
set -e

CURRENT=`pwd`

#CGO_ENABLED=0 GOOS=linux GOARCH=amd64

cd $(dirname $0)
for name in `ls -d */|sed 's/\///g'`
do
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "../bin/$name" ./"$name"
done

ls ../bin/
cd "$CURRENT"
