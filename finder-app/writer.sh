#!/bin/bash

if [ $# -ne 2 ] 
then
    echo "not two arguments"
    exit 1
fi

dirpath=$(dirname "$1")

mkdir -p "$dirpath"
if [ $? -ne 0 ] 
then
    echo "could not create directory path: $dirpath"
    exit 1
fi
echo "$2" > "$1"
if [ $? -ne 0 ] 
then
    echo "Could not write to file: $1"
    exit 1
fi

exit 0
