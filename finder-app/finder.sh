#!/bin/sh

if [ $# -ne 2 ]
then
    echo "not two arguments"
    exit 1
elif [ ! -d "$1" ]
then
    echo "arg1 should be anexisting directory"
    exit 1
else
    X=$(find "$1" -type f | wc -l)
    Y=$(grep -r "$2" "$1" | wc -l)
    echo "The number of files are $X and the number of matching lines are $Y"
    exit 0
fi
