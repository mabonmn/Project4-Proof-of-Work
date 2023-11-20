#!/bin/bash

for i in {16..26}; do
    echo "Running main.py with argument i=$i"
    python main.py $i

    # Rename files
    mv ../data/solution.txt ../data/solutions_$i.txt
    mv ../data/target.txt ../data/target_$i.txt

    echo "Files renamed to solutions_$i.txt and target_$i.txt"
done
