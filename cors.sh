#!/bin/sh


filename=$1

        echo "==========>CORS Me<============"

        cat $1 | CorsMe -t 70 -wildcard -output ~/targets/$1_cors.txt

        echo "==========>CORS Scanner<============"

       python ~/tools/CORScanner/cors_scan.py -i $1 -t 500 | tee -a ~/targets/$1_cors.txt


while read line; do

        echo "==========>Theft Fuzzer<============"

        python3 ~/tools/theftfuzzer/theftfuzzer.py -d $line | tee -a ~/targets/$1_cors.txt

done < $filename
