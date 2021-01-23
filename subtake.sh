#!/bin/sh


filename=$1

        echo "==========>Subjack<============"


        subjack -w $1 -t 100 -timeout 30 -o ~/targets/$1_subtake.txt -ssl

        echo "==========>Subdover<============"


        python3 ~/tools/subdover/subdover.py -l $1 -t 1000 -o /tmp/subtemp.txt

        cat /tmp/subtemp.txt >> ~/targets/$1_subtake.txt

        rm /tmp/subtemp.txt

        echo "==========>Subzy<============"

        subzy -targets $1 -concurrency 1000 -timeout 30 -hide_fails | tee -a $1_subtake.txt

#        echo "==========>SubOver<============"


#        SubOver -l ../dump/$line.txt -t 100 -timeout 30 -o -https | tee -a $1_subover.txt


done < $filename
