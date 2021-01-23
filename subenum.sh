#!/bin/sh


filename=$1


while read line; do


        echo "==========>Findomain<============"


        findomain -t $line --threads 200 -u ~/targets/$line.txt


        echo "==========>Asset finder<============"


        assetfinder --subs-only $line | tee -a ~/targets/$line.txt


        echo "==========>Sub finder<============"


        subfinder -d $line -t 200 -recursive -silent | tee -a ~/targets/$line.txt

        echo "============Crobat Rapid7 Sonar DNS==============="

        crobat -s $line | tee -a ~/targets/$line.txt

        echo "============Chaos==================================="

        chaos -d $line -silent | tee -a ~/targets/$line.txt

#       echo "============Crt.sh==================================="

#       curl -sk https://crt.sh/?q=%.$line&output=json | tr ',' '\n' | awk -F'"' '/name_value/ {gsub(/\*\./, "", $4); gsub(/\\n/,"\n",$4);print $4}' | sort -u


        echo "============Censys==================================="

        python ~/tools/censys-subdomain-finder/censys_subdomain_finder.py $line -o ~/targets/temp.txt

#        echo "==========>Amass<============"


#        amass enum -passive -noalts -norecursive -d $line | tee -a ../dump/$line.txt

        cat  ~/targets/temp.txt >> ~/targets/$line.txt

        rm ~/targets/temp.txt

        sort -u ~/targets/$line.txt -o ~/targets/$line.txt

        echo "============httpx==================================="

        httpx -l ~/targets/$line.txt -silent | tee -a ~/targets/$line-alive.txt

done < $filename
