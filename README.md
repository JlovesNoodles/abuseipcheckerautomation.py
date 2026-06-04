# abuseipcheckerautomation.py
This is just a simple IP reputation checker automation

**Bulk IP reputation checker. Queries VirusTotal + AbuseIPDB and tells you what to block.**
185.220.101.47    VT:HIT  Abuse:HIT  →  BLOCK
8.8.8.8           VT:NO HIT  Abuse:NO HIT  →  benign

**Both sources must flag an IP for it to be marked BLOCK.**


**Setup**
pip install requests


**Get free keys at virustotal.com and abuseipdb.com.**

**Usage**

bashpython3 ipcheck.py ips.txt --vt YOUR_VT_KEY --abuse YOUR_ABUSE_KEY


**
One IP per line in your input file. Private/invalid IPs are skipped automatically.**
