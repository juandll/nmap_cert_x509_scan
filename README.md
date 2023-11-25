# nmap_cert_x509_scan
A script that analizes a web server x509 certificates to get information about something odd on the cert.

## First steps
- clone the repo: ```git clone https://github.com/juandll/nmap_cert_x509_scan.git```
- move to the folder: ```cd nmap_cert_x509_scan```
- Locate the nmap scripts folder: ``` locate *.nse ```
- With the locate command you will find where are the nmap scripts, with that path: ``` mv ./untrustedX509certs.nse /path/to/nmap/scripts/ ``` or ``` cp ./untrustedX509certs.nse /path/to/nmap/scripts/ ``` 
- now, you have the two test blacklists wich are necessary for the script to run: ```blacklist.csv``` and ```sslblacklist.csv```
- you can run ```nmap -p 443 --script untrustedX509certs.nse <detination host or IP>``` if you are running the command in the same folder the blacklists are located. If not, you can add a script argument to set the path to the blacklist: ``` nmap -p 443 --script untrustedX509certs.nse --script-args blacklist=/path/to/blacklist.csv,ssl_blacklist=/path/to/sslblacklist.csv <detination host or IP>```

### Blacklists
The blacklist.csv file contains infromations of date, CN and level of danger of a cert. these values are separated by ';' and every entry is separated by a new line.

The sslblacklist.csv contains information of the listing date, SHA1 fingerprint of cert and the listing reason. these values are separated by ',' and every entry is separated by a new line.

### Authors
-  Javier Gallego Monter
- Juan Diego Llano M.
