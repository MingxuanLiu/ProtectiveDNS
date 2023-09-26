This tool can be used to discover Protective DNS resolvers on the Internet.
In a nutshell, the idea of the tool is to compare the results returned by resolver with those in authoritative name servers and Passive DNS. If the inconsistency of the results exceeds a threshold for a resolver, then that resolver is determined to have Protective function enabled.

If you are interested in our work, you are welcome to read our paper "Understanding the Implementation and Security Implications of Protective DNS Services".

Step I. Collecting Domain Names
As described in the paper, we selected a list of test domains from a list of seven open source malicious domains.
Use domain_prepare.py to select a domain name and its associated information.

Step II. Querying open DNS servers
Our scanning process used an existing scanning tool, Xmap (https://github.com/idealeer/xmap).
The specific use of Xmap is listed in the folder scan_with_xmap.

Step III. dentifying PDNS
First, we use the dns_authoritative.py to get the results of the domain name resolution from the authoritative name servers.
Second, using compare_multi.py, the comparison analysis process is handled by multiple processes and the results of each comparison are written in a document.
Finally, using identification_multi.py, we judge the results for each resolver, identifying Protective DNS resolvers based on thresholds.

Besides, some configuration information is recorded in config.py, such as the specific values of the threshold.

The censor_prepare.py is used to pre-collect censorship results that can be used to distinguish between rewrites caused by Protective DNS.

Under the Tools folder save:
- log.py, used to initialise the log file.
- geoip2, IP information database (from GeoLite)
- sp_ip.json, special IP List

The logs folder is used to store log files.

The data folder is used to store files that are used for overall script task execution.
- The domain folder is used to store information related to domain names, such as the results returned by authoritative servers, the results of domain name selection, and information about domain names that return dynamic IP addresses.
    - all folder saves all domains downloaded from 7 blocklists.
    - auth folder saves the authorative DNS responses for blocklists.
- The ip_infos folder is used to store IP addresses and their associated information.
- The resolvers folder stores the resolver and its related information, including the stable open resolver as well as IP address information (including PTR, ASN, etc.), pre-test result of censorship information, etc.

Several folders store the result files inside.
- The scan_results folder is to save the results of the raw data from scanning.
- The analysis_results folder is to save the comparison (from compare_multi.py) and identification (identification_multi.py) results.

Finally, we make publicly available in the open_source_results folder the identification of the 17,601 PDNS resolvers we eventually found in the paper.

Finally, we open-source the identification results of the 17,601 PDNS resolvers mentioned in our paper, which is saved in the open_source_results.
