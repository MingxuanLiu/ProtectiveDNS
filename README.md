# Protective DNS Identifier

This tool can be used to discover Protective DNS resolvers on the Internet.
In a nutshell, the idea of the tool is to compare the results returned by resolver with those in authoritative name servers and Passive DNS. If the inconsistency of the results exceeds a threshold for a resolver, then that resolver is determined to have Protective function enabled.

If you are interested in our work, please read our paper **"[*Understanding the Implementation and Security Implications of Protective DNS Services, NDSS 2024*](https://www.ndss-symposium.org/ndss-paper/understanding-the-implementation-and-security-implications-of-protective-dns-services/)"** to find more details.


# Description
## Step I. Collecting Domain Names
As described in the paper, we selected a list of test domains from a list of seven open source malicious domains.
Use <ins>domain_prepare.py</ins> to select a domain name and its associated information.



## Step II. Querying open DNS servers
Our scanning process used an existing scanning tool, [*Xmap*](https://github.com/idealeer/xmap).
The specific use of Xmap is listed in the folder <ins>scan_with_xmap</ins>.

## Step III. dentifying PDNS
First, we use the <ins>dns_authoritative.py</ins> to get the results of the domain name resolution from the authoritative name servers.

Second, using <ins>compare_multi.py</ins>, the comparison analysis process is handled by multiple processes and the results of each comparison are written in a document.

Finally, using <ins>identification_multi.py</ins>, we judge the results for each resolver, identifying Protective DNS resolvers based on thresholds.

## Other
Besides, some configuration information is recorded in <ins>config.py</ins>, such as the specific values of the threshold.

The <ins>censor_prepare.py</ins> is used to pre-collect censorship results that can be used to distinguish between rewrites caused by Protective DNS.

Under the <ins>tools</ins> folder save:
- <ins>log.py</ins>, used to initialise the log file.
- <ins>geoip2</ins> folder, IP information database (from GeoLite)
- <ins>sp_ip.json</ins>, special IP List

The <ins>logs</ins> folder is used to store log files.

The <ins>data</ins> folder is used to store files that are used for overall script task execution.
- The <ins>domain</ins> folder is used to store information related to domain names, such as the results returned by authoritative servers, the results of domain name selection, and information about domain names that return dynamic IP addresses.
    - <ins>all</ins> folder saves all domains downloaded from 7 blocklists.
    - <ins>auth</ins> folder saves the authorative DNS responses for blocklists.
- The <ins>ip_infos</ins> folder is used to store IP addresses and their associated information.
- The <ins>resolvers</ins> folder stores the resolver and its related information, including the stable open resolver as well as IP address information (including PTR, ASN, etc.), pre-test result of censorship information, etc.

Several folders store the result files inside.
- The <ins>scan_results</ins> folder is to save the results of the raw data from scanning.
- The <ins>analysis_result</ins>s folder is to save the comparison (from <ins>compare_multi.py</ins>) and identification (<ins>identification_multi.py</ins>) results.

## Identification results (Open Source)
Finally, we open-source the identification results of sampled 10,000 PDNS resolvers (with no vulnerable ones) mentioned in our paper, which is saved in the <ins>open_source_results</ins>.

### Open Source Description
Please get a day's processing results at the following link: [download](https://drive.google.com/drive/folders/1O0uhJGb5uUQ-zQD1fvPHbGI66Y6WuhA2?usp=drive_link).

Due to ethical considerations and to avoid disclosing operations that may have security risks, 
1) we only made one day's results here and only sampled the results of the first 5,050 domains; 
2) we anonymised IP addresses for non-special purposes;
3) we filtered out the results of the vulnerable PDNS resolvers and did not make them public.

# Contact
If you have more relevant data or any questions, please contact liumx96 [AT] gmail.com. We would provide responses as soon as possible.
