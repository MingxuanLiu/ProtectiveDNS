#!/bin/bash
clear


if [ "$#" -ne 5 ];
then
    echo "[*] DNS Scanning"
    echo "[*] Usage: $0 <resolver file> <domain file> <domain number> <date> <scan rate>"
    exit 0
fi

# Variables 
#   $1: <resolver file>
#   $2: <domain file>
#   $3: <domain number>
#   $4: <date>
#   $4: <scan rate>
# Write your bash script here

resolvers=$1
domain_tag="raws:recurse:file:${2}"
domain_num=$3
date=$4
rate=$5
result_txt="results/result_${date}.txt"
result_log="results/result_${date}.log"

# save several fields of DNS responses
${xmap} -4 -x 32 -p 53 -M dnsx -O json -i eth0 --output-fields=saddr,ttl,dns_rcode,dns_questions,dns_answers,raw_data,timestamp_ts --output-filter="success = 1 && (repeat = 0 || repeat =1)" -I ${resolvers} -o ${result_txt} --metadata-file=${result_log} -R ${rate} -P ${domain_num} --probe-args=${domain_tag} --est-elements=100000000


# save all fields of DNS responses
# ${xmap} -4 -x 32 -p 53 -M dnsx -O json -i eth0 --output-fields=* --output-filter="success = 1 && (repeat = 0 || repeat =1)" -I ${resolvers} -o ${result_txt} --metadata-file=${result_log} -R ${rate} -P ${domain_num} --probe-args=${domain_tag} --est-elements=100000000
