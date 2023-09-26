#-*- coding:utf-8 -*-
import os
import sys
import json
import IPy
import csv
import time
import subprocess
import random
from urllib.request import urlparse

from bs4 import BeautifulSoup as bs
from urllib.request import urlopen
from urllib.parse import urlparse

from tools.log import *


cates_final = ['Botnet', 'Malware', 'Phishing', 'Adlut', 'Tracker']
domain_main_path = 'data/domain'
vt_apikey = "yourkey"

# logging
run_dm = time.localtime()
run_m = str(run_dm.tm_mon)
run_d = str(run_dm.tm_mday)
if len(run_m)==1:
    run_m_str = '0'+run_m
else:
    run_m_str = run_m
if len(run_d)==1:
    run_d_str = '0'+run_d
else:
    run_d_str = run_d
run_date = run_m_str + run_d_str
logger = init_log("logs/domain_prepare.{}.log".format(run_date))

def is_ip(ipaddress):
    try:
        IPy.IP(ipaddress)
        return True
    except Exception as e:
        return False

# https://urlhaus.abuse.ch/api/
def urlhaus():
    cmd = f"curl -L https://urlhaus.abuse.ch/downloads/csv/ -o {domain_main_path}/all/urlhaus.zip"
    tmp = os.system(cmd)
    cmd = f"unzip -p {domain_main_path}/all/urlhaus.zip > {domain_main_path}/all/urlhaus.txt "
    tmp = os.system(cmd)
    fr = open(os.path.join(domain_main_path,'all/urlhaus.txt'), 'r', encoding='utf-8')
    n = 0
    haus_domains, haus_domains_online = {}, {}
    for line in fr:
        if line.startswith("#"):
            continue
        line_list = line.strip('\t\n').split(',')

        if 'http://' in line_list[2] or 'https://' in line_list[2]:
            domain = urlparse(line_list[2][1:-1]).netloc.split(':')[0]
        else:
            domain_tmp = line_list[2][1:-1]
            domain = urlparse('http://'+domain_tmp).netloc.split(':')[0]
        
        if is_ip(domain)==True:
            continue
        else:
            n += 1
            status = line_list[3].strip("\"").lstrip("\"")
            haus_domains[domain] = {'info':{'tag':"Malware"}}
            if status=='online':
                haus_domains_online[domain] = {'info':{'tag':"Malware"}}
    logger.info('[+] urlhaus: {}, {}, {}'.format(n, len(haus_domains), len(haus_domains_online)))
    with open(os.path.join(domain_main_path,'all/urlhaus.json'), 'w', encoding='utf-8') as f:
        json.dump(haus_domains, f)
    with open(os.path.join(domain_main_path,'all/urlhaus_online.json'), 'w', encoding='utf-8') as f:
        json.dump(haus_domains_online, f)
    return

# https://cybercrime-tracker.net
def cybercrime():
    cmd = f"curl -L https://cybercrime-tracker.net/all.php -o {domain_main_path}/all/cybercrime.txt"
    tmp = os.system(cmd)
    fr = open(os.path.join(domain_main_path,'all/cybercrime.txt'), 'r', encoding='utf-8')
    cyber_domains = {}
    n = 0
    for line in fr:
        line = line.strip('\t\n')
        line = 'https://'+line
        domain = urlparse(line).netloc.split(':')[0]
        if is_ip(domain)==False:
            n += 1
            cyber_domains[domain] = {'info':{'tag':"None"}}
    logger.info('[+] cybercrime: {}, {}'.format(n, len(cyber_domains)))
    with open(os.path.join(domain_main_path,'all/cybercrime.json'), 'w', encoding='utf-8') as f:
        json.dump(cyber_domains, f)
    return

# https://zonefiles.io/f/compromised/domains/full/
def zonefile():
    cmd = f"curl -L https://zonefiles.io/f/compromised/domains/full/ -o {domain_main_path}/all/zonefile_compromised_domains_full.txt"
    tmp = os.system(cmd)
    fr = open(os.path.join(domain_main_path,'all/zonefile_compromised_domains_full.txt'), 'r', encoding='utf-8')
    cyber_domains = {}
    n = 0
    for line in fr:
        line = line.strip('\t\n')
        domain = line
        if is_ip(domain)==False:
            n += 1
            cyber_domains[domain] = {'info':{'tag':"None"}}
    logger.info('[+] zonefile: {}, {}'.format(n, len(cyber_domains)))
    with open(os.path.join(domain_main_path,'all/zonefile.json'), 'w', encoding='utf-8') as f:
        json.dump(cyber_domains, f)
    return

# https://github.com/maravento/blackweb
def blackweb():
    cmd = f"curl -L https://github.com/maravento/blackweb/blob/master/blackweb.tar.gz -o {domain_main_path}/all/blackweb.tar.gz"
    tmp = os.system(cmd)
    fr = open(os.path.join(domain_main_path,'all/blackweb.txt'), 'r', encoding='utf-8')
    cyber_domains = {}
    n = 0
    for line in fr:
        line = line.strip('\t\n').lstrip('.')
        if line.startswith('#'):
            continue
        line = 'https://'+line
        domain = urlparse(line).netloc.split(':')[0]
        if is_ip(domain)==False:
            n += 1
            cyber_domains[domain] = {'info':{'tag':"None"}}
    logger.info('[+] blackweb: {}, {}'.format(n, len(cyber_domains)))
    with open(os.path.join(domain_main_path,'all/blackweb.json'), 'w', encoding='utf-8') as f:
        json.dump(cyber_domains, f)
    return

# https://www.iblocklist.com/
def i_blocklist():
    i_blocklist_path = f"{domain_main_path}/all/I-Blocklist"
    i_blocklist_domains = {}
    files = os.listdir(i_blocklist_path)
    for file_ in files:
        n_domain = 0
        f_tmp = open(os.path.join(i_blocklist_path, file_), 'r', encoding='utf-8')
        try:
            lines = f_tmp.readlines()
        except Exception as e:
            print(file_, e)
        if lines[2].startswith("# Blacklists")==False:
            continue
        for line in lines[4:]:
            line = line.strip('\t\n')
            domain = line.split(':')[0]
            if is_ip(domain)==False:
                n_domain += 1
                if domain not in i_blocklist_domains:
                    i_blocklist_domains[domain] = {'info':{'tag':[]}}
                i_blocklist_domains[domain]['info']['tag'].append(file_)          
        logger.info('[+] i-blocklist - {}: {}, {}'.format(file_, n_domain, len(i_blocklist_domains)))
    with open(os.path.join(domain_main_path,'all/i_blocklist.json'), 'w', encoding='utf-8') as f:
        json.dump(i_blocklist_domains, f)
    return

# https://www.iblocklist.com/
# https://www.iblocklist.com/lists?fileformat=hosts&archiveformat=gz
# http://list.iblocklist.com/?list=cgbdjfsybgpgyjpqhsnd&fileformat=hosts&archiveformat=gz
# http://list.iblocklist.com/?list=qlprgwgdkojunfdlzsiv&fileformat=hosts&archiveformat=gz
# http://security-research.dyndns.org/pub/botnet/ponmocup/ponmocup-finder/ponmocup-infected-domains-history.txt
def dyn_domains():
    fr = open(os.path.join(domain_main_path,'all/dyndns/dyn_botnet_1'), 'r', encoding='utf-8')
    fr2 = open(os.path.join(domain_main_path,'all/dyndns/dyn_malware_1'), 'r', encoding='utf-8')
    fr3 = open(os.path.join(domain_main_path,'all/dyndns/dyn_infect_1'), 'r', encoding='utf-8')
    fr4 = open(os.path.join(domain_main_path,'all/dyndns/dyn_infect_2'), 'r', encoding='utf-8')
    fr5 = open(os.path.join(domain_main_path,'all/dyndns/dyn_suspicious_1'), 'r', encoding='utf-8')
    cyber_domains = {}

    a,b,c,d,n = 0,0,0,0,0
    for line in fr:
        line = line.strip('\t\n').lstrip('.')
        if line.startswith('#'):
            continue
        line = 'https://'+line
        domain = urlparse(line).netloc.split(':')[0]
        if is_ip(domain)==False:
            n += 1
            a += 1
            cyber_domains[domain] = {'info':{'tag':'Botnet'}}

    for line in fr2:
        line = line.strip('\t\n').lstrip('.')
        if line.startswith('#'):
            continue
        line = 'https://'+line
        domain = urlparse(line).netloc.split(':')[0]
        if is_ip(domain)==False:
            n += 1
            b += 1
            cyber_domains[domain] = {'info':{'tag':'Malware'}}

    for line in fr3:
        line = line.strip('\t\n').lstrip('.')
        if line.startswith('#'):
            continue
        line = 'https://'+line
        domain = urlparse(line).netloc.split(':')[0]
        if is_ip(domain)==False:
            n += 1
            c += 1
            cyber_domains[domain] = {'info':{'tag':'infected'}}

    for line in fr4:
        line = line.strip('\t\n').lstrip('.')
        if line.startswith('#'):
            continue

        line_1 = line.split(':')[1].split('-')[0][1:-1]
        line_1 = 'https://'+line_1
        domain = urlparse(line_1).netloc.split(':')[0]
        if is_ip(domain)==False:
            n += 1
            c += 1
            cyber_domains[domain] = {'info':{'tag':'infected'}}
        
        line_2 = line.split(':')[3][2:-8]
        line_2 = 'https://'+line_2
        domain = urlparse(line_2).netloc.split(':')[0]
        if is_ip(domain)==False:
            n += 1
            c += 1
            cyber_domains[domain] = {'info':{'tag':'infected'}}

    for line in fr5:
        line = line.strip('\t\n').lstrip('.')
        if line.startswith('#'):
            continue
        line = 'https://'+line
        domain = urlparse(line).netloc.split(':')[0]
        if is_ip(domain)==False:
            n += 1
            d += 1
            cyber_domains[domain] = {'info':{'tag':'suspicious'}}
    logger.info('[+] Dyn: {},{} (all), {}(botnet), {}(Malware), {}(infected), {}(suspicious)'.format(n, len(cyber_domains), a, b, c, d))

    with open(os.path.join(domain_main_path,'all/dyn_domains.json'), 'w', encoding='utf-8') as f:
        json.dump(cyber_domains, f)
    return

# https://www.stopforumspam.com
def stop_forum():
    cmd = f"curl -L https://www.stopforumspam.com/downloads/toxic_domains_whole.txt -o {domain_main_path}/all/stopforum"
    tmp = os.system(cmd)
    fr = open(os.path.join(domain_main_path,'all/stopforum'), 'r', encoding='utf-8')
    cyber_domains = {}
    n = 0
    for line in fr:
        line = line.strip('\t\n').lstrip('.')
        if line.startswith('#'):
            continue
        line = 'https://'+line
        domain = urlparse(line).netloc.split(':')[0]
        if is_ip(domain)==False:
            n += 1
            cyber_domains[domain] = {'info':{'tag':"None"}}
    logger.info('[+] stop forum: {}, {}'.format(n, len(cyber_domains)))
    with open(os.path.join(domain_main_path,'all/stopforum.json'), 'w', encoding='utf-8') as f:
        json.dump(cyber_domains, f)
    return

def combination():
    files = os.listdir(os.path.join(domain_main_path, 'akk'))
    whole_domains = {}
    for file_ in files:
        if file_.startswith("2_") or file_.startswith('3_'):
            continue
        if file_.endswith('.json')==False or file_.startswith('whole'):
            continue
        with open(os.path.join(domain_main_path, "all/"+file_), 'r', encoding='utf-8') as f:
            tmp_json = json.load(f)
        logger.info("[+] File: {} with {} domains".format(file_, len(tmp_json)))

        source_tag = file_[:-5]
        if source_tag=="i_blocklist":
            for domain in tmp_json.keys():
                # print(file_, tmp_json[domain])
                if domain not in whole_domains:
                    for tag_ in tmp_json[domain]['info']['tag']:
                        whole_domains[domain] = {'info':{tag_:1}, 'source':{source_tag:1}}
                else:
                    whole_domains[domain]['source'][source_tag] = 1
                    for tag_ in tmp_json[domain]['info']['tag']:
                        if tag_ not in whole_domains[domain]['info']:
                            whole_domains[domain]['info'][tag_] = 1
                        else:
                            whole_domains[domain]['info'][tag_] += 1
        else:
            for domain in tmp_json.keys():
                # print(file_, tmp_json[domain])
                if domain not in whole_domains:
                    whole_domains[domain] = {'info':{tmp_json[domain]['info']['tag']:1}, 'source':{source_tag:1}}
                else:
                    whole_domains[domain]['source'][source_tag] = 1
                    if tmp_json[domain]['info']['tag'] not in whole_domains[domain]['info']:
                        whole_domains[domain]['info'][tmp_json[domain]['info']['tag']] = 1
                    else:
                        whole_domains[domain]['info'][tmp_json[domain]['info']['tag']] += 1
        logger.info('[+] {} --> Whole domains: {}'.format(source_tag, len(whole_domains))) 

    logger.info('[+] Whole domains: {}'.format(len(whole_domains)))    
    with open(os.path.join(domain_main_path, 'all/whole_domains.json'), 'w', encoding='utf-8') as f:
        json.dump(whole_domains, f)

    # with open(os.path.join(domain_main_path, 'whole_domains.json'), 'r', encoding='utf-8') as f:
    #     whole_domains = json.load(f)
    # print('[+] Whole domains: {}'.format(len(whole_domains))) 
    
    source_3, source_2 = {}, {}
    source_3_infos, source_2_infos = {'domains':{}, 'sources':{}, 'tags':{}}, {'domains':{}, 'sources':{}, 'tags':{}}
    for domain in whole_domains.keys():
        if len(whole_domains[domain]['source'])>=3:
            source_3[domain] = whole_domains[domain]
            source_3_infos['domains'][domain] = 1
            for ss in whole_domains[domain]['source'].keys():
                if ss not in source_3_infos['sources']:
                    source_3_infos['sources'][ss] = 0
                source_3_infos['sources'][ss] += 1
            for tag in whole_domains[domain]['info'].keys():
                if tag not in source_3_infos['tags']:
                    source_3_infos['tags'][tag] = 0
                source_3_infos['tags'][tag] += 1
        if len(whole_domains[domain]['source'])>=2:
            source_2[domain] = whole_domains[domain]
            source_2_infos['domains'][domain] = 1
            for ss in whole_domains[domain]['source'].keys():
                if ss not in source_2_infos['sources']:
                    source_2_infos['sources'][ss] = 0
                source_2_infos['sources'][ss] += 1
            for tag in whole_domains[domain]['info'].keys():
                if tag not in source_2_infos['tags']:
                    source_2_infos['tags'][tag] = 0
                source_2_infos['tags'][tag] += 1
    logger.info('[+] Overlap in 3 sources: {}'.format(len(source_3_infos['domains'])))
    for ss in source_3_infos['sources'].keys():
        # print(ss, source_3_infos['sources'][ss])
        logger.info("[+] 3 Source {} for {}".format(ss, str(source_3_infos['sources'][ss])))
    for tag in source_3_infos['tags'].keys():
        # print(tag, source_3_infos['tags'][tag])
        logger.info("[+] 3 Tags {} for {}".format(tag, source_3_infos['tags'][tag]))
    
    logger.info('[+] Overlap in 2 sources: {}'.format(len(source_2_infos['domains'])))
    for ss in source_2_infos['sources'].keys():
        # print(ss, source_2_infos['sources'][ss])
        logger.info("[+] 2 Source {} for {}".format(ss, str(source_2_infos['sources'][ss])))
    for tag in source_2_infos['tags'].keys():
        # print(tag, source_2_infos['tags'][tag])
        logger.info("[+] 2 Tags {} for {}".format(tag, source_2_infos['tags'][tag]))
    
    with open(os.path.join(domain_main_path, '3_sources_domains.info.json'), 'w', encoding='utf-8') as f:
        json.dump(source_3_infos, f)
    with open(os.path.join(domain_main_path, '2_sources_domains.info.json'), 'w', encoding='utf-8') as f:
        json.dump(source_2_infos, f)
    with open(os.path.join(domain_main_path, '3_sources_domains.json'), 'w', encoding='utf-8') as f:
        json.dump(source_3, f)
    with open(os.path.join(domain_main_path, '2_sources_domains.json'), 'w', encoding='utf-8') as f:
        json.dump(source_2, f)
    return

# Virus Total Query 
def domain_virustotal():
    import requests
    url = "https://www.virustotal.com/api/v3/domains/{}"
    headers = {
        "accept": "application/json",
        "x-apikey": f"{vt_apikey}"
    }

    with open(os.path.join(domain_main_path, '2_sources_domains.json'), 'r', encoding='utf-8') as f:
        source_2_infos = json.load(f)
    
    fw = open(os.path.join(domain_main_path, '2_sources_domains.ti.txt'), 'w', encoding='utf-8')
    n = 0
    for domain in source_2_infos['domains'].keys():
        url_domain = url.format(domain)
        response = requests.get(url_domain, headers=headers)
        response_json = json.loads(response.text)
        response_str = json.dumps(response_json)
        n += 1
        fw.write("{}\t{}\n".format(domain, response_str))

    return

# Domain Selection --> 10000 malicious domains
def domain_select():
    with open(os.path.join(domain_main_path, '2_sources_domains.cates_final.json'), 'r') as f:
        domain_final_tag = json.load(f)
    print('[+] 2 source domains: {}'.format(len(domain_final_tag)))

    with open(os.path.join(domain_main_path, '2_sources_domains.json'), 'r', encoding='utf-8') as f:
        source_2_infos = json.load(f)
    print('[+] 2 source domains: {}'.format(len(source_2_infos))) 

    tags = ["Malware", "Botne(DGA)", "Trojan", "Porn", "Spam", "Phishing", "Ad-Tracker"]

    cates_domains, random_1k_domains = {}, {}
    for tag in tags:
        random_1k_domains[tag] = {}
        cates_domains[tag] = {}
    print(random_1k_domains, cates_domains)

    for domain in domain_final_tag:
        if domain_final_tag[domain]=="None":
            continue
        cates_domains[domain_final_tag[domain]][domain] = source_2_infos[domain]['source']
    
    for cate in cates_domains:
        domains_all = list(cates_domains[cate].keys())
        print(cate, len(domains_all))
        domains_random = random.sample(domains_all, 1000)
        random_1k_domains[cate] = domains_random

    selected_domains = {}
    for cate in random_1k_domains:
        print(cate, len(random_1k_domains[cate]))
        for domain in random_1k_domains[cate]:
            selected_domains[domain] = {"source": source_2_infos[domain]['source'], "tag": cate}

    with open(os.path.join(domain_main_path, '2_sources_domains.select_cates.json'), 'w') as f:
        json.dump(random_1k_domains, f)
    print('[+] 2 source domains selected: {}'.format(len(random_1k_domains)))

    with open(os.path.join(domain_main_path, '2_sources_domains.select_domains.json'), 'w') as f:
        json.dump(selected_domains, f)
    print('[+] 2 source domains selected: {}'.format(len(selected_domains)))
    return

# Combine with normal domain names from Tranco
def domain_malicious_tranco():
    tranco_domain_path = f"{domain_main_path}/traco_150.json"
    with open(tranco_domain_path, 'r', encoding='utf-8') as f:
        ma_tranco_domains = json.load(f)
    print(len(ma_tranco_domains))
    
    tranco_domains = {}
    for domain in ma_tranco_domains:
        if ma_tranco_domains[domain]["tag"]!="malicious":
            tranco_domains[domain] = 1
    
    with open(os.path.join(domain_main_path, 'tranco_domains.json'), 'w') as f:
        json.dump(tranco_domains, f)
    print('[+] Domains from Tranco Top: {}'.format(len(tranco_domains)))
    return

# Generate scanning file
def build_scan_list():
    with open(os.path.join(domain_main_path, 'tranco_domains.json'), 'r') as f:
        tranco_domains = json.load(f)
    print('[+] Domains from Tranco Top: {}'.format(len(tranco_domains)))
    with open(os.path.join(domain_main_path, '2_sources_domains.select_domains.json'), 'r') as f:
        selected_domains = json.load(f)
    print('[+] 2 source domains selected: {}'.format(len(selected_domains)))

    fw = open(os.path.join(domain_main_path, 'scanning_list.malicious_tranco.txt'), 'w', encoding='utf-8') 
    tranco_domain_list = list(tranco_domains.keys())
    malicious_domain_list = list(selected_domains.keys())
    shuffle_malicious_domain = random.shuffle(malicious_domain_list)

    n,i = 0,0
    for domain in malicious_domain_list:
        n += 1
        if n%50==0:
            fw.write("{},{}\n".format("A", domain))
            if i<100:
                fw.write("{},{}\n".format("A", tranco_domain_list[i]))
            else:
                fw.write("{},{}\n".format("A", tranco_domain_list[i-100]))
            i += 1
        else:
            fw.write("{},{}\n".format("A", domain))
        
    fw.close()
    return

def main():
    urlhaus()
    cybercrime()
    zonefile()
    blackweb()
    i_blocklist()
    dyn_domains()
    stop_forum()
    combination()
    
    # TI query from VirusTotal and our partner, here we only put the code for Virustotal
    # domain_virustotal()

    # Domain Selection with VT results and results from our partner
    # domain_select()

    # Combine with normal domain names from Tranco
    # domain_malicious_tranco()

    # Generate scanning file
    # build_scan_list()
    return

if __name__=='__main__':
    main()