#-*- coding:utf-8 -*-
import os
import sys
import json
import copy
import traceback
from subprocess import Popen, PIPE
import time
import re
import asyncio
import geoip2.webservice
import geoip2.database
import geoip2.models
import ipaddress
import binascii
from aslookup import get_as_data
import ipaddress
import random
import dns.resolver

# sys.path.append('/home/lmx/data/malformed/tools/program')
# from app.log import *
sys.path.append("../")
from config import *

asn_reader = geoip2.database.Reader('/home/lmx/program/data/geoip2/230607/GeoLite2-ASN_20230606/GeoLite2-ASN.mmdb')
cc_reader = geoip2.database.Reader('/home/lmx/program/data/geoip2/230607/GeoLite2-City_20230606/GeoLite2-City.mmdb')

def geolite(ip):
    try:
        response_asn = asn_reader.asn(ip)
        asn = response_asn.autonomous_system_number
        aso = response_asn.autonomous_system_organization
        pre = response_asn._prefix_len
        subnet = "{}/{}".format(ip, pre)
        pre_net = str(ipaddress.ip_network(subnet, strict=False))
    except:
        asn, aso, pre_net  = 'None', 'None', 'None'
    try:
        response_cc = cc_reader.city(ip)
        ccn = response_cc.registered_country.iso_code
    except:
        ccn = 'None'
    return asn, aso, pre_net, ccn

def resolver_4_censor():
    with open("data/resolvers/open_ip_infos.json", 'r', encoding='utf-8') as f:
        ip_infos = json.load(f)
    print(len(ip_infos), ip_infos.keys())

    f = open("data/resolvers/resolver_230411.txt", 'r', encoding='utf-8')
    open_resolvers = {}
    for line in f:
        line = line.strip('\t\n')
        open_resolvers[line] = 1
    print(len(open_resolvers))

    censor_resolvers = {}
    for key in ip_infos['as']:
        first_ip = list(ip_infos['as'][key].keys())[0]
        asn, aso, pre_net, ccn = geolite(first_ip)
        if pre_net=="None":
            continue
        net = ipaddress.ip_network(pre_net)
        net_ips = list(net.hosts())
        subnet_str = pre_net.split('/')[0]

        while subnet_str in open_resolvers:
            index = random.randint(0, len(net_ips)-1)
            subnet_str = str(net_ips[index])   
            
        if subnet_str not in censor_resolvers:
            censor_resolvers[subnet_str] = ip_infos['as'][key]
        else:
            for kk in ip_infos['as'][key].keys():
                if kk not in censor_resolvers[subnet_str]:
                    censor_resolvers[subnet_str][kk] = 1
    print(len(censor_resolvers))

    with open("data/resolvers/censor_subnets.json", 'w', encoding='utf-8') as f:
        json.dump(censor_resolvers, f)
    fw = open("data/resolvers/censor_subnets.txt", 'w', encoding='utf-8')
    for subnet in censor_resolvers:
        fw.write("{}\n".format(subnet))
    return

def censor_preprocess():
    f = open("data/resolvers/censor_result.txt", 'r', encoding='utf-8')
    fw = open("data/resolvers/censor_result.has.txt", 'w', encoding='utf-8')
    n = 0
    for line in f:
        line = line.strip('\t\n')
        line_dict = json.loads(line)
        resolver_ip = line_dict['saddr']
        domain = line_dict['dns_questions'][0]['name']
        if len(line_dict['dns_answers'])==0:
            continue
        n += 1
        fw.write("{}\n".format(line))
    # 41957
    print(n)
    f.close()
    fw.close()
    return

def censor_groundtruth():
    f_auth = open("data/resolvers/auth_London.txt", 'r', encoding='utf-8')
    f = open("data/resolvers/censor_result.has.txt", 'r', encoding='utf-8')

    all_dns_list = ["103.144.38.0", "168.227.208.0"]
    auth_results, censor_ground = {}, {}
    for line in f_auth:
        line = line.strip('\t\n')
        line_dict = json.loads(line)
        domain = line_dict['domain']
        a_results = line_dict['a']
        rres = {}
        for rr in a_results:
            rdata = rr['rdata']
            rtype = rr['type']
            rres[rdata] = rtype
        auth_results[domain] = rres
    print(len(auth_results))

    censor_resolver_info = {}
    for line in f:
        line = line.strip('\t\n')
        line_dict = json.loads(line)
        resolver_ip = line_dict['saddr']
        asn, aso, pre_net, ccn = geolite(resolver_ip)
        domain = line_dict['dns_questions'][0]['name']
        a_results = line_dict['dns_answers']
        
        rres = {}
        # 判断是否跟权威的结果一致
        auth_list = set(list(auth_results[domain].keys()))
        for rr in a_results:
            rdata = rr['rdata']
            rtype = rr['type']
            rres[rdata] = rtype
        resolver_list = set(list(rres.keys()))
        print(domain, resolver_ip, auth_list, resolver_list)
        overlap = auth_list & resolver_list
        if len(overlap)==0:
            censor_ground[str(asn)+"|"+domain] = {"represent": resolver_ip, "rr": rres}
    
    with open("data/resolvers/censor_result.ground.json", 'w', encoding='utf-8') as fw:
        json.dump(censor_ground, fw)
    return

def main():
    resolver_4_censor()
    censor_preprocess()
    censor_groundtruth()
    return

if __name__=='__main__':
    main()