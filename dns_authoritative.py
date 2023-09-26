#-*- coding:utf-8 -*-
import os
import sys
import json
import time
import dns.resolver

def dns_query_func(domain, query_type=None, resolver_lists=None):
    if resolver_lists==None:
        resolver = dns.resolver.get_default_resolver()
    else:
        resolver = dns.resolver.Resolver()
        resolver.nameervers = resolver_lists
    rrset = []
    rcode = 0
    try:
        if sys.version > '3':
            answers = resolver.resolve(domain, query_type, lifetime=5)
        else:
            answers = resolver.query(domain, query_type, lifetime=5)
        for item in answers.response.sections[1]:
            for iitem in item.to_text().split('\n'):
                item_list = item.to_text().split(' ')
                i_list = {"name": item_list[0], "ttl": item_list[1], "type": item_list[3], "rdata": item_list[4].split('\n')[0]}
                rrset.append(i_list)
        rcode = answers.response.rcode()
    except Exception as error:
        if type(error)==dns.resolver.NXDOMAIN:
            # print('test')
            rcode = 3
    return rrset, rcode

def main():
    with open('data/domain/final_domain.json', 'r', encoding='utf-8') as f:
        domains = json.load(f)
    print(len(domains))

    with open('data/domain/whole_auth.json', 'r', encoding='utf-8') as f:
        domain_infos = json.load(f)
    print(len(domain_infos))

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

    fw = open('data/domain/auth/domain_ns_a.{}.txt'.format(run_date), 'w', encoding='utf-8')
    n = 0
    for domain in domains:
        if domains[domain]['tag']=='tranco':
            continue
        nses, rcode_ns = dns_query_func(domain, "NS", ['8.8.8.8', '8.8.4.4', '1.1.1.1'])
        ips, rcode_a = dns_query_func(domain, "A", nses)
        ips_aaaa, rcode_aaaa = dns_query_func(domain, "AAAA", nses)
        tmp = {"domain":domain, "ns":nses, "ns_rcode": rcode_ns, "a":ips, "a_rcode": rcode_a, "aaaa":ips_aaaa, "aaaa_rcode": rcode_aaaa}
        fw.write("{}\n".format(json.dumps(tmp)))
        n += 1
        if n%1000==0:
            print(n, domain)

        if rcode_a.value==0:
            domain_infos[domain]['auth']["Rcode"] = rcode_a.value
        for rr_a in ips:
            if rr_a not in domain_infos[domain]['auth']["A"]:
                domain_infos[domain]['auth']["A"].append(rr_a)

    with open('data/domain/whole_auth.{}.json'.format(run_date), 'w', encoding='utf-8') as f:
        json.dump(domain_infos, f)
    return

if __name__=='__main__':
    main()