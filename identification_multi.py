import os
import time
import json
import argparse
import textwrap
import traceback
import ipaddress
import IPy
from multiprocessing import Pool
import geoip2.webservice
import geoip2.database
import geoip2.models

from config import *
from tools.log import *

# Arguments
def parse_arguments():
    """Parses command line arguments. """

    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("Compare DNS responses"))
    
    # mode
    parser.add_argument('-date', '--date', type=str, help='One date for pre-processing or comparison.')

    args = parser.parse_args()

    return args

logger = "" 
domain_infos, resolver_infos, whole_ip_infos, unstable_domains = {}, {}, {}, {}
result_file_main_path, analysis_main_path = "", ""
args = parse_arguments()
asn_reader = geoip2.database.Reader('tools/geoip2/GeoLite2-ASN_20230606/GeoLite2-ASN.mmdb')
cc_reader = geoip2.database.Reader('tools/geoip2/GeoLite2-City_20230606/GeoLite2-City.mmdb')
censor_groundtruth = {}

# Preparation of required documents
def analysis_prepare():
    # global definition 
    global logger 
    global domain_infos
    global resolver_infos
    global whole_ip_infos
    global result_file_main_path
    global analysis_main_path
    global censor_groundtruth
    global unstable_domains

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

    result_file_main_path = 'scan_results/{}/'.format(args.vantage)
    analysis_main_path = 'analysis_results/{}/'.format(args.vantage)
    logger = init_log('logs/compare_pdns_auth_open_'+run_date+'.log')
    logger.info("[+] Analysis Prepare Start...")

    # load domains
    with open('data/domain/whole_domains.all_infos.json', 'r', encoding='utf-8') as f:
        domain_infos = json.load(f)
    logger.info("[+] All Domain Names (with Tranco): {}".format(len(domain_infos)))

    f_m_u = open('data/domain/malicious_domains.unstable.txt', 'r', encoding='utf-8')
    for line in f_m_u:
        line = line.strip('\t\n').split('\t')
        unstable_domains[line[0]] = 1
    logger.info("[+] IP result unstable Domain Names: {}".format(len(unstable_domains)))

    # Resolver List：resolver_infos
    f_re = open(open_resolver_stable_path, 'r', encoding='utf-8')
    resolver_infos = {}
    for line in f_re:
        line = line.strip('\t\n')
        resolver_infos[line] = {}
    logger.info("[+] Open Resolvers: {}".format(len(resolver_infos)))

    # IP Information：whole_ip_infos
    with open(os.path.join(ip_info_main_path, 'ip_whole_info.json'), 'r', encoding='utf-8') as f:
        whole_ip_infos = json.load(f)
    logger.info("[+] Related IP information: {}".format(len(whole_ip_infos)))

    # Censorship Groundtruth
    with open("data/resolvers/censor_result.ground.json", 'r', encoding='utf-8') as f:
        censor_groundtruth = json.load(f)
    logger.info("[+] Censorship Groundtruth: {}".format(len(censor_groundtruth)))
    return

def results_resolver_multi(date_tag, worker_id, num_workers):
    date_main_path = os.path.join(analysis_main_path, '{}'.format(date_tag))
    domain_receive_main_path = os.path.join(date_main_path, 'domains'.format(date_tag))
    resolver_result_main_path = os.path.join(date_main_path, 'results'.format(date_tag))
    cases_main_path = os.path.join(date_main_path, 'cases'.format(date_tag))
    logger.info("[+] Create results folders for {}, worker {}".format(date_tag, worker_id))

    stas_main_path = os.path.join(analysis_main_path, '{}/{}'.format(date_tag, "final_stas"))
    
    chunk_lists = os.listdir(domain_receive_main_path)
    chunk_worker_lists = []
    p_size = len(chunk_lists) // num_workers
    if worker_id==(num_workers-1):
        chunk_worker_lists = chunk_lists[(worker_id*p_size):]
    else:
        chunk_worker_lists = chunk_lists[(worker_id*p_size): (worker_id+1)*p_size]
    
    pdns_resolvers = []
    for chunk in chunk_worker_lists:
        logger.info("[+] Analysis process for chunk: {}".format(chunk))
        whole_result_path = os.path.join(stas_main_path, '{}.{}.log'.format(date_tag, chunk))
        if os.path.exists(whole_result_path):
            fw = open(whole_result_path, 'a+', encoding='utf-8')
        else:
            fw = open(whole_result_path, 'w', encoding='utf-8')
            fw.write('{}\t{}\t'.format("Resolver", "Tranco_num"))
            tmp_resolver_dict = {"num":{}, "same":{}, "censor":{}, "diff_rcode":{}, "diff_a_pdns":{}, "diff_a_private":{}, "diff_a_self_sinkhole":{}}
            for key in tmp_resolver_dict.keys():
                fw.write("Malicious_{}\t".format(key))
            fw.write("\n")
        
        # Initialization
        tmp_result_dict = {}

        tmp_re_domains_path = os.path.join(domain_receive_main_path, chunk)
        tmp_re_results_path = os.path.join(resolver_result_main_path, chunk)
        fr_result = open(tmp_re_domains_path, 'r', encoding='utf-8')
        fr2_result = open(tmp_re_results_path, 'r', encoding='utf-8')
        for line in fr_result:
            line = line.strip("\t\n")
            try:
                line_dict = json.loads(line)
            except Exception as e:
                logger.warning("[+] Json load error for Domains: {}-{}: {}".format(date_tag, resolver_ip, line))
                continue
            resolver_ip = line_dict['resolver']
            domain = line_dict['domain']
            tag = line_dict['tag']
            if resolver_ip not in tmp_result_dict:
                # Initialization
                tmp_resolver_dict = {"tranco": 0, "malicious":{"num":0, "same":0, "diff_rcode":0, "diff_a_pdns":0, "diff_a_private":0, "diff_a_self_sinkhole":0, "unstable": 0}}
                tmp_result_dict[resolver_ip] = tmp_resolver_dict
            
            if tag=='malicious':
                tmp_result_dict[resolver_ip]['malicious']['num'] += 1
            else:
                tmp_result_dict[resolver_ip]['tranco'] += 1
        
        for line in fr2_result:
            line = line.strip("\t\n")
            try:
                line_dict = json.loads(line)
            except Exception as e:
                logger.warning("[+] Json load error for Results: {}-{}: {}".format(date_tag, resolver_ip, line))
                continue
            resolver_ip = line_dict['resolver_ip']
            domain = line_dict['domain']
            compare_tmp = line_dict['compare']
            if resolver_ip not in tmp_result_dict:
                # Initialization
                tmp_resolver_dict = {"tranco": 0, "malicious":{"num":0, "same":0, "censor":0, "diff_rcode":0, "diff_a_pdns":0, "diff_a_private":0, "diff_a_self_sinkhole":0, "unstable": 0}}
                tmp_result_dict[resolver_ip] = tmp_resolver_dict
            
            if compare_tmp['same']==1:
                tmp_result_dict[resolver_ip]['malicious']['same'] += 1
            if compare_tmp['rcode']==1:
                tmp_result_dict[resolver_ip]['malicious']['diff_rcode'] += 1
            if compare_tmp['a_pdns_private']==1 and len(line_dict['resolver']['a_records'].keys())>0:
                tmp_result_dict[resolver_ip]['malicious']['diff_a_private'] += 1
            if compare_tmp['a_pdns_self_sinkhole']==1 and len(line_dict['resolver']['a_records'].keys())>0:
                tmp_result_dict[resolver_ip]['malicious']['diff_a_self_sinkhole'] += 1
            # if compare_tmp['a_pdns']==1 and len(line_dict['resolver']['a_records'].keys())>0:
            if compare_tmp['a_pdns']==1:
                tmp_result_dict[resolver_ip]['malicious']['diff_a_pdns'] += 1

        for resolver_ip in tmp_result_dict.keys():
            tmp_resolver_dict = tmp_result_dict[resolver_ip]
            fw.write("{}\t{}\t".format(resolver_ip, tmp_resolver_dict['tranco']))
            for key in tmp_resolver_dict['malicious'].keys():
                fw.write("{}\t".format(tmp_resolver_dict['malicious'][key]))
            fw.write("\n")

            # Determine if it is a PDNS based on the threshold value
            if tmp_resolver_dict['malicious']['diff_a_pdns']>=THRESHOLD:
                pdns_resolvers.append(resolver_ip)


        logger.info("[+] Analysis finished for chunk: {}, {} resolvers, {} pdnses".format(chunk, len(tmp_result_dict), len(resolver_ip)))
    logger.info("[+] Post Analysis for {}.".format(date_tag))
    return pdns_resolvers

def analysis_main_func(workers=15):
    analysis_prepare()
    logger.info("[+] Analysis preparation...")

    date = args.date
    logger.info("[+] Analysis process for {}".format(date))
    
    stas_main_path = os.path.join(os.path.join(analysis_main_path, date), '{}'.format("final_stas"))
    if os.path.exists(stas_main_path)==False:
        os.makedirs(stas_main_path)
    logger.info("[+] Create folders...")

    s_time = time.time()
    pdns_num = 0
    pool = Pool(processes=workers)
    pdns_resolvers = []
    workers_thread = []
    for i in range(workers):
        w = pool.apply_async(results_resolver_multi, (date, i, workers), )
        workers_thread.append(w)
    pool.close()
    pool.join()
    for w in workers_thread:
        result = w.get() 
        for i in result:
            pdns_resolvers.append(i)
    logger.info("[+] Totally find {} PDNS resolvers".format(len(pdns_resolvers)))
    
    pdns_path = os.path.join(analysis_main_path, "{}/pdns_resolvers.txt".format(date))
    fw = open(pdns_path, 'w', encoding='utf-8')
    for i in pdns_resolvers:
        fw.write("{}\n".format(i))
    logger.info("[+] Saved for date: {}".format(date))
    time_spend = time.time()-s_time
    logger.info("[+] {} seconds spent for {}".format(time_spend, date))
    return

def main():
    analysis_main_func()
    return

if __name__=='__main__':
    main()