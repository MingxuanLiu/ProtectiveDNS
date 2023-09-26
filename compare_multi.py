import os
import time
import json
import argparse
import textwrap
import traceback
import ipaddress
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
    parser.add_argument('-multi', '--multi', action='store_true', help='Whether run on multiprocessing mode.')  
    parser.add_argument('-date', '--date', type=str, help='One date for pre-processing or comparison.')
    parser.add_argument('-vantage', '--vantage', type=str, help='One vatage result for pre-processing or comparison.')

    args = parser.parse_args()

    return args

logger = "" 
domain_infos, resolver_infos, whole_ip_infos, unstable_domains = {}, {}, {}, {}
result_file_main_path, analysis_main_path = "", ""
sinkhole_keywords = {"sinkhole", "blackhole", "seized", "blocked", "blocked", "suspended", "microsoftinternetsafety"}
args = parse_arguments()
asn_reader = geoip2.database.Reader('tools/geoip2/GeoLite2-ASN_20230606/GeoLite2-ASN.mmdb')
cc_reader = geoip2.database.Reader('tools/geoip2/GeoLite2-City_20230606/GeoLite2-City.mmdb')
censor_groundtruth = {}

# Preparation of required documents
def compare_prepare():
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

    multi = args.multi
    result_file_main_path = 'scan_results/{}/'.format(args.vantage)
    analysis_main_path = 'analysis_results/{}/'.format(args.vantage)
    if multi:
        logger = init_log('logs/compare_pdns_auth_open_'+run_date+'.log')
    else:
        logger = init_log('logs/compare_pdns_auth_open_single_'+run_date+'.log')
    logger.info("[+] Compare Prepare Start...")

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

# Drop Incomplete rows
def safe_readline(f):
    pos = f.tell()
    while True:
        try:
            return f.readline()
        except UnicodeDecodeError:
            pos -= 1
            f.seek(pos)

# Get IP Information
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

# Compare Function -- Multi process
def compare_func_multi(date_tag, worker_id, num_workers, auth_json):
    date_main_path = os.path.join(analysis_main_path, '{}'.format(date_tag))
    domain_receive_main_path = os.path.join(date_main_path, 'domains'.format(date_tag))
    resolver_result_main_path = os.path.join(date_main_path, 'results'.format(date_tag))
    cases_main_path = os.path.join(date_main_path, 'cases'.format(date_tag))
    logger.info("[+] Create results folders for {}, worker {}".format(date_tag, worker_id))
        
    case_I = os.path.join(cases_main_path, 'case.no_question.normal.{}.log'.format(date_tag))
    case_II = os.path.join(cases_main_path, 'case.disformat.normal.{}.log'.format(date_tag))
    if os.path.exists(case_I):
        fw = open(case_I, 'a+', encoding='utf-8')
    else:
        fw = open(case_I, 'w', encoding='utf-8')
    if os.path.exists(case_II):
        fw2 = open(case_II, 'a+', encoding='utf-8')
    else:
        fw2 = open(case_II, 'w', encoding='utf-8')
    
    result_path = os.path.join(result_file_main_path, "result_{}.txt".format(date_tag))

    num_process, num_question, num_format = 0,0,0
    num_drop = 0
    with open(result_path, 'r', encoding='utf-8') as f:
        size = os.fstat(f.fileno()).st_size 
        chunk_size = size // num_workers
        offset = worker_id * chunk_size
        if worker_id==(num_workers-1):
            end = size
        else:
            end = offset + chunk_size
        f.seek(offset)
        if offset > 0:
            safe_readline(f)    # drop first incomplete line
        line = f.readline()
        logger.info(str(chunk_size)+" "+str(offset)+" "+str(end))
        while line:
            line = line.strip('\n\t')
            try:
                line_dict = json.loads(line)
            except Exception as e:
                logger.warning("[+]  Date: {}; Error: json.loads {}".format(date_tag, line))
                line = f.readline()
                continue
            num_process += 1
            if num_process%100000==0:
                logger.info("[+] {} processed for {} ({} worker, offset {}), {} no question, {} format error".format(num_process, date_tag, worker_id, offset, num_question, num_format))
        
            resolver_ip = line_dict['saddr']
            re_int = int(ipaddress.ip_address(resolver_ip))
            # Divide the IP address space into 100 blocks
            tmp_re_domains_path = os.path.join(domain_receive_main_path, "{}".format(int(re_int/42949672)))
            tmp_re_results_path = os.path.join(resolver_result_main_path, "{}".format(int(re_int/42949672)))
            fw_result = open(tmp_re_domains_path, 'a+', encoding='utf-8')
            fw2_result = open(tmp_re_results_path, 'a+', encoding='utf-8')
            
            rcode = str(line_dict['dns_rcode'])

            try:
                qname = line_dict['dns_questions'][0]['name'].lower()
            except Exception as e:
                if len(line_dict['dns_answers'])>0:
                    qname = line_dict['dns_answers'][0]['name']
                else:
                    num_question += 1
                    fw.write("{}\t{}\n".format(resolver_ip, line))
                    line = f.readline()
                    continue
            
            try: 
                domain_tag = domain_infos[qname]['tag']
            except Exception as e:
                num_format += 1
                fw2.write("{}\t{}\n".format(resolver_ip, line))
                line = f.readline()
                continue
            
            # Compare Process
            if domain_tag=='malicious' and resolver_ip in resolver_infos:
                tmp_re_domain_dict = {"domain": qname, "resolver": resolver_ip, "tag": "malicious"}
                tmp_re_domain_str = json.dumps(tmp_re_domain_dict)
                fw_result.write("{}\n".format(tmp_re_domain_str))

                # baseline - Passive DNS
                baseline_pdns = domain_infos[qname]['pdns']
                pdns_ips, pdns_cnames = {}, {}
                for item in baseline_pdns.keys():
                    if baseline_pdns[item]['type']=="A":
                        pdns_ips[item] = 1
                    elif baseline_pdns[item]['type']=="CNAME":
                        pdns_cnames[item] = 1

                # baseline - Authoritative 
                baselines = auth_json[qname]
                base_result = {'rcode': baselines['Rcode'], 'a_records':{}, 'cname_records':{}}
                au_sinkholed = False
                if len(baselines['A'])>0:
                    for item in baselines['A']:
                        if item['type']=='A':
                            base_result['a_records'][item['rdata']] = 1
                        elif item['type']=="CNAME":
                            base_result['cname_records'][item['rdata']] = 1

                # compare
                compare_tmp = {'same':0, 'rcode':0, 'a_pdns_private':0, 'a_pdns_self_sinkhole':0, 'a_pdns':0, 'censor':0}
                rrset = line_dict['dns_answers']
                re_tmp= {'rcode': rcode, 'a_records':{}}

                # Rcode Compare
                if str(rcode)!=str(base_result['rcode']):
                    compare_tmp['rcode'] = 1
                else:
                    # baseline - Authoritative --> to compare format
                    au_ips, au_ases, au_cnames = {}, {}, {}
                    for rr in base_result['a_records'].keys():
                        au_ips[rr] = 1
                        if rr in whole_ip_infos:
                            au_ases[whole_ip_infos[rr]['as_number']] = 1
                        else:
                            asn, aso, pre_net, ccn = geolite(rr)
                            au_ases[asn] = 1
                    for rr in base_result['cname_records'].keys():
                        au_cnames[rr.strip('.')] = 1
                    
                    # resolver result --> to compare format
                    re_ips, re_ases, re_cnames = {}, {}, {}
                    re_sinkholed, re_sinkhole_key = False, False
                    if len(rrset)>0:
                        for rr in rrset:
                            rr_str = rr['rdata']
                            re_tmp['a_records'][rr_str] = rr
                            if rr['type_str']=='A':
                                re_ips[rr_str] = 1
                                if rr_str in whole_ip_infos:
                                    re_ases[whole_ip_infos[rr_str]['as_number']] = 1
                                else:
                                    asn, aso, pre_net, ccn = geolite(rr_str)
                                    re_ases[asn] = 1
                            elif rr['type_str']=='CNAME':
                                re_cnames[rr_str] = 1
                                for kk in sinkhole_keywords:
                                    if kk in rr_str:
                                        re_sinkhole_key = True
                    
                    # Determining whether it is a censor case
                    asn, aso, pre_net, ccn = geolite(resolver_ip)
                    asn_domain = "|".join([str(asn), qname])
                    if asn_domain in censor_groundtruth:
                        censor_base = set(list(censor_groundtruth[asn_domain]['rr'].keys()))
                        re_results = set(list(re_ips.keys())+list(re_cnames.keys()))
                        overlap_cr = list(censor_base & re_results)
                        if len(overlap_cr)>0:
                            compare_tmp['censor'] = 1

                    # Judgement of inconsistency with authoritative results
                    overlap_a = list(set(au_ips) & set(re_ips))
                    overlap_as = list(set(au_ases) & set(re_ases))
                    overlap_cname = list(set(au_cnames) & set(re_cnames))
                    # Judgement of inconsistency with Passive DNS results
                    overlap_rr_pdns = list(set(re_ips) & set(pdns_ips))
                    overlap_cname_pdns = list(set(re_cnames) & set(pdns_cnames))                    

                    if len(overlap_a)==0:
                        if len(au_ips)==0 and len(re_ips)==0:
                            pass
                        else:
                            if len(overlap_as)==0:
                                if len(au_ases)==0 and len(re_ases)==0:
                                    pass
                                else:
                                    if len(overlap_cname)==0 and re_sinkhole_key==True:
                                        compare_tmp['a_pdns'] = 1
                                        compare_tmp['a_pdns_self_sinkhole'] = 1
                                    if '47.75.69.19' in re_ips:
                                        compare_tmp['a_pdns'] = 1
                                    if 'Private' in re_ases and 'Private' not in au_ases:
                                        compare_tmp['a_pdns'] = 1
                                        compare_tmp['a_pdns_private'] = 1
                                    elif len(overlap_rr_pdns)==0 and len(overlap_cname_pdns)==0:
                                        if qname not in unstable_domains:
                                            compare_tmp['a_pdns'] = 1
                                            
                    
                # It's the same if it's all the same.
                same_tag = True
                for kk in compare_tmp.keys():
                    if kk!='same' and compare_tmp[kk]!=0:
                        same_tag = False
                if same_tag:
                    compare_tmp['same'] = 1
                
                com_re_result_dict = {"domain": qname, "resolver_ip": resolver_ip, 'compare': compare_tmp, 'resolver': re_tmp, 'authoritative': base_result}
                com_re_result_str = json.dumps(com_re_result_dict)
                fw2_result.write("{}\n".format(com_re_result_str))
            elif domain_tag=='tranco':
                if resolver_ip in resolver_infos:
                    tmp_re_domain_dict = {"domain": qname, "resolver": resolver_ip, "tag": "tranco"}
                    tmp_re_domain_str = json.dumps(tmp_re_domain_dict)
                    fw_result.write("{}\n".format(tmp_re_domain_str))

            if f.tell() > end:
                logger.info("[+] Finished ({} worker, offset {}): {} processed, {} no question, {} format error".format(worker_id, offset, num_process, num_question, num_format))
                break
            line = f.readline()

            fw_result.close()
            fw2_result.close()
    
    fw.close()
    fw2.close()
    return

# Compare Function -- Single process
def compare_func_single(date_tag, auth_json):
    date_main_path = os.path.join(analysis_main_path, '{}'.format(date_tag))
    domain_receive_main_path = os.path.join(date_main_path, 'domains'.format(date_tag))
    resolver_result_main_path = os.path.join(date_main_path, 'results'.format(date_tag))
    cases_main_path = os.path.join(date_main_path, 'cases'.format(date_tag))
    logger.info("[+] Create results folders for {}".format(date_tag))
        
    case_I = os.path.join(cases_main_path, 'case.no_question.normal.{}.log'.format(date_tag))
    case_II = os.path.join(cases_main_path, 'case.disformat.normal.{}.log'.format(date_tag))
    if os.path.exists(case_I):
        fw = open(case_I, 'a+', encoding='utf-8')
    else:
        fw = open(case_I, 'w', encoding='utf-8')
    if os.path.exists(case_II):
        fw2 = open(case_II, 'a+', encoding='utf-8')
    else:
        fw2 = open(case_II, 'w', encoding='utf-8')
    
    result_path = os.path.join(result_file_main_path, "result_{}.txt".format(date_tag))

    num_process, num_question, num_format = 0,0,0
    num_drop = 0
    for line in open(result_path, 'r'):
        line = line.strip('\n\t')
        try:
            line_dict = json.loads(line)
        except Exception as e:
            logger.warning("[+]  Date: {}; Error: json.loads {}".format(date_tag, line))
            line = f.readline()
            continue
        num_process += 1
        if num_process%100000==0:
            logger.info("[+] {} processed for {} ({} worker, offset {}), {} no question, {} format error".format(num_process, date_tag, worker_id, offset, num_question, num_format))
    
        resolver_ip = line_dict['saddr']
        re_int = int(ipaddress.ip_address(resolver_ip))
        # Divide the IP address space into 100 blocks
        tmp_re_domains_path = os.path.join(domain_receive_main_path, "{}".format(int(re_int/42949672)))
        tmp_re_results_path = os.path.join(resolver_result_main_path, "{}".format(int(re_int/42949672)))
        fw_result = open(tmp_re_domains_path, 'a+', encoding='utf-8')
        fw2_result = open(tmp_re_results_path, 'a+', encoding='utf-8')
        
        rcode = str(line_dict['dns_rcode'])

        try:
            qname = line_dict['dns_questions'][0]['name'].lower()
        except Exception as e:
            if len(line_dict['dns_answers'])>0:
                qname = line_dict['dns_answers'][0]['name']
            else:
                num_question += 1
                fw.write("{}\t{}\n".format(resolver_ip, line))
                line = f.readline()
                continue
            
        try: 
            domain_tag = domain_infos[qname]['tag']
        except Exception as e:
            num_format += 1
            fw2.write("{}\t{}\n".format(resolver_ip, line))
            line = f.readline()
            continue
            
        # Compare Process
        if domain_tag=='malicious' and resolver_ip in resolver_infos:
            tmp_re_domain_dict = {"domain": qname, "resolver": resolver_ip, "tag": "malicious"}
            tmp_re_domain_str = json.dumps(tmp_re_domain_dict)
            fw_result.write("{}\n".format(tmp_re_domain_str))

            # baseline - Passive DNS
            baseline_pdns = domain_infos[qname]['pdns']
            pdns_ips, pdns_cnames = {}, {}
            for item in baseline_pdns.keys():
                if baseline_pdns[item]['type']=="A":
                    pdns_ips[item] = 1
                elif baseline_pdns[item]['type']=="CNAME":
                    pdns_cnames[item] = 1

            # baseline - Authoritative 
            baselines = auth_json[qname]
            base_result = {'rcode': baselines['Rcode'], 'a_records':{}, 'cname_records':{}}
            au_sinkholed = False
            if len(baselines['A'])>0:
                for item in baselines['A']:
                    if item['type']=='A':
                        base_result['a_records'][item['rdata']] = 1
                    elif item['type']=="CNAME":
                        base_result['cname_records'][item['rdata']] = 1

            # compare
            compare_tmp = {'same':0, 'rcode':0, 'a_pdns_private':0, 'a_pdns_self_sinkhole':0, 'a_pdns':0, 'censor':0}
            rrset = line_dict['dns_answers']
            re_tmp= {'rcode': rcode, 'a_records':{}}

            # Rcode Compare
            if str(rcode)!=str(base_result['rcode']):
                compare_tmp['rcode'] = 1
            else:
                # baseline - Authoritative --> to compare format
                au_ips, au_ases, au_cnames = {}, {}, {}
                for rr in base_result['a_records'].keys():
                    au_ips[rr] = 1
                    if rr in whole_ip_infos:
                        au_ases[whole_ip_infos[rr]['as_number']] = 1
                    else:
                        asn, aso, pre_net, ccn = geolite(rr)
                        au_ases[asn] = 1
                for rr in base_result['cname_records'].keys():
                    au_cnames[rr.strip('.')] = 1
                
                # resolver result --> to compare format
                re_ips, re_ases, re_cnames = {}, {}, {}
                re_sinkholed, re_sinkhole_key = False, False
                if len(rrset)>0:
                    for rr in rrset:
                        rr_str = rr['rdata']
                        re_tmp['a_records'][rr_str] = rr
                        if rr['type_str']=='A':
                            re_ips[rr_str] = 1
                            if rr_str in whole_ip_infos:
                                re_ases[whole_ip_infos[rr_str]['as_number']] = 1
                            else:
                                asn, aso, pre_net, ccn = geolite(rr_str)
                                re_ases[asn] = 1
                        elif rr['type_str']=='CNAME':
                            re_cnames[rr_str] = 1
                            for kk in sinkhole_keywords:
                                if kk in rr_str:
                                    re_sinkhole_key = True
                
                # Determining whether it is a censor case
                asn, aso, pre_net, ccn = geolite(resolver_ip)
                asn_domain = "|".join([str(asn), qname])
                if asn_domain in censor_groundtruth:
                    censor_base = set(list(censor_groundtruth[asn_domain]['rr'].keys()))
                    re_results = set(list(re_ips.keys())+list(re_cnames.keys()))
                    overlap_cr = list(censor_base & re_results)
                    if len(overlap_cr)>0:
                        compare_tmp['censor'] = 1

                # Judgement of inconsistency with authoritative results
                overlap_a = list(set(au_ips) & set(re_ips))
                overlap_as = list(set(au_ases) & set(re_ases))
                overlap_cname = list(set(au_cnames) & set(re_cnames))
                # Judgement of inconsistency with Passive DNS results
                overlap_rr_pdns = list(set(re_ips) & set(pdns_ips))
                overlap_cname_pdns = list(set(re_cnames) & set(pdns_cnames))                    

                if len(overlap_a)==0:
                    if len(au_ips)==0 and len(re_ips)==0:
                        pass
                    else:
                        if len(overlap_as)==0:
                            if len(au_ases)==0 and len(re_ases)==0:
                                pass
                            else:
                                if len(overlap_cname)==0 and re_sinkhole_key==True:
                                    compare_tmp['a_pdns'] = 1
                                    compare_tmp['a_pdns_self_sinkhole'] = 1
                                if '47.75.69.19' in re_ips:
                                    compare_tmp['a_pdns'] = 1
                                if 'Private' in re_ases and 'Private' not in au_ases:
                                    compare_tmp['a_pdns'] = 1
                                    compare_tmp['a_pdns_private'] = 1
                                elif len(overlap_rr_pdns)==0 and len(overlap_cname_pdns)==0:
                                    if qname not in unstable_domains:
                                        compare_tmp['a_pdns'] = 1
                                        
                
            # It's the same if it's all the same.
            same_tag = True
            for kk in compare_tmp.keys():
                if kk!='same' and compare_tmp[kk]!=0:
                    same_tag = False
            if same_tag:
                compare_tmp['same'] = 1
            
            com_re_result_dict = {"domain": qname, "resolver_ip": resolver_ip, 'compare': compare_tmp, 'resolver': re_tmp, 'authoritative': base_result}
            com_re_result_str = json.dumps(com_re_result_dict)
            fw2_result.write("{}\n".format(com_re_result_str))
        elif domain_tag=='tranco':
            if resolver_ip in resolver_infos:
                tmp_re_domain_dict = {"domain": qname, "resolver": resolver_ip, "tag": "tranco"}
                tmp_re_domain_str = json.dumps(tmp_re_domain_dict)
                fw_result.write("{}\n".format(tmp_re_domain_str))

        fw_result.close()
        fw2_result.close()
    logger.info("[+] Finished: {} processed, {} no question, {} format error".format(num_process, num_question, num_format))
    fw.close()
    fw2.close()
    return

# Main Function for Comparing
def compare_process(workers=20):
    compare_prepare()
    logger.info("[+] Compare preparation Finished...")
    date = args.date

    logger.info("[+] Compare process for {}".format(date))

    auth_path_tmp = "data/domains/qax/auth/whole_auth.json"
    f_au_tmp = open(auth_path_tmp, 'r', encoding='utf-8')
    auth_json = json.load(f_au_tmp)
    logger.info("[+] Load Results of Authoritative...")
    
    # Create a results file for the current date
    date_main_path = os.path.join(analysis_main_path, '{}'.format(date))
    domain_receive_main_path = os.path.join(date_main_path, 'domains'.format(date))
    resolver_result_main_path = os.path.join(date_main_path, 'results'.format(date))
    cases_main_path = os.path.join(date_main_path, 'cases'.format(date))
    if os.path.exists(date_main_path)==False:
        os.makedirs(date_main_path)
        os.makedirs(domain_receive_main_path)
        os.makedirs(resolver_result_main_path)
        os.makedirs(cases_main_path)
    logger.info("[+] Create folders...")

    # Starting to perform comparisons
    s_time = time.time()
    if args.multi:
        pool = Pool(processes=workers)
        for i in range(workers):
            w = pool.apply_async(compare_func_multi, (date, i, workers, auth_json), )
        pool.close()
        pool.join()
        # break
    else:
        compare_func_single(date, auth_json)
        # break
    logger.info("[+] Saved for date: {}".format(date))
    time_spend = time.time()-s_time
    logger.info("[+] {} seconds spent for {}".format(time_spend, date))
    return


vantage_list = ['US', 'UK', 'JP']
# Compare between results from different vantage points
def compare_vantage():
    compare_vantage = args.vantage
    date = args.date
    other_vantage = [i for i in vantage_list if i!=compare_vantage]

    fw = open('analysis_results/{}/{}/{}'.format(compare_vantage, date, 'diff_vantage.txt'), 'w', encoding='utf-8')
    for i in range(87):
        other_vantage_results = {}
        for o_v in other_vantage:
            resolver_result_main_path = os.path.join('analysis_results/{}/{}'.format(o_v, date), 'results'.format(date))
            try:
                f_tmp = open(os.path.join(resolver_result_main_path, '{}'.format(str(i))))
            except Exception as e:
                continue
            try:
                for line in f_tmp:
                    line = line.strip('\t\n')
                    line_dict = json.loads(line)
                    domain = line_dict['domain']
                    resolver = line_dict['resolver_ip']
                    key = domain + "|" + resolver
                    if key not in other_vantage_results:
                        other_vantage_results[key] = line_dict['resolver']
                    else:
                        if line_dict['resolver']['rcode']=="0" and other_vantage_results[key]["rcode"]!="0":
                            other_vantage_results[key]["rcode"]=="0"
                        for item in line_dict['resolver']['a_records']:
                            if item not in other_vantage_results[key]['a_records']:
                                other_vantage_results[key]['a_records'][item] = line_dict['resolver']['a_records'][item]
            except Exception as e:
                continue
        
        resolver_result_main_path = os.path.join('analysis_results/{}/{}'.format(compare_vantage, date), 'results'.format(date))
        try:
            f_re = open(os.path.join(resolver_result_main_path, '{}'.format(str(i))))
        except Exception as e:
                continue
        for line in f_re:
            line = line.strip('\t\n')
            line_dict = json.loads(line)
            domain = line_dict['domain']
            resolver = line_dict['resolver_ip']
            key = domain + "|" + resolver
            if key not in other_vantage_results:
                fw.write("{}\t{}\t{}\n".format(compare_vantage, domain, resolver))
            else:
                a_results = set(list(line_dict['resolver']['a_records'].keys()))
                b_results = set(list(other_vantage_results[key]['a_records'].keys()))
                overlap = a_results & b_results
                if len(overlap)==0:
                    fw.write("{}\t{}\t{}\n".format(compare_vantage, domain, resolver))
    return 

def main():
    compare_process()
    compare_vantage()
    return

if __name__=="__main__":
    main()