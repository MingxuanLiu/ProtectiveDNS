#-*- coding:utf-8 -*-
import os

MAX_BLOCK_LENGTH = 1000

RCODE_LIST = {0:"NoError", 1:"FormErr", 2:"ServFail", 3:"NXDomain", 4:"NotImp", 5:"Refused", 6:"YXDomain",
              7:"YXRRset", 8:"NXRRset", 9:"NotAuth", 10:"NotZone", 11:"DSOTYPENI"}
COMPARE_CLASS = {'rcode_match':0, 'ip_match':0, 'ip_as_match':0, 'ip_country_match':0, 'ip_city_match':0, 'ip_isp_match':0}

# Identification Threshold
THRESHOLD = 50


################### Open Resolver ###################
open_resolver_main_path = 'data/resolvers/'
open_resolver_stable_path = os.path.join(open_resolver_main_path, 'stable_open_resolver.txt')

################### IP Infos Path ###################
ip_info_main_path = 'data/ip_infos'

################### Result Path ###################
result_main_path_public = 'results'
