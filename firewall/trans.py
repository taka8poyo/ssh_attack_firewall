#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import datetime
import json
import pprint
import sys
import re
import calendar
from utils import str2time, time2str
import calculate_acf


## one ip -> ip_list (dict {"ip":{"timestamp":[array]}}) count no use
def transform_log(log_data, drop_dict, ip):
    ip_list = {}

    for line in log_data:
        dict_data = json.loads(line)
        if dict_data["src_ip"] == ip:
            # if dict_data["eventid"] == ("cowrie.login.failed" or "cowrie.login.success"):
            if dict_data["eventid"] == ("cowrie.session.connect"):
                if dict_data["src_ip"] in ip_list:
                    ip_list[dict_data["src_ip"]]["count"] += 1
                else:
                    ip_list[dict_data["src_ip"]] = {"count":1}
                    ip_list[dict_data["src_ip"]]["timestamp"] = []
                ip_list[dict_data["src_ip"]]["timestamp"].append(str2time(dict_data["timestamp"].split("Z")[0].split(".")[0]))

    if ip in drop_dict:
        if not ip in ip_list:
            ip_list[ip] = {"timestamp":[]}
        for key_ip, time_list in drop_dict.items():
            if ip == key_ip: 
                for time in time_list:
                    ip_list[ip]["timestamp"].append(time)
    return ip_list 


## return list for acf of one ip
def make_acf_type(ip_list_time):
    timestamp_list = []
    start_time = ip_list_time[0]
            
    for timestamp in ip_list_time:
        tmp = int((timestamp - start_time).total_seconds())
        while tmp > 0:
            timestamp_list.append(0)
            tmp += -1
        timestamp_list.append(1)
        start_time = timestamp

    return timestamp_list

# def make_acf_type3(acf_list_0_1):
#     tmp = []

#     for i in range(int(len(acf_list_0_1)/3)):
#         if acf_list_0_1[i*3] or acf_list_0_1[i*3+1] or acf_list_0_1[i*3+2]:
#             tmp.append(1)
#         else:
#             tmp.append(0)
#     return tmp
    
## first ture, past is false
def bool_first_ip(log_data, ip):
    for line in log_data:
        dict_data = json.loads(line)
        if dict_data["src_ip"] == ip:
            return False
    return True

## all log
def sys_trans_dict(drop_path):
    syslog = open(drop_path)
    sys_dict = {}

    for line2 in syslog:
        tmp = line2.replace('\n', '')
        ip_str = re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', tmp)
        if ip_str:
            ip = str(ip_str.group())
            time = re.search(r'[A-Z][a-z]{1,2} [0-9]{1,2} [0-9]{1,2}\:[0-9]{1,2}\:[0-9]{1,2}', tmp)
            if time: 
                timestamp_str = str(time.group())
                words = timestamp_str.split(" ")
                months = {}
                for i ,v in enumerate(calendar.month_abbr):
                    months[v] = i
                time_string = "2018-" + str(months[str(words[0])]) + "-" + str(words[1]) + " " + words[2]
                time_datetime = datetime.datetime.strptime(time_string, '%Y-%m-%d %H:%M:%S')
                
                if not ip in sys_dict:
                    sys_dict[ip] = []
                    sys_dict[ip].append(time_datetime)
                else:
                    sys_dict[ip].append(time_datetime)
    return sys_dict


if __name__=='__main__':
    log_data = open("./all_json.json", "r")
    path_sys = './DROP.log'
    ip = '195.3.147.49'
    syslog = sys_trans_dict(path_sys)
    ip_l = transform_log(log_data, syslog, ip)
    pprint.pprint(make_acf_type(ip_l[ip]['timestamp']))

    # pprint.pprint(ip_l)
