import datetime
import json
import sys
sys.path.append('../firewall/')
import calculate_acf
import trans

path_cowrie_json = './all.json'

f = open(path_cowrie_json)

def str2time(str_object):
    return datetime.datetime.strptime(str_object, "%Y-%m-%dT%H:%M:%S")
def time2str(time_object):
    return str('{0:%Y-%m-%d %H:%M:%S}'.format(time_object))

def transform_log(log_data):
    ip_list = {}
    count_attack = 0
    for line in log_data:
        dict_data = json.loads(line)
        if dict_data["eventid"] == ("cowrie.login.failed" or "cowrie.login.success"):
            count_attack +=1
            if dict_data["src_ip"] in ip_list:
                ip_list[dict_data["src_ip"]]["count"] += 1
            else:
                ip_list[dict_data["src_ip"]] = {"count":1}
                ip_list[dict_data["src_ip"]]["timestamp"] = []
            ip_list[dict_data["src_ip"]]["timestamp"].append(str2time(dict_data["timestamp"].split("Z")[0].split(".")[0]))
    return ip_list

ip = transform_log(f)


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


for key, values in ip.items():
    time = make_acf_type(values['timestamp'])
    print(calculate_acf.caluculate_peaktime(time))
