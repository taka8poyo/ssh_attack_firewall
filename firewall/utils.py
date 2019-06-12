import datetime
import glob
import os
import json
import subprocess
import re



def str2time(str_object):
    return datetime.datetime.strptime(str_object, "%Y-%m-%dT%H:%M:%S")
def time2str(time_object):
    return str('{0:%Y-%m-%d %H:%M:%S}'.format(time_object))


def make_all(path_null, path_cowrie_date, path_cowrie_json):
    for f in glob.glob(path_null):
            os.system("/bin/cat " + f + " > all.json")

    for g in glob.glob(path_cowrie_date):
            os.system("/bin/cat " + g + " >> all.json")

    for h in glob.glob(path_cowrie_json):
            os.system("/bin/cat " + h + " >> all.json")

def update_time_file(path, data_dict):
    tmp = {}
    for key, time_value in data_dict.items():
        tmp[key] = time2str(time_value)
    with open(path, "w") as fo:
        json.dump(tmp, fo)

def update_second_file(path, data_dict):
    with open(path, "w") as fo:
        json.dump(data_dict, fo)

def get_value_dict_time(path):
     tmp_dict = {}
     with open(path) as f:
        for line in f:
            tmp_dict = json.loads(line)
     for key, value in tmp_dict.items():
        tmp_dict[key] = datetime.datetime.strptime(value, "%Y-%m-%d %H:%M:%S" )
     return tmp_dict

def get_value_second(path):
     tmp_dict = {}
     with open(path) as f:
        for line in f:
            tmp_dict = json.loads(line)
            for key, value in tmp_dict.items():
                tmp_dict[key] = int(value)
     return tmp_dict


def make_lines_set(path):
    f = open(path)
    lines = f.readlines()
    sets = set(lines)
    f.close()
    return sets


## return ip_list
def get_ip_list(cowrie_path, tmp_path):
    ip_list =[]
    cowrie_json_set = make_lines_set(cowrie_path)                      
    tmp_set = make_lines_set(tmp_path)
    results = cowrie_json_set.difference(tmp_set)

    for result in results:
        if "src_ip" in result:
            text = result.replace('\n', '')
            matchObj = re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', text)

            if matchObj:
                ip_list.append(matchObj.group())

    cmd1 = "cp /data/cowrie/log/cowrie.json ./tmp.json"
    subprocess.call(cmd1.split())

    return list(set(ip_list))

def get_ip_from_drop(path_drop, tmp_path):
    ip_list =[]
    drop_set = make_lines_set(path_drop)                      
    tmp_set = make_lines_set(tmp_path)
    results = drop_set.difference(tmp_set)

    for result in results:
        text = result.replace('\n', '')
        matchObj = re.search(r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', text)
        if matchObj:
                ip_list.append(matchObj.group())
    
    cmd = "/bin/cp /var/log/iptables/DROP.log ./tmp.log"
    subprocess.call(cmd.split())

    return list(set(ip_list))


def set_block(ip):
    print(datetime.datetime.now())
    print(ip + '- blocking')
    cmd2 = "/sbin/iptables -I DOCKER -s " + ip + " -j LOG --log-prefix DROP: "
    cmd1 = "/sbin/iptables -I DOCKER -s " + ip + " -j DROP"
    subprocess.call(cmd1.split())
    subprocess.call(cmd2.split())


def unset_block(ip):
    print(datetime.datetime.now())
    print(ip + '- release')
    cmd1 = "/sbin/iptables -D DOCKER -s " + ip + " -j DROP"
    cmd2 = "/sbin/iptables -D DOCKER -s " + ip + " -j LOG --log-prefix DROP: "
    subprocess.call(cmd1.split())
    subprocess.call(cmd2.split())
