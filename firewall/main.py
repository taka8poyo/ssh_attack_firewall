import blocking
import datetime
from utils import make_all, get_ip_from_drop, get_ip_list
import trans


def main_routine():
    ## cowrie.json and it's copy 'tmp.json'
    cowrie_path = '/data/cowrie/log/cowrie.json'
    tmp_path = './tmp.json'
    drop_path = '/var/log/iptables/DROP.log'
    tmp_path_drop = './tmp.log'

    ## to make all.json
    path_null = 'null.json'
    path_cowrie_date = '/data/cowrie/log/cowrie.json.2018*'
    path_cowrie = '/data/cowrie/log/cowrie.json'

    ## get ip from log when log file is changed
    ip_list_cowrie = get_ip_list(cowrie_path, tmp_path)
    ip_list_drop = get_ip_from_drop(drop_path, tmp_path_drop)
    ip_list_cowrie.extend(ip_list_drop)
    ip_list_cowrie = list(set(ip_list_cowrie))

    ## make all.json file
    make_all(path_null, path_cowrie_date, path_cowrie)
    if not ip_list_cowrie == []: 
        try:
            for ip in ip_list_cowrie:
                block = blocking.Blocking(ip)
                block.calculation()
                block.blocking()
                block.release()
                block.update_file()
                # block.log()
        except KeyError:
            print('key error')
       