import datetime
import ipaddress
import json
import os
import requests
import signal
import sys
import time
import calculate_acf as myacf
import trans
import detect_abnormal as ab
import utils
# from pprint import pprint


class Blocking():
    def __init__(self, ip):
        self.path_all_json = "./all.json"
        self.path_block_ip_time_json = "./log/block_ip_time_dict.json"
        self.path_peak_time = './log/peak_time.json'
        self.path_abnormal = './log/abnormal.json'
        self.path_drop_log = '/var/log/iptables/DROP.log'
        self.path_release = './log/release.json'
        self.path_next_block = './log/next_block.json'
        self.path_current_block_ip = './log/current_block_ip.txt'

        self.ip = ip
        self.ip_time_count_dict = trans.transform_log(open(self.path_all_json), trans.sys_trans_dict(self.path_drop_log), self.ip)

        self.time_list = self.ip_time_count_dict[self.ip]["timestamp"]

        self.now = datetime.datetime.now()

        
        ## current blocking dict {'ip':'last_attack_time(str)'}
        self.block_ip_time_dict ={} 
        if os.path.exists(self.path_block_ip_time_json):
            self.block_ip_time_dict = utils.get_value_dict_time(self.path_block_ip_time_json)  
        ## release     
        self.release_dict = {}
        if os.path.exists(self.path_release):
            self.release_dict = utils.get_value_dict_time(self.path_release)
        if not self.ip in self.release_dict:
            self.release_dict[self.ip] = self.now + datetime.timedelta(hours = 3)
        ## for periodic block dict {'ip':'datetime(str)'}
        self.next_block_dict ={}
        if os.path.exists(self.path_next_block):
            self.next_block_dict = utils.get_value_dict_time(self.path_next_block)
        if not self.ip in self.next_block_dict:
            self.next_block_dict[self.ip] = self.now + datetime.timedelta(hours = -1)
        ##  {'ip':'peak_time (int)'}
        self.peak_time_dict ={}
        self.peak_time = 60*60*3
        if os.path.exists(self.path_peak_time):
            self.peak_time_dict = utils.get_value_second(self.path_peak_time)
        if self.ip in self.peak_time_dict: 
            self.peak_time = self.peak_time_dict[self.ip]
        else:
            self.peak_time_dict[self.ip] = self.peak_time
           

        ## abnormal detect dict {'ip':'count'}
        self.abnormal_dict = {}
        if os.path.exists(self.path_abnormal):
           self.abnormal_dict = utils.get_value_second(self.path_abnormal)
        else:
            self.abnormal_dict[self.ip] = 0
        if not self.ip in self.abnormal_dict:
            self.abnormal_dict[self.ip] = 0
        
        ## for periodic release dict {'ip':'datetime(str)'}
        
        self.current_block_ip_list =[]
        if os.path.exists(self.path_current_block_ip):
            with open(self.path_current_block_ip) as f:
                for line in f:
                    self.current_block_ip_list.append(line.replace('\n', ''))
                    self.current_block_ip_list = list(set(self.current_block_ip_list))
        

    def update_file(self):
        utils.update_time_file(self.path_block_ip_time_json, self.block_ip_time_dict)
        utils.update_time_file(self.path_release, self.release_dict)
        utils.update_time_file(self.path_next_block, self.next_block_dict)
        utils.update_second_file(self.path_abnormal, self.abnormal_dict)
        utils.update_second_file(self.path_peak_time, self.peak_time_dict)

        with open(self.path_current_block_ip, "w") as f:
            for line in self.current_block_ip_list:
                f.write(line)
                f.write('\n')


    def bool_detect_abnormal(self):
        if ab.bool_abnormal(self.time_list, self.peak_time):
            self.abnormal_dict[self.ip] +=1 
        if self.abnormal_dict[self.ip] > 2:
            return True
        return False


    # def log(self):
    #     print('peak')
    #     pprint(self.peak_time_dict)
    #     print('block_last time')
    #     pprint(self.block_ip_time_dict)
    #     print('next_block')
    #     pprint(self.next_block_dict)
    #     print('abnormal')
    #     pprint(self.abnormal_dict)
    #     print('current_block')
    #     pprint(self.current_block_ip_list)
    #     print('release')
    #     pprint(self.release_dict)
        

    def release(self):
        for ip, last in self.block_ip_time_dict.items():
            last_atack = last
            diff = int((self.now - last_atack).total_seconds())
            tmp_peak_time = self.peak_time_dict[ip]

            if diff > tmp_peak_time*5:
                self.block_ip_time_dict.pop(ip)
                self.release_dict.pop(ip)
                self.next_block_dict.pop(ip)
                self.abnormal_dict.pop(ip)
                utils.unset_block(ip)
                self.current_block_ip_list.remove(ip)
                self.current_block_ip_list = list(set(self.current_block_ip_list))
            
        #[TODO] bad release time
        for ip, release_time in self.release_dict.items():
            if release_time < self.now:
                self.block_ip_time_dict[ip] = self.now 
                self.release_dict[ip] = self.now + datetime.timedelta(seconds = self.peak_time_dict[ip])
                utils.unset_block(ip)
                self.current_block_ip_list.remove(ip)
                self.current_block_ip_list = list(set(self.current_block_ip_list))
                


    def blocking(self):
        for ip, time in self.next_block_dict.items():
            if not ip in self.current_block_ip_list: 
                if time < self.now:
                    self.current_block_ip_list.append(ip)
                    self.current_block_ip_list = list(set(self.current_block_ip_list))
                    utils.set_block(ip)


    
    def calculation(self):
        if len(self.time_list) == 1:
            ## first attack
            print(self.now)
            print('first attack')
            self.peak_time = 60*60*3 
            self.peak_time_dict[self.ip] = self.peak_time
            self.release_dict[self.ip] = self.now + datetime.timedelta(hours = 3)
            self.next_block_dict[self.ip] = self.now + datetime.timedelta(hours = -1)
            self.block_ip_time_dict[self.ip] = self.now
        else:
            if self.ip in self.current_block_ip_list:
                tmp = trans.make_acf_type(self.time_list)
                self.peak_time = myacf.caluculate_peaktime(tmp) 
                self.peak_time_dict[self.ip] = self.peak_time
                self.block_ip_time_dict[self.ip] = self.now
                if self.peak_time < 60*10: # for short attack
                    # self.next_block_dict[self.ip] = self.now + datetime.timedelta(days = 1)
                    self.release_dict[self.ip] = self.now + datetime.timedelta(days = 1)
                    self.peak_time = 60*60*3
                else:
                    self.next_block_dict[self.ip] = self.now + datetime.timedelta(seconds = self.peak_time*9/10)
                    self.release_dict[self.ip] = self.now + datetime.timedelta(seconds = self.peak_time/10) 

            else:
                ## now blocking, but peak time is innappropriate
                if self.bool_detect_abnormal():
                    print(self.now)
                    print('abnormal is detected')
                    tmp = trans.make_acf_type(self.time_list[-3:])
                    self.peak_time = myacf.caluculate_peaktime(tmp)
                    self.peak_time_dict[self.ip] = self.peak_time
                    self.block_ip_time_dict[self.ip] = self.now
                    self.abnormal_dict[self.ip] = 0

                    if self.peak_time < 60*10: # for short attack
                    # self.next_block_dict[self.ip] = self.now + datetime.timedelta(days = 1)
                        self.release_dict[self.ip] = self.now + datetime.timedelta(days = 1)
                        self.peak_time = 60*60*3
                    else:
                        self.release_dict[self.ip] = self.now + datetime.timedelta(seconds = self.peak_time/10) 
                        self.next_block_dict[self.ip] = self.now +datetime.timedelta(hours = -1)

                else:
                    self.block_ip_time_dict[self.ip] = self.now ## failed block -> cowrie.json
                    