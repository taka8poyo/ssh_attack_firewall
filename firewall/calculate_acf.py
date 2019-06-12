import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import csv
import statsmodels.api as sm
from statistics import mean

## calcurate auto corration
## one ip and time (list) -> return acf list 
def acf(log_data_list):
    length = len(log_data_list)
    if length == 1:
        value = [0.5]
    else:
        value = sm.tsa.stattools.acf(log_data_list, fft='True', nlags=length)
    return abs(value)


## caluculate peak time
## acf_value (list) -> return peak_time
def peak_time(acf_value):
    peak_time = 0
    for index in range(len(acf_value)):
        list_item = acf_value[index]
        if list_item == 1:
            pass
        elif list_item > 0.1:
            peak_time = index
            break

    if peak_time < 60*10:
        peak_time = 60*60*3
    
    return peak_time


## return peak_time   
def caluculate_peaktime(log_data_list):
    return peak_time(acf(log_data_list))


## block_function 
## return % of block success no use
def block_ip_par(peak_time, ip_list_time):
    time = 0
    attack =[]
    block_time = int(peak_time/5/2)
    for line in ip_list_time:
        if peak_time==0:
            tmp =0
        else:
            tmp = int(time / peak_time)
        tmp_time = time - peak_time*tmp
        if (tmp_time > block_time) and (tmp_time < peak_time - block_time):
            attack.append(line)
        time +=1
    return int(100 - sum(attack)/sum(ip_list_time)*100)


    
