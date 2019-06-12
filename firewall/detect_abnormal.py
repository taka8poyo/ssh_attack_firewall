import datetime
import math

## return culcurate outliers 
def detect_function(x , peak_time):
    try:
        if x < peak_time/2:
            y = 101/math.exp(int(peak_time/2))*math.exp(x) -1
        else:
            y = 100/(math.exp(int(peak_time/2)) - math.exp(peak_time))*(math.exp(x) - math.exp(peak_time))
    except OverflowError:
        print('overflowerror')
        print('peak_time is' + str(peak_time))
        return 30
    return y
    

## get time_list, peak_time if anbnomal return True
## time_list = ["datetime",...]
def bool_abnormal(time_list, peak_time):
    last_timestamp = time_list[-2]
    this_timestamp = time_list[-1]
    diff = int((this_timestamp - last_timestamp).total_seconds())

    if  diff > peak_time:
        diff -= peak_time
        
    ans = int(detect_function(diff, peak_time))

    if ans  > 70:
        return True
    else:
        return False
