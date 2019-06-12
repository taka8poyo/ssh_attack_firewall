from utils import set_block
from time import sleep


if __name__=='__main__':
    sleep(180)
    path_current = './log/current_block_ip.txt'
    # path_current = './current_block_ip.txt'
    with open(path_current) as f:
        for line in f:
            ip = line.replace('\n', '')
            set_block(ip)