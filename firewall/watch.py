from __future__ import print_function
import sys
import time
import subprocess
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
import main

class MyHandler(PatternMatchingEventHandler):
    def __init__(self, patterns):
        super(MyHandler, self).__init__(patterns=patterns)
    
    def on_modified(self, event):
        main.main_routine()

# [TODO] too much surveillance
def watch(watch_dirs):
    event_handler = MyHandler(["*"])
    observer = Observer()
    for watch_dir in watch_dirs:
        observer.schedule(event_handler, watch_dir)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    path_cowrie  ='/data/cowrie/log/'
    path_drop = '/var/log/iptables'
    watch_dirs = [path_cowrie, path_drop]
    watch(watch_dirs)
