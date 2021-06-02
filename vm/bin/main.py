#!/usr/bin/env python
# -*- coding: UTF-8 -*-

from __future__ import print_function
import os
import sys
import time
import signal
import logging
import threading
from daemon import Daemon
from server import SockServer
from worker import Worker
from tftp import TftpServer

from config import LOG_FORMAT, LOG_GRADE, SERVER_PORT, VM_NUM
workers = None
daemon = None
main_server = None
tftp_server = None

def log_config():
    logging.basicConfig(stream=sys.stderr, level=LOG_GRADE, format=LOG_FORMAT)

def sigterm_handler(signo, frame):
    global workers
    global main_server
    global tftp_server
    logging.info('recv exit signal')
    tftp_server.exit()
    main_server.sock_exit()
    workers.worker_stop()
    raise SystemExit(0)

# 屏蔽信号
def signal_process():
    for i in range(signal.SIGHUP, signal.SIGSYS):
        if i == signal.SIGTERM:
            signal.signal(signal.SIGTERM, sigterm_handler)
        elif i == signal.SIGKILL or i == signal.SIGSTOP:
            continue
        else:
            signal.signal(i, signal.SIG_IGN)
    
class MainSocket(SockServer):
    def sock_callback(self, worker, socket, data):
        dict = {}
        dict["type"] = 2
        dict["data"] = data
        dict["socket"] = socket
        worker.task_append(dict)

class MainDaemon(Daemon):
    # 重写Daemon启动
    def run(self):
        # 信号处理
        signal_process()
        log_config()
        global workers
        global main_server
        global tftp_server
        tftp_server = TftpServer()
        tftp_thread = threading.Thread(target = tftp_server.run,args=[])
        tftp_thread.start()
        workers = Worker(worker_num = VM_NUM)
        workers.worker_run()
        main_server = MainSocket(port=SERVER_PORT)
        main_server.sock_epollwait(workers)


if __name__ == '__main__':
    PIDFILE = '/run/vmpd.pid'
    LOG = '/tmp/vmpd.log'
    daemon = MainDaemon(pidfile=PIDFILE, stdout=LOG, stderr=LOG)

    if len(sys.argv) != 2:
        print('Usage: {} [start|stop]'.format(sys.argv[0]), file=sys.stderr)
        raise SystemExit(1)
	
    if 'start' == sys.argv[1]:
        daemon.start()
    elif 'stop' == sys.argv[1]:
        daemon.stop()
    elif 'restart' == sys.argv[1]:
        daemon.restart()
    else:
        print('Unknown command {!r}'.format(sys.argv[1]), file=sys.stderr)
        raise SystemExit(1)
