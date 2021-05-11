#!/usr/bin/env python
# -*- coding: UTF-8 -*-

from __future__ import print_function
import os
import sys
import time
import signal
import logging
from daemon import Daemon
from server import SockServer
from worker import Worker

workers = None
daemon = None
main_server = None

LOG_FORMAT = "%(asctime)s - %(levelname)s - %(message)s"
def Log_Config():
    logging.basicConfig(stream=sys.stderr, level=logging.DEBUG, format=LOG_FORMAT)

def sigterm_handler(signo, frame):
    global workers
    global main_server
    main_server.sock_exit()
    workers.worker_stop()
    raise SystemExit(0)

class MainSocket(SockServer):
    def sock_callback(self, worker, socket, data):
        dict = {}
        dict["type"] = 2
        dict["data"] = data
        dict["socket"] = socket
        worker.task_append(dict)

class MainDaemon(Daemon):
    def run(self):
        signal.signal(signal.SIGTERM, sigterm_handler)
        Log_Config()
        logging.info('Daemon started with pid {}\n'.format(os.getpid()))
        global workers
        global main_server
        workers = Worker(worker_num = 2)
        workers.worker_run()
        main_server = MainSocket(port=8080)
        main_server.sock_epollwait(workers)


if __name__ == '__main__':
    PIDFILE = '/tmp/daemon-example.pid'
    LOG = '/tmp/daemon-example.log'
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
