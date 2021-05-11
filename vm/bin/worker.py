#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import threading
from collections import deque as dq
import sys
import logging

#重写用于事件队列的deque，使得对deque的变动会触发信号量
class deque(dq):
    #存储信号的集合
    sign = set()
    #重写append、appendleft、extend、extendleft方法
    def append(self, *args, **kwargs):
        dq.append(self, *args, **kwargs)
        self.sign_set()

    def appendleft(self, *args, **kwargs):
        dq.appendleft(self, *args, **kwargs)
        self.sign_set()
        
    def extend(self, *args, **kwargs):
        dq.extend(self, *args, **kwargs)
    
    def extendleft(self, *args, **kwargs):
        dq.extendleft(self, *args, **kwargs)

    #触发信号
    def sign_set(self):
        for s in self.sign:
            s.set()

    #添加一个信号
    def add_sign(self,s):
        self.sign.add(s)

class Worker(object):
    def __init__(self, worker_num=1):
        self.worker_num = worker_num
        self.worker = 0
        self.worker_isrun = [1 for i in range(worker_num)]
        self.worker_list = []
        self.queue_list =[deque() for i in range(worker_num)]

    def worker_callback(self, queue):
        dict = queue.pop()
        task = dict["type"]
        if task == 2:
            logging.info("pop number: %s %s numbers left" % (dict["data"], len(queue)))
        elif task == 1:
            # 一般走不到这个流程
            logging.info("worker recv exit task \n")

    def worker_proc(self, i):
        sign = threading.Event()
        self.queue_list[i].add_sign(sign)
        logging.info ("worker %d run \n" % i)
        while self.worker_isrun[i]:
            if self.queue_list[i]:
                self.worker_callback(self.queue_list[i])
            else:
                logging.info("queue empty\n")
                sign.wait()
                sign.clear()

    def worker_run(self):
        for i in range(self.worker_num):
            self.worker_list.append(threading.Thread(target=self.worker_proc, name = "Worker_%s" % i, args=[i]))
        for worker in self.worker_list:
            worker.start()
        
    def worker_stop(self):
        logging.info("workers exit\n")
        for i in range(self.worker_num):
            self.worker_isrun[i] = 0
        dict = {}
        dict["type"] = 1
        for i in range(self.worker_num):
            self.task_append(dict)
    
    def task_append(self, data):
        self.worker += 1
        if self.worker == self.worker_num:
            self.worker = 0
        self.queue_list[self.worker].appendleft(data)
        