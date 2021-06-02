#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import os
import threading
from collections import deque as dq
import sys
import logging
import json
import queue
import uuid
import xml.etree.ElementTree as ET
import subprocess
import time
import re
import random
import libvirt

import yara_rule
#import vm_proc
from config import WORKER_PATH, XML_PATH, IMG_PATH, VM_NUM, VM_MEM, VM_CPU, RPC_PATH

#check_vm = False
vm_current_num = None
vm_num = None
virt_conn = None
#{"id":"","name":"","tty":"","mac":"",'img':'',"ip":"","status":""}
vm_info = []

def generate_mac_addr():
    mac_list = [ 0x5e, 0x24, 0x81,random.randint(0x00, 0x7f),random.randint(0x00, 0xff),random.randint(0x00, 0xff) ]
    mac = ':'.join(map(lambda x: "%02x" % x, mac_list))
    logging.info('mac addr %s' % mac)
    return mac

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


"""
"""
def timeout_command(command, timeout):
    import subprocess, datetime, time, signal
    ret = 0
    cmd = command.split(" ")
    start = datetime.datetime.now()
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    while process.poll() is None:
        time.sleep(1)
        now = datetime.datetime.now()
        if (now - start).seconds > timeout:
            print "Killing process %d" % process.pid
            os.kill(process.pid, signal.SIGKILL)
            os.waitpid(-1, os.WNOHANG)
            ret = -1
            break
        elif process.returncode != None:
            break
    return ret, process.stdout.readlines()

def parse_xml(path):
    global vm_info
    tree = ET.parse(path)
    root = tree.getroot()
    info = {}
    name = root.find('name')
    if name is not None:
        info['name'] = name.text
    else:
        logging.error('parse xml: xml file not find name')
    disksource = root.find('devices/disk/source')
    if disksource is not None:
        info['img'] = disksource.attrib['file']
    else:
        logging.error('parse xml: xml file not find disk source')
    mac = root.find('devices/interface/mac')
    if mac is not None:
        info['mac'] = mac.attrib['address']
        mac.set("address",info['mac'])
    else:
        logging.error('parse xml: xml file not find mac') 
    console = root.find('devices/console')
    if console is not None:
        info['tty'] = console.attrib['tty']
    else:
        logging.error('parse xml: xml file not find console')
    num = len(vm_info)
    info['id'] = num
    info['ip'] = ''
    info['status'] = -1
    vm_info.append(info)

def get_xml():
    dir, filename = os.path.split(XML_PATH)
    files = os.listdir(dir)
    if len(files) > 0:
        for file in files:
            if file != filename and file.endswith("xml"):
                path = dir + os.path.sep + file
                parse_xml(path)

def create_xml(info):
    dir, filename = os.path.split(XML_PATH)
    path =  dir + os.path.sep + info['name'] + '.xml'
    # exist
    if os.path.exists(path):
        return path
    # not exist
    tree = ET.parse(XML_PATH)
    root = tree.getroot()
    
    name = root.find('name')
    if name is not None:
        name.text = info['name']
    else:
        logging.error('xml file not find name') 
    mem = root.find('memory')
    if mem is not None:
        mem.text = str(VM_MEM)
    else:
        logging.error('xml file not find memory')
    currmem = root.find('currentMemory')
    if currmem is not None:
       currmem.text = str(VM_MEM)
    else:
        logging.error('xml file not find currentMemory')
    vcpu = root.find('vcpu')
    if vcpu is not None:
       vcpu.text = str(VM_CPU)
    else:
        logging.error('xml file not find vcpu')    

    uuid = root.find('uuid')
    if uuid is not None:
        uuid.text = info['name']
    else:
        logging.error('xml file not find uuid')
    disksource = root.find('devices/disk/source')
    if disksource is not None:
        disksource.set('file',info['img'])
    else:
        logging.error('xml file not find disk source')
    mac = root.find('devices/interface/mac')
    if mac is not None:
        mac.set("address",info['mac'])
    else:
        logging.error('xml file not find mac') 

    console = root.find('devices/console')
    if console is not None:
        console.set('tty', info['tty'])
        tty = console.find('source')
        if tty is not None:
            tty.set('tty', info['tty'])
        else:
            logging.error('xml file not find tty') 
    else:
        logging.error('xml file not find console')

    tree.write(path)
    return path

'''
libvirt can get vm ip, but vm need install qemu-guest-agent
interfaceAddresses(self, source, flags=0)
    returns a dictionary of domain interfaces along with their MAC and IP addresses
arp -a
(192.168.122.224) at 5e:50:00:e4:a9:e2 [ether] on virbr0
'''
def vm_get_ip(info):
    ret, rettxt = timeout_command(command='arp -a', timeout = 2)
    for line in rettxt:
        if line.find(info['mac']) != -1:
            ip = re.findall(r'\d+\.\d+\.\d+\.\d+',line)
            info['ip'] = ip[0]
            logging.info('get ip %s' % info['ip'])

def vm_check_ip():
    global vm_info
    for info in vm_info:
        if len(info['ip']) == 0:
            vm_get_ip(info)

def vm_virt_status(domainName):
    conn = libvirt.open('qemu:///system')
    if conn == None:
        logging.error('vm status: libvirt connect qemu failed')
        return -1
    try:
        dom = conn.lookupByName(domainName)
        if dom == None:
            conn.close()
            return -1
        else:
            flag = dom.isActive()
            conn.close()
            return flag
    except:
        logging.error('vm status: Failed to get domain object %s' % domainName)
        conn.close()
        return -1

def vm_virt_start(info):
    path = create_xml(info)
    if os.path.exists(path):
        if not os.path.exists(info['img']):
            logging.warning('virr start copy img %s' % info['img'])
            cmd = 'cp ' + IMG_PATH + ' ' + info['img']
            timeout_command(cmd, 5)
        buf = file(path, "r").read()
        conn = libvirt.open('qemu:///system')
        if conn == None:
            logging.error('vm status: libvirt connect qemu failed')
            return -1
        else:
            conn.createXML(buf)
            dom = conn.lookupByName(info['name'])
            if dom == None:
                logging.error('vm start: define vm failed %s path' % path)
                conn.close()
                return -1
            else:
                conn.close()
                logging.info('vm start: find start vm')
                info['status'] = 1
                return 0
    else:
        logging.error("vm start: xml file not exit, path %s" % path)
        return -1

def vm_virt_destroy(domainName):
    conn = libvirt.open('qemu:///system')
    if conn == None:
        logging.error('vm status: libvirt connect qemu failed')
        return -1
    else:
        try:
            dom = conn.lookupByName(domainName)
            if dom == None:
                logging.error('vm destroy: Failed to get the domain object %s' % domainName)
                conn.close()
                return -1
            else:
                dom.destroy()
                conn.close()
                return 0
        except:
            logging.error('vm destroy: can not find domain object %s' % domainName)
            return -1

def vm_exit():
    global vm_info
    for info in vm_info:
        vm_virt_destroy(info['name'])
        cmd = 'rm -f ' + info['img']
        timeout_command(cmd, 2)

def vm_restart():
    global vm_info
    logging.info('vm restart')
    for info in vm_info:
        if -1 == info['status']:
            # start vm
            vm_virt_start(info)
            # wait vm start
            time.sleep(5)
            vm_get_ip(info)
            

def vm_update_status():
    global vm_info
    count = 0
    for info in vm_info:
        if 1 == vm_virt_status(info['name']):
            count += 1
            info['status'] = 1
        else:
            info['status'] = -1
    #logging.info('get running vm count %d' % count)
    return count

def vm_info_init():
    #if data.has_key('num'):
    global vm_num
    global vm_info
    global vm_current_num
    #global check_vm
    dir, filename = os.path.split(IMG_PATH)
    current_num = len(vm_info)
    while vm_num > current_num:
        info = {}
        info['id'] = current_num
        info['name'] = str(uuid.uuid1())
        info['tty'] = '/dev/pts/' + str(current_num+5)
        info['mac'] = generate_mac_addr()
        info['status'] = -1
        info['ip'] = ''
        info['img'] = dir + os.path.sep + info['name'][0:8] + '.qcow2'
        vm_info.append(info)
        #logging.info('vm info id %d ' % info['id'])
        current_num += 1
    #check_vm = True
    vm_current_num = vm_num
    #else:
    #    logging.error('get start vm info error do not has num')    

# encap json
def encap_json_data(data):
    try:
        json_data = json.dumps(data)
    except ValueError:
        logging.error("json format error")
        return 0
    return json_data

def send_busy_code(socket):
    ret = {'ret':'busy'}
    data = json.dumps(ret)
    try:
        socket.send(data.encode('utf-8'))
    except:
        logging.error("send busy code failed")

# if error, send data
def send_data(socket, rettxt):
    data = json.dumps(rettxt)
    try:
        socket.send(data.encode('utf-8'))
    except:
        logging.error("error send data failed")
    return

# check json format
def parse_json_data(data):
    try:
        data = json.loads(data)
    except ValueError:
        logging.error("json format error")
        return 0
    
    if check_json_data(data):
        return data
    return 0

# 
def check_json_data(data):
    if data.has_key("msgtype") and data.has_key("filename"):
        return 1
    logging.error("recv data check failed")
    return


def worker_busy(data):
    rettxt = {}
    rettxt['errcode'] = 4
    jsondata = parse_json_data(data["data"])
    if jsondata != 0:
        path = WORKER_PATH + os.path.sep + jsondata['filename']
        cmd = 'rm -f ' + path
        timeout_command(cmd,2)
        rettxt['filename'] = jsondata['filename']
    send_data(data['socket'], rettxt)

    return 

'''
ret (errcode)
0 : success
1 : no find file
2 : vm invalid
3 : timeout
4 : thread busy
'''


class Worker(object):
    def __init__(self, worker_num=1):
        self.worker_num = worker_num
        self.worker = 0
        # worker end
        self.worker_isrun = [1 for i in range(worker_num)]
        # worker thread
        self.worker_list = []
        # queue task
        self.queue_list =[deque() for i in range(worker_num)]
        # worker flag busy or idle
        self.worker_flag = [0 for i in range(worker_num)]
        self.timer_queue = queue.Queue(1)
        self.timer_exit = False
    
    def thread_Timer(self):
        if self.timer_exit:
            return
        global vm_num
        if vm_num > vm_update_status():
            vm_restart()
        vm_check_ip()

        t1 = threading.Timer(5, self.thread_Timer)
        t1.start()

    def worker_monitor_threat(self):
        t1 = threading.Timer(5, self.thread_Timer)
        t1.start()

    def worker_callback(self, queue , i):
        dict = queue.pop() 
        socket = dict["socket"]
        task = dict["type"]
        data = dict['data'].decode()
        rettxt = {}
        if task == 2:
            # json format check
            data = parse_json_data(data)
            if not data:
                logging.info('parse json fail')
                rettxt['errcode'] = 1
                send_data(socket, rettxt)
                self.worker_flag[i] = 0
                return -1
            rettxt['filename'] = data['filename']
            logging.debug("data check success")
            
            global vm_info
            info = vm_info[i]
            if len(info['ip']) == 0 or info['status'] != 1:
                rettxt['errcode'] = 2
                send_data(socket, rettxt)
                logging.error("check json data failed")
                self.worker_flag[i] = 0
                return -1

            url = 'http://' + info.get('ip') + ':8000'
            path = WORKER_PATH + os.path.sep + data["filename"]
            cmd = 'python ' + RPC_PATH + ' ' + url + ' ' + path
            if not os.path.exists(path):
                rettxt['errcode'] = 1
                send_data(socket, rettxt)
                logging.error('file not exist')
                return -1
            ret, reports = timeout_command(cmd, 30)
            #ret, report = vm_proc.vm_client_proc(url, data["path"]);
            #if 0 == ret and "" != report:
            #    ret, rettxt = yara_rule.yara_process_match(report)
            #    if 0 == ret and "" != rettxt:
            #        success_send_data(socket, rettxt)
            #    else:
            #        error_send_data(socket)
            #    self.worker_flag[i] = 0
            #    return ret
            cmd ='rm -f ' + path
            timeout_command(cmd, 2)
            if ret == 0 and "" != reports:
                report = "".join(reports)
                ret, rettxt = yara_rule.yara_process_match(report)
                if 0 == ret and "" != rettxt:
                    rettxt['filename'] = data['filename']
                    send_data(socket, rettxt)
                else:
                    rettxt['errcode'] = 3
                    rettxt['filename'] = data['filename']
                    send_data(socket, rettxt)
                self.worker_flag[i] = 0
                return ret
            else:
                rettxt['errcode'] = 3
                send_data(socket, rettxt)
                self.worker_flag[i] = 0
                return -1

        elif task == 1:
            logging.debug("worker recv exit task")

    def worker_proc(self, i):
        sign = threading.Event()
        self.queue_list[i].add_sign(sign)
        #logging.info ("worker %d run " % i)
        while self.worker_isrun[i]:
            if self.queue_list[i]:
                self.worker_callback(self.queue_list[i], i)
            else:
                #logging.info("queue empty")
                sign.wait()
                sign.clear()

    def worker_run(self):
        # init timer queue
        #self.timer_queue = queue.Queue(1)
        global vm_num
        vm_num = VM_NUM

        # yara rule init
        yara_rule.yara_init_rule()

        # get xml file
        get_xml()
        # init vm info
        vm_info_init()

        # init timer threat
        self.worker_monitor_threat()
        
        # workers threat init
        for i in range(self.worker_num):
            self.worker_list.append(threading.Thread(target=self.worker_proc, name = "Worker_%s" % i, args=[i]))
        for worker in self.worker_list:
            worker.start()


    # worker stop
    def worker_stop(self):
        logging.info("workers exit")
        self.timer_exit = True
        for i in range(self.worker_num):
            self.worker_isrun[i] = 0
        dict = {}
        dict["type"] = 1
        for i in range(self.worker_num):
            self.queue_list[i].appendleft(dict)
        vm_exit()
            
    
    # worker append task
    def task_append(self, data):
        worker = self.worker
        self.worker += 1
        while worker != self.worker:
            if self.worker == self.worker_num:
                self.worker = 0
            if self.worker_flag[self.worker] == 0:
                break
            self.worker += 1
        
        # can not find idle worker
        if worker == self.worker:
            worker_busy(data)
            send_busy_code(data['socket'])
            return
        self.queue_list[self.worker].appendleft(data)
        self.worker_flag[self.worker] = 1
