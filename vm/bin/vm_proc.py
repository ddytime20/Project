#!/usr/bin/env python
# -*- coding: UTF-8 -*-
from __future__ import print_function
import os
import sys
import time
import base64
import peutils
import logging
from xml.sax.saxutils import unescape
from xmlrpclib import ServerProxy
from config import MAX_RETRIES

try:
    import pefile
    have_pe = True
except ImportError:
    have_pe = False
    pefile = None

def checkPacker(the_file):
    if False == have_pe:
        print("do not have pefile module")
        return None

    try:
        pe  = pefile.PE(the_file, fast_load=True)
        sig = peutils.SignatureDatabase("UserDB.TXT")
        matches = sig.match_all(pe, ep_only = True)
    except:
        matches = None

    return matches

def connect(url):
    url = url.strip("\r").strip("\n")
    s = ServerProxy(url, allow_none=True)
    try:
        status = s.ping()
        #logging.debug("Checking server %s status: %s" %(url, status))
        if status != "[ALIVE]":
            return None
    except:
        #logging.debug("Error:" + str(sys.exc_info()[1]))
        return None
    
    return s

# connect vm, get report write file
def rpc_client_proc(url, filename, retries = 0):
    #if retries > MAX_RETRIES:
    s = connect(url)
    if s is None:
        #logging.debug("No server available")
        return -1
    '''
    basename = os.path.basename(filename)
    ret = checkPacker(filename) 
    if ret:
        if len(ret) > 0:
            #logging.debug("Dumping file %s packed with:" % basename)
    '''
    buf = file(filename, "rb").read()
    origbuf = buf
    buf = base64.b64encode(buf)

    try:
        logging.debug("start dump")
        ret = s.dump(buf, 10)
    except:
        #logging.debug("Error running dump (%s), retry number %d..." % (sys.exc_info()[1], retries))
        if retries+1 < MAX_RETRIES:
            main(url, filename, retries+1)
        else:
            return -1

    if not ret:
        #logging.debug("Error: No response received!")
        return -1

    if ret.has_key("report"):
        report = []
        for line in ret["report"]:
            report.append(unescape(line))
        ret = "".join(report)
        print(ret)

    return 0


# connect vm get report
def vm_client_proc(url, filename, retries = 0):
    if retries > MAX_RETRIES:
        logging.debug("Error: Too many retries (%d), exitting..." % MAX_RETRIES)
    s = connect(url)
    if s is None:
        logging.debug("No server available")
        return -1, ""

    basename = os.path.basename(filename)
    ret = checkPacker(filename) 
    if ret:
        if len(ret) > 0:
            logging.debug("Dumping file %s packed with:" % basename)

    buf = file(filename, "rb").read()
    origbuf = buf
    buf = base64.b64encode(buf)

    # dump获取report
    try:
        logging.debug("start dump")
        ret = s.dump(buf, 10)
    except:
        logging.debug("Error running dump (%s), retry number %d..." % (sys.exc_info()[1], retries))
        if retries+1 < MAX_RETRIES:
            main(url, filename, output, retries+1)
        else:
            return -1, ""
    
    if not ret:
        logging.debug("Error: No response received!")
        return -1, ""
    report = []
    if ret.has_key("report"):
        if ret["report"]:
            logging.debug("get report success")
            for line in ret["report"]:
                if line:
                    report.append(unescape(line)) # 字符转义
            ret = "".join(report)
            return 0, ret
    else:
        logging.debug("there is not generate report")
        return -1,""

if __name__ == '__main__':
    rpc_client_proc(sys.argv[1], sys.argv[2], retries = 1)
    
