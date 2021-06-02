#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import os
import re
import string
import sys
import logging
from config import YARA_RULE_PATH

try:
    import yara  # pip yara-python
    has_yara = True
except ImportError:
    yara = None
    has_yara = False

yara_rules = None

"""
Scan a dictionary of YARA rule files to determine
which are valid for compilation.

Arguments:
	yara_files: path to folder containing rules
"""
def yara_rule_check(yara_files):
    result = dict()
    for yara_id in yara_files:
        fname = yara_files[yara_id]
        try:
            yara.compile(filepath=fname)
            result[yara_id] = fname
        except yara.SyntaxError:
            logging.warning('Syntax Error found in YARA file: {}'.format(fname))
    return result

"""
list file
"""
def list_files(path):
    lsdir = os.listdir(path)
    dirs = [i for i in lsdir if os.path.isdir(os.path.join(path, i))]
    if dirs:
        for i in dirs:
            list_files(os.path.join(path, i))
    files = [i for i in lsdir if os.path.isfile(os.path.join(path,i))]
    return files

"""
Import a folder of YARA rule files

Arguments:
	yara_path: path to folder containing rules
Results:
	rules: a yara.Rules structure of available YARA rules
"""
def yara_import_rules(yara_path):
    yara_files = {}
    
    logging.info('Loading YARA rules from folder: {}'.format(yara_path))
    files = list_files(yara_path)

    # 获取所有的rule文件放到yara_files
    for file_name in files:
        file_extension = os.path.splitext(file_name)[1]
        if '.yar' in file_extension:
            yara_files[file_name.split(os.sep)[-1]] = os.path.join(yara_path, file_name)

    # 对rule检查，保证rule可以编译过
    yara_files = yara_rule_check(yara_files)
    rules = ''
    # 编译rule
    if yara_files:
        try:
            rules = yara.compile(filepaths=yara_files)
            logging.info('YARA rules loaded. Total files imported: %d' % (len(yara_files)))
        except yara.SyntaxError:
            logging.error('YARA rules disabled , rule format error.')

    return rules

"""
Scan a given file to see if it matches a given set of YARA rules

Arguments:
	file_path: full path to a file to scan
	rules: a yara.Rules structure of available YARA rules
Results:
	results: a string value that's either null (no hits)
			 or formatted with hit results
"""
def yara_filescan(file_path, rules):
    if not rules:
        return '','',''
    
    if os.path.isdir(file_path):
        logging.debug('file: {} is dir \n'.format(file_path))
        return '','',''
    
    matchrules = ''
    score = 0
    desc = ''
    results = ''

    try:
        matches = rules.match(file_path)
    except yara.Error:  # If can't open file
        logging.debug('YARA can\'t open file: {}'.format(file_path))
        return '','',''

    # 命中规则，组装信息
    if matches:
        matchrules = '\t[YARA: {}]'.format(', '.join(str(x) for x in matches))
        if 'description' in matches[0].meta:
            desc = matches[0].meta['description']
        for i in matches:
            if ('severity' in i.meta) and (i.meta['severity'] > score):
                score = i.meta['severity']
                desc = i.meta['description']
    else:
        logging.debug('YARA not match file: {}'.format(file_path))

    return matchrules,score,desc

"""
Given the location of CSV and TXT files, parse the CSV for notable items

Arguments:
	csv_file: path to csv output to parse
	report: OUT string text containing the entirety of the text report
	timeline: OUT string text containing the entirety of the CSV report
"""
def yara_init_rule():
    global yara_rules
    global yara_rules
    logging.info('YARA init_rule starting')
    
    if False == has_yara:
        logging.error('do not have yara module')
        return
    yara_rules = yara_import_rules(YARA_RULE_PATH)
    if yara_rules:
        logging.info('YARA init_rule successfully!')
    else:
        logging.error('YARA init_rule Failed!')

"""
Given the location of CSV and TXT files, parse the CSV for notable items

Arguments:
	csv_file: path to csv output to parse
	report: OUT string text containing the entirety of the text report
	timeline: OUT string text containing the entirety of the CSV report
"""
# 匹配文件
def yara_process_file(filename):
    global yara_rules
    yara_hits = ''
    score = 0
    desc = ''
    ret = 0
    
    if os.path.exists(filename) and yara_rules:
        yara_hits,score,desc = yara_filescan(filename, yara_rules)
        if len(yara_hits) == 0:
            ret = -1
            logging.debug('Processing match yara Failed!')
        else:
            logging.debug(yara_hits)
    else:
        logging.debug('file {} not exit or rules init failed'.format(filename))
        ret = -1
    
    rettxt = [{'file':filename, 'ret':ret, 'matchrules':yara_hits, 'score':score, 'description':desc}]
    return ret, rettxt

# 直接对内容匹配 str
def yara_process_match(report):
    global yara_rules
    
    if yara_rules:
        try:
            matches = yara_rules.match(data=report)
        except yara.Error:  
            logging.warning('YARA cant match report')
            return -1,''
    else:
        logging.warning('YARA yara_rule init failed cant match')
        return -1,''

    if matches:
        matchrules = []
        desc = ''
        score = 0
        max_serverity = 0

        if 'description' in matches[0].meta:
            desc = matches[0].meta['description']

        for i in matches:
            if 'severity' in i.meta:
                score += i.meta['severity']
                if i.meta['severity'] > max_serverity:
                    max_serverity = i.meta['severity']
                    desc = i.meta['description']
                    matchrules.insert(0, str(i))
                else:
                    matchrules.append(str(i))
            else:
                matchrules.append(str(i))
    else:
        logging.debug('YARA not match file')
        return -1,''
    
    rettxt = {'errcode':0, 'rulename':matchrules, 'score':score, 'desc':desc}
    return 0,rettxt
