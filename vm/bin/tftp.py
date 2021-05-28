#!/usr/bin/env python
# -*- coding: UTF-8 -*-
from __future__ import print_function
# import
import sys, os
import struct
import datetime
import select
from socket import *
from threading import Thread

try: 
	from config import WORKER_PATH
except ImportError:
	WORKER_PATH = '.'

'''
tftp server:support uploand and download
opcode operation
1．Read request (RRQ)
2．Write request (WRQ)
3．Data (DATA)
4．Acknowledgment (ACK)
5．Error (ERROR)
'''
 
# upload thread
def upload_thread(fileName, clientInfo, mode):
	start = datetime.datetime.now()
	blocknum = 0 # block num
	filepath = WORKER_PATH + os.path.sep + fileName
	# open with binary
	f = open(filepath, 'wb')

	# create new udp socket
	s = socket(AF_INET, SOCK_DGRAM)

	# pack Acknowledgment and block num
	sendDataFirst = struct.pack("!HH", 4, blocknum)
	blocknum += 1
	now = datetime.datetime.now()
	# send ack, use new socket
	s.sendto(sendDataFirst, clientInfo)

	while (now - start).seconds < 10:
		# recv file data
		recvData, clientInfo = s.recvfrom(1024)

		#print(recvData, clientInfo)

		# unpack
		packetOpt = struct.unpack("!H", recvData[:2])  # opcode operation
		packetNum = struct.unpack("!H", recvData[2:4]) # block num

		#print(packetOpt, packetNum)

		# check opcode and block num
		if packetOpt[0] == 3 and packetNum[0] == blocknum:
			#　wirite file
			f.write(recvData[4:])

			# each block answer ack
			sendData = struct.pack("!HH", 4, blocknum)
			s.sendto(sendData, clientInfo)

			blocknum += 1

			if len(recvData) < 516:
				print("用户"+str(clientInfo), end='')
				print('upload '+fileName+' success !')
				break
		now = datetime.datetime.now()
	# close file
	f.close()

	# close socket
	s.close()

	# exit
	exit()
 
 
# download thread 
def download_thread(filename, clientInfo, mode):
	# create udp socket
	filepath = WORKER_PATH + os.path.sep + filename
	s = socket(AF_INET, SOCK_DGRAM)
	# block num
	blocknum = 0
 
	try:
		f = open(filepath,'rb')
	except:
		# pack, send erroe msg
		errorData = struct.pack('!HHHb', 5, 5, 5, blocknum)
		s.sendto(errorData, clientInfo)

		# thread exit
		exit()
 
	while True:
		# read local file 512 byte
		readFileData = f.read(512)
 
		blocknum += 1
 
		# pack and send data to client
		sendData = struct.pack('!HH', 3, blocknum) + readFileData
		s.sendto(sendData, clientInfo)
		
		# send success
		if len(sendData) < 516:
			print('client '+str(clientInfo), end='')
			print('downfile '+fileName+' success!')
			break
 
		# recv ack 
		recvData, clientInfo = s.recvfrom(1024)
		
		#print(recvData, clientInfo)
 
		# unpcak
		packetOpt = struct.unpack("!H", recvData[:2])  #opcode operation
		packetNum = struct.unpack("!H", recvData[2:4]) #block num
 
		#print(packetOpt, packetNum)
 
		if packetOpt[0] != 4 or packetNum[0] != blocknum:
			print("transport file failed")
			break
 
	# close file
	f.close()
 
	# close socket
	s.close()
 
	# exit thread
	exit()
 
class TftpServer(object):
	def __init__(self, port=69):
		self.isrun = True
		# create udp socket
		self.sock = socket(AF_INET, SOCK_DGRAM)

		# fix rebind port
		self.sock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)

		# bind port 69
		self.sock.bind(('', port))
		# creat epoll
		self.epoll = select.epoll()
		self.epoll.register(self.sock.fileno(), select.EPOLLIN|select.EPOLLET)
	
	def run(self):
		while self.isrun:
			epoll_list = self.epoll.poll()
			for fd, event in epoll_list:
				recvData, clientInfo = self.sock.recvfrom(1024)
				opcode = struct.unpack('!H',recvData[:2])
				for index, ch in enumerate(recvData[2:]):
					if ch == '\0':
						break
				fileend = 2+index
				fileName = recvData[2:fileend].decode('gb2312')
				mode = recvData[fileend+1:]
				print(fileName)
				print(mode)
				# download
				if opcode[0] == 1:
					t = Thread(target=download_thread, args=(fileName, clientInfo, mode))
					t.start()

				# upload
				elif opcode[0] == 2:
					t = Thread(target=upload_thread, args=(fileName, clientInfo, mode))
					t.start()
	def exit(self):
		self.isrun = False
		self.epoll.unregister(self.sock.fileno())
		self.sock.close()
		self.epoll.close()

def main():
	tftp = TftpServer(port = 69)
	tftp.run()
	tftp.exit()

# main
if __name__ == '__main__':
	main()
