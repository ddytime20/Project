#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import sys
import socket
import select
import logging

class SockServer(object):
    def __init__(self, port=8080):
        self.server_isrun = 1
        # 创建套接字
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('0.0.0.0', port))
        self.server_socket.listen(1)
        self.documents_root = port
        # 创建epoll对象
        self.epoll = select.epoll()
        self.epoll.register(self.server_socket.fileno(), select.EPOLLIN|select.EPOLLET)
        # 创建添加的fd对应的套接字
        self.fd_socket = dict()

    def sock_callback(self, worker, socket, data):
        print(data)
    
    def sock_epollwait(self, worker):
        while self.server_isrun:
            # epoll 进行 fd 扫描的地方 -- 未指定超时时间则为阻塞等待
            epoll_list = self.epoll.poll()
            for fd, event in epoll_list:
                # 如果是服务器套接字可以收数据，那么意味着可以进行accept
                if fd == self.server_socket.fileno():
                    logging.info('accept new connect\n')
                    sys.stdout.flush()
                    new_socket, new_addr = self.server_socket.accept()
                    # 向 epoll 中注册 连接 socket 的 可读 事件
                    self.epoll.register(new_socket.fileno(), select.EPOLLIN | select.EPOLLET | select.EPOLLHUP | select.EPOLLERR)
                    # 记录这个信息
                    self.fd_socket[new_socket.fileno()] = new_socket
                # 接收到数据
                elif event == select.EPOLLIN:
                    request = self.fd_socket[fd].recv(8192).decode("utf-8")
                    if request:
                        self.sock_callback(worker, self.fd_socket[fd], request)
                    else:
                        logging.info('close connect\n')
                        sys.stdout.flush()
                        # 在epoll中注销客户端的信息
                        self.epoll.unregister(fd)
                        # 关闭客户端的文件句柄
                        self.fd_socket[fd].close()
                        # 在字典中删除与已关闭客户端相关的信息
                        del self.fd_socket[fd]

    def sock_senddata(self, socket, data):
        socket.send(data.encode('utf-8'))

    def sock_close(self, socket):
        fd = socket.fileno()
        if fd in self.fd_socket.keys():
            # 在epoll中注销客户端的信息
            self.epoll.unregister(fd)
            # 关闭客户端的文件句柄
            self.fd_socket[fd].close()
            # 在字典中删除与已关闭客户端相关的信息
            del self.fd_socket[fd]
        else:
            logging.info("fd not exit \n")

    def sock_exit(self):
        logging.info("socket exit\n")
        self.server_isrun = 0
        for fileno, socket in self.fd_socket.items():
            self.epoll.unregister(fd)
            socket.close()
            del self.fd_socket[fd]
        self.epoll.unregister(self.server_socket.fileno())
        self.epoll.close()
        self.server_socket.close()