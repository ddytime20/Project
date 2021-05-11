#!/bin/bash

#定义程序名，在同一个机器上必须唯一
APP_NAME="main.py"
APP_DIR="/home/share/code/python/vm/"
SHELL_DIR=$(cd "$(dirname "$0")";pwd)
SHELL_NAME=`basename $0`
PID_RET=""
CHECK_INTERVAL_SECONDS=5
# 将APP_NAME写到文件 计算md5 -表示从标准输入中读取
APP_MD5=`echo ${APP_NAME} | md5sum - | awk '{print $1}'`
#echo $SHELL_DIR
#echo $SHELL_NAME

# 获取进程的pid
get_pid() {
  PID_RET=`ps -ef | grep "python" | grep "start" | grep ${APP_NAME} | awk '{print $2}'`
}

# 获取watch dog的pid
get_watch_pid() {
  PID_RET=`ps -ef | grep ${SHELL_NAME} | grep watch | grep ${APP_MD5} | awk '{print $2}'`
}

#实现启动进程接口
start_proc() {
  nohup python ${APP_NAME} start > /dev/null 2>&1 &
}

#实现结束进程接口，${1}为传入的进程号
stop_proc() {
  nohup python ${APP_NAME} stop > /dev/null 2>&1 &
}


# switch_appdir
switch_appdir() {
  # 切换工作目录判断执行文件是否存在
  cd ${APP_DIR}
  if [ ! -e ${APP_NAME} ];then
    echo "ERROR: ${APP_NAME} is not exists"
  fi
}

# 启动进程同时启动watch dog
start() {
  get_pid
  # -z 字符串长度为0 则为真
  if [ -z "${PID_RET}" ];then
    switch_appdir
    start_proc
    sleep 1
    get_pid
    if [ ! -z "${PID_RET}" ];then
      echo "start ${APP_NAME} ok, pid ${PID_RET}"
    else
      echo "start ${APP_NAME} fail"
      return 1
    fi
  else
    echo "${APP_NAME} is running pid ${PID_RET}"
  fi
  get_watch_pid
  if [ -z "${PID_RET}" ];then
    cd ${SHELL_DIR}
    #echo ${APP_MD5}
    nohup sh ${SHELL_NAME} watch ${APP_MD5} > /dev/null 2>&1 &
    get_watch_pid
    echo "start ${APP_NAME} watch ok, pid ${PID_RET}"
  else
    echo "${APP_NAME} watch is running pid ${PID_RET}"
  fi
}

# 停止进程同时停止watch dog
stop() {
  get_watch_pid
  if [ ! -z "${PID_RET}" ];then
    kill -9 ${PID_RET}
  if [ ${?} -eq 0 ];then
    echo "stop watch ${APP_NAME} pid ${PID_RET} ok"
  else
    echo "stop watch ${APP_NAME} pid ${PID_RET} fail"
    return 1
  fi
  else
    echo "${APP_NAME} watch is not running"
  fi
  get_pid
  if [ ! -z "${PID_RET}" ];then
    switch_appdir
    stop_proc ${PID_RET}
  if [ ${?} -eq 0 ];then
    echo "stop ${APP_NAME} pid ${PID_RET} ok"
  else
    echo "stop ${APP_NAME} pid ${PID_RET} fail"
    return 1
  fi
  else
    echo "${APP_NAME} is not running"
  fi
}

# 获取进程状态
get_status() {
  get_pid
  if [ ! -z "${PID_RET}" ];then
    echo "${APP_NAME} is running pid ${PID_RET}"
  else
    echo "${APP_NAME} is not running"
  fi
  get_watch_pid
  if [ ! -z ${PID_RET} ];then
    echo "${APP_NAME} watch is running pid ${PID_RET}"
  else
    echo "${APP_NAME} watch is not running"
  fi
}

# start watch dog
watch() {
  cd ${APP_DIR}
  while :
  do
    sleep ${CHECK_INTERVAL_SECONDS}
    get_pid
    if [ -z "${PID_RET}" ];then
      echo "${APP_NAME} is not running now start it"
      start
    fi
  done
}

case "$1" in
    start)
        start
        ;;
    stop)
        stop
        ;;
    restart)
        stop
        start
        ;;
    status)
        get_status
        ;;
    watch)
      echo $2
      if [ "$2" = "$APP_MD5" ];then
      watch
    fi
      ;;
    *)
    echo "Usage:sh $0 {start|stop|status|restart}"
    exit 2
esac
