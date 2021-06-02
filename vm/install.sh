#!/bin/bash
SHELL_DIR=$(cd "$(dirname "$0")";pwd)
SBIN_DIR=/sbin/vmpd
#INSTALL_DIR="\/home\/"
SERVICE_DIR="/usr/lib/systemd/system"
VM_DAEMON="vm_daemon"
#echo "$SHELL_DIR/config"

source "$SHELL_DIR/config"

function check_env(){
    if [ -f "$SBIN_DIR" ]; then
        echo "$SBIN_DIR file exit"
        exit 0
    fi
    if [ ! -x "$INSTALL_DIR" ]; then 
        mkdir "$INSTALL_DIR"
    fi
    if [ ! -x "$INSTALL_DIR$VM_DAEMON" ]; then
        mkdir "$INSTALL_DIR$VM_DAEMON"
    fi
    if [ ! -x "$SHELL_DIR/$VM_DAEMON/work_space" ]; then
        mkdir "$SHELL_DIR/$VM_DAEMON/work_space"
    fi
}

function config_py(){
    local path=$SHELL_DIR/$VM_DAEMON"/bin/config.py"
    local result=$(cat ${path} | sed -n "/^WORK_DIR*/"p)
    if [ -z "$result" ]; then
        sed -i "2a\WORK_DIR = \'$INSTALL_DIR$VM_DAEMON/\'" "$path"
    else
        sed -i -E "s#WORKER_DIR.*#WORKER_DIR = \'$INSTALL_DIR$VM_DAEMON/\'#g" "$path"
    fi

    local num=$(cat "$path" | sed -n '/^VM_NUM*/'p) 
    if [ -z "$num" ]; then
        sed -i "3a\VM_NUM = $VM_NUM" "$path"
    else
        sed -i -E "s#VM_NUM.*#VM_NUM = $VM_NUM#g" "$path"
    fi

    local cpu=$(cat "$path" | sed -n '/^VM_CPU*/'p)
    if [ -z "$cpu" ]; then
        sed -i "3a\VM_CPU = $VM_CPU" "$path"
    else
        sed -i -E "s#VM_CPU.*#VM_CPU = $VM_CPU#g" "$path"
    fi

    local mem=$(cat "$path" | sed -n '/^VM_MEM*/'p)
    if [ -z "$mem" ]; then
        sed -i "3a\VM_MEM = $VM_MEM" "$path"
    else
        sed -i -E "s#VM_MEM.*#VM_MEM = $VM_MEM#g" "$path"
    fi

    local port=$(cat "$path" | sed -n '/^SERVER_PORT*/'p)
    if [ -z "$port" ]; then
        sed -i "3a\SERVER_PORT = $SERVER_PORT" "$path"
    else
        sed -i -E "s#SERVER_PORT.*#SERVER_PORT = $SERVER_PORT#g" "$path"
    fi
}

function clean_file(){
    systemctl disable vmpd.service 1>/dev/null 2>&1 
    if [ -f "$SBIN_DIR" ]; then
        unlink $SBIN_DIR
    fi
    if [ -d "$INSTALL_DIR$VM_DAEMON" ]; then
        rm -rf $INSTALL_DIR$VM_DAEMON/*
    fi
    if [ -f "$SERVICE_DIR/vmpd.service" ]; then
        rm -f $SERVICE_DIR/vmpd.service
    fi
}

function install(){
    check_env
    config_py
    cp -rf $SHELL_DIR/$VM_DAEMON/* $INSTALL_DIR$VM_DAEMON/
    if [ ! -f "$INSTALL_DIR$VM_DAEMON/watch_dog/watch_dog.sh" ]; then
        echo "watch_dog.sh not exist"
        clean_file
        exit 0
    fi    
    ln -s $INSTALL_DIR$VM_DAEMON/watch_dog/watch_dog.sh $SBIN_DIR

    if [ ! -f "$SHELL_DIR/vmpd.service" ]; then
        echo "vmpd.service not exist"
        clean_file
        exit 0
    fi
    cp "$SHELL_DIR/vmpd.service" "$SERVICE_DIR/"
    chmod 754 "$SERVICE_DIR/vmpd.service"
    systemctl daemon-reload
}

function uninstall(){
    systemctl stop vmpd.service 1>/dev/null 2>&1 
    clean_file
}

case "$1" in
    install)
        install
        ;;
    uninstall)
        uninstall
        ;;
    *)
    echo "Usage:sh $0 {install|uninstall}"
    exit 2
esac
