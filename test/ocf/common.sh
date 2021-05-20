#!/usr/bin/env bash

source $rootdir/test/common/autotest_common.sh
rpc_py=$rootdir/scripts/rpc.py
spdk_pid='?'

function start_spdk() {
    $SPDK_BIN_DIR/spdk_tgt --json $1 &
    spdk_pid=$!
    trap 'killprocess $spdk_pid; exit 1' SIGINT SIGTERM EXIT
    waitforlisten $spdk_pid
}

function stop_spdk() {
    killprocess $spdk_pid
    trap - SIGINT SIGTERM EXIT
}

function create_partitions() {
    # $1 - device name
    # $2 - number of partitions
    # $3 - size of the partition

    $rpc_py bdev_split_create $1 $2 -s $3
}

function prepare_nvme_config() { 
	jq . <<- CONFIG > "$curdir/config"
		{"subsystems":[
		$($rootdir/scripts/gen_nvme.sh)
		]}
	CONFIG
}

function save_and_clean_bdev_config() {
    $rpc_py save_config > "$curdir/config"
    echo $(cat "$curdir/config" | jq 'del(.subsystems[] | select(.subsystem != "bdev"))' | jq 'del(.subsystems[] | .config[] | select(.method != "bdev_split_create" and .method != "bdev_nvme_attach_controller" and .method != "bdev_ocf_create"))') > "$curdir/config"
}

function remove_config() {
    rm -f $curdir/config
}

function clear_nvme() {
    mapfile -t bdf < <(get_first_nvme_bdf)

    # Clear metadata on NVMe device
    $rootdir/scripts/setup.sh reset

    name=$(get_nvme_name_from_bdf "${bdf[0]}")
    mountpoints=$(lsblk /dev/$name --output MOUNTPOINT -n | wc -w)
    if [ "$mountpoints" != "0" ]; then
      exit 1
    fi
    dd if=/dev/zero of=/dev/$name bs=1M count=1000 oflag=direct
    $rootdir/scripts/setup.sh
}

function get_cache_mode() {
    # $1 - CAS device name
    query=".[] | select(.name==\"$1\").driver_specific.mode"
    mode=$($rpc_py bdev_get_bdevs | jq "$query")
    echo $mode
}

function get_cache_line_size() {
    # $1 - CAS device name
    query=".[] | select(.name==\"$1\").driver_specific.cache_line_size"
    line_size=$($rpc_py bdev_get_bdevs | jq "$query")
    echo $line_size
}

function get_stat() {
    # $1 - CAS device name
    # $2 - stat section
    # $3 - stat name
    # $4 - return type (count/percentage/units)
    echo $($rpc_py bdev_ocf_get_stats "$1" | jq ".$2.$3.$4" | sed 's/^\"\(.*\)\"$/\1/')
}

function get_stat_json() {
    # $1 - CAS device name
    echo $($rpc_py bdev_ocf_get_stats "$1")
}
