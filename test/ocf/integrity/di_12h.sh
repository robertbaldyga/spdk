#!/usr/bin/env bash

if [ $# -ne 1 ]
then 
    echo >&2 "There should be cache mode passed as the script's argument."
    exit 1
fi


curdir=$(dirname $(readlink -f "${BASH_SOURCE[0]}"))
rootdir=$(readlink -f $curdir/../../..)
source $rootdir/test/ocf/common.sh
source $rootdir/scripts/common.sh
source $rootdir/test/common/autotest_common.sh
rpc_py=$rootdir/scripts/rpc.py

# Setup NVMe devices
$rootdir/scripts/setup.sh
prepare_nvme_config

# Start SPDK app
start_spdk "$curdir/config"

# Create partitions for cache and core device
create_partitions Nvme0n1 1 100
create_partitions Nvme1n1 1 150

# Create CAS device
$rpc_py bdev_ocf_create cas_dev $1 Nvme0n1p0 Nvme1n1p0 --create --force

# Save current config and stop SPDK app
save_and_clean_bdev_config
stop_spdk

# Run fio to fill cache space
fio_bdev $curdir/fill.fio --aux-path=/tmp/ --ioengine=spdk_bdev --spdk_json_conf="$curdir/config"

# Check if cache is filled properly
start_spdk "$curdir/config"

occupancy=$(get_stat cas_dev usage occupancy percentage)
if (( $(echo "100-$occupancy > 5" |bc -l) ))
then
    echo >&2 "Cache is not filled properly. Occupancy=$occupancy"
    exit 1
fi

stop_spdk

# Run fio with data integrity verify option for 12h
fio_bdev $curdir/di_12h.fio --aux-path=/tmp/ --ioengine=spdk_bdev --spdk_json_conf="$curdir/config"

