sudo scripts/rpc.py bdev_nvme_attach_controller -b nvme0 -t PCIe -a 0000:e4:00.0
sudo scripts/rpc.py bdev_nvme_attach_controller -b nvme1 -t PCIe -a 0000:e5:00.0
sudo scripts/rpc.py bdev_ftl_create -b FTL0 -d nvme0n1 -c nvme1n1 --overprovisioning 18 --l2p-dram-limit 2048 --core-mask 0x3
