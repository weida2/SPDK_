sudo HUGEMEM=40960 ./scripts/setup.sh
sudo build/bin/vhost -S /var/tmp -m 0x3 2>&1 | tee trace_vhost.log
