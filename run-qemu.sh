qemu-system-x86_64 -m 16384 -smp 16 -cpu host -enable-kvm \
   -hda /home/weixiangjiang/images/u20s.qcow2 \
   -netdev user,id=net0,hostfwd=tcp::32001-:22 \
   -device e1000,netdev=net0 -display none -vga std \
   -daemonize -pidfile /var/run/qemu_0 \
   -object memory-backend-file,id=mem,size=16G,mem-path=/dev/hugepages,share=on \
   -numa node,memdev=mem \
   -chardev socket,id=char0,path=/var/tmp/vhost.1 \
   -device vhost-user-blk-pci,num-queues=8,id=blk0,chardev=char0 \
