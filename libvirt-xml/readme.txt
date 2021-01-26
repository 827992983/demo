做镜像：
qemu-img create -f qcow2 uos20arm64 20G
qemu-img create -f qcow2 uos20arm64 .swp 1G
 
# 替换下面命令中的<debian>为正确的iso名称
virt-install --connect=qemu:///system --name=debianx64 --arch=x86_64 --ram=1024 --vcpus=1 --os-type=linux --hvm --virt-type kvm --cdrom=/image/debian/<debian>.iso --disk path=/image/debian/debianx64,bus=virtio,cache=none,format=qcow2 --disk path=/image/debian/debianx64.swp,bus=virtio,cache=none,format=qcow2 --network bridge=virbr0,model=virtio --accelerate --graphics vnc,listen=0.0.0.0

我的命令：
virt-install --connect=qemu:///system --name=uos20arm64 --arch=aarch64 --ram=4096 --vcpus=2 --os-type=linux --hvm --virt-type kvm --cdrom=/pitrix/iso/uniontechos-desktop-20-professional-1030-fix_arm64.iso --disk path=/pitrix/vms/test/uos20arm64,bus=virtio,cache=none,format=qcow2 --network bridge=virbr0,model=virtio --accelerate --graphics vnc,listen=0.0.0.0
