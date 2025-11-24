# Kubernetes Provisioning & Setup
# Requirements
1. Windows 11 Host
2. VMware Workstation Pro (17)
3. Ubuntu Server 24.04.3 LTS iso
4. Hardware support for 4 vCPU cores & 8/16 GB RAM
# Provisioning
1. Typical Installation
2. Installer disc image file (iso) -> select Ubuntu Server 24.04.3
3. Name VM: KubernetesResearch
4. Set Disc Capacity = 80 GB (or more)
5. Customize Hardware:
	1. Memory: Set 16384 MB / 16 GB, minimum of 8192 MB / 8 GB memory
	2. Processors: 1 processor with 4 cores per processor.
	3. Do not enable Virtualization Intel VT-x/EPT or AMD-V/RVI (no need)
	4. Do not Virtualize CPU performance counters (no need)
	5. Set network to NAT / Bridged, needed for initial setup. Will be changed before exploitation
![vmware workstation pro VM settings](https://github.com/JRiesterer/kubelab/blob/master/ref/vmsettings.png)
6. Run the VM to Manually install Ubuntu
	1. Select "Try or Install Ubuntu Server"
	2. Select language (English)
	3. Install base (non-minimized) Ubuntu Server without Third-Party Drivers
	4. Configure your network (likely ens33)
	5. Do not configure a proxy
	6. Use the default mirror location: "http://us.archive.ubuntu.com/ubuntu"
	7. Use entire disk for install
		1. Do not set up the disk as an LVM group. This will simplify our use of snapshots and 80 GB is more than enough to house our lab environment. We should not need to increase the size of the partition.
	8. Use standard partition settings (ext4)
	9. Fill out profile information
		1. Your name: dev
		2. Your servers name: kubelab
		3. Pick a username: labadmin
		4. Choose and confirm a password: labadmin
	10. Skip Ubuntu Pro
	11. Install OpenSSH Server
		1. Enable Install OpenSSH Server
		2. Allow password authentication over SSH
		3. Do not import an SSH key
	12. Skip / Deselect all "Featured Server Snaps"
		1. packages / installation / setup will be handled in the provisioning script
	13. Select "Done" and wait for installation/setup to complete
	14. Once completed select "I Finished Installing" in VMware Workstation
	15. In the VM, click "Reboot Now"
	16. You may see an error that installation media has not been removed, wait a few seconds and hit enter to reboot. VMware Workstation should remove the installation media after you clicked "I Finished Installing" but it has a small delay on when it updates.
# Setup
Ensure that your VM is operational (turn it off and back on)
Attempt to login to ensure that your account works and that you know your password

1. Save an initial, clean snapshot to use if installation fails / to test your setup
	1. Shut down the VM completely
	2. VM > Snapshot > Take Snapshot: Name it kubelab_base_clean
2. Run the following commands to reach a checkpoint location
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install open-vm-tools open-vm-tools-desktop -y
sudo sytemctl enable ssh
sudo systemctl start ssh
sudo reboot
```
3. Save a new snapshot (avoids wasting time and allows copy-paste)
4. Run the following:
```bash
git clone https://github.com/JRiesterer/kubelab.git
cd kubelab
chmod +x *.sh
```
5. Finish setup with `sudo ./setup.sh` 
6. Check `docker` group status (`groups`, `newgrp docker`)
7. Check system security settings with `sudo kubelab-security-check`

# GOAT Finalization
Run the setup script for kubernetes-goat
```bash
cd /opt/kubelab/kubernetes-goat/
bash setup-kubernetes-goat.sh
```

Wait for the pods to be built and come online:
`kubectl get pods`
![[Pasted image 20251019141323.png]]

Enable access by port-forwarding the pods using:
`bash access-kubernetes-goat.sh`
Ensure you are in the `/opt/kubelab/kubernetes-goat/` directory

Snapshot taken "kubelab_goat_exposed"
Shut down VM, put in Bridged mode to enable access to exposed ports

VM > Network Adapter > Bridged
Get IP using `ifconfig` or `ip addr`
Connect to services using that IP address and relevant ports from the host machine.
`IP: 192.168.1.31` for example