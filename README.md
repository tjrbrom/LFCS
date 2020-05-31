# LFCS
Notes on the Linux Foundation Certified System Admin cert

Linux FS Hierarchy
/usr:	it’s like the “program files” on windows, the binaries reside there
/boot:	linux kernel is here
/dev: 	device files are here ex. sda (hard disk)
/etc:	config files
/home: user home directories
/opt: 	for applications, like databases
/proc: 	interface to the linux kernel, useful for providing system information
/root:	home for root user
/run: 	temporary stuff
/srv: 	stores info about services
/sys:	hardware info
/tmp:	tmp files
/var:	a wide variety of files, like the log files in /var/log

Directories
mkdir -p newdir1/newdir2 (it will create the directories recursively)

Absolute & Relative paths
cp /dir1/file2 (the first slash means dir1 from home dir)
rm \* (the backslash escapes the wildcard, so it will interpret it as a file with name “*”)

Hard & Symbolic links
Hard links cannot be used across devices/partitions, and cannot point to dirs
ls -li (will display the inode number of the links)
ln -s (to create sym link)

Finding files with find
mkdir /root/amy; find / -user amy -exec cp {} /root/amy \;
find /etc -exec grep -l amy {} \; -exec cp {} root/amy/ \; 2>/dev/null
find /etc -name ‘*’ -type f | xargs grep “127.0.0.1”

Tar archive
tar -cvf my_archive.tar /home (c is for create, v is for verbose, f is specifying the archive file)
tar -xvf my_archive -C /tmp (x for extracting, -C to extract to /tmp)
tar -tvf my_archive (t shows the contents of an archive)
tar czvf /tmp/comp.tgz /home (z for compressed archive)
use -z for gzip compression, -j for bzip compression

dd if=/def/zero of=bigfile1 bs=1M count=1024 (will create a one gigabyte file of zeroes)
gzip bigfile1 (will replace it with bigfile1.gz)
gunzip bigfile1.gz (uncompress)
(zip, gzip, bzip do the same thing with different performance and size result)
file bigfile1 (analises the metadata to provide information)

Vi
i for insert mode
Esc to get back to cmd mode
:w to save
o for open a new line
v for visual, d for delete, p for paste, y for copy
dd for deleting a line
u for undo
:q! for exit
/ for searching
gg to go the the start
:% for substitute (search-replace) ex. :%s/are/ARE/g (g for replace all)
:wq! for write and quit

Grep
grep -i amy /etc/* 2>/dev/null (i for case insensitive)
ps aux | grep ssh | grep -v grep (v for exclude lines with the word “grep”)
-R for recursive, -l for file name only, -A3 for “3 lines after”, -B3 for “3 lines before”

Regex
. any one character
^ begin of line
$ end of line
\< begin of word
\> end of word
\A start of a file
\Z end of a file
{n} exact n times
{n,} min n times
{,n} n times max
{n,o} between n and o times
* zero or more times
+ one or more times
? zero or one time

Text Processing Utils
cut : filter output from text file
sort : sort files, often used in pipes
tr : translates upper to lower
awk : search for patterns
sed : editor to batch-modify text files

cut -d : -f 1 /etc/passwd (fields that are delimited with a colon, -f for filtering)
echo hello | tr [:lower:] [:upper:] (lower to upper)
sed -n 5p /etc/passwd (prints the fifth line)
sed -i s/how/HOW/g (substitutes how with HOW, -i to immediately write changes)
sed -i -e ‘2d’ myfile (deletes line 2 from myfile)
awk -F : ‘{ print $4 }’ /etc/passwd (prints fourth column)
awk -F : ‘/amy/ { print $4 }’ /etc/passwd (prints fourth column for line with text amy)
sort -n (n for numeric)

Connecting to a server
su – (opens a root shell, dollar sign changes to #)
su (prompts for root password, enters the root shell, but doesn’t open a new login shell)
exit goes back
su – (this again opens a login shell)
su – amy (logs as user amy)
usermod -aG wheel user (adds user to the group wheel, needs to relog for changes to take effect) (by adding user to group wheel, he now has admin privileges)
sudo useradd lori
grep lori /etc/passwd (shows that lori has been created)
sudo -i (opens root shell (#))

sudo visudo (opens the sudo command with root privileges)
sudo passwd lori (sets a password for lori)

cd /etc/sudoers.d (inside here you can create snapin files)

Virtual terminal
chvt (to login to a virtual shell)

SSH
cd .ssh/ (contains know_hosts file)
ssh-keygen
ssh-copy-id 192.168.1.10
scp /etc/hosts 192.168.1.10:/tmp

Some basic Bash Shell
sort < /etc/services (the < is standard input)
ls > myfile (the > is standard output)
who > myfile (overwrites myfile contents with who output)
ls >> myfile (appends myfile contents with ls output)
grep -R root /etc &>~/myfile (redirects stdout as well as error output to myfile)
pas aux | tee psfile | grep ssh (tee combines writing output somewhere and at the sime time, redirecting it as input somewhere else)

Working with history
history
!i (repeats the last command started with i)
!164 (repeats the command number 164)

Alias
alias help=man

Bash startup files
/etc/environment : contains a list of variables, and it’s processed first when starting bash
/etc/profile : executed when users login
/etc/profile.d/ : contains snap ins
~/.bash_profile : used as a user specific version
~/.bash_logout : processed when a user logs out
/etc/bashrc : processed every time a subshell starts
~/.bashrc : user-specific file may be used

User & Group Management
id amy (gives information about user amy)
useradd -c “the boss” -G wheel -s /bin/passwd bob 
(this user will have the common field “the boss”, with a default shell to /bin/passwd)
groupadd testgroup
usermod -aG testgroup amy (with -G amy becomes now a member of testgroup, -a avoids overwriting previous group memberships)
userdel bob (deletes bob)
groupdel testgroup (deletes the group)
useradd -D (specifies default settings, /etc/login.defs default config file)
/etc/skel (this is a skeleton dir, everything I put in there will be copied to the user home directory)
/etc/shadow (shows config for users)
passwd -S linda (status for the user)
passwd -uf linda (unlock pass with u, force with f)
passwd linda (changes pass)
echo password | passwd --stdin linda (stdin allows passwd to receive the pass from a pipe)
change linda (configure linda)
grep linda /etc/shadow (to check the changes)
/etc/group
/etc/passwd
vipw (temp file to apply changes to user settings)
vigr (same for group editing)


Managing sessions
loginctl list-sessions (list of open sessions)
loginctl session-status 153 (specified session status)
loginctl kill-session 2 (session num 2 is gone)

Permissions
mkdir -p /data/account
cd /data
chgrp account account (first account is the group, second account is the name of the item where I want to change ownership, the goupr ownership will change from root to account)
chmod 770 account/ (user owner 7, group owner 7, others 0)
chmod g-w account/ (removed write permission from group)
chmod g+w account/ (added back)
su – anna (login with user anna)
cd /data/account/
touch anna1
after creating a file, anna is the user and the group owner
chown anna account (makes user anna the user owner of dir account)
chown anna:account file2 (we can also change user and group ownership like that)
chmod u-w,g+w file2 (user anna has read, group account has read/write) 
anna can’t write there, because she has only read perm as the user owner, and group permission of write doesn’t apply to the user owner, although she is part of the group
chmod u+w file2 (anna now has write permission, like the account group)

Advanced Permissions
special permissions are: suid(4), sgid(2), sticky(1)
Using suid set, you run on the file as user owner
With sgid set, you run on a file as group owner, and on dir as group owner
Last, with sticky, you can delete dir if you are the owner
chmod 4770 (the 4 is the SUID special permission)
find / -perm /4000 (finds permission with per mask 4000, slash 4 means we need a 4 on the first pos, and zeroes that the others don’t matter) (4 refers to the special permission position, so the find is going to give all files that have SUID special permission)
chmod g+s /data/account (sgid, applies special group ownership to dir, so that users of files on the same dir that belong to different groups, can share group dir permissions)
chmod +t /data/account (will set sticky special permission on the account dir, so that a user can delete files, only if he is the owner of it, or the owner of the dir that includes it)

umask (reads current umask)
umask 022 (sets default permissions on files to 644, default is 666)
umask 027 (sets default permissions on files to 750, default is 777)


MBR & GPT Partitions
lsblk (list of disks)
fdisk /dev/sdb (partitioning sdb)
	m for help, p for print, n for new partition, w to write
partprobe (to save any partition changes)
/proc/partitions (file of all partitions)
gdisk /dev/sdb (for GPT partitioning)

Creating file systems
mkfs.xfs /dev/sdb1 (creates a .xfs file system)


Mounting fs
Connecting a filesystem to a partition is called mounting.
mount /dev/sda1 /mnt (mounts sda1 to mnt dir which is used for temp mounts)
umount /mnt (we need to be out of mnt to unmount)
findmnt (not sure…)

Network Configuration
ip a (information like in ifconfig)
ip route show (shows routes)
/etc/resolv.conf (contains mapping of names and ip addresses)
ip route del default via 192.168… (deletes default route with corresponding ip)
ip route add default via 192.168… (adds default route with corresponding ip)
ip addr del dev ens33 192.168…/24 (removes the ip address)
dhclient (reaches to dhcp to reobtain the ipv4 addr)
ip addr add dev ens33 10.0.0.10/24 (instead of using dhcp, adds an ip manualy)

Network device names
p<port>p<slot> (PCI, PCI port)
em123 (Ethernet motherboard portnumber)
eno123 (EtherNet onboard)
eth0 (in other cases)

Hostnames
hostname -I (shows all ips assigned to this host)
/etc/hostname
hostnamectl (control the hostname)
hostnamectl status
uname -a (kernel name, version)
hostnamectl set-hostname centos.example.com (logout and login to see change)

/etc/hosts (Instead of dns, we can use this)

/etc/nsswitch.conf (defines order of information lookup)

Network Tools
ping -f google.com (ping flood)
ping -f -s 4096 ubuntu (sends 4 kilobytes to the ubuntu machine)
netstat -tulpen | less (overview of everything that is listening)
ss -tuna | less (same things)
yum install nmap
nmap 192.168.4.2 (connects and does a port scan)
dig nu.nl (dns info)

Managing Time
date -s 14:53 (updates system time)
hwclock -w (system clock to hardware clock)
hwclock -s (the opposite)
timedatectl (sets time, timezone, status etc.)
timedatectl list-timezones
timedatectl set-timezone Europe/Amsterdam

NTP
timedatctl status (among other info, shows if we use NTP)
chronyc sources (NTP servers information)
ntpdate pool.ntp.org (sets the date from an NTP server at the specified uri)

SYSTEMD
systemd manages everything (units)
/usr/lib/systemd/system (default units)
/etc/systemd (custom units)
systemctl -t help (list of all unit types)
systemctl list-unit-files
systemctl list-units (all units that have been started, active, waiting, failed)
yum install vsftpd
systemctl status vsftpd
systemctl enable vsftpd
systemctl start vsftpd
systemctl disable vsftpd
systemctl stop vsftpd
systemctl cat vsftpd.service
systemctl show vsftpd.service
systemctl edit vsftpd.service
daemon-reload (to load edit changes)
systemctl start vsftpd.service

.target is a group of services
 
isolate switches between targets

Shell Jobs
dd if=/dev/zero of=/dev/null (copies block devices, if input, of output, does nothing)
^Z to stop the job temporarily
bg
dd if=/dev/zero of=/dev/null & (adding & sends job to the background)
jobs (all background jobs)
bg (will move a job to the background)
fg (runs the last job in the foreground)
fg 2 (same for second one)
Ctrl+C to get rid of it

top
top (shows all processes)
top -u user (top for a specific user)
press f while in top, and select what properties to display

ps
ps aux (processes)
ps -ef
ps fax
ps aux --sort pmem (sorting by memory usage)
systemctl isolate multi-user.target (goes into this target, log in as root, run ps aux --sort pmem, and see that without UI processes running, more memory is free)

top
press r (brings PID to renice(adjust current priority))
press Enter and set it to a num from -20 up to 19
q
renice -n 5 12230 (resets priority of example id 12230 to 5)
nice (should check it, similar to renice)

kill
ps aux | grep dd
kill -9 12228 (kills the dd job with process id 12228, -9 will force kill)
kilall dd (will kill all dd processes)

Managing Libraries/Packages
ldd /usr/bin/passwd (all used libraries)
yum repolist (shows available repos)
/etc/yum.repos.d (config files of repos)
yum search nmap (searches in the repositories)
yum install nmap-frontend
yum list installed
yum remove nmap
yum update (updates the entire system, if updates are available on the repo)
yum provides semanage (downloads a db file list and searches for semanage)
yum groups list
yum groups install “Compute Node” (example, installs all packages in this group)
yum history undo 6 (reverts particular change)

apt is Ubuntu-equivalent of yum
/etc/apt/sources.list
apt search nmap
apt install nmap
apt remove nmap
apt autoremove (removes all unneeded)

RPM (redhat package manager, deprecated)
 

Task Scheduling
systemctl status crond (the cron daemon running by default)
/etc/crontab (specification, not generally used)
crontab -e (opens editor to specify what to do, example: 5 * * * * logger hello)
/etc/cron.d
/var/log/messages (can check cron logs here)

Timers
/usr/lib/systemd/system (contains timers)
systemctl status fstrim.timer
systemctl enable --now fstrim.timer (--now enables and starts at the same time)

systemctl status atd
at 12:12 (runs something only once, at the specified time)
atq (shows what is waiting to be executed)
atrm 1 (removes it)

Journalctl
journalctl (everything happened since boot)
journalctl -u (logs for these units)
journalctl -u sshd (shows logs for specific unit)
systemctl status sshd (the same info)
journalctl --dmesg (reads the kernel ring buffer messages)
journalctl -u crond --since yesterday -p info (all logs with status info since yest)

Rsyslog
/etc/rsyslog.*
cat and check the rsyslog.conf properties RULES part
/var/log/messages (all log messages here)



Shell Basics
# !/bin/bash (this explains that the script is of type bash)
echo what dir do you want to go to?
read DIR (stops and waits for user input, stores it to var DIR)
cd $DIR (refers to the value of the var we defined)
pwd
ls
exit 0 (the 0 informs the parent shell, that everything is fine)

if [ -z $1 ] (if the first argument is empty)
then
	echo you have do provide argument
	exit 6
fi
echo the argument is $1




COUNTER=$1
COUNTER=$(( COUNTER * 60 ))
minusone() {
	COUNTER=$(( COUNTER - 1 ))
	sleep 1
}
while [ $COUNTER -gt 0 ] (while greater than 0)
do
	echo you still have $COUNTER seconds left
	minusone
done
[ $COUNTER = 0 ] && echo time is up && minusone (if c = 0 then echo else minusone)
[ $COUNTER = “-1” ] && echo you now are one second late && minusone
while true
do
	echo you are now ${COUNTER#-} seconds late (we remove the minus)
	minusone
done



Ulimit
/etc/security/limits.conf

PAM
pluggable authentication modules
ldd $(which passwd)
ldd $(which su)
/etc/pam.d (if the configuration is PAM aware, it will check this file for config)
/lib64/security (PAM libraries)
/etc/securetty (defines terminals that are secure for root to log in)
chvt 3 (can’t login as root)
/etc/pam.d/login (if you go here and comment out the first line, root can now login inside chvt 3)
/etc/pam.d/su (if we add this line here, then go to chvt 3 and login as some user, then run su -, it won’t work)

Secure mount options
findmnt (shows some devices)
/etc/fstab (replace defaults option with noexec, for example on /mydata mount)
mount -o remount, rw /mydata/
mount | grep mydata (we see that noexec is set. We can’t execute scripts anymore in mydata, even if chmod +x is issued)

Configure Networking
ip link show (shows active network cards)
/etc/sysconfig/network-scripts (parameters for these network cards)
systemctl status NetworkManager (manages the config)
systemctl stop NetworkManager (nothing happens, just the config utilities stop)
systemctl status network (logs show what it is doing, responsible for activating network interfaces)
nmtui (configures anything, must have NetworkManager  running, so start it again)
man nmcli-examples
Network conf in Ubuntu
/etc/netplan (check some .yaml files there for configuration example)
netplan apply (applies the configuration)
ip a (to check wether it was applied)
ip route show (routing table)

networkd
yum install systemd-networkd systemd-resolved
systemctl disable --now NetworkManager
systemctl enable systemd-networkd
systemctl enable systemd-resolved
rm /etc/resolv.conf
ln -s /run/systemd/resolve/resolve.conf /etc/resolv.conf
mkdir /etc/systemd/network
cd /etc/systemd/network
ip link show (current network interfaces)
vim 10-static-ens33.network
[Match]
Name=ens33
[Network]
Address=192.168.4.229/24
Gateway=192.168.4.2
DNS=127.0.0.1

reboot
ip a (we can see that the ip is available)
systemctl status systemd-networkd 
(if it’s inactive, run the below commands)
systemctl stop systemd-networkd
systemctl start systemd-networkd

/etc/resolv.conf
systemctl status named
cat /etc/resolv.conf

Systemd units
systemctl cat httpd.service (config for httpd service)
systemctl show httpd.service
systemctl cat sshd.service
systemctl edit httpd.service
systemctl restart httpd
systemctl daemon-reload (if the change is not seen, maybe because service was in use)
systemctl status -l httpd
killall httpd

Systemd Sockets
cd /etc/systemd/network
systemctl list-unit-finles | grep socket
systemctl list-unit-files | grep sshd
systemctl enable sshd.socket
systemctl enable sshd.service
systemctl stop sshd.service
systemctl status sshd.service
systemctl status sshd.socket
systemctl start sshd.socket
ssh localhost
Systemd Timers
systemctl list-unit-files | grep timer
systemctl list-unit-files | grep systemd-tmpfiles-clean
systemctl cat systemd-tmpfiles-clean.timer
systemctl cat systemd-tmpfiles-clean.service
systemctl cat fstrim.service
systemctl cat fstrim.timer
systemctl status fstrim.timer
systemctl enable --now fstrim.timer

Systemd Cgroups
Used for putting hardware limitations on resources
/etc/systemd/system

touch stress.service
[Unit]
Description=Create some stress
[Service]
Type=simple
ExecStart=/usr/bin/dd if=/dev/zero of=/dev/null
CPUShares=1024

touch stress2.service
[Unit]
Description=Create some stress
[Service]
Type=simple
ExecStart=/usr/bin/dd if=/dev/zero of=/dev/null
CPUShares=512

systemctl daemon-reload
systemctl start stress.service
systemctl start stress2.service
After that, we ca run top and check the result

Systemd unit dependencies
systemctl start sshd (will fail)
systemctl status sshd -l (shows a dependency failure)
systemctl cat sshd.service (shows a Requisite of vsftpd.service)
vim /usr/lib/systemd/system/sshd.service (go there and comment out (#) the “Requisite” line)
systemctl daemon-reload
systemctl start sshd.service

Systemd self-healing
systemctl edit vsftpd.service
[Service]
Restart=always
RestartSec=3

(after stopped/killed, will restart automatically after 3 seconds)

rsyslogd
/etc/rsyslog/rsyslog.conf (settings are here)
/etc/rsyslog.d (snap-ins here, these files end in .conf)
After any change, run systemctl restart rsyslog
Log Rotation
Ensures that log files rotate based on certain criteria
/var/log
/etc/logrotate.conf (default config file)
/etc/logrotate.d (snap-ins)
/etc/cron.daily/ (here is the cronjob for logrotate)

systemd-journald persistent
/etc/systemd/journald.conf
mkdir /var/log/journal
systemctl force-reload systemd-journald
reboot
uptime
journalctl (logs show proof that the journal is now persistent)

Kernel management
lsmod (kernel modules and dependencies)
modinfo e1000 (info on network card e1000)
lspci -k (lists the pci bus and kernel module associations)
cd /etc/modprobe.d
vim mlx4.conf
modprobe ext4 (loads kernel modules)
lsmod | grep ext4
modprobe -r ext4 (unloads kernel modules)

/proc (fs that provides interface to linux kernel)
mount | grep proc
/proc/sys (kernel tunables)
cd /proc/sys/net
cd /ipv6/conf/all (all network cards, conf files for ipv6)
echo 1 > disable_ipv6 (ips are gone)
vim /etc/sysctl.conf (go here to make the above setting persistent):
net.ipv6.conf.all.disable_ipv6 = 1 (after reboot, this takes effect)
sysctl -a  | less
sysctl -a  | grep icmp

Boot
systemctl poweroff (shutsdown all services and the machine)
vim /etc/default/grub (basic boot options for grub)
GRUB_CMDLINE_LINUX=… (remove the “rhgb quiet”)

vim /boot/grub2/grub.cfg (do not edit this file)
grub2-mkconfig -o /boot/grub2/grub.cfg
reboot
the system will now start without graphical boot (rhgb and quiet where removed)
swap systemd.unit=rescue.target
Ctrl+x

Enter GRUB boot loader again, and press E for edit mode
remove rhgb and quiet and type systemd.unit=emergency.target (all this is runtime only)
Ctrl+x
Ctrl+D to continue after adding root password
vim /etc/fstab (remove the last wrong line that caused the problem)
vim /etc/config/selinux (SELINUX=disabled, for now)
Enter GRUB boot loader again, and press E for edit mode
remove rhgb and quiet and add rd.break (to not require the root password)
Ctrl+x
mount (check the info, /sysroot says ro (read only) )
mount -o remount,rw /sysroot (now becomes rw, so we can reset the password)
chroot /sysroot/ (will make sysroot our actual root dir)
passwd (to enter the new root passwd
exit
poweroff

Firewall
firewall-cmd --list-all (lists all configuration)
firewall-cmd --get-services (all available services)
firewall-cmd --add-service http (adds it to the config)
firewall-cmd --reload (http goes away, because it was not persisted)
firewall-cmd --add-service http --permanent (adds it permanently, but not to runtime, so run reload  next)
firewall-cmd --reload
cd /usr/lib/firewalld/services (services as xml files)
vim ftp.xml
cp ssh.xml /etc/firewalld/services/sander.xml
vim /etc/firewalld/services/sander.xml (add some names and a port)
firewall-cmd --get-services (new service not showing up yet)
firewall-cmd --reload (done, we can see it now)
firewall-cmd --add-service sander --permanent
firewall-cmd --help | grep forward
firewall-cmd --add-port=port=2222:proto=tcp:toport=22

UFW (ubuntu)
ufw status
iptables -L (no default firewall)
ufw allow ssh
ufw enable (to enable fw)
ufw status (ssh can be accessed fron anywhere it seems)
ufw app list (wee probably only see OpenSSH)
ufw app info OpenSSH
ufw logging on
ufw disable

ip tables
iptables -L (input, forward and output chains)
Let’s modify them to allow ssh
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -L (we can see accepting ssh traffic, the output policy is still DROP)
iptables -A OUTPUT -m state --state=ESTABLISHED,RELATED -j ACCEPT
We can see that policy is still DROP, but the state module is loaded
iptables-save command will save to /etc/sysconfig/iptables
reboot

Access Control
Check the videos again for AppArmor and SELinux

MBR Partitions
lsblk (lists block devices, partitions appear here)
fdisk /dev/sdb
n for new, p for primary, +1G for 1 gigabyte partition, w to write

Extended / Logical
cat /proc/partitions (similar to lsblk)
fdisk /dev/sda
check video for creation details
partprobe (updates /proc/partitions with the changes)

GPT Partitions
lsblk
parted /dev/sdc
print
mklabel (choose gpt type)
mkpart (Start? 0, End? 500M, I)
print
quit

gdisk /dev/sdb (same things)

SSD
for ssd fstrim needs to be active
systemctl cat fstrim.service
systemctl cat fstrim.timer (has to be enabled)

Swap Partition
free -m (shows current swap usage)
grep ctive /proc/meminfo
vmstat 2 10 (2 second intervals, 10 total times)
lsblk (create a swap partition somewhere on those)
gdisk /dev/sdc
p, n for next, 2, first sector default, second sector +1G, L, 8200 for swap, p, w
mkswap /dev/sdc2
swapon /dev/sdc2
free -m (swap space has now increased)
vim /etc/fstab (add it in this file: /dev/sdc2 swap swap defaults 0 0)
reboot

Encrypted Partition
gdisk /dec/sdc (num 3, +1G)
partprobe
cryptsetup luksFormat /dev/sdc3
cryptsetup luksOpen /dev/sdc3 secret
ll /dev/mapper
mkfx.xfs /dev/mapper/secret
mount /dev/mapper/secret /mnt (temporary mount on /mnt)
cp /etc/hosts /etc/passwd /mnt
ls /mnt
unmount /mnt
cryptsetup luksClose secret
ll /dev/mapper (“secret” no longer there)
vim /etc/fstab (for persistence, we have do add here: /dev/mapper/secret /secret xfs defaults 0 0)
vim /etc/crypttab (we specify here the name of the secret device, and the partition used: secret /dev/sdc3)
reboot

File Systems
mkfs
mkfs.ext4 /dev/sdb1
mkfs.ext4 -N 262144 /dev/sdb1 (create with more inodes)
tune2fs -l /dev/sdb1 (all properties listed)
mkfs.xfs /dev/sdb2
xfs 

Persist mounts
vim /etc/fstab (here we specify what to mount and where: /dev/sdb1 /ext4 ext4 defaults 0 0)
mkdir /ext4
mount -a  (mounts everything in fstab that hasn’t been mounted)

Label and UUID
vim /etc/fstab (/dev/sda5 /books ext4 defaults 0 0) (/dev/sda6 /videos ext4 defaults 0 0)
mkdir /books /videos
mount -a
unmount /books
fdisk /dev/sda (d for delete, 5 to delete sda5)
vim /etc/fstab (comment out /dev/sda5)
reboot
if there is a problem with sda6 while booting, we need to start troubleshooting:
fdisk -l /dev/sda (sda5 appears, but not sda6, what really happened is device name change)
	vim /etc/fstab (comment out /dev/sda6)
blkid (output shows devices with their UUID)
xfs_admin -L videos /dev/sda5 (the fs now has new label “videos”) (for label on ext file systems: tune2fs -L videos /dev/sda5)
vim /etc/fstab (instead of mounting /dev/sda5, I will now use LABEL=videos for name)

Systemd mounts
systemctl cat tmp.mount (check the options)
mount | grep tmp
systemctl enable --now tmp.mount
mount | grep tmp (tmpfs is now mounted on /tmp)
vim /etc/systemd/system/books.mount
systemctl daemon-reload
systemctl enable --now books.mount
mount | grep books
…see the videos for the rest

systemd automount
systemctl list-unit-files | grep automount
systemctl list-unit-files | grep proc-sys-fs
systemctl cat proc-sys-fs-binfmt-misc.automount (check the options there)
vim /etc/systemd/system/books.automount
[Automount]
Where=/books
systemctl daemon-reload
systemctl disable --now books.mount
systemctl enable --now books.automount
cd /books
mount | grep books

LVM logical volumes
gdisk /dev/sdb (p, n for new, default, +500M, Hex code 8e00 for LVM, w, Y)
partprobe
pvcreate /dev/sdb3 (create physical volume)
pvs (list of physical volumes)
vgcreate vgdata /dev/sdb3
vgs
vgdisplay vgdata
lvcreate -l 100M -n lvdata /dev/vgdata (creates the logical volume)
ls -l /dev/vgdata/lvdata (this is what was created)
mkfs.btrfs /dev/vgdata/lvdata
mount /dev/vgdata/lvdata /mnt
mkdir /mydata
vim /etc/fstab (add here this line: /dev/vgdata/lvdata /mydata btrfs defaults 0 0)
mount -a

LVM volumes persist
lvs
mount | grep lvdata (maybe already mounted)
ls -l /dev/mapper/vgdata-lvdata /dev/vgdata/lvdata
vim /etc/fstab (add here the following:
		/dev/vgdata/lvdata /lvdata btrfs defaults 0 0
mount -a (if we get doesn’t exist, do the following:
		mkdir /lvdata
		mount -a

LVM resize operations
If you want to resize logical volume, you may need to resize the volume group, and even the physical volume
mount | grep lv (lvext4 and lvxfs for example)
df -h | grep lv (current fs use)
vgs
lvreduce -L -100M -r /dev/vgdata/lvext4
vgs (100M of avlble space in vgdata)
lvextend -L +100M -r /dev/vgdata/lvxfs
df -h | grep lv (h for more readable)

fdisk /dev/sda (n, Command: t, 6, 8e (for LVM), w)
partprobe
lsblk | grep sda
vgextend vgdata /dev/sda6
vgs 
(we can use the available space of the group now to create logical volumes)

LVM mirrors and stripes
check videos again

LVM Snapshots
vgs (if there is not available space we should allocate some)
fdisk -l /dev/sda
(we will add a new partition, grow the volume group, and use a snapshot)
partprobe
vgextend centos_centos /dev/sda7
vgs (the free space we allocated with fdisk can me seen here)
lvcreate -s -n root-snap -L 400M /dev/mapper/centos_centos-root
lvs (we should see the root-snap)
mount /dev/centos_centos/root-snap /mnt

RAID volumes
lsblk
fdisk /dev/sdd (use all of the disk space, use type fd for RAID)
fdisk /dev/sde (the same)
lsblk
mdadm --create /dev/md0 --level=1 --raid-disks=2 /dev/sdd1 /dev/sde1
mkfs.ext4 /dev/md0
mkdir /raid
vim /etc/fstab (/dev/md0 /raid ext4 defaults 0 0)
mount -a
mdadm --detail --scan >>/etc/mdadm.conf (made the configuration persistent)
cat /proc/mdstat
mdadm --details /dev/md0

Recovering from failure
mdadm --create /dev/md1 --level=5 --raid-disks=3 --spare-devices=1 /dev/sdf /dev/sdg /dev/sdh /dev/sdi
mdadm --detail /dev/md1
mdadm --fail /dev/md1 /dev/sdg (device se to faulty, the spare takes over)
mdadm --detail /dev/md1
mdadm /dev/sdg
mdadm --remove /dev/md1 /dev/sdg (removing the faulty device)
mdadm --add /dev/md1 /dev/sdg
mdadm --detail /dev/md1

Quota
Limits space available for users on a fs
mount | grep ext4
yum install -y quota
vim /etc/fstab (instead of defaults keyword, write usrquota,grpquota, on the disk on ext4)
mount -o remount,rw /ext4
mount | grep ext4
chmod 777 /ext4
useradd lisa
quotacheck -mavug
quota -vu lisa (current quota for the user, nothing so far)
quotaon -a (activate quota on all fs tha support it)
edquota -u lisa (quota editor, set soft to 1000, hard to 1000)
su - lisa
cd /ext4
dd if=/dev/zero of=/lisafile
exit
repquota -aug

Quota on XFS
mount | grep xfs (we got /dev/mapper/vgdata-lvxfs)
vim /etc/fstab (/dev/vgdata/lvxfs /lvxfs xfs uquota 0 0)
mount -o remount /lvxfs
umount /lvxfs
mount -a
mount | grep xfs
xfs_quota -x -c ‘limit bsoft=10m bhard=20m linda’ /lvxfs
xfs_quota -x -c report /lvxfs
chmod 777 /lvxfs/
su - linda
cp /etc/a* /lvxfs
xfs_quota -x -c report /lvxfs
dd if=/dev/zero of=/lvxfs/biglinda
exit

SSH service config
vim /etc/ssh/sshd_config (check video again for specifics)

SSH public/private keys
su - anna
ssh-keygen
ssh-copy-id user@ubuntu (or wherever)
ssh user@ubuntu
cat .ssh/authorized_keys
exit
ssh user@ubuntu
ssh-agent /bin/bash
ssh-add
ssh user@ubuntu (no need for passphrases anymore!)
exit
exit
su - anna
ssh user@ubuntu (now we need a passphrase again, since anna logged out. So in the new shell, the ssh-agent needs to be started again)

scp
scp user@ubuntu:/etc/hosts . (copying hosts to .) (will get permission denied if hosts already exists) (-R for entiry dir structure)
scp user@ubuntu:/etc/hosts . -P 2022 (if connecting to ssh process running on different port, -P port)
scp user@ubuntu:/etc/hosts root@192.168.4.82:/tmp (from the one server to the other)

rsync
mkdir /root/tmp
rsync /etc/[a-d]* /tmp
ls /tmp
rsync -avz /tmp/ user@ubuntu:~ (copies tmp to user@ubuntu home)
cp /var/log/messages /tmp/cmessages
rsync -avz /tmp/ user@ubuntu:~ (-z compresses while in progress
ls -l /tmp/cmessages
rm tmp/b* -f
rsync -avz /tmp/ user@ubuntu:~
ssh user@ubuntu
ls (contents all move in user dir, the b* files that were removed still exist here)
rsync -avz --delete /tmp/ user@ubuntu:~ (dangerous, compares /tmp with the user@ubuntu home dir, and deletes everything it doesn’t find there)

ssh port forwarding
ssh -4 -L 2233:192.169.4.82:22 localhost (first the port to define, then where to go (host:port), minus 4 for ipv4 only otherwise it defaults to 6)
exit
ssh -p 2233 localhost (forwards to the remote host)

Web Service config
/etc/httpd/conf/httpd.conf (the Apache config)
check the videos again

Config Virtual hosts
vim /etc/hosts (put my own ip follow by account.example.com sales.example.com account sales)
ping account (should get response)
yum install httpd -y
cd /etc/httpd/conf
vim httpd.conf (defaults here, add after DocumentRoot:
	<Directory /web>
		Require all granted
		AllowOverride None
</Directory>
cd /etc/httpd/conf.d/
vim account.example.com.conf (config with the name of the virtual host)
<VirtualHost *:80> (binds to all ip addresses port 80)
		ServerAdmin root@account.example.com
		DocumentRoot /web/account
		ServerName account.example.com
		# ErrorLog logs/account.example.com
	</VirtualHost>
mkdir -p /web/account
mkdir -p /web/sales
vim /web/account/index.html
	Welcome to account
vim /web/sales/index.html
Welcome to sales
semanage fcontext -a -t httpd_sys_content_t “/web(/.*)?” 
ls -ldZ /web
reboot
restorecon -R /web (to apply the context to this dir)
ls -ldZ /web
cd /etc/httpd/conf.d/
cp account.example.com.conf sales.example.com.conf
vim sales.example.com.conf
	replace word account with word sales
systemctl restart httpd
yum install curl eliks -y
curl http://sales.example.com (should be getting Welcome to sales)

Web Access restriction
yum install httpd-manual -y
systemctl restart httpd
systemctl status httpd
htpasswd -c /etc/httpd/htpasswd linda
cd /etc/httpd/conf.d
vim sales.example.com.conf
<VirtualHost>…
	…	
<Directory /web/sales>
		AuthType Basic
		AuthName “whatever”
		AuthUserFile /etc/httpd/htpasswd
		Require valid-user
	</Directory>
</VirtualHost>
systemctl restart httpd
curl http://sales.example.coms (if used from the browser, promts for user and pass)

FTP config
yum install vsftpd
yum list all | grep ftp
vim /etc/vsftpd/vsftpd.conf (check it out)
grep ftp /etc/passwd
cd /var/ftp/pub
touch file{1..10}
systemctl start vsftpd
systemctl status vsftpd
yum install lftp
lftp localhost (connects to localhost as the anonymous user)
cd pub
get file9 (downloads it and copies it to current dir)

DNS Server BIND config
Bind is the most common linux dns server
check video for details

Caching DNS
yum install unbound
vim /etc/unbound/unbound.conf (uncomment the interface 0.0.0.0, 
access-control: 192.168.4.0/24 allow
forward-zone: 
name: “.”
						forward-addr: 8.8.8.8
					domain-insecure: mydomain.local
systemctl start unbound
systemctl status unbound

NFS & CIFS File Shares
yum intall nfs-utils
vim /etc/exports
	/data *(rw,no_root_squash)
systemctl start nfs-server
systemctl status nfs-server
nfsclient -L localhost
showmount -e localhost (shows all mounts, -e means export)
firewall-cmd --add-service nfs (if running firewalld)

Persist NFS share
Logged in Ubuntu machine
sudo apt install nfs-common
showmount -e centos
sudo mount centos:/data /mnt
sudo vim /etc/fstab (add here for persisting: centos:/data /data nfs _netdev 0 0)
sudo mkdir /data
sudo mount -a
mount | grep nfs

Samba Server
yum install samba
vim /etc/samba/smb.conf
	[data]
		comment = my data
		path = /data
		browseable = yes
		writeable = yes
		valid users = linda
systemctl start smb	
systemctl status smb	
smbpasswd -a linda (creating the samba user)
firewall-cmd --list-all
firewall-cmd --get-services
firewall-cmd --add-service samba --permanent (adds the service to the peristing config as well as the runtime)

Mounting samba shares
On the Ubuntu machine (as client)
apt instll cifs-utils samba-client
smbclient -L 192.168.4.224 (skip the pass)
mount -o username=linda.password=password //192.168.4.224/data /mnt
mount | grep data
vim /etc/fstab (//centos/data /cifs cifs _netdev.username=linda,password=password 0 0)
mkdir /cifs
mount -a
vim /etc/fstab

config DB server
yum install mariadb-server
Another way is:
systemctl enable --now maradb
	mysql_secure_installation
mysql -u root -p (brings us to the maria prompt)

Simple Database
In Maria DB prompt:
create database people
use people;
create table users(firstname VARCHAR(20), lastname VARCHAT(20), birthyear INT);
insert into users(firstname, lastname, birthyear) values(‘Linda’, ‘Thomsen’, ‘1976’);
select * from users;

Understanding Email Handling
check video again

Config Postfix Server
systemctl status postfix
cd /etc/postfix
vim master.cf (configures which services are running and with how many processes timeouts etc.)
vim main.cf (all Postfix config)
	inet_interfaces=all
	inet_protocols=ipv4
	myorigin=$mydomain
systemctl restart postfix
ss -tuna | grep 25

Dovecot as IMAP server
yum install dovecot mutt
mail -s “hello linda” linda < .
id linda (shows that group of linda is “mail”)
rpm -qa | grep dove (shows dovecot is already installed)
vim /etc/dovecot/dovecot.conf
	protocols
	listen
vim /etc/dovecot/conf.d/10-mail.conf
	mail_location
systemctl restart dovecot
systemctl enable dovecot (to get it back up automatically after reboot)
mutt -f imap://linda@localhost

Web proxy config
yum install squid
systemctl enable squid
vim /etc/squid/squid.conf
	acl blockedsite url_regex ^http://.*.oracle.com/.*$
	acl blockedsite url_regex ^https://.*.oracle.com/.*$
	http_access deny blockedsite
systemclt  start squid
systemctl status squid -l
(if I now try to go to oracle.com with my browser, I should get an error)

KVM
grep vmx /proc/cpuinfo (check if this system is ready for vm)
lsmod | grep kvm
systemctl status libvirtd
systemctl enable --now libvirtd
yum install virt-manager
virt-manager (starts a graphical utility, which assists in creating a vm)
	check video for the options

Managing KVM
virsh list --all
virsh list (vms running)
virsh list --all
virsh edit centos7.0 (config editor a specific vm)
virsh destroy 2
virsh start centos7.0
systemctl status libvirtd -l
virsh list (we see that it’s now running)
