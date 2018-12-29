# -EBEKv2.0

EternalBlue SMB Exploit Toolkit | Auto-Spread| EXE DLL PS Supported

#######################
#  EBEK REQUIREMENTS  #
#######################

* Python 2.7

* Pip

* Build-Essential

* Libssl-dev

* Libffi-dev

* Python-dev

* Impacket

* Pycrypto

* Clint

* Pyasn1


###############################
#  Debian Based OS - Install  #
###############################

apt-get install python python-pip build-essential libssl-dev libffi-dev python-dev

pip install impacket pycrypto clint ipaddress pyasn1


###############################
#  CentOS Based OS - Install  # 
###############################

yum install python python-pip build-essential libssl-dev libffi-dev python-dev

pip install impacket pycrypto clint ipaddress pyasn1


################################
#  Windows Based OS - Install  #
################################

pip install impacket pycrypto clint ipaddress pyasn1


#####################
#  Auto-Mode Usage  #
#####################

python auto_mode.py 192.0.0.0/8

Any Valid CIDR Range may be supplied.
https://www.ripe.net/about-us/press-centre/IPv4CIDRChart_2015.pdf

Example:
192.168.1.0/24 = 256 IP's
192.168.0.0/16 = 64K IP's
192.0.0.0/8    = 16M IP's
0.0.0.0/0      = 4096M IP's

- EXE or DLL Supported.
- All executions with SYSTEM privileges.
