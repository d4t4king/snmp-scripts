#!/bin/bash

CY="\033[0;36m"
YL="\033[1;33m"
BL="\033[1;34m"
RD="\033[1;31m"
GY="\033[0;37m"
NC="\033[0m"

#getopts e LONG

#if [ $LONG eq "e" ]; then
#CSFILE="ecs"
#else 
CSFILE="cs"
#fi

ping -c 2 $1 > /dev/null 2>&1
S=$?
if [ $S == 1 ]; then
	echo -e "${RD}Unable to ping target ($1) ${NC}"
elif [ $S == 2 ]; then
	echo -e "${CY}Unable to resolve hostname. (NXDOMAIN)${NC}"
fi

nslookup $1

#sudo hping3 -2 -p 161 -c 3 -i u1000 $1 
#H=$?
sudo nmap -sU -p161 --script snmp-sysdescr $1

#if [ $H != 0 -a $S != 0 ]; then
if [ $S != 0 ]; then
	echo -e "${RD}Target appears dead.${NC}"
	exit 1
fi

# Fix for spoaces
OLD_IFS=$IFS
IFS=$'\n'

if [ "$1x" == "x" ] ; then
	echo -e "${RD}NEED A HOST TO CHECK!!!${NC}"
	exit 1
fi

for C in `cat $CSFILE | sort`; do
#for C in private; do
	echo -e "$CY >>>>> snmpwalk -v1 -c $RD$C $GY$1 $NC"
	snmpwalk -v1 -c $C $1 | head -5
done

IFS=$OLD_IFS

