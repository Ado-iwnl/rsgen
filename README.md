# Reverse Shell Generator: rsgen.sh

rsgen is a tool to generate an one line reverse shell and launch a nc listener.

## Usage

```
[+] Usage: rsgen.sh -i [interface] -p [port] [-axblrgnjwPNOALRG, --ps] 

[+] OPTIONS:

	-i --interface : Interface to grep the IP
	-I --lhost : Local IP
	-p --lport : Listen Port
	-Q --no-listener : Do not launch a listener

[+] SHELLS:

	-a --all : Diplay all reverse shell except OpenSSL
	-x --php : PHP reverse shell
	-P --python : python reverse shell
	--ps --powershell : Powershell reverse shell
 	-b --bash --sh : bash or sh reverse shell
   		--tcp : TCP reverse shell
   		--udp : UDP reverse shell
	-S --socat : Socat reverse shell
	-l --perl : Perl reverse shell  (-l for larry Wall)
	-r --ruby : Ruby reverse shell
	-g --go : Golang: Reverse shell
	-n --nc : Netcat reverse shell
	-N --nc-bsd : Netcat open BSD reverse shell
	-C --ncat : Ncat reverse  shell
	-O --open-ssl : Creates a self signed certificate and lauch a nc listener, OpenSSL reverse shell
	-A --awk : AWK reverse shell
	-j --java : Java reverse shell
	-w --war : WAR reverse shell
	-L --lua : Lua reverse shell
	-R --node : NodeJS reverse shell
	-G --groovy : Groovy reverse shell

[+] Examples:

	rsgen -i tun0 -p 9090 -ps (Powershell)
	rsgen -i eth0 -p 443 -b --tcp (Bash TCP)
	rsgen -I 192.168.1.2 -x -p 4444 -Q (Php and Dont launch a nc listener)
	rsgen -I 10.10.14.128 -p 5656 -S (Socat) 
```

## Output

![alt text](https://raw.githubusercontent.com/darn0b/rsgen/master/screenshot.png)

## Install

If you want:

```
ln -s $(pwd)/rsgen.sh /some/dir/in/PATH
```

## Todo

Add more reverse shells
URL encode feature
Copy the command to the clipboard


