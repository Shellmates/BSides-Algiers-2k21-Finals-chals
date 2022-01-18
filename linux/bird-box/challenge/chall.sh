#!/bin/bash
printf "ZeroCool@mctf:~$ "
BAD="bash sh perl python nc netcat php ruby xterm Xnest xhost"
while read command;
do
	check=1
	for word in $BAD;do
		if [[ "$command" == *"$word"* ]]; then
  			check=0;
		fi
	done

	if [[ $check -eq 1 ]] ; then 
		bash -c "$command" >/dev/null 2>&1;
		if [[ $? -eq 0 ]] ; then 
			echo "GOOD";
		else 
			echo "BAD";
		fi
	else 
			echo "NOOO";
	fi
	printf "ZeroCool@mctf:~$ ";
done