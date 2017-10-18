#!/bin/bash

if [[ $# < 3 ]]; then
	echo "Syntax is $@ break_address break_offset function_size"
	exit 1;
fi

break_address=$1
break_offset=$2
function_size=$3
func_start=$(($break_address - $break_offset))
func_end=$(($func_start + $function_size))
objdump -S -D vmlinux --start-address=$func_start --stop-address=$func_end | less
