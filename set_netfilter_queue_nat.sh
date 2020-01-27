#!/bin/bash

$QUEUE_NUM

INPUT_QUEUE_NUM=0
OUTPUT_QUEUE_NUM=1
if [ $# -eq 2 ]
then
	$INPUT_QUEUE_NUM = $1
	$OUTPUT_QUEUE_NUM = $2
elif [ $# -ne 0 ]
then
	echo "Usage: ${0} [Input Queue Number] [Output Queue Number]"
	exit 1
fi

sudo iptables -F
sudo iptables -t nat -A PREROUTING -j NFQUEUE --queue-num $INPUT_QUEUE_NUM
sudo iptables -t nat -A POSTROUTING -j NFQUEUE --queue-num $OUTPUT_QUEUE_NUM

