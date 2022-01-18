#!/bin/bash
socat -dd -T300 tcp-l:7001,reuseaddr,fork,keepalive exec:./chall.sh
