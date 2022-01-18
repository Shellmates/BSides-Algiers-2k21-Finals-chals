#!/bin/sh

nohup php -S 127.0.0.1:9009 > phpd.log 2>&1 &
apache2-foreground
