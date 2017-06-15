#!/bin/sh
for i in 0 1 2 3 4 5 ; do
    for j in 0 1 2 ; do
        echo 1 > /sys/devices/system/cpu/cpu$i/cpuidle/state$j/disable;
    done;
done
