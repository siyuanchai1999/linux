#!/bin/bash

# $1 should be the address that keeps triggering page fault
# the script trunc everything after the fist page fault of given addr 
# and dump the output to the mmu_tail.log

line=$(grep -n $1 mmu.log | cut --delimiter=: -f1 | head -1)
echo $line
tail -n +$line mmu.log > mmu_tail.log
