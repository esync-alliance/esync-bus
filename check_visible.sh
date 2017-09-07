#!/bin/bash

echo "** Any symbols printed below are invisible, and must be fixed. See ESYNC-738 for details"

objdump -tT libxl4bus.so |awk '{ if (match($NF,"^xl4bus_")) { print $NF; } }' | sort | uniq -u
