# build_armv6_static.sh
#
# This script builds a C program using a older version of GCC compiler (4.9.3) to crosscompile for armv6 arch
# Older comiler was found here - https://github.com/raspberrypi/tools
# -std=c11 (use C standard 11)
# -static (Bind all includes into compiled binary)
# -march (Use armv6 mirco architecture)

#!/bin/bash

src=$1
bin=$2

tools/arm-bcm2708/arm-linux-gnueabihf/bin/arm-linux-gnueabihf-gcc-4.9.3 -std=c11 -static -march=armv6 -mfpu=vfp -mfloat-abi=hard $src -o $bin
