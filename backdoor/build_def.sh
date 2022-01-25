# build_def.sh
#
# Simple build for raspberry PI GCC toolchain

#!/bin/bash

src=$1
bin=$2

gcc $src -o $bin
