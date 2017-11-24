#!/bin/bash
export ARCH=arm
export CROSS_COMPILE=arm-linux-androideabi-
export PATH=$PATH:/home/esslab/android/arm-linux-androideabi-4.6/bin

#make mako_defconfig
make -j4

: <<'END'
if [ $1 == "0" ]; then
    
    make -j4 M=trace_bio/
    make -j4 
 elif [ $1 == "1" ]; then 
    
    make -j4 M=trace_bio
    #make -j4 
    #make -j4 M=include/linux
    #make -j4 M=trace_bio
    make -j4 CFLAGS+=-DCONFIG_TRACEBIO CONFIG_TRACEBIO=1
else
    echo "0  normal comile , 1 compile with trace_bio "
fi
END
