#!/bin/sh


g++ -c -fpermissive -g $(pkg-config --cflags pinktrace) -o faultme.o faultme.cpp
g++ -c -fpermissive -g $(pkg-config --cflags pinktrace) util.cpp -o util.o
g++ -fpermissive -g -o faultme faultme.o util.o $(pkg-config --libs pinktrace) -lunwind-ptrace -lunwind-generic -lunwind -lcrypto