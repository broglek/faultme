#!/bin/sh


g++ -c -fpermissive -g $(pkg-config --cflags pinktrace) -o faultme.o faultme.cpp
g++ -c -fpermissive -g $(pkg-config --cflags pinktrace) link_locate.cpp -o link_locate.o
g++ -c -fpermissive -g $(pkg-config --cflags pinktrace) util.cpp -o util.o
g++ -fpermissive -o faultme faultme.o link_locate.o util.o $(pkg-config --libs pinktrace)