#!/bin/sh


gcc -c -g $(pkg-config --cflags pinktrace) -o faultme.o faultme.c
gcc -c -g $(pkg-config --cflags pinktrace) link_locate.c -o link_locate.o
gcc -c -g $(pkg-config --cflags pinktrace) util.c -o util.o
gcc -o  faultme faultme.o link_locate.o util.o $(pkg-config --libs pinktrace)