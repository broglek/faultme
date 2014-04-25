#!/bin/sh


gcc -c $(pkg-config --cflags pinktrace) -o faultme.o faultme.c
gcc -c $(pkg-config --cflags pinktrace) link_locate.c -o link_locate.o
gcc -c $(pkg-config --cflags pinktrace) util.c -o util.o
gcc -o faultme faultme.o $(pkg-config --libs pinktrace)