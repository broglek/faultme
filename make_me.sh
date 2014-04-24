#!/bin/sh


gcc -c $(pkg-config --cflags pinktrace) -o faultme.o faultme.c
gcc -o faultme faultme.o $(pkg-config --libs pinktrace)