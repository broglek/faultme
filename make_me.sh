#!/bin/sh


gcc -c $(pkg-config --cflags pinktrace) -o example.o example.c
gcc -o example example.o $(pkg-config --libs pinktrace)