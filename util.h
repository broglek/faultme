#include <stdint.h>

#ifndef Faultme_Util
#define Faultme_Util

void read_data(int pid, unsigned long addr, void *vptr, int len);
char *read_str(int pid, unsigned long addr, int len);
uintptr_t get_return_address(int pid);

#endif
