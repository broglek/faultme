#include <stdint.h>
#include <string.h>
#include <string>
using namespace std;

#ifndef Faultme_Util
#define Faultme_Util

void read_data(int pid, unsigned long addr, void *vptr, int len);
char *read_str(int pid, unsigned long addr, int len);
string get_return_address(int pid);

#endif
