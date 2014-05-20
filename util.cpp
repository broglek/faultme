#include "util.h"
#include <pinktrace/pink.h>
#include <stdlib.h>

void read_data(int pid, unsigned long addr, void *vptr, int len)
{
  int i, count;
  long word;
  unsigned long *ptr = (unsigned long *) vptr;
  count = i = 0;
  while (count < len) {
    pink_util_peekdata(pid, addr + count, &word);
    count += sizeof(unsigned long);
    if(count > len){
      int dif = sizeof(unsigned long) - (count - len);
      memcpy(&ptr[i++], &word, dif);
    }
    else{
      ptr[i++] = word;
    }
  }
}

char *read_str(int pid, unsigned long addr, int len)
{
  char *ret = calloc(32, sizeof(char));
  read_data(pid, addr, ret, len);
  return ret;
}
