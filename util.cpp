#include "util.h"
#include <asm/ptrace.h>
#include <pinktrace/pink.h>
#include <stdlib.h>
#include <stdio.h>
#include <err.h>

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
  char *ret = (char *) calloc(32, sizeof(char));
  read_data(pid, addr, ret, len);
  return ret;
}

uintptr_t get_return_address(int pid)
{
  // *apparently* PTRACE_GETREGS on x64 
  // returns more data than a struct pt_regs can handle :/
  // THANKS PTRACE.
  struct pt_regs *regs = (struct pt_regs *) malloc(2 * sizeof(struct pt_regs));
  if(!pink_util_get_regs(pid, regs)){
    perror("ptrace couldn't get registers\n");
    free(regs);
    exit(0);
  }
  
  printf("rbp seems to be: %lx\n", regs->rbp);
  uintptr_t ret;
  pink_util_peekdata(pid, (regs->rbp) + sizeof(uintptr_t), &ret);
  free(regs);
  printf("ret addr seems to be: %lx\n", ret);
  return ret;
}
