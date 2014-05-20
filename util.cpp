#include "util.h"
//#include <asm/ptrace.h>
#include <libunwind.h>
#include <libunwind-ptrace.h>
#include <errno.h>
#include <pinktrace/pink.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <err.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <sys/ptrace.h>

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


  unw_addr_space_t aspace = unw_create_addr_space(&_UPT_accessors, 0);
  void *upt_info = _UPT_create(pid);
  unw_word_t ip, sp;
  unw_cursor_t cursor;

  unw_init_remote(&cursor, aspace, upt_info);

  do
    {
      unw_get_reg(&cursor, UNW_REG_IP, &ip);
      unw_get_reg(&cursor, UNW_REG_SP, &sp);
      printf ("ip=%016lx sp=%016lx\n", ip, sp);
    }
  while (unw_step (&cursor) > 0);

  // *apparently* PTRACE_GETREGS on x64 
  // returns more data than a struct pt_regs can handle :/
  // THANKS PTRACE.
  struct user_regs_struct *regs = (struct user_regs_struct *) malloc(sizeof(struct user_regs_struct));
  if(!pink_util_get_regs(pid, regs)){
    perror("ptrace couldn't get registers\n");
    free(regs);
    exit(0);
  }

  //printf("rip seems to be: %lx\n", regs->rip);
  printf("rbp seems to be: %llx\n", regs->rbp);
  uintptr_t rbp;
  rbp = ptrace(PTRACE_PEEKUSER, pid, RBP * 8, 0);
  printf("other rbp seems to be: %llx\n", rbp);
  
  uintptr_t ret;
  if(!pink_util_peekdata(pid, (regs->rbp), &ret)){ printf("%s", strerror(errno));}
  uintptr_t ret2;
  printf("ret addr seems to be: %lx\n", ret);
  
  if(!pink_util_peekdata(pid, ret, &ret2)){printf("%s", strerror(errno));}
  printf("ret2 addr seems to be: %lx\n", ret2);
  uintptr_t ret3;
  pink_util_peekdata(pid, (ret2), &ret3);
  printf("ret3 addr seems to be: %lx\n", ret3);
  uintptr_t ret4;
  pink_util_peekdata(pid, (ret3), &ret4);
  printf("ret4 addr seems to be: %lx\n", ret4);
  free(regs);
  return ret;
}
