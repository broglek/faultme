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

#include "openssl/sha.h"

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


  unsigned char hash[SHA256_DIGEST_LENGTH];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);



  do
    {
      unw_get_reg(&cursor, UNW_REG_IP, &ip);
      unw_get_reg(&cursor, UNW_REG_SP, &sp);
      SHA256_Update(&sha256, ip, sizeof(unw_word_t));
      printf ("ip=%016lx sp=%016lx\n", ip, sp);
    }
  while (unw_step (&cursor) > 0);
  _UPT_destroy(upt_info);
  // *apparently* PTRACE_GETREGS on x64 
  // returns more data than a struct pt_regs can handle :/
  // THANKS PTRACE.
  return 0;
}
