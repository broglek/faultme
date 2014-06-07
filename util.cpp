#include "util.h"
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

#include "openssl/md5.h"

using namespace std;


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

string get_callchain_id(int pid)
{


  unw_addr_space_t aspace = unw_create_addr_space(&_UPT_accessors, 0);
  void *upt_info = _UPT_create(pid);
  unw_word_t ip, sp, offset;
  unw_cursor_t cursor;
  char *symbol_name = (char *) malloc(2000);

  unw_init_remote(&cursor, aspace, upt_info);


  unsigned char hash[MD5_DIGEST_LENGTH];
  MD5_CTX md5;
  MD5_Init(&md5);


  int rr = 0;
  do
    {
      unw_get_reg(&cursor, UNW_REG_IP, &ip);
      unw_get_reg(&cursor, UNW_REG_SP, &sp);
      unw_get_proc_name(&cursor, symbol_name, 2000, &offset); 
      MD5_Update(&md5, &ip, sizeof(unw_word_t));
      printf ("ip=%016lx sp=%016lx (%s)\n", ip, sp, symbol_name);
    }
  while (rr = unw_step (&cursor) > 0);
  _UPT_destroy(upt_info);

  MD5_Final(hash, &md5);

  char md5string[33];
  for(int i = 0; i < 16; ++i)
    sprintf(&md5string[i*2], "%02x", (unsigned int)hash[i]);
  // *apparently* PTRACE_GETREGS on x64 
  // returns more data than a struct pt_regs can handle :/
  // THANKS PTRACE.  Never forget.
  free(symbol_name);
  return string(md5string);
}
