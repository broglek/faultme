#ifndef Link_Locate
#define Link_Locate

#include <link.h>
#include "util.h"

struct link_map *locate_linkmap(int pid);
void resolv_tables(int pid, struct link_map *map, unsigned long *symtab, unsigned long *strtab, int *nchains);
unsigned long find_sym_in_tables(int pid, struct link_map *map, char *sym_name, unsigned long symtab, 
				 unsigned long strtab, int nchains);

#endif
