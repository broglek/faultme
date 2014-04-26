#include "link_locate.h"
#include <stdlib.h>
#include <pinktrace/pink.h>
#include <stdio.h>


struct link_map *locate_linkmap(int pid)
{
  Elf64_Ehdr *ehdr = malloc(sizeof(Elf64_Ehdr));
  Elf64_Phdr *phdr = malloc(sizeof(Elf64_Phdr));
  Elf64_Dyn *dyn = malloc(sizeof(Elf64_Dyn));
  Elf64_Word got;
  struct link_map *l = malloc(sizeof(struct link_map));
  unsigned long phdr_addr, dyn_addr, map_addr;
  //Read ELF Header
  read_data(pid, 0x00400000, ehdr, sizeof(Elf64_Ehdr));
  phdr_addr = 0x00400000 + ehdr->e_phoff;
  //phdr_addr = 0x00400000 + sizeof(Elf64_Ehdr);
  //Read Program Header Table start
  read_data(pid, phdr_addr, phdr, sizeof(Elf64_Phdr));

  while (phdr->p_type != PT_DYNAMIC) {
    read_data(pid, phdr_addr += sizeof(Elf64_Phdr), phdr,
	      sizeof(Elf64_Phdr));
  }

  //Go through entries in Dynamic Section to find GOT
  read_data(pid, phdr->p_vaddr, dyn, sizeof(Elf64_Dyn));
  dyn_addr = phdr->p_vaddr;

  while (dyn->d_tag != DT_PLTGOT) {
    read_data(pid, dyn_addr +=
	      sizeof(Elf64_Dyn), dyn, sizeof(Elf64_Dyn));
  }

  got = (Elf64_Word) dyn->d_un.d_ptr;
  got += 8; //Link map is second GOT entry (double check this?)


  read_data(pid, (unsigned long) got, &map_addr, (sizeof(unsigned long)));
  read_data(pid, map_addr, l, sizeof(struct link_map));
  free(phdr);
  free(ehdr);
  free(dyn);
  return l;
}

void resolv_tables(int pid, struct link_map *map, unsigned long *symtab, unsigned long *strtab, int *nchains)
{
  Elf64_Dyn *dyn = malloc(sizeof(Elf64_Dyn));
  unsigned long addr;
  addr = (unsigned long) map->l_ld;
  read_data(pid, addr, dyn, sizeof(Elf64_Dyn));
  while (dyn->d_tag) {
    switch (dyn->d_tag) {
    case DT_HASH:
      read_data(pid, dyn->d_un.d_ptr +
		map->l_addr + 4, nchains,
		sizeof(int));
      break;
    case DT_STRTAB:
      *strtab = dyn->d_un.d_ptr;
      break;
    case DT_SYMTAB:
      *symtab = dyn->d_un.d_ptr;
      break;
    default:
      break;
    }
    addr += sizeof(Elf64_Dyn);
    read_data(pid, addr, dyn, sizeof(Elf64_Dyn));
  }
  free(dyn);
}

unsigned long find_sym_in_tables(int pid, struct link_map *map, char *sym_name, unsigned long symtab,
                                 unsigned long strtab, int nchains)
{
  Elf64_Sym *sym = malloc(sizeof(Elf64_Sym));
  char *str;
  int i = 0;
  while (i < nchains) {
    read_data(pid, symtab + (i * sizeof(Elf64_Sym)), sym,
	      sizeof(Elf64_Sym));
    i++;
    if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC)
      continue;

    /* read symbol name from the string table */
    str = read_str(pid, strtab + sym->st_name, 32);
    printf("%s\n", str);
    /* compare it with our symbol*/
    if (strcmp(str, sym_name) == 0) {
      printf("\nSuccess: got it\n");
      return (map->l_addr + sym->st_value);
    }
  }
  /* no symbol found, return 0 */
  printf("\nSorry, No such sym %s\n", sym_name);
  return 0;
}
