/* Copyright (C) 2023 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

#include "dynlib.h"
#include "elf.h"
#include "kern.h"
#include "libc.h"
#include "pt.h"


#ifndef ELFLDR_PORT
#define ELFLDR_PORT 9021
#endif

#define PAGE_SIZE 0x4000

#define PROT_NONE  0x0
#define PROT_READ  0x1
#define PROT_WRITE 0x2
#define PROT_EXEC  0x4

#define MAP_SHARED    0x1
#define MAP_PRIVATE   0x2
#define MAP_FIXED     0x10
#define MAP_ANONYMOUS 0x1000

#define ROUND_PG(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x) ((x) & ~(PAGE_SIZE - 1))
#define PFLAGS(x)   ((((x) & PF_R) ? PROT_READ  : 0) | \
		     (((x) & PF_W) ? PROT_WRITE : 0) | \
		     (((x) & PF_X) ? PROT_EXEC  : 0))


static intptr_t
elfldr_load(pid_t pid, uint8_t *elf, size_t size) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr*)elf;
  Elf64_Phdr *phdr = (Elf64_Phdr*)(elf + ehdr->e_phoff);
  Elf64_Shdr *shdr = (Elf64_Shdr*)(elf + ehdr->e_shoff);

  intptr_t base_addr = -1;
  size_t base_size = 0;

  size_t min_vaddr = -1;
  size_t max_vaddr = 0;

  // Sanity check, we only support 64bit ELFs.
  if(ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E' ||
     ehdr->e_ident[2] != 'L'  || ehdr->e_ident[3] != 'F') {
    return -1;
  }

  // Compute size of virtual memory region.
  for(int i=0; i<ehdr->e_phnum; i++) {
    if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
      continue;
    }

    if(phdr[i].p_vaddr < min_vaddr) {
      min_vaddr = phdr[i].p_vaddr;
    }

    if(max_vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
      max_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
    }
  }

  min_vaddr = TRUNC_PG(min_vaddr);
  max_vaddr = ROUND_PG(max_vaddr);
  base_size = max_vaddr - min_vaddr;

  int flags = MAP_PRIVATE | MAP_ANONYMOUS;
  if(ehdr->e_type == ET_DYN) {
    base_addr = 0;
  } else if(ehdr->e_type == ET_EXEC) {
    base_addr = min_vaddr;
    flags |= MAP_FIXED;
  } else {
    return 0;
  }

  // Reserve an address space of sufficient size.
  if((base_addr=pt_mmap(pid, base_addr, base_size, PROT_NONE,
			flags, -1, 0)) == -1) {
    return 0;
  }

  // Commit segments to reserved address space.
  for(int i=0; i<ehdr->e_phnum; i++) {
    size_t aligned_memsz = ROUND_PG(phdr[i].p_memsz);
    intptr_t addr = base_addr + phdr[i].p_vaddr;
    int alias_fd = -1;
    int shm_fd = -1;

    if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
      continue;
    }

    if(phdr[i].p_flags & PF_X) {
      if((shm_fd=pt_jitshm_create(pid, 0, aligned_memsz,
				  PROT_WRITE | PFLAGS(phdr[i].p_flags))) < 0) {
	return 0;
      }

      if((addr=pt_mmap(pid, addr, aligned_memsz, PFLAGS(phdr[i].p_flags),
		       MAP_FIXED | MAP_SHARED, shm_fd, 0)) == -1) {
	return 0;
      }

      if((alias_fd=pt_jitshm_alias(pid, shm_fd, PROT_WRITE | PROT_READ)) < 0) {
	return 0;
      }

      if((addr=pt_mmap(pid, 0, aligned_memsz, PROT_WRITE | PROT_READ,
		       MAP_SHARED, alias_fd, 0)) == -1) {
	return 0;
      }

      if(pt_copyin(pid, elf + phdr[i].p_offset, addr, phdr[i].p_memsz)) {
	return 0;
      }

      pt_munmap(pid, addr, aligned_memsz);
      pt_close(pid, alias_fd);
      pt_close(pid, shm_fd);
    } else {
      if((addr=pt_mmap(pid, addr, aligned_memsz, PROT_WRITE,
		       MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
		       -1, 0)) == -1) {
	return 0;
      }
      if(pt_copyin(pid, elf + phdr[i].p_offset, addr, phdr[i].p_memsz)) {
	return 0;
      }
    }
  }

  // Relocate positional independent symbols.
  for(int i=0; i<ehdr->e_shnum; i++) {
    if(shdr[i].sh_type != SHT_RELA) {
      continue;
    }

    Elf64_Rela* rela = (Elf64_Rela*)(elf + shdr[i].sh_offset);
    for(int j=0; j<shdr[i].sh_size/sizeof(Elf64_Rela); j++) {
      if((rela[j].r_info & 0xffffffffl) == R_X86_64_RELATIVE) {
	intptr_t value_addr = (base_addr + rela[j].r_offset);
	intptr_t value = base_addr + rela[j].r_addend;
	if(pt_copyin(pid, &value, value_addr, 8)) {
	  return 0;
	}
      }
    }
  }

  // Set protection bits on mapped segments.
  for(int i=0; i<ehdr->e_phnum; i++) {
    size_t aligned_memsz = ROUND_PG(phdr[i].p_memsz);
    intptr_t addr = base_addr + phdr[i].p_vaddr;

    if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
      continue;
    }

    if(pt_mprotect(pid, addr, aligned_memsz, PFLAGS(phdr[i].p_flags))) {
      return 0;
    }
  }

  return base_addr + ehdr->e_entry;
}


intptr_t
elfldr_args(pid_t pid) {
  int victim_sock;
  int master_sock;
  intptr_t buf;
  int pipe0;
  int pipe1;

  if((buf=pt_mmap(pid, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
		  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) == -1) {
    return 0;
  }

  if((master_sock=pt_socket(pid, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    return 0;
  }

  pt_setint(pid, buf+0x00, 20);
  pt_setint(pid, buf+0x04, IPPROTO_IPV6);
  pt_setint(pid, buf+0x08, IPV6_TCLASS);
  pt_setint(pid, buf+0x0c, 0);
  pt_setint(pid, buf+0x10, 0);
  pt_setint(pid, buf+0x14, 0);
  if(pt_setsockopt(pid, master_sock, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, buf, 24)) {
    return 0;
  }

  if((victim_sock=pt_socket(pid, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    return 0;
  }

  pt_setint(pid, buf+0x00, 0);
  pt_setint(pid, buf+0x04, 0);
  pt_setint(pid, buf+0x08, 0);
  pt_setint(pid, buf+0x0c, 0);
  pt_setint(pid, buf+0x10, 0);
  if(pt_setsockopt(pid, victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, buf, 20)) {
    return 0;
  }

  if(kern_overlap_sockets(pid, master_sock, victim_sock)) {
    return 0;
  }

  if(pt_pipe(pid, buf)) {
    return 0;
  }
  pipe0 = pt_getint(pid, buf);
  pipe1 = pt_getint(pid, buf+4);

  intptr_t args       = buf;
  intptr_t dlsym      = dynlib_resolve_sceKernelDlsym(pid);
  intptr_t rwpipe     = buf + 0x100;
  intptr_t rwpair     = buf + 0x200;
  intptr_t kpipe_addr = kern_get_proc_file(pid, pipe0);
  intptr_t payloadout = buf + 0x300;

  pt_setlong(pid, args + 0x00, dlsym);
  pt_setlong(pid, args + 0x08, rwpipe);
  pt_setlong(pid, args + 0x10, rwpair);
  pt_setlong(pid, args + 0x18, kpipe_addr);
  pt_setlong(pid, args + 0x20, kern_get_data_baseaddr());
  pt_setlong(pid, args + 0x28, payloadout);
  pt_setint(pid, rwpipe + 0, pipe0);
  pt_setint(pid, rwpipe + 4, pipe1);
  pt_setint(pid, rwpair + 0, master_sock);
  pt_setint(pid, rwpair + 4, victim_sock);
  pt_setint(pid, payloadout, 0);

  return args;
}


static int
elfldr_get_procname(pid_t pid, char* name) {
  int mib[4] = {1, 14, 1, pid};
  size_t ki_size = 1096;
  char ki_buf[ki_size];

  if(sysctl(mib, 4, ki_buf, &ki_size, 0, 0) < 0) {
    return -1;
  }

  strcpy(name, ki_buf + 447);

  return 0;
}


static pid_t
elfldr_find_pid(const char* name) {
  char procname[255];

  for(pid_t pid=1; pid<10000; pid++) {
    if(elfldr_get_procname(pid, procname) < 0) {
      continue;
    }
    if(!strcmp(procname, name)) {
      return pid;
    }
  }

  return -1;
}


int
elfldr_exec(const char* procname, uint8_t *elf, size_t size) {
  uint8_t priv_caps[16] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
			   0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
  uint8_t prev_caps[16];
  struct reg r;
  pid_t pid;

  if((pid=elfldr_find_pid(procname)) < 0) {
    return -1;
  }

  if(kern_get_ucred_caps(pid, prev_caps)) {
    return -1;
  }
  if(kern_set_ucred_caps(pid, priv_caps)) {
    return -1;
  }

  if(pt_attach(pid)) {
    kern_set_ucred_caps(pid, prev_caps);
    return -1;
  }

  if(pt_getregs(pid, &r)) {
    kern_set_ucred_caps(pid, prev_caps);
    pt_detach(pid);
    return -1;
  }

  r.r_rip = elfldr_load(pid, elf, size);
  r.r_rdi = elfldr_args(pid);

  kern_set_ucred_caps(pid, prev_caps);

  if(!r.r_rip || !r.r_rdi) {
    pt_detach(pid);
    return -1;
  }

  if(pt_setregs(pid, &r)) {
    pt_detach(pid);
    return -1;
  }

  return pt_detach(pid);
}


static ssize_t
elfldr_read(int connfd, uint8_t **data) {
  uint8_t buf[0x4000];
  off_t offset = 0;
  ssize_t len;

  *data = 0;
  while((len=read(connfd, buf, sizeof(buf)))) {
    *data = realloc(*data, offset + len);
    if(*data == 0) {
      return -1;
    }

    memcpy(*data + offset, buf, len);
    offset += len;
  }
  return offset;
}


int
elfldr_serve(const char* procname) {
  struct sockaddr_in server_addr;
  struct sockaddr_in client_addr;
  socklen_t addr_len;
  uint8_t *elf;
  size_t size;
  int connfd;
  int srvfd;

  if((srvfd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    return -1;
  }

  if(setsockopt(srvfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
    return -1;
  }

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(ELFLDR_PORT);

  if(bind(srvfd, &server_addr, sizeof(server_addr)) != 0) {
    return -1;
  }

  if(listen(srvfd, 5) != 0) {
    return -1;
  }

  addr_len = sizeof(client_addr);
  while(1) {
    if((connfd=accept(srvfd, &client_addr, &addr_len)) < 0) {
      continue;
    }

    if((size=elfldr_read(connfd, &elf))) {
      elfldr_exec(procname, elf, size);
      free(elf);
    }
    close(connfd);
  }
  close(srvfd);

  return 0;
}


static void*
elfldr_thread(void *arg) {
  elfldr_serve((const char*)arg);
  return 0;
}


int
elfldr_spawn_server(const char* procname) {
  pthread_t trd;
  return pthread_create(&trd, 0, elfldr_thread, (void*)procname);
}
