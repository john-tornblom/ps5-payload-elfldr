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

#include "elf.h"
#include "kern.h"
#include "libc.h"
#include "payload.h"


#define ROUND_PG(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x) ((x) & ~(PAGE_SIZE - 1))
#define PFLAGS(x)   ((((x) & PF_R) ? PROT_READ  : 0) | \
		     (((x) & PF_W) ? PROT_WRITE : 0) | \
		     (((x) & PF_X) ? PROT_EXEC  : 0))


/**
 * Load an ELF into memory, and jump to its entry point.
 **/
static intptr_t
elfldr_exec(const payload_args_t *args, uint8_t *elf, size_t size) {
  uint8_t priv_caps[16] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
			   0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
  uint8_t prev_caps[16];
  Elf64_Ehdr *ehdr = (Elf64_Ehdr*)elf;
  Elf64_Phdr *phdr = (Elf64_Phdr*)(elf + ehdr->e_phoff);
  Elf64_Shdr *shdr = (Elf64_Shdr*)(elf + ehdr->e_shoff);

  void* base_addr = (void*)-1;
  size_t base_size = 0;

  size_t min_vaddr = -1;
  size_t max_vaddr = 0;

  pid_t pid = getpid();
  int error = 0;

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
    base_addr = (void*)min_vaddr;
    flags |= MAP_FIXED;
  } else {
    return -1;
  }

  // Reserve an address space of sufficient size.
  if((base_addr=mmap(base_addr, base_size, PROT_NONE,
		     flags, -1, 0)) == (void*)-1) {
    return -1;
  }

  kern_get_ucred_caps(pid, prev_caps);
  kern_set_ucred_caps(pid, priv_caps);

  // Commit segments to reserved address space.
  for(int i=0; i<ehdr->e_phnum; i++) {
    size_t aligned_memsz = ROUND_PG(phdr[i].p_memsz);
    void* addr = base_addr + phdr[i].p_vaddr;
    int alias_fd = -1;
    int shm_fd = -1;

    if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
      continue;
    }

    if(phdr[i].p_flags & PF_X) {
      if((shm_fd=jitshm_create(0, aligned_memsz,
			       PROT_WRITE | PFLAGS(phdr[i].p_flags))) < 0) {
	error = -1;
	break;
      }

      if((addr=mmap((void*)addr, aligned_memsz, PFLAGS(phdr[i].p_flags),
		    MAP_FIXED | MAP_SHARED, shm_fd, 0)) == (void*)-1) {
	error = -1;
	break;
      }

      if((alias_fd=jitshm_alias(shm_fd, PROT_WRITE | PROT_READ)) < 0) {
	error = -1;
	break;
      }

      if((addr=mmap(0, aligned_memsz, PROT_WRITE | PROT_READ,
		    MAP_SHARED, alias_fd, 0)) == (void*)-1) {
	error = -1;
	break;
      }

      memcpy(addr, elf + phdr[i].p_offset, phdr[i].p_memsz);
      munmap(addr, aligned_memsz);
      close(alias_fd);
      close(shm_fd);
    } else {
      if((addr=mmap(addr, aligned_memsz, PROT_WRITE,
		    MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
		    -1, 0)) == (void*)-1) {
	error = -1;
	break;
      }
      memcpy(addr, elf + phdr[i].p_offset, phdr[i].p_memsz);
    }
  }

  // Relocate positional independent symbols.
  for(int i=0; i<ehdr->e_shnum && !error; i++) {
    if(shdr[i].sh_type != SHT_RELA) {
      continue;
    }

    Elf64_Rela* rela = (Elf64_Rela*)(elf + shdr[i].sh_offset);
    for(int j=0; j<shdr[i].sh_size/sizeof(Elf64_Rela); j++) {
      if((rela[j].r_info & 0xffffffffl) == R_X86_64_RELATIVE) {
	uint64_t* value_addr = (base_addr + rela[j].r_offset);
	*value_addr = (uint64_t)base_addr + rela[j].r_addend;
      }
    }
  }

  // Set protection bits on mapped segments.
  for(int i=0; i<ehdr->e_phnum && !error; i++) {
    size_t aligned_memsz = ROUND_PG(phdr[i].p_memsz);
    void* addr = base_addr + phdr[i].p_vaddr;

    if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
      continue;
    }

    if(mprotect(addr, aligned_memsz, PFLAGS(phdr[i].p_flags))) {
      error = -1;
      break;
    }
  }

  if(!error) {
    int (*_start)(const payload_args_t *) = base_addr + ehdr->e_entry;
    _start(args);
  }

  munmap(base_addr, base_size);
  kern_set_ucred_caps(pid, prev_caps);

  return error;
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
elfldr_serve(const payload_args_t *args, uint16_t port) {
  struct sockaddr_in server_addr;
  struct sockaddr_in client_addr;
  socklen_t addr_len;

  int stdout_fd;
  int stderr_fd;

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
  server_addr.sin_port = htons(port);

  if(bind(srvfd, &server_addr, sizeof(server_addr)) != 0) {
    return -1;
  }

  if(listen(srvfd, 5) != 0) {
    return -1;
  }

  addr_len = sizeof(client_addr);
  while(1) {
    if((connfd=accept(srvfd, &client_addr, &addr_len)) < 0) {
      return -1;
    }

    if((size=elfldr_read(connfd, &elf))) {
      stdout_fd = dup(1);
      stderr_fd = dup(2);
      dup2(connfd, 1);
      dup2(connfd, 2);
      elfldr_exec(args, elf, size);
      dup2(stdout_fd, 1);
      dup2(stderr_fd, 2);
      free(elf);
    }
    close(connfd);
  }
  close(srvfd);

  return 0;
}


static void*
elfldr_thread(void *args) {
  while(1) {
    elfldr_serve((const payload_args_t *)args, 9021);
    sleep(10);
  }
  return 0;
}


int
elfldr_socksrv(const payload_args_t *args) {
  pthread_t trd;

  signal(SIGCHLD, SIG_IGN);
  return pthread_create(&trd, 0, elfldr_thread, (void*)args);
}
