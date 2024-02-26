/* Copyright (C) 2024 John Törnblom

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

#include <elf.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>

#include <sys/un.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <ps5/kernel.h>
#include <ps5/mdbg.h>

#include "elfldr.h"
#include "klog.h"
#include "pt.h"


#ifndef IPV6_2292PKTOPTIONS
#define IPV6_2292PKTOPTIONS 25
#endif


/**
 * Convenient macros.
 **/
#define ROUND_PG(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x) ((x) & ~(PAGE_SIZE - 1))
#define PFLAGS(x)   ((((x) & PF_R) ? PROT_READ  : 0) | \
		     (((x) & PF_W) ? PROT_WRITE : 0) | \
		     (((x) & PF_X) ? PROT_EXEC  : 0))


/**
 * Context structure for the ELF loader.
 **/
typedef struct elfldr_ctx {
  uint8_t* elf;
  pid_t    pid;

  intptr_t base_addr;
  size_t   base_size;
} elfldr_ctx_t;


/**
 * Absolute path to the SceSpZeroConf eboot.
 **/
static const char* SceSpZeroConf = "/system/vsh/app/NPXS40112/eboot.bin";


/**
* Parse a R_X86_64_RELATIVE relocatable.
**/
static int
r_relative(elfldr_ctx_t *ctx, Elf64_Rela* rela) {
  intptr_t loc = ctx->base_addr + rela->r_offset;
  intptr_t val = ctx->base_addr + rela->r_addend;

  return mdbg_copyin(ctx->pid, &val, loc, sizeof(val));
}


/**
 * Parse a PT_LOAD program header.
 **/
static int
pt_load(elfldr_ctx_t *ctx, Elf64_Phdr *phdr) {
  intptr_t addr = ctx->base_addr + phdr->p_vaddr;
  size_t memsz = ROUND_PG(phdr->p_memsz);

  if(!phdr->p_memsz) {
    return 0;
  }

  if((addr=pt_mmap(ctx->pid, addr, memsz, PROT_WRITE | PROT_READ,
		   MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
		   -1, 0)) == -1) {
    pt_perror(ctx->pid, "[elfldr.elf] mmap");
    return -1;
  }

  if(!phdr->p_filesz) {
    return 0;
  }

  if(mdbg_copyin(ctx->pid, ctx->elf+phdr->p_offset, addr, phdr->p_filesz)) {
    pt_perror(ctx->pid, "[elfldr.elf] mdbg_copyin");
    return -1;
  }

  return 0;
}


/**
 * Reload a PT_LOAD program header with executable permissions.
 **/
static int
pt_reload(elfldr_ctx_t *ctx, Elf64_Phdr *phdr) {
  intptr_t addr = ctx->base_addr + phdr->p_vaddr;
  size_t memsz = ROUND_PG(phdr->p_memsz);
  int prot = PFLAGS(phdr->p_flags);
  int alias_fd = -1;
  int shm_fd = -1;
  void* data = 0;
  int error = 0;

  if(!(data=malloc(memsz))) {
    klog_perror("[elfldr.elf] malloc");
    return -1;
  }

  // Backup data
  else if(mdbg_copyout(ctx->pid, addr, data, memsz)) {
    pt_perror(ctx->pid, "[elfldr.elf] mdbg_copyout");
    error = -1;
  }

  // Create shm with executable permissions.
  else if((shm_fd=pt_jitshm_create(ctx->pid, 0, memsz,
				   prot | PROT_READ | PROT_WRITE)) < 0) {
    pt_perror(ctx->pid, "[elfldr.elf] jitshm_create");
    error = -1;
  }

  // Map shm into an executable address space.
  else if((addr=pt_mmap(ctx->pid, addr, memsz, prot,
			MAP_FIXED | MAP_PRIVATE,
			shm_fd, 0)) == -1) {
    pt_perror(ctx->pid, "[elfldr.elf] mmap");
    error = -1;
  }

  // Create an shm alias fd with write permissions.
  else if((alias_fd=pt_jitshm_alias(ctx->pid, shm_fd,
				    PROT_READ | PROT_WRITE)) < 0) {
    pt_perror(ctx->pid, "[elfldr.elf] jitshm_alias");
    error = -1;
  }

  // Map shm alias into a writable address space.
  else if((addr=pt_mmap(ctx->pid, 0, memsz, PROT_READ | PROT_WRITE, MAP_SHARED,
			alias_fd, 0)) == -1) {
    pt_perror(ctx->pid, "[elfldr.elf] mmap");
    error = -1;
  }

  // Resore data
  else {
    if(mdbg_copyin(ctx->pid, data, addr, memsz)) {
      pt_perror(ctx->pid, "[elfldr.elf] mdbg_copyin");
      error = -1;
    }
    pt_msync(ctx->pid, addr, memsz, MS_SYNC);
    pt_munmap(ctx->pid, addr, memsz);
  }

  free(data);
  pt_close(ctx->pid, alias_fd);
  pt_close(ctx->pid, shm_fd);

  return error;
}


/**
 * Load an ELF into the address space of a process with the given pid.
 **/
static intptr_t
elfldr_load(pid_t pid, uint8_t *elf) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr*)elf;
  Elf64_Phdr *phdr = (Elf64_Phdr*)(elf + ehdr->e_phoff);
  Elf64_Shdr *shdr = (Elf64_Shdr*)(elf + ehdr->e_shoff);

  elfldr_ctx_t ctx = {.elf = elf, .pid=pid};

  size_t min_vaddr = -1;
  size_t max_vaddr = 0;

  int error = 0;

  // Sanity check, we only support 64bit ELFs.
  if(ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E' ||
     ehdr->e_ident[2] != 'L'  || ehdr->e_ident[3] != 'F') {
    klog_puts("[elfldr.elf] elfldr_load: Malformed ELF file");
    return 0;
  }

  // Compute size of virtual memory region.
  for(int i=0; i<ehdr->e_phnum; i++) {
    if(phdr[i].p_vaddr < min_vaddr) {
      min_vaddr = phdr[i].p_vaddr;
    }

    if(max_vaddr < phdr[i].p_vaddr + phdr[i].p_memsz) {
      max_vaddr = phdr[i].p_vaddr + phdr[i].p_memsz;
    }
  }

  min_vaddr = TRUNC_PG(min_vaddr);
  max_vaddr = ROUND_PG(max_vaddr);
  ctx.base_size = max_vaddr - min_vaddr;

  int flags = MAP_PRIVATE | MAP_ANONYMOUS;
  int prot = PROT_READ | PROT_WRITE;
  if(ehdr->e_type == ET_DYN) {
    ctx.base_addr = 0;
  } else if(ehdr->e_type == ET_EXEC) {
    ctx.base_addr = min_vaddr;
    flags |= MAP_FIXED;
  } else {
    puts("[elfldr.elf] elfldr_load: ELF type not supported");
    return 0;
  }

  // Reserve an address space of sufficient size.
  if((ctx.base_addr=pt_mmap(pid, ctx.base_addr, ctx.base_size, prot,
			    flags, -1, 0)) == -1) {
    pt_perror(pid, "[elfldr.elf] pt_mmap");
    return 0;
  }

  // Parse program headers.
  for(int i=0; i<ehdr->e_phnum && !error; i++) {
    switch(phdr[i].p_type) {
    case PT_LOAD:
      error = pt_load(&ctx, &phdr[i]);
      break;
    }
  }

  // Apply relocations.
  for(int i=0; i<ehdr->e_shnum && !error; i++) {
    if(shdr[i].sh_type != SHT_RELA) {
      continue;
    }

    Elf64_Rela* rela = (Elf64_Rela*)(elf + shdr[i].sh_offset);
    for(int j=0; j<shdr[i].sh_size/sizeof(Elf64_Rela); j++) {
      switch(rela[j].r_info & 0xffffffffl) {
      case R_X86_64_RELATIVE:
	error = r_relative(&ctx, &rela[j]);
	break;
      }
    }
  }

  // Set protection bits on mapped segments.
  for(int i=0; i<ehdr->e_phnum && !error; i++) {
    if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
      continue;
    }

    if(phdr[i].p_flags & PF_X) {
      error = pt_reload(&ctx, &phdr[i]);
    } else {
      if(pt_mprotect(pid, ctx.base_addr + phdr[i].p_vaddr,
		     ROUND_PG(phdr[i].p_memsz),
		     PFLAGS(phdr[i].p_flags))) {
	pt_perror(pid, "[elfldr.elf] pt_mprotect");
	error = 1;
      }
    }
  }

  if(pt_msync(pid, ctx.base_addr, ctx.base_size, MS_SYNC)) {
    pt_perror(pid, "[elfldr.elf] pt_msync");
    error = 1;
  }

  if(error) {
    pt_munmap(pid, ctx.base_addr, ctx.base_size);
    return 0;
  }

  return ctx.base_addr + ehdr->e_entry;
}




/**
 * Create payload args in the address space of the process with the given pid.
 **/
static intptr_t
elfldr_payload_args(pid_t pid) {
  int victim_sock;
  int master_sock;
  intptr_t buf;
  int pipe0;
  int pipe1;

  if((buf=pt_mmap(pid, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
		  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) == -1) {
    pt_perror(pid, "[elfldr.elf] pt_mmap");
    return 0;
  }

  if((master_sock=pt_socket(pid, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    pt_perror(pid, "[elfldr.elf] pt_socket");
    return 0;
  }

  mdbg_setint(pid, buf+0x00, 20);
  mdbg_setint(pid, buf+0x04, IPPROTO_IPV6);
  mdbg_setint(pid, buf+0x08, IPV6_TCLASS);
  mdbg_setint(pid, buf+0x0c, 0);
  mdbg_setint(pid, buf+0x10, 0);
  mdbg_setint(pid, buf+0x14, 0);
  if(pt_setsockopt(pid, master_sock, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, buf, 24)) {
    pt_perror(pid, "[elfldr.elf] pt_setsockopt");
    return 0;
  }

  if((victim_sock=pt_socket(pid, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    pt_perror(pid, "[elfldr.elf] pt_socket");
    return 0;
  }

  mdbg_setint(pid, buf+0x00, 0);
  mdbg_setint(pid, buf+0x04, 0);
  mdbg_setint(pid, buf+0x08, 0);
  mdbg_setint(pid, buf+0x0c, 0);
  mdbg_setint(pid, buf+0x10, 0);
  if(pt_setsockopt(pid, victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, buf, 20)) {
    pt_perror(pid, "[elfldr.elf] pt_setsockopt");
    return 0;
  }

  if(kernel_overlap_sockets(pid, master_sock, victim_sock)) {
    puts("[elfldr.elf] kernel_overlap_sockets() failed");
    return 0;
  }

  if(pt_pipe(pid, buf)) {
    pt_perror(pid, "[elfldr.elf] pt_pipe");
    return 0;
  }
  pipe0 = pt_getint(pid, buf);
  pipe1 = pt_getint(pid, buf+4);

  intptr_t args       = buf;
  intptr_t dlsym      = pt_resolve(pid, "LwG8g3niqwA");
  intptr_t rwpipe     = buf + 0x100;
  intptr_t rwpair     = buf + 0x200;
  intptr_t kpipe_addr = kernel_get_proc_file(pid, pipe0);
  intptr_t payloadout = buf + 0x300;

  mdbg_setlong(pid, args + 0x00, dlsym);
  mdbg_setlong(pid, args + 0x08, rwpipe);
  mdbg_setlong(pid, args + 0x10, rwpair);
  mdbg_setlong(pid, args + 0x18, kpipe_addr);
  mdbg_setlong(pid, args + 0x20, KERNEL_ADDRESS_DATA_BASE);
  mdbg_setlong(pid, args + 0x28, payloadout);
  mdbg_setint(pid, rwpipe + 0, pipe0);
  mdbg_setint(pid, rwpipe + 4, pipe1);
  mdbg_setint(pid, rwpair + 0, master_sock);
  mdbg_setint(pid, rwpair + 4, victim_sock);
  mdbg_setint(pid, payloadout, 0);

  return args;
}


/**
 * Prepare registers of a process for execution of an ELF.
 **/
static int
elfldr_prepare_exec(pid_t pid, uint8_t *elf) {
  intptr_t entry;
  intptr_t args;
  struct reg r;

  if(pt_getregs(pid, &r)) {
    klog_perror("[elfldr.elf] pt_getregs");
    return -1;
  }

  if(!(entry=elfldr_load(pid, elf))) {
    klog_puts("[elfldr.elf] elfldr_load() failed");
    return -1;
  }

  if(!(args=elfldr_payload_args(pid))) {
    klog_puts("[elfldr.elf] elfldr_payload_args() failed");
    return -1;
  }

  r.r_rip = entry;
  r.r_rdi = args;
  r.r_rsi = 0; // argc
  r.r_rdx = 0; // argv
  r.r_r10 = 0; // envp

  if(pt_setregs(pid, &r)) {
    klog_perror("[elfldr.elf] pt_setregs");
    return -1;
  }

  return 0;
}


/**
 * Set the name of a process.
 **/
static int
elfldr_set_procname(pid_t pid, const char* name) {
  intptr_t buf;

  if((buf=pt_mmap(pid, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
		  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) == -1) {
    pt_perror(pid, "[elfldr.elf] pt_mmap");
    return -1;
  }

  mdbg_copyin(pid, name, buf, strlen(name)+1);
  pt_syscall(pid, SYS_thr_set_name, -1, buf);
  pt_msync(pid, buf, PAGE_SIZE, MS_SYNC);
  pt_munmap(pid, buf, PAGE_SIZE);

  return 0;
}


/**
 * Escape jail and raise privileges.
 **/
int
elfldr_raise_privileges(pid_t pid) {
  uint8_t caps[16] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
  intptr_t vnode;

  if(!(vnode=kernel_get_root_vnode())) {
    return -1;
  }
  if(kernel_set_proc_rootdir(pid, vnode)) {
    return -1;
  }
  if(kernel_set_proc_jaildir(pid, 0)) {
    return -1;
  }
  if(kernel_set_ucred_uid(pid, 0)) {
    return -1;
  }
  if(kernel_set_ucred_caps(pid, caps)) {
    return -1;
  }

  return 0;
}


/**
 * Execute an ELF inside the process with the given pid.
 **/
int
elfldr_exec(pid_t pid, int stdio, uint8_t* elf) {
  uint8_t caps[16];
  intptr_t jaildir;
  intptr_t rootdir;
  uint64_t authid;
  int error = 0;

  // backup privileges
  jaildir = kernel_get_proc_jaildir(pid);
  if(!(rootdir=kernel_get_proc_rootdir(pid))) {
    klog_puts("[elfldr.elf] kernel_get_proc_rootdir() failed");
    pt_detach(pid);
    return -1;
  }
  if(kernel_get_ucred_caps(pid, caps)) {
    klog_puts("[elfldr.elf] kernel_get_ucred_caps() failed");
    pt_detach(pid);
    return -1;
  }
  if(!(authid=kernel_get_ucred_authid(pid))) {
    klog_puts("[elfldr.elf] kernel_get_ucred_authid() failed");
    pt_detach(pid);
    return -1;
  }

  if(elfldr_raise_privileges(pid)) {
    klog_puts("[elfldr.elf] Unable to raise privileges");
    pt_detach(pid);
    return -1;
  }

  if(stdio > 0) {
    stdio = pt_rdup(pid, getpid(), stdio);

    pt_close(pid, STDERR_FILENO);
    pt_close(pid, STDOUT_FILENO);
    pt_close(pid, STDIN_FILENO);

    pt_dup2(pid, stdio, STDIN_FILENO);
    pt_dup2(pid, stdio, STDOUT_FILENO);
    pt_dup2(pid, stdio, STDERR_FILENO);

    pt_close(pid, stdio);
  }

  if(elfldr_prepare_exec(pid, elf)) {
    error = -1;
  }

  // restore privileges
  if(kernel_set_proc_jaildir(pid, jaildir)) {
    klog_puts("[elfldr.elf] kernel_set_proc_jaildir() failed");
    error = -1;
  }
  if(kernel_set_proc_rootdir(pid, rootdir)) {
    klog_puts("[elfldr.elf] kernel_set_proc_rootdir() failed");
    error = -1;
  }

  if(kernel_set_ucred_caps(pid, caps)) {
    klog_puts("[elfldr.elf] kernel_set_ucred_caps() failed");
    error = -1;
  }
  if(kernel_set_ucred_authid(pid, authid)) {
    klog_puts("[elfldr.elf] kernel_set_ucred_authid() failed");
    error = -1;
  }

  if(pt_detach(pid)) {
    klog_perror("[elfldr.elf] pt_detach");
    error = -1;
  }

  return error;
}


/**
 * Execute an ELF inside a new process.
 **/
pid_t
elfldr_spawn(int stdio, uint8_t* elf) {
  char* argv[] = {"homebrew", 0};
  uint8_t int3instr = 0xcc;
  struct kevent evt;
  intptr_t brkpoint;
  uint8_t orginstr;
  pid_t pid = -1;
  int kq;

  if((kq=kqueue()) < 0) {
    klog_perror("[elfldr.elf] kqueue");
    return -1;
  }

  if((pid=syscall(SYS_rfork, RFPROC | RFCFDG)) < 0) {
    klog_perror("[elfldr.elf] rfork");
    close(kq);
    return pid;
  }

  if(!pid) {
    if(open("/dev/deci_stdin", O_RDONLY) < 0) {
      klog_perror("open");
      _exit(-1);
    }
    if(open("/dev/deci_stdout", O_WRONLY) < 0) {
      klog_perror("open");
      _exit(-1);
    }
    if(open("/dev/deci_stderr", O_WRONLY) < 0) {
      klog_perror("open");
      _exit(-1);
    }

    if(syscall(SYS_ptrace, PT_TRACE_ME, 0, 0, 0) < 0) {
      klog_perror("[elfldr.elf] ptrace");
      _exit(-1);
    }

    if(execve(SceSpZeroConf, argv, 0) < 0) {
      klog_perror("[elfldr.elf] execve");
      _exit(-1);
    }
    _exit(-1);
  }

  EV_SET(&evt, pid, EVFILT_PROC, EV_ADD, NOTE_EXEC | NOTE_EXIT, 0, NULL);
  if(kevent(kq, &evt, 1, &evt, 1, NULL) < 0) {
    klog_perror("[elfldr.elf] kevent");
    kill(pid, SIGKILL);
    pt_detach(pid);
    close(kq);
    return -1;
  }

  close(kq);
  if(waitpid(pid, 0, 0) < 0) {
    klog_perror("[elfldr.elf] waitpid");
    pt_continue(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }

  // The proc is now in the STOP state, with the instruction pointer pointing at
  // the libkernel entry. Insert a breakpoint at the eboot entry.
  if(!(brkpoint=kernel_dynlib_entry_addr(pid, 0))) {
    klog_puts("[elfldr.elf] kernel_dynlib_entry_addr() failed");
    kill(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }
  brkpoint += 58;// offset to invocation of main()
  if(mdbg_copyout(pid, brkpoint, &orginstr, sizeof(orginstr))) {
    klog_perror("[elfldr.elf] mdbg_copyout");
    kill(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }
  if(mdbg_copyin(pid, &int3instr, brkpoint, sizeof(int3instr))) {
    klog_perror("[elfldr.elf] mdbg_copyin");
    kill(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }

  // Continue execution until we hit the breakpoint, then remove it.
  if(pt_continue(pid, SIGCONT)) {
    klog_perror("[elfldr.elf] pt_continue");
    kill(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }
  if(waitpid(pid, 0, 0) == -1) {
    klog_perror("[elfldr.elf] waitpid");
    kill(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }
  if(mdbg_copyin(pid, &orginstr, brkpoint, sizeof(orginstr))) {
    klog_perror("[elfldr.elf] mdbg_copyin");
    kill(pid, SIGKILL);
    pt_detach(pid);
    return -1;
  }

  // Execute the ELF
  elfldr_set_procname(pid, "homebrew");
  if(elfldr_exec(pid, stdio, elf)) {
    kill(pid, SIGKILL);
    return -1;
  }

  return pid;
}


/**
 * Fint the pid of a process with the given name.
 **/
pid_t
elfldr_find_pid(const char* name) {
  int mib[4] = {1, 14, 8, 0};
  pid_t pid = -1;
  size_t buf_size;
  uint8_t *buf;

  if(sysctl(mib, 4, 0, &buf_size, 0, 0)) {
    klog_perror("[elfldr.elf] sysctl");
    return -1;
  }

  if(!(buf=malloc(buf_size))) {
    klog_perror("[elfldr.elf] malloc");
    return -1;
  }

  if(sysctl(mib, 4, buf, &buf_size, 0, 0)) {
    klog_perror("[elfldr.elf] sysctl");
    free(buf);
    return -1;
  }

  for(uint8_t *ptr=buf; ptr<(buf+buf_size);) {
    int ki_structsize = *(int*)ptr;
    pid_t ki_pid = *(pid_t*)&ptr[72];
    char *ki_tdname = (char*)&ptr[447];

    ptr += ki_structsize;
    if(!strcmp(name, ki_tdname)) {
      pid = ki_pid;
    }
  }

  free(buf);

  return pid;
}

