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

#include "libc.h"
#include "pt.h"
#include "syscall.h"

#define PT_READ_D   2
#define PT_WRITE_D  5
#define PT_CONTINUE 7
#define PT_STEP     9
#define PT_ATTACH   10
#define PT_DETACH   11
#define PT_IO       12
#define PT_GETREGS  33
#define PT_SETREGS  34

#define PIOD_READ_D  1
#define PIOD_WRITE_D 2


struct ptrace_io_desc {
  int    piod_op;
  void  *piod_offs;
  void  *piod_addr;
  size_t piod_len;
};


int
pt_attach(pid_t pid) {
  if(ptrace(PT_ATTACH, pid, 0, 0) == -1) {
    return -1;
  }

  if(waitpid(pid, 0, 0) == -1) {
    return -1;
  }

  return 0;
}


int
pt_detach(pid_t pid) {
  if(ptrace(PT_DETACH, pid, 0, 0) == -1) {
    return -1;
  }

  return 0;
}


int
pt_continue(pid_t pid) {
  if(ptrace(PT_CONTINUE, pid, 1, SIGCONT) == -1) {
    return -1;
  }

  return 0;
}


int
pt_getregs(pid_t pid, struct reg *r) {
  return ptrace(PT_GETREGS, pid, (intptr_t)r, 0);
}


int
pt_setregs(pid_t pid, const struct reg *r) {
  return ptrace(PT_SETREGS, pid, (intptr_t)r, 0);
}


int
pt_getint(pid_t pid, intptr_t addr) {
  return ptrace(PT_READ_D, pid, addr, 0);
}


int
pt_setint(pid_t pid, intptr_t addr, int val) {
  return ptrace(PT_WRITE_D, pid, addr, val);
}


int
pt_copyin(pid_t pid, void* buf, intptr_t addr, size_t len) {
  struct ptrace_io_desc iod = {
    .piod_op = PIOD_WRITE_D,
    .piod_offs = (void*)addr,
    .piod_addr = buf,
    .piod_len = len};

  while(ptrace(PT_IO, pid, (intptr_t)&iod, 0)) {
    if(errno != EAGAIN) {
      return -1;
    }
  }

  return 0;
}


int
pt_setchar(pid_t pid, intptr_t addr, char val) {
  return pt_copyin(pid, &val, addr, sizeof(val));
}


int
pt_setlong(pid_t pid, intptr_t addr, long val) {
  return pt_copyin(pid, &val, addr, sizeof(val));
}


static int
pt_step(int pid) {
  if(ptrace(PT_STEP, pid, (intptr_t)1, 0)) {
    return -1;
  }

  if(waitpid(pid, 0, 0) < 0) {
    return -1;
  }

  return 0;
}


uint64_t
pt_call(pid_t pid, intptr_t addr,
	uint64_t arg1, uint64_t arg2, uint64_t arg3,
	uint64_t arg4, uint64_t arg5, uint64_t arg6) {
  struct reg jmp_reg;
  struct reg bak_reg;

  if(pt_getregs(pid, &bak_reg)) {
    return -1;
  }

  memcpy(&jmp_reg, &bak_reg, sizeof(jmp_reg));
  jmp_reg.r_rip = addr;
  jmp_reg.r_rdi = arg1;
  jmp_reg.r_rsi = arg2;
  jmp_reg.r_rdx = arg3;
  jmp_reg.r_rcx = arg4;
  jmp_reg.r_r8  = arg5;
  jmp_reg.r_r9  = arg5;

  if(pt_setregs(pid, &jmp_reg)) {
    return -1;
  }

  // single step until the function returns
  while(jmp_reg.r_rsp <= bak_reg.r_rsp) {
    if(pt_step(pid)) {
      return -1;
    }
    if(pt_getregs(pid, &jmp_reg)) {
      return -1;
    }
  }

  // restore registers
  if(pt_setregs(pid, &bak_reg)) {
    return -1;
  }

  return jmp_reg.r_rax;
}


static uint64_t
pt_syscall(pid_t pid, int sysno,
	   uint64_t arg1, uint64_t arg2, uint64_t arg3,
	   uint64_t arg4, uint64_t arg5, uint64_t arg6) {
  intptr_t addr = dynlib_resolve(pid, 0x2001, "HoLVWNanBBc");
  struct reg jmp_reg;
  struct reg bak_reg;

  if(!addr) {
    return -1;
  } else {
    addr += 0xa;
  }
  
  if(pt_getregs(pid, &bak_reg)) {
    return -1;
  }

  memcpy(&jmp_reg, &bak_reg, sizeof(jmp_reg));
  jmp_reg.r_rip = addr;
  jmp_reg.r_rax = sysno;
  jmp_reg.r_rdi = arg1;
  jmp_reg.r_rsi = arg2;
  jmp_reg.r_rdx = arg3;
  jmp_reg.r_r10 = arg4;
  jmp_reg.r_r8  = arg5;
  jmp_reg.r_r9  = arg6;

  if(pt_setregs(pid, &jmp_reg)) {
    return -1;
  }

  // single step until the function returns
  while(jmp_reg.r_rsp <= bak_reg.r_rsp) {
    if(pt_step(pid)) {
      return -1;
    }
    if(pt_getregs(pid, &jmp_reg)) {
      return -1;
    }
  }

  // restore registers
  if(pt_setregs(pid, &bak_reg)) {
    return -1;
  }

  return jmp_reg.r_rax;
}


int
pt_jitshm_create(pid_t pid, intptr_t name, size_t size, int flags) {
  return (int)pt_syscall(pid, 0x215, name, size, flags, 0, 0, 0);
}


int
pt_jitshm_alias(pid_t pid, int fd, int flags) {
  return (int)pt_syscall(pid, 0x216, fd, flags, 0, 0, 0, 0);
}


intptr_t
pt_mmap(pid_t pid, intptr_t addr, size_t len, int prot, int flags,
	int fd, off_t off) {
  return pt_syscall(pid, SYS_mmap, addr, len, prot, flags, fd, off);
}


int
pt_munmap(pid_t pid, intptr_t addr, size_t len) {
  return pt_syscall(pid, SYS_munmap, addr, len, 0, 0, 0, 0);
}


int
pt_mprotect(pid_t pid, intptr_t addr, size_t len, int prot) {
  return pt_syscall(pid, SYS_mprotect, addr, len, prot, 0, 0, 0);
}


int
pt_close(pid_t pid, int fd) {
  return (int)pt_syscall(pid, SYS_close, fd, 0, 0, 0, 0, 0);
}


int
pt_socket(pid_t pid, int domain, int type, int protocol) {
  return (int)pt_syscall(pid, SYS_socket, domain, type, protocol, 0, 0, 0);
}


int
pt_setsockopt(pid_t pid, int fd, int level, int optname, intptr_t optval,
	      socklen_t optlen) {
  return (int)pt_syscall(pid, SYS_setsockopt, fd, level, optname, optval,
			 optlen, 0);
}


int
pt_bind(pid_t pid, int sockfd, intptr_t addr, socklen_t addrlen) {
  return (int)pt_syscall(pid, SYS_bind, sockfd, addr, addrlen, 0, 0, 0);
}


ssize_t
pt_recvmsg(pid_t pid, int fd, intptr_t msg, int flags) {
  return (int)pt_syscall(pid, SYS_recvmsg, fd, msg, flags, 0, 0, 0);
}


int
pt_dup2(pid_t pid, int oldfd, int newfd) {
  return (int)pt_syscall(pid, SYS_dup2, oldfd, newfd, 0, 0, 0, 0);
}


int
pt_pipe(pid_t pid, intptr_t pipefd) {
  intptr_t faddr = dynlib_resolve(pid, 0x2001, "-Jp7F+pXxNg");
  return (int)pt_call(pid, faddr, pipefd, 0, 0, 0, 0, 0);
}


void
pt_perror(pid_t pid, const char *s) {
  intptr_t faddr = dynlib_resolve(pid, 0x2001, "9BcDykPmo1I"); //__error
  intptr_t addr = pt_call(pid, faddr, 0, 0, 0, 0, 0, 0);
  int err = pt_getint(pid, addr);
  char buf[255];

  strcpy(buf, s);
  strcat(buf, ": ");
  strcat(buf, strerror(err));
  puts(buf);
}
