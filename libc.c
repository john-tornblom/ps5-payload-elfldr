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

#include "kern.h"
#include "libc.h"
#include "payload.h"
#include "syscall.h"


static int   (*sce_htons)(uint16_t);
static int   (*sce_sleep)(int);
static void* (*sce_malloc)(size_t);
static void* (*sce_realloc)(void*, size_t);
static void  (*sce_free)(void*);
static void* (*sce_memset)(void*, int, size_t);
static void* (*sce_memcpy)(void*, const void*, size_t);
static char* (*sce_strcpy)(const char*, const char*);
static int   (*sce_strcmp)(const char*, const char*);
static int   (*sce_strncmp)(const char*, const char*, size_t);
static int   (*sce_strcat)(char*, const char*);
static void  (*sce_puts)(const char*);
static void  (*sce_perror)(const char*);
static char* (*sce_strerror)(int);
static int*  (*sce_errno)(void);

static intptr_t sce_syscall;
asm(".intel_syntax noprefix\n"
    ".global syscall\n"
    ".type syscall @function\n"
    "syscall:\n"
    "  mov rax, rdi\n"                      // sysno
    "  mov rdi, rsi\n"                      // arg1
    "  mov rsi, rdx\n"                      // arg2
    "  mov rdx, rcx\n"                      // arg3
    "  mov r10, r8\n"                       // arg4
    "  mov r8,  r9\n"                       // arg5
    "  mov r9,  qword ptr [rsp + 8]\n"      // arg6
    "  jmp qword ptr [rip + sce_syscall]\n" // syscall
    "  ret\n"
    );


int
libc_init(const payload_args_t *args) {
  int error;

  if((error=args->sceKernelDlsym(0x2001, "htons", &sce_htons))) {
    return error;
  }
  if((error=args->sceKernelDlsym(0x2001, "sleep", &sce_sleep))) {
    return error;
  }
  if((error=args->sceKernelDlsym(0x2001, "getpid", &sce_syscall))) {
    return error;
  }
  sce_syscall += 0xa; // jump directly to syscall instruction

  if((error=args->sceKernelDlsym(0x2, "malloc", &sce_malloc))) {
    return error;
  }
  if((error=args->sceKernelDlsym(0x2, "realloc", &sce_realloc))) {
    return error;
  }
  if((error=args->sceKernelDlsym(0x2, "free", &sce_free))) {
    return error;
  }
  if((error=args->sceKernelDlsym(0x2, "memset", &sce_memset))) {
    return error;
  }
  if((error=args->sceKernelDlsym(0x2, "memcpy", &sce_memcpy))) {
    return error;
  }
  if((error=args->sceKernelDlsym(0x2, "strcpy", &sce_strcpy))) {
    return error;
  }
  if((error=args->sceKernelDlsym(0x2, "strcmp", &sce_strcmp))) {
    return error;
  }
  if((error=args->sceKernelDlsym(0x2, "strncmp", &sce_strncmp))) {
    return error;
  }
  if((error=args->sceKernelDlsym(0x2, "strcat", &sce_strcat))) {
    return error;
  }
  if((error=args->sceKernelDlsym(0x2, "puts", &sce_puts))) {
    return error;
  }
  if((error=args->sceKernelDlsym(0x2, "perror", &sce_perror))) {
    return error;
  }
  if((error=args->sceKernelDlsym(0x2, "strerror", &sce_strerror))) {
    return error;
  }
  return 0;
}


int
open(const char *path, int flags) {
  return (int)syscall(SYS_open, path, flags);
}


int
unlink(const char *path) {
  return (int)syscall(SYS_unlink, path);
}


ssize_t
read(int fd, void *buf, size_t cnt) {
  return syscall(SYS_read, fd, buf, cnt);
}


ssize_t
write(int fd, const void *buf, size_t cnt) {
  return syscall(SYS_write, fd, buf, cnt);
}


int
dup2(int oldfd, int newfd) {
  return (int)syscall(SYS_dup2, oldfd, newfd);
}


int
close(int fd) {
  return (int)syscall(SYS_close, fd);
}


int
socket(int dom, int ty, int proto) {
  return (int)syscall(SYS_socket, dom, ty, proto);
}


int
setsockopt(int fd, int lvl, int name, const void *val, socklen_t len) {
  return (int)syscall(SYS_setsockopt, fd, lvl, name, val, len);
}


int
bind(int fd, const struct sockaddr_in *addr, socklen_t addr_len) {
  return (int)syscall(SYS_bind, fd, addr, addr_len);
}


int
listen(int fd, int backlog) {
  return (int)syscall(SYS_listen, fd, backlog);
}


int
accept(int fd, struct sockaddr_in *addr, socklen_t *addr_len) {
  return (int)syscall(SYS_accept, fd, addr, addr_len);
}


ssize_t sendmsg(int fd, const struct msghdr *msg, int flags) {
  return (ssize_t)syscall(SYS_sendmsg, fd, msg, flags);
}


pid_t
getpid(void) {
  return (pid_t)syscall(SYS_getpid);
}


int
kill(pid_t pid, int sig) {
  return (int)syscall(SYS_kill, pid, sig);
}


pid_t
rfork(int flags) {
  return (pid_t)syscall(SYS_rfork, flags);
}


pid_t
waitpid(pid_t pid, int *status, int opts) {
  return (pid_t)syscall(SYS_wait4, pid, status, opts, 0);
}


int
ptrace(int request, pid_t pid, intptr_t addr, int data) {
  uint8_t privcaps[16] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                          0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
  pid_t mypid = getpid();
  uint8_t caps[16];
  uint64_t authid;
  int ret;

  if(kern_get_ucred_auth_id(mypid, &authid)) {
    return -1;
  }
  if(kern_get_ucred_caps(mypid, caps)) {
    return -1;
  }

  if(kern_set_ucred_auth_id(mypid, 0x4800000000010003l)) {
    return -1;
  }
  if(kern_set_ucred_caps(mypid, privcaps)) {
    return -1;
  }

  ret = (int)syscall(SYS_ptrace, request, pid, addr, data);

  if(kern_set_ucred_auth_id(mypid, authid)) {
    return -1;
  }
  if(kern_set_ucred_caps(mypid, caps)) {
    return -1;
  }

  return ret;
}


int
sysctl(const int *name, size_t namelen, void *oldp, size_t *oldlenp,
       const void *newp, size_t newlen) {
  return syscall(SYS___sysctl, name, namelen, oldp, oldlenp, newp, newlen);
}


int
jitshm_create(const char* name, size_t size, int flags) {
  return (int)syscall(0x215, name, size, flags);
}


int
jitshm_alias(int fd, int flags) {
  return (int)syscall(0x216, fd, flags);
}


void*
mmap(void* addr, size_t len, int prot, int flags, int fd, off_t off) {
  return (void*)syscall(SYS_mmap, addr, len, prot, flags, fd, off);
}


int
munmap(void* addr, size_t len) {
  return (int)syscall(SYS_munmap, addr, len);
}


int
mprotect(void* addr, size_t len, int prot) {
  return (int)syscall(SYS_mprotect, addr, len, prot);
}


void*
malloc(size_t len) {
  return sce_malloc(len);
}


void*
realloc(void *ptr, size_t len) {
  return sce_realloc(ptr, len);
}


void
free(void *ptr) {
  return sce_free(ptr);
}


void*
memset(void *dst, int c, size_t len) {
  return sce_memset(dst, c, len);
}


void*
memcpy(void *dst, const void* src, size_t len) {
  return sce_memcpy(dst, src, len);
}


char*
strcpy(char *dst, const char *src) {
  return sce_strcpy(dst, src);
}


int
strcmp(const char* s1, const char* s2) {
  return sce_strcmp(s1, s2);
}


int
strncmp(const char *s1, const char *s2, size_t len) {
  return sce_strncmp(s1, s2, len);
}


int
strcat(char* s1, const char* s2) {
  return sce_strcat(s1, s2);
}


uint16_t
htons(uint16_t val) {
  return sce_htons(val);
}


uint32_t
sleep(uint32_t seconds) {
  return sce_sleep(seconds);
}


void puts(const char *s) {
  sce_puts(s);
}


void
perror(const char* s) {
  sce_perror(s);
}


char*
strerror(int error) {
  return sce_strerror(error);
}


int* geterrno(void) {
  return sce_errno();
}
