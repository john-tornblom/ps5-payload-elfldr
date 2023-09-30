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
#include "syscall.h"


/**
 * Parameters for the ELF loader.
 **/
#define ELFLDR_UNIX_SOCKET "/system_tmp/elfldr.sock"


/**
 * Convenient macros.
 **/
#define ROUND_PG(x) (((x) + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1))
#define TRUNC_PG(x) ((x) & ~(PAGE_SIZE - 1))
#define PFLAGS(x)   ((((x) & PF_R) ? PROT_READ  : 0) | \
		     (((x) & PF_W) ? PROT_WRITE : 0) | \
		     (((x) & PF_X) ? PROT_EXEC  : 0))


#include "payload_launchpad_elf.c"


/**
 * Load an ELF into the address space of a process with the given pid.
 **/
static intptr_t
elfldr_load(pid_t pid, uint8_t *elf, size_t size) {
  Elf64_Ehdr *ehdr = (Elf64_Ehdr*)elf;
  Elf64_Phdr *phdr = (Elf64_Phdr*)(elf + ehdr->e_phoff);
  Elf64_Shdr *shdr = (Elf64_Shdr*)(elf + ehdr->e_shoff);

  intptr_t base_addr = -1;
  size_t base_size = 0;

  size_t min_vaddr = -1;
  size_t max_vaddr = 0;

  int error = 0;

  // Sanity check, we only support 64bit ELFs.
  if(ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E' ||
     ehdr->e_ident[2] != 'L'  || ehdr->e_ident[3] != 'F') {
    puts("[elfldr.elf] elfldr_load: Malformed ELF file");
    return 0;
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
    puts("[elfldr.elf] elfldr_load: ELF type not supported");
    return 0;
  }

  // Reserve an address space of sufficient size.
  if((base_addr=pt_mmap(pid, base_addr, base_size, PROT_NONE,
			flags, -1, 0)) == -1) {
    pt_perror(pid, "[elfldr.elf] pt_mmap");
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
	pt_perror(pid, "[elfldr.elf] pt_jitshm_create");
	error = 1;
	break;
      }

      if((addr=pt_mmap(pid, addr, aligned_memsz, PFLAGS(phdr[i].p_flags),
		       MAP_FIXED | MAP_SHARED, shm_fd, 0)) == -1) {
	pt_perror(pid, "[elfldr.elf] pt_mmap");
	error = 1;
	break;
      }

      if((alias_fd=pt_jitshm_alias(pid, shm_fd, PROT_WRITE | PROT_READ)) < 0) {
	pt_perror(pid, "[elfldr.elf] pt_jitshm_alias");
	error = 1;
	break;
      }

      if((addr=pt_mmap(pid, 0, aligned_memsz, PROT_WRITE | PROT_READ,
		       MAP_SHARED, alias_fd, 0)) == -1) {
	pt_perror(pid, "[elfldr.elf] pt_mmap");
	error = 1;
	break;
      }

      if(pt_copyin(pid, elf + phdr[i].p_offset, addr, phdr[i].p_memsz)) {
	pt_perror(pid, "[elfldr.elf] pt_copyin");
	error = 1;
	break;
      }

      pt_munmap(pid, addr, aligned_memsz);
      pt_close(pid, alias_fd);
      pt_close(pid, shm_fd);
    } else {
      if((addr=pt_mmap(pid, addr, aligned_memsz, PROT_WRITE,
		       MAP_FIXED | MAP_ANONYMOUS | MAP_PRIVATE,
		       -1, 0)) == -1) {
	pt_perror(pid, "[elfldr.elf] pt_mmap");
	error = 1;
	break;
      }
      if(pt_copyin(pid, elf + phdr[i].p_offset, addr, phdr[i].p_memsz)) {
	pt_perror(pid, "[elfldr.elf] pt_copyin");
	error = 1;
	break;
      }
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
	intptr_t value_addr = (base_addr + rela[j].r_offset);
	intptr_t value = base_addr + rela[j].r_addend;
	if(pt_copyin(pid, &value, value_addr, 8)) {
	  pt_perror(pid, "[elfldr.elf] pt_copyin");
	  error = 1;
	  break;
	}
      }
    }
  }

  // Set protection bits on mapped segments.
  for(int i=0; i<ehdr->e_phnum && !error; i++) {
    size_t aligned_memsz = ROUND_PG(phdr[i].p_memsz);
    intptr_t addr = base_addr + phdr[i].p_vaddr;

    if(phdr[i].p_type != PT_LOAD || phdr[i].p_memsz == 0) {
      continue;
    }

    if(pt_mprotect(pid, addr, aligned_memsz, PFLAGS(phdr[i].p_flags))) {
      pt_perror(pid, "[elfldr.elf] pt_mprotect");
      error = 1;
      break;
    }
  }

  if(error) {
    pt_munmap(pid, base_addr, base_size);
    return 0;
  }

  return base_addr + ehdr->e_entry;
}


/**
 * Create payload args in the address space of the process with the given pid.
 **/
intptr_t
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

  pt_setint(pid, buf+0x00, 20);
  pt_setint(pid, buf+0x04, IPPROTO_IPV6);
  pt_setint(pid, buf+0x08, IPV6_TCLASS);
  pt_setint(pid, buf+0x0c, 0);
  pt_setint(pid, buf+0x10, 0);
  pt_setint(pid, buf+0x14, 0);
  if(pt_setsockopt(pid, master_sock, IPPROTO_IPV6, IPV6_2292PKTOPTIONS, buf, 24)) {
    pt_perror(pid, "[elfldr.elf] pt_setsockopt");
    return 0;
  }

  if((victim_sock=pt_socket(pid, AF_INET6, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
    pt_perror(pid, "[elfldr.elf] pt_socket");
    return 0;
  }

  pt_setint(pid, buf+0x00, 0);
  pt_setint(pid, buf+0x04, 0);
  pt_setint(pid, buf+0x08, 0);
  pt_setint(pid, buf+0x0c, 0);
  pt_setint(pid, buf+0x10, 0);
  if(pt_setsockopt(pid, victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, buf, 20)) {
    pt_perror(pid, "[elfldr.elf] pt_setsockopt");
    return 0;
  }

  if(kern_overlap_sockets(pid, master_sock, victim_sock)) {
    puts("[elfldr.elf] kern_overlap_sockets() failed");
    return 0;
  }

  if(pt_pipe(pid, buf)) {
    pt_perror(pid, "[elfldr.elf] pt_pipe");
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


/**
 * Get the pid of a process with the given name.
 **/
static pid_t
elfldr_find_pid(const char* name) {
  int mib[4] = {1, 14, 8, 0};
  pid_t pid = -1;
  size_t buf_size;
  uint8_t *buf;

  if(sysctl(mib, 4, 0, &buf_size, 0, 0)) {
    perror("[elfldr.elf] sysctl");
    return -1;
  }

  if(!(buf=malloc(buf_size))) {
    perror("[elfldr.elf] malloc");
    return -1;
  }

  if(sysctl(mib, 4, buf, &buf_size, 0, 0)) {
    perror("[elfldr.elf] sysctl");
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


/**
 * Send a file descriptor to a process that listens on a UNIX domain socket
 * with the given socket path.
 **/
static int
elfldr_sendfd(const char *sockpath, int fd) {
  struct sockaddr_un addr = {0};
  struct msghdr msg = {0};
  struct cmsghdr *cmsg;
  uint8_t buf[24];
  int sockfd;

  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, sockpath);

  memset(&msg, 0, sizeof(msg));
  msg.msg_name = &addr;
  msg.msg_namelen = sizeof(struct sockaddr_un);
  msg.msg_control = buf;
  msg.msg_controllen = sizeof(buf);
  
  memset(buf, 0, sizeof(buf));
  cmsg = (struct cmsghdr *)buf;
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type  = SCM_RIGHTS;
  cmsg->cmsg_len   = 20;
  *((int *)&buf[16]) = fd;

  if((sockfd=socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
    perror("[elfldr.elf] socket");
    return -1;
  }

  if(sendmsg(sockfd, &msg, 0) < 0) {
    perror("[elfldr.elf] sendmsg");
    close(sockfd);
    return -1;
  }

  return close(sockfd);
}


/**
 * Pipe stdout of a process with the given pid to a file descriptor, where
 * communication is done via a UNIX domain socket of the given socket path.
 **/
static int
elfldr_stdout(pid_t pid, const char *sockpath, int fd) {
  struct sockaddr_un addr = {0};
  intptr_t ptbuf;
  int sockfd;

  if((ptbuf=pt_mmap(pid, 0, PAGE_SIZE, PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0)) == -1) {
    pt_perror(pid, "[elfldr.elf] pt_mmap");
    return -1;
  }

  if((sockfd=pt_socket(pid, AF_UNIX, SOCK_DGRAM, 0)) < 0) {
    pt_perror(pid, "[elfldr.elf] pt_socket");
    pt_munmap(pid, ptbuf, PAGE_SIZE);
    return -1;
  }

  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, sockpath);
  pt_copyin(pid, &addr, ptbuf, sizeof(addr));
  if(pt_bind(pid, sockfd, ptbuf, sizeof(addr))) {
    pt_perror(pid, "[elfldr.elf] pt_bind");
    pt_munmap(pid, ptbuf, PAGE_SIZE);
    pt_close(pid, sockfd);
    return -1;
  }

  if(elfldr_sendfd(sockpath, fd)) {
    pt_munmap(pid, ptbuf, PAGE_SIZE);
    pt_close(pid, sockfd);
    return -1;
  }

  intptr_t hdr = ptbuf;
  intptr_t iov = ptbuf + 0x100;
  intptr_t control = ptbuf + 0x200;

  pt_setlong(pid, hdr + __builtin_offsetof(struct msghdr, msg_name), 0);
  pt_setint(pid, hdr + __builtin_offsetof(struct msghdr, msg_namelen), 0);
  pt_setlong(pid, hdr + __builtin_offsetof(struct msghdr, msg_iov), iov);
  pt_setint(pid, hdr + __builtin_offsetof(struct msghdr, msg_iovlen), 1);
  pt_setlong(pid, hdr + __builtin_offsetof(struct msghdr, msg_control), control);
  pt_setint(pid, hdr + __builtin_offsetof(struct msghdr, msg_controllen), 24);
  if(pt_recvmsg(pid, sockfd, hdr, 0) < 0) {
    pt_perror(pid, "[elfldr.elf] pt_recvmsg");
    pt_munmap(pid, ptbuf, PAGE_SIZE);
    pt_close(pid, sockfd);
    return -1;
  }

  if((fd=pt_getint(pid, control+16)) < 0) {
    pt_munmap(pid, ptbuf, PAGE_SIZE);
    pt_close(pid, sockfd);
    return -1;
  }

  if(pt_munmap(pid, ptbuf, PAGE_SIZE)) {
    pt_perror(pid, "[elfldr.elf] pt_munmap");
    pt_close(pid, sockfd);
    pt_close(pid, fd);
  }

  if(pt_close(pid, sockfd)) {
    pt_perror(pid, "[elfldr.elf] pt_close");
    pt_close(pid, fd);
    return -1;
  }

  return fd;
}


int
elfldr_exec(const char* procname, int stdout, uint8_t *elf, size_t size) {
  uint8_t privcaps[16] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                          0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
  uint8_t caps[16];
  intptr_t payload_entry;
  intptr_t payload_args;
  intptr_t launch_entry;
  struct reg jmp_reg;
  struct reg bak_reg;
  pid_t pid;

  if((pid=elfldr_find_pid(procname)) < 0) {
    puts("[elfldr.elf] elfldr_find_pid() failed");
    return -1;
  }

  if(pt_attach(pid)) {
    perror("[elfldr.elf] pt_attach");
    return -1;
  }

  if(kern_get_ucred_caps(pid, caps)) {
    puts("[elfldr.elf] kern_get_ucred_caps() failed");
    pt_detach(pid);
    return -1;
  }

  if(kern_set_ucred_caps(pid, privcaps)) {
    puts("[elfldr.elf] kern_set_ucred_caps() failed");
    pt_detach(pid);
    return -1;
  }

  if(pt_getregs(pid, &bak_reg)) {
    perror("[elfldr.elf] pt_getregs");
    kern_set_ucred_caps(pid, caps);
    pt_detach(pid);
    return -1;
  }
  memcpy(&jmp_reg, &bak_reg, sizeof(jmp_reg));

  if(stdout > 0) {
    unlink(ELFLDR_UNIX_SOCKET);
    if((stdout=elfldr_stdout(pid, ELFLDR_UNIX_SOCKET, stdout)) < 0) {
      puts("[elfldr.elf] elfldr_stdout() failed");
      kern_set_ucred_caps(pid, caps);
      pt_detach(pid);
      return -1;
    }
    unlink(ELFLDR_UNIX_SOCKET);
  }

  if(!(payload_entry=elfldr_load(pid, elf, size))) {
    puts("[elfldr.elf] elfldr_load() failed");
    kern_set_ucred_caps(pid, caps);
    pt_detach(pid);
    return -1;
  }

  if(!(payload_args=elfldr_payload_args(pid))) {
    puts("[elfldr.elf] elfldr_args() failed");
    kern_set_ucred_caps(pid, caps);
    pt_detach(pid);
    return -1;
  }

  if(!(launch_entry=elfldr_load(pid, payload_launchpad_elf,
				payload_launchpad_elf_len))) {
    puts("[elfldr.elf] elfldr_load() failed");
    kern_set_ucred_caps(pid, caps);
    pt_detach(pid);
    return -1;
  }

  jmp_reg.r_rip = launch_entry;
  jmp_reg.r_rsp -= 8;
  jmp_reg.r_rdi = payload_entry;
  jmp_reg.r_rsi = payload_args;
  jmp_reg.r_rdx = stdout;
  if(pt_setregs(pid, &jmp_reg)) {
    perror("[elfldr.elf] pt_setregs");
    kern_set_ucred_caps(pid, caps);
    pt_detach(pid);
    return -1;
  }

  if(pt_continue(pid)) {
    perror("[elfldr.elf] pt_continue");
    kern_set_ucred_caps(pid, caps);
    pt_detach(pid);
    return -1;
  }
  if(waitpid(pid, 0, 0) == -1) {
    perror("[elfldr.elf] waitpid");
    kern_set_ucred_caps(pid, caps);
    pt_detach(pid);
  }

  if(pt_setregs(pid, &bak_reg)) {
    perror("[elfldr.elf] pt_setregs");
    kern_set_ucred_caps(pid, caps);
    pt_detach(pid);
    return -1;
  }

  puts("[elfldr.elf] running ELF...");
  kern_set_ucred_caps(pid, caps);
  if(pt_detach(pid)) {
    perror("[elfldr.elf] pt_detach");
    return -1;
  }

  return 0;
}


/**
 * Read an ELF from a given socket connection.
 **/
static ssize_t
elfldr_read(int connfd, uint8_t **data) {
  uint8_t buf[0x4000];
  off_t offset = 0;
  ssize_t len;

  *data = 0;
  while((len=read(connfd, buf, sizeof(buf)))) {
    *data = realloc(*data, offset + len);
    if(*data == 0) {
      perror("[elfldr.elf] realloc");
      return -1;
    }

    memcpy(*data + offset, buf, len);
    offset += len;
  }

  return offset;
}


/**
 * Accept ELFs from the given port, and execute them inside the process
 * with the given name.
 **/
int
elfldr_serve(const char* procname, uint16_t port) {
  struct sockaddr_in server_addr;
  struct sockaddr_in client_addr;
  socklen_t addr_len;

  uint8_t *elf;
  size_t size;

  int connfd;
  int srvfd;

  //
  // launch socket server
  //
  if((srvfd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("[elfldr.elf] socket");
    return -1;
  }

  if(setsockopt(srvfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
    perror("[elfldr.elf] setsockopt");
    close(srvfd);
    return -1;
  }

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(port);

  if(bind(srvfd, &server_addr, sizeof(server_addr)) != 0) {
    perror("[elfldr.elf] bind");
    close(srvfd);
    return -1;
  }

  if(listen(srvfd, 5) != 0) {
    perror("[elfldr.elf] listen");
    close(srvfd);
    return -1;
  }

  addr_len = sizeof(client_addr);
  while(1) {
    if((connfd=accept(srvfd, &client_addr, &addr_len)) < 0) {
      perror("[elfldr.elf] accept");
      close(connfd);
      close(srvfd);
      return -1;
    }

    // We got a connection, read ELF and launch it in the given process.
    if((size=elfldr_read(connfd, &elf))) {
      elfldr_exec(procname, connfd, elf, size);
      free(elf);
    }
    close(connfd);
  }
  close(srvfd);

  return 0;
}


int
elfldr_socksrv(const char* procname, uint16_t port) {
  pid_t pid;

  // kill previous instances of elfldr.elf
  while((pid=elfldr_find_pid("elfldr.elf")) > 0) {
    if(kill(pid, SIGKILL)) {
      perror("[elfldr.elf] kill");
    }
    sleep(1);
  }

  // fork process
  if((pid=syscall(SYS_rfork, RFPROC | RFNOWAIT | RFFDG)) < 0) {
    perror("[elfldr.elf] rfork");
    return -1;
  }
  // parent process should just return
  if(pid) {
    return pid;
  }

  // initialize child process
  syscall(SYS_setsid);              // become session leader
  syscall(0x1d0, -1, "elfldr.elf"); // set proc name
  dup2(open("/dev/console", 1), 1); // set stdout to /dev/klog
  dup2(open("/dev/console", 2), 1); // set stderr to /dev/klog

  while(1) {
    puts("[elfldr.elf] Launching socket server...");
    elfldr_serve(procname, port);
    sleep(10);
  }

  // unreacheable
  return syscall(SYS_exit, 0);
}
