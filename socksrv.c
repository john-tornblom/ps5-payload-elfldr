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

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysctl.h>
#include <sys/wait.h>

#include <ps5/kernel.h>

#include "elfldr.h"
#include "pt.h"


/**
 * Name of the process.
 **/
#define PROCNAME "elfldr.elf"


/**
 * Read an ELF from a given file descriptor.
 **/
static uint8_t*
readsock(int fd) {
  uint8_t buf[0x4000];
  uint8_t* data = 0;
  off_t offset = 0;
  ssize_t len;

  while((len=read(fd, buf, sizeof(buf)))) {
    data = realloc(data, offset + len + 1);
    if(data == 0) {
      perror("[elfldr.elf] realloc");
      return 0;
    }

    memcpy(data + offset, buf, len);
    offset += len;
  }

  data[offset] = 0;

  return data;
}


/**
 * Process connections in induvidual threads.
 **/
static void
on_connection(int fd) {
  uint8_t* elf;

  if(!(elf=readsock(fd))) {
    return;
  }

  // Check for the ELF magic header
  if(!memcmp(elf, "\x7f\x45\x4c\x46", 4)) {
    elfldr_spawn(fd, elf);
  }

  free(elf);
}


/**
 * Serve ELF loader via a socket.
 **/
static int
serve_elfldr(uint16_t port) {
  struct sockaddr_in srvaddr;
  struct sockaddr_in cliaddr;
  char ip[INET_ADDRSTRLEN];
  struct ifaddrs *ifaddr;
  int ifaddr_wait = 1;
  socklen_t socklen;
  int connfd;
  int srvfd;

  if(getifaddrs(&ifaddr) == -1) {
    perror("[elfldr.elf] getifaddrs");
    return -1;
  }

  // Enumerate all AF_INET IPs
  for(struct ifaddrs *ifa=ifaddr; ifa!=NULL; ifa=ifa->ifa_next) {
    if(ifa->ifa_addr == NULL) {
      continue;
    }

    if(ifa->ifa_addr->sa_family != AF_INET) {
      continue;
    }

    // Skip localhost
    if(!strncmp("lo", ifa->ifa_name, 2)) {
      continue;
    }

    struct sockaddr_in *in = (struct sockaddr_in*)ifa->ifa_addr;
    inet_ntop(AF_INET, &(in->sin_addr), ip, sizeof(ip));

    // Skip interfaces without an IP
    if(!strncmp("0.", ip, 2)) {
      continue;
    }
    ifaddr_wait = 0;

    printf("[elfldr.elf] Serving ELF loader on %s:%d (%s)\n", ip, port, ifa->ifa_name);
  }

  freeifaddrs(ifaddr);

  if(ifaddr_wait) {
    return 0;
  }

  if((srvfd=socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("[elfldr.elf] socket");
    return -1;
  }

  if(setsockopt(srvfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
    perror("[elfldr.elf] setsockopt");
    return -1;
  }

  memset(&srvaddr, 0, sizeof(srvaddr));
  srvaddr.sin_family = AF_INET;
  srvaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  srvaddr.sin_port = htons(port);

  if(bind(srvfd, (struct sockaddr*)&srvaddr, sizeof(srvaddr)) != 0) {
    perror("[elfldr.elf] bind");
    return -1;
  }

  if(listen(srvfd, 5) != 0) {
    perror("[elfldr.elf] listen");
    return -1;
  }

  while(1) {
    socklen = sizeof(cliaddr);
    if((connfd=accept(srvfd, (struct sockaddr*)&cliaddr, &socklen)) < 0) {
      perror("[elfldr.elf] accept");
      break;
    }

    on_connection(connfd);
    close(connfd);
  }

  return close(srvfd);
}


/**
 * Initialize stdout and stderr to /dev/console.
 **/
static void
init_stdio(void) {
  int fd = open("/dev/console", O_WRONLY);

  close(STDERR_FILENO);
  close(STDOUT_FILENO);

  dup2(fd, STDOUT_FILENO);
  dup2(fd, STDERR_FILENO);

  close(fd);
}


/**
 *
 **/
int main() {
  const int port = 9021;
  pid_t pid;

  // We are running inside SceRedisServer, fork the process
  signal(SIGCHLD, SIG_IGN);
  if((pid=syscall(SYS_rfork, RFPROC | RFNOWAIT | RFFDG))) {
    return 0;
  }

  init_stdio();
  syscall(SYS_setsid);
  signal(SIGCHLD, SIG_IGN);
  printf("[elfldr.elf] ELF loader was compiled at %s %s\n", __DATE__, __TIME__);

  // Kill existing instances of the ELF loader.
  while((pid=elfldr_find_pid(PROCNAME)) > 0) {
    if(kill(pid, SIGKILL)) {
      perror("[elfldr.elf] kill");
    }
    sleep(1);
  }

  syscall(SYS_thr_set_name, -1, PROCNAME);
  kernel_set_proc_rootdir(getpid(), kernel_get_root_vnode());

  while(1) {
    serve_elfldr(port);
    sleep(3);
  }

  return 0;
}

