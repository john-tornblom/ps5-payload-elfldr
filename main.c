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
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <sys/syscall.h>

#include <ps5/kernel.h>

#include "elfldr.h"


/**
 * Name of the process.
 **/
#define PROCNAME "elfldr.elf"


/**
 * Data structure used to send UI notifications on the PS5.
 **/
typedef struct notify_request {
  char useless1[45];
  char message[3075];
} notify_request_t;


/**
 * Send a UI notification request.
 **/
int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);


/**
 * Send a notification to the UI and stdout.
 **/
static void
notify(const char *fmt, ...) {
  notify_request_t req;
  va_list args;

  bzero(&req, sizeof req);
  va_start(args, fmt);
  vsnprintf(req.message, sizeof req.message, fmt, args);
  va_end(args);

  sceKernelSendNotificationRequest(0, &req, sizeof req, 0);
  printf("[%s] %s\n", PROCNAME, req.message);
}


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
 *
 **/
static int
serve_elfldr(uint16_t port) {
  struct sockaddr_in srvaddr;
  struct sockaddr_in cliaddr;
  char ip[INET_ADDRSTRLEN];
  struct ifaddrs *ifaddr;
  int ifaddr_wait = 1;
  socklen_t socklen;
  uint8_t* elf;
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

    // skip localhost
    if(!strncmp("lo", ifa->ifa_name, 2)) {
      continue;
    }

    struct sockaddr_in *in = (struct sockaddr_in*)ifa->ifa_addr;
    inet_ntop(AF_INET, &(in->sin_addr), ip, sizeof(ip));

    // skip interfaces without an ip
    if(!strncmp("0.", ip, 2)) {
      continue;
    }
    ifaddr_wait = 0;

    notify("Serving ELF loader on %s:%d (%s)\n", ip, port, ifa->ifa_name);
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

    if(!(elf=readsock(connfd))) {
      close(connfd);
      continue;
    }

    if(!memcmp(elf, "\x7f\x45\x4c\x46", 4)) {
      elfldr_spawn(elf);
    } else {
      write(connfd, "Not an ELF file\n", 16);
    }
    free(elf);
    close(connfd);
  }

  return close(srvfd);
}


int main() {
  const int port = 9021;
  pid_t pid;

  signal(SIGCHLD, SIG_IGN);
  if((pid=syscall(SYS_rfork, RFPROC | RFNOWAIT | RFFDG))) {
    return pid;
  }

  signal(SIGCHLD, SIG_IGN);
  while((pid=elfldr_find_pid(PROCNAME)) > 0) {
    if(kill(pid, SIGKILL)) {
      perror("[elfldr.elf] kill");
    }
    sleep(1);
  }

  syscall(SYS_setsid);
  syscall(SYS_thr_set_name, -1, PROCNAME);
  dup2(open("/dev/console", O_WRONLY), STDOUT_FILENO);
  dup2(open("/dev/console", O_WRONLY), STDERR_FILENO);
  kernel_set_proc_rootdir(getpid(), kernel_get_root_vnode());

  while(1) {
    serve_elfldr(port);
    sleep(3);
  }

  return 0;
}

