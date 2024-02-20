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

#include <signal.h>
#include <stdio.h>

#include <sys/syscall.h>
#include <sys/wait.h>

#include <ps5/kernel.h>

#include "elfldr.h"
#include "klog.h"
#include "pt.h"
#include "socksrv_elf.c"


/**
 * Wait for a child process to terminate.
 **/
static int
waitpid_nohang(pid_t pid) {
  pid_t res;

  while(1) {
    if((res=waitpid(pid, 0, WNOHANG)) < 0) {
      return -1;
    } else if(!res) {
      sleep(1);
      continue;
    } else {
      return -1;
    }
  }
}


/**
 * We are running inside SceRedisServer, fork and detach from it.
 **/
int
main() {
  pid_t pid;

  if((pid=syscall(SYS_rfork, RFPROC | RFNOWAIT | RFFDG))) {
    return pid;
  }

  while((pid=elfldr_find_pid("elfldr(bootstrap)")) > 0) {
    if(kill(pid, SIGKILL)) {
      klog_perror("kill");
      _exit(-1);
    }
    sleep(1);
  }

  while((pid=elfldr_find_pid("elfldr(socksrv)")) > 0) {
    if(kill(pid, SIGKILL)) {
      klog_perror("kill");
      _exit(-1);
    }
    sleep(1);
  }

  syscall(SYS_thr_set_name, -1, "elfldr(bootstrap)");
  while(1) {
    if((pid=elfldr_spawn(-1, socksrv_elf)) < 0) {
      _exit(-1);
    }

    waitpid_nohang(pid);
    sleep(3);
  }

  return 0;
}
