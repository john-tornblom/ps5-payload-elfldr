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
#include <stdlib.h>
#include <string.h>
#include <sys/sysctl.h>

#include <ps5/kernel.h>

#include "elfldr.h"
#include "klog.h"
#include "pt.h"

#include "bootstrap_elf.c"


/**
 * Escape jail and raise privileges.
 **/
static int
raise_privileges(pid_t pid) {
  uint8_t privcaps[16] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                          0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
  intptr_t vnode;

  if(!(vnode=kernel_get_root_vnode())) {
    klog_puts("[elfldr.elf] kernel_get_root_vnode() failed");
    return -1;
  }
  if(kernel_set_proc_rootdir(pid, vnode)) {
    klog_puts("[elfldr.elf] kernel_set_proc_rootdir() failed");
    return -1;
  }
  if(kernel_set_ucred_caps(pid, privcaps)) {
    klog_puts("[elfldr.elf] kernel_set_ucred_caps() failed");
    return -1;
  }

  return 0;
}


/**
 * Attach to SceRedisServer and run bootstrap.elf.
 **/
int
main() {
  pid_t mypid = getpid();
  uint8_t qa_flags[16];
  uint8_t caps[16];
  uint64_t authid;
  intptr_t vnode;
  pid_t vpid;
  int ret;

  if(kernel_get_qaflags(qa_flags)) {
    klog_puts("[elfldr.elf] kernel_get_qa_flags() failed");
    return -1;
  }
  qa_flags[1] |= 0x03; // Enable debugging with ptrace
  if(kernel_set_qaflags(qa_flags)) {
    klog_puts("[elfldr.elf] kernel_set_qa_flags() failed");
    return -1;
  }

  // backup privileges
  if(!(vnode=kernel_get_proc_rootdir(mypid))) {
    klog_puts("[elfldr.elf] kernel_get_proc_rootdir() failed");
    return -1;
  }
  if(kernel_get_ucred_caps(mypid, caps)) {
    klog_puts("[elfldr.elf] kernel_get_ucred_caps() failed");
    return -1;
  }
  if(!(authid=kernel_get_ucred_authid(mypid))) {
    klog_puts("[elfldr.elf] kernel_get_ucred_authid() failed");
    return -1;
  }

  if((vpid=elfldr_find_pid("SceRedisServer")) < 0) {
    klog_puts("[elfldr.elf] elfldr_find_pid() failed");
    return -1;
  }

  // raise our privileges and run bootstrap.elf inside SceRedisServer
  if(!raise_privileges(mypid)) {
    if(!pt_attach(vpid)) {
      ret = elfldr_exec(vpid, -1, bootstrap_elf);
    } else {
      klog_perror("[elfldr.elf] pt_attach");
    }
  }

  // restore privileges
  if(kernel_set_proc_rootdir(mypid, vnode)) {
    klog_puts("[elfldr.elf] kernel_set_proc_rootdir() failed");
    return -1;
  }
  if(kernel_set_ucred_caps(mypid, caps)) {
    klog_puts("[elfldr.elf] kernel_set_ucred_caps() failed");
    return -1;
  }
  if(kernel_set_ucred_authid(mypid, authid)) {
    klog_puts("[elfldr.elf] kernel_set_ucred_authid() failed");
    return -1;
  }

  return ret;
}

