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

#include <stdio.h>

#include <ps5/kernel.h>

#include "elfldr.h"
#include "pt.h"

#include "socksrv_elf.c"


/**
 * Attach to SceRedisServer and run socksrv.elf.
 **/
int
main() {
  uint8_t qa_flags[16];
  uint8_t caps[16];
  intptr_t vnode;
  pid_t pid;
  int ret;

  if(kernel_get_qaflags(qa_flags)) {
    puts("[elfldr.elf] kernel_get_qa_flags() failed");
    return -1;
  }
  qa_flags[1] |= 0x03; // Enable debugging with ptrace
  if(kernel_set_qaflags(qa_flags)) {
    puts("[elfldr.elf] kernel_set_qa_flags() failed");
    return -1;
  }

  if((pid=elfldr_find_pid("SceRedisServer")) < 0) {
    puts("[elfldr.elf] elfldr_find_pid() failed");
    return -1;
  }

  // backup privileges
  if(!(vnode=kernel_get_proc_rootdir(pid))) {
    puts("[elfldr.elf] kernel_get_proc_rootdir() failed");
    return -1;
  }
  if(kernel_get_ucred_caps(pid, caps)) {
    puts("[elfldr.elf] kernel_get_ucred_caps() failed");
    return -1;
  }

  if(pt_attach(pid)) {
    perror("[elfldr.elf] pt_attach");
    return -1;
  }

  ret = elfldr_exec(pid, socksrv_elf);

  // restore privileges
  if(kernel_set_proc_rootdir(pid, vnode)) {
    puts("[elfldr.elf] kernel_set_proc_rootdir() failed");
    return -1;
  }
  if(kernel_set_ucred_caps(pid, caps)) {
    puts("[elfldr.elf] kernel_set_ucred_caps() failed");
    return -1;
  }

  return ret;
}

