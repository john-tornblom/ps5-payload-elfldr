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
#include <unistd.h>

#include <ps5/kernel.h>

#include "elfldr.h"
#include "elfldr_elf.c"
#include "pt.h"


/**
 * sceKernelSpawn() is not available in libkernel_web, which is what is used by
 * the webkit exploit entry point. However, we do not actually use it during
 * bootstraping, hence we just define an empty implementation to silence the
 * linker.
 **/
int sceKernelSpawn(pid_t* pid, int dbg, const char* binpath, const char* rootpath,
		   char* const argv[]) {
  return -1;
}


int main() {
  uint8_t privcaps[16] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                          0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
  uint8_t qa_flags[16];
  uint8_t caps[16];
  int error;
  pid_t pid;

  if(kernel_get_qaflags(qa_flags)) {
    puts("[elfldr.elf] kernel_get_qa_flags() failed");
    return -1;
  }
  qa_flags[1] |= 0x03;
  if(kernel_set_qaflags(qa_flags)) {
    puts("[elfldr.elf] kernel_set_qa_flags() failed");
    return -1;
  }

  if((pid=elfldr_find_pid("ScePartyDaemon")) < 0) {
    puts("[elfldr.elf] elfldr_find_pid() failed");
    return -1;
  }

  if(pt_attach(pid)) {
    perror("[elfldr.elf] pt_attach");
    return -1;
  }

  if(kernel_get_ucred_caps(pid, caps)) {
    puts("[elfldr.elf] kern_get_ucred_caps() failed");
    pt_detach(pid);
    return -1;
  }

  if(kernel_set_ucred_caps(pid, privcaps)) {
    puts("[elfldr.elf] kern_set_ucred_caps() failed");
    pt_detach(pid);
    return -1;
  }

  error = elfldr_exec(pid, elfldr_elf);

  if(kernel_set_ucred_caps(pid, caps)) {
    puts("[elfldr.elf] kern_set_ucred_caps() failed");
    pt_detach(pid);
    return -1;
  }

  if(pt_detach(pid)) {
    perror("[elfldr.elf] pt_detach");
    return -1;
  }

  return error;
}
