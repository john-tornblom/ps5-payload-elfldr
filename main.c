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

#include "elfldr.h"
#include "kern.h"
#include "libc.h"

#ifdef ELFLDR_BOOTSTRAP
#include "elfldr-socksrv_elf.c"
#endif


int
main() {
  uint8_t caps[16] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
		      0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
  uint8_t qa_flags[16];

  // enable debugging
  if(kern_get_qa_flags(qa_flags)) {
    return -1;
  }
  qa_flags[1] |= 0x03;
  if(kern_set_qa_flags(qa_flags)) {
    return -1;
  }
  if(kern_set_ucred_auth_id(getpid(), 0x4800000000010003l)) {
    return -1;
  }
  if(kern_get_ucred_caps(getpid(), caps)) {
    return -1;
  }
  
#ifdef ELFLDR_BOOTSTRAP
  return elfldr_exec("ScePartyDaemon", -1, elfldr_socksrv_elf,
		     elfldr_socksrv_elf_len);
#else
  return elfldr_socksrv("SceRedisServer");
#endif
}

