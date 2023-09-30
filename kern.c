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
#include "kern.h"
#include "payload.h"


static int (*sysctlbyname)(const char*, void*, size_t*, const void*, size_t);

static intptr_t ADDRESS_DATA_BASE      = 0;
static intptr_t ADDRESS_ALLPROC        = 0;
static intptr_t ADDRESS_QA_FLAGS       = 0;

static off_t OFFSET_PROC_P_UCRED = 0x40;
static off_t OFFSET_PROC_P_PID   = 0xBC;

static off_t OFFSET_UCRED_CR_SCEAUTHID = 0x58;
static off_t OFFSET_UCRED_CR_SCECAPS   = 0x60;


static int master_sock = -1;
static int victim_sock = -1;
static int rw_pipe[2] = {-1, -1};
static intptr_t pipe_addr = 0;


static uint32_t
kern_get_fw_version(void) {
  uint32_t version = 0;
  size_t size = sizeof(version);

  if(sysctlbyname("kern.sdk_version", &version, &size, 0, 0)) {
    return 0;
  }

  return version;
}


/**
 *
 **/
int
kern_init(const payload_args_t *args) {
  int error = 0;

  if((error=args->sceKernelDlsym(0x2001, "sysctlbyname", &sysctlbyname))) {
    return error;
  }

  if((master_sock=args->rwpair[0]) < 0) {
    return -1;
  }

  if((victim_sock=args->rwpair[1]) < 0) {
    return -1;
  }

  if((rw_pipe[0]=args->rwpipe[0]) < 0) {
    return -1;
  }

  if((rw_pipe[1]=args->rwpipe[1]) < 0) {
    return -1;
  }

  if(!(pipe_addr=args->kpipe_addr)) {
    return -1;
  }

  if(!(ADDRESS_DATA_BASE=args->kdata_base_addr)) {
    return -1;
  }

  switch(kern_get_fw_version() & 0xffff0000) {
  case 0x3000000:
  case 0x3100000:
  case 0x3200000:
  case 0x3210000:
    ADDRESS_ALLPROC        = ADDRESS_DATA_BASE + 0x276DC58;
    ADDRESS_QA_FLAGS       = ADDRESS_DATA_BASE + 0x6466498;
    break;

  case 0x4020000:
    ADDRESS_ALLPROC        = ADDRESS_DATA_BASE + 0x27EDCB8;
    ADDRESS_QA_FLAGS       = ADDRESS_DATA_BASE + 0x6505498;
    break;

  case 0x4000000:
  case 0x4030000:
  case 0x4500000:
  case 0x4510000:
    ADDRESS_ALLPROC        = ADDRESS_DATA_BASE + 0x27EDCB8;
    ADDRESS_QA_FLAGS       = ADDRESS_DATA_BASE + 0x6506498;
    break;

  default:
    return -1;
  }

  return 0;
}


static int
kern_write(intptr_t addr, unsigned long *data) {
  intptr_t victim_buf[3];

  // sanity check for invalid kernel pointers
  if(!(addr & 0xffff000000000000)) {
    return -1;
  }

  victim_buf[0] = addr;
  victim_buf[1] = 0;
  victim_buf[2] = 0;

  if(setsockopt(master_sock, IPPROTO_IPV6, IPV6_PKTINFO, victim_buf, 0x14)) {
    return -1;
  }

  if(setsockopt(victim_sock, IPPROTO_IPV6, IPV6_PKTINFO, data, 0x14)) {
    return -1;
  }

  return 0;
}


int
kern_copyin(const void *udaddr, intptr_t kaddr, size_t len) {
  intptr_t write_buf[3];

  // Set pipe flags
  write_buf[0] = 0;
  write_buf[1] = 0x4000000000000000;
  write_buf[2] = 0;
  if(kern_write(pipe_addr, (unsigned long *) &write_buf)) {
    return -1;
  }

  // Set pipe data addr
  write_buf[0] = kaddr;
  write_buf[1] = 0;
  write_buf[2] = 0;
  if(kern_write(pipe_addr + 0x10, (unsigned long *) &write_buf)) {
    return -1;
  }

  // Perform write across pipe
  if(write(rw_pipe[1], udaddr, len) < 0) {
    return -1;
  }

  return 0;
}


int
kern_copyout(intptr_t kaddr, void *udaddr, size_t len) {
  intptr_t write_buf[3];

  // Set pipe flags
  write_buf[0] = 0x4000000040000000;
  write_buf[1] = 0x4000000000000000;
  write_buf[2] = 0;
  if(kern_write(pipe_addr, (unsigned long *) &write_buf)) {
    return -1;
  }

  // Set pipe data addr
  write_buf[0] = kaddr;
  write_buf[1] = 0;
  write_buf[2] = 0;
  if(kern_write(pipe_addr + 0x10, (unsigned long *) &write_buf)) {
    return -1;
  }

  // Perform read across pipe
  if(read(rw_pipe[0], udaddr, len) < 0) {
    return -1;
  }

  return 0;
}


intptr_t
kern_get_data_baseaddr(void) {
  return ADDRESS_DATA_BASE;
}


int
kern_get_qa_flags(uint8_t val[16]) {
  return kern_copyout(ADDRESS_QA_FLAGS, val, 16);
}

int
kern_set_qa_flags(const uint8_t val[16]) {
  return kern_copyin(val, ADDRESS_QA_FLAGS, 16);
}


intptr_t
kern_get_proc(pid_t pid) {
  pid_t other_pid = 0;
  intptr_t addr = 0;
  intptr_t next = 0;

  if(kern_copyout(ADDRESS_ALLPROC, &addr, sizeof(addr))) {
    return 0;
  }

  while(addr) {
    if(kern_copyout(addr + OFFSET_PROC_P_PID, &other_pid,
		      sizeof(other_pid))) {
      return 0;
    }

    if(pid == other_pid) {
      break;
    }

    if(kern_copyout(addr, &next, sizeof(next))) {
      return 0;
    }

    addr = next;
  }

  return addr;
}


static intptr_t
kern_get_proc_ucred(pid_t pid) {
  intptr_t proc = 0;
  intptr_t ucred = 0;

  if(!(proc=kern_get_proc(pid))) {
    return 0;
  }

  if(kern_copyout(proc + OFFSET_PROC_P_UCRED, &ucred,
		    sizeof(ucred))) {
    return 0;
  }

  return ucred;
}


int
kern_get_ucred_auth_id(pid_t pid, uint64_t *val) {
  intptr_t ucred = 0;

  if(!(ucred=kern_get_proc_ucred(pid))) {
    return -1;
  }

  if(kern_copyout(ucred + OFFSET_UCRED_CR_SCEAUTHID, val, 8)) {
    return -1;
  }

  return 0;
}


int
kern_set_ucred_auth_id(pid_t pid, uint64_t val) {
  intptr_t ucred = 0;

  if(!(ucred=kern_get_proc_ucred(pid))) {
    return -1;
  }

  if(kern_copyin(&val, ucred + OFFSET_UCRED_CR_SCEAUTHID, 8)) {
    return -1;
  }

  return 0;
}


int
kern_get_ucred_caps(pid_t pid, uint8_t caps[16]) {
  intptr_t ucred = 0;

  if(!(ucred=kern_get_proc_ucred(pid))) {
    return -1;
  }

  if(kern_copyout(ucred + OFFSET_UCRED_CR_SCECAPS, caps, 16)) {
    return -1;
  }

  return 0;
}


int
kern_set_ucred_caps(pid_t pid, const uint8_t caps[16]) {
  intptr_t ucred = 0;

  if(!(ucred=kern_get_proc_ucred(pid))) {
    return -1;
  }

  if(kern_copyin(caps, ucred + OFFSET_UCRED_CR_SCECAPS, 16)) {
    return -1;
  }

  return 0;
}



intptr_t
kern_get_proc_file(pid_t pid, int fd) {
  intptr_t fd_files;
  intptr_t fde_file;
  intptr_t file;
  intptr_t proc;
  intptr_t p_fd;

  if(!(proc=kern_get_proc(pid))) {
    return 0;
  }

  if(kern_copyout(proc + 0x48, &p_fd, sizeof(p_fd))) {
    return 0;
  }

  if(kern_copyout(p_fd, &fd_files, sizeof(fd_files))) {
    return 0;
  }

  if(kern_copyout(fd_files + 8 + (0x30 * fd),
		    &fde_file, sizeof(fde_file))) {
    return 0;
  }

  if(kern_copyout(fde_file, &file, sizeof(file))) {
    return 0;
  }

  return file;
}


static intptr_t
kern_get_proc_inp6_outputopts(pid_t pid, int fd) {
  intptr_t inp6_outputopts;
  intptr_t so_pcb;
  intptr_t file;

  if(!(file=kern_get_proc_file(pid, fd))) {
    return 0;
  }

  if(kern_copyout(file + 0x18, &so_pcb, sizeof(so_pcb))) {
    return 0;
  }

  if(kern_copyout(so_pcb + 0x120, &inp6_outputopts,
		    sizeof(inp6_outputopts))) {
    return 0;
  }

  return inp6_outputopts;
}



static int
kern_inc_so_count(pid_t pid, int fd) {
  intptr_t file;
  int so_count;

  if(!(file=kern_get_proc_file(pid, fd))) {
    return -1;
  }

  if(kern_copyout(file, &so_count, sizeof(so_count))) {
    return -1;
  }

  so_count++;
  if(kern_copyin(&so_count, file, sizeof(so_count))) {
    return -1;
  }
  return 0;
}


int
kern_overlap_sockets(pid_t pid, int master_sock, int victim_sock) {
  intptr_t master_inp6_outputopts;
  intptr_t victim_inp6_outputopts;
  intptr_t pktinfo;
  unsigned int tclass;

  if(kern_inc_so_count(pid, master_sock)) {
    return -1;
  }

  if(!(master_inp6_outputopts=kern_get_proc_inp6_outputopts(pid,
							    master_sock))) {
    return -1;
  }

  if(kern_inc_so_count(pid, victim_sock)) {
    return -1;
  }

  if(!(victim_inp6_outputopts=kern_get_proc_inp6_outputopts(pid,
							    victim_sock))) {
    return -1;
  }

  pktinfo = victim_inp6_outputopts + 0x10;
  if(kern_copyin(&pktinfo, master_inp6_outputopts + 0x10,
		   sizeof(pktinfo))) {

    return -1;
  }

  tclass = 0x13370000;
  if(kern_copyin(&tclass, master_inp6_outputopts + 0xc0, sizeof(tclass))) {
    return -1;
  }

  return 0;
}

