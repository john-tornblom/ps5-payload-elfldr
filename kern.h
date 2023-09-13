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

#pragma once

#include "libc.h"

intptr_t kern_get_data_baseaddr(void);
intptr_t kern_get_proc(pid_t pid);
intptr_t kern_get_proc_file(pid_t pid, int fd);

int kern_copyin(const void *udaddr, intptr_t kaddr, size_t len);
int kern_copyout(intptr_t kaddr, void *udaddr, size_t len);

int kern_get_qa_flags(uint8_t flags[16]);
int kern_set_qa_flags(const uint8_t flags[16]);

int kern_get_ucred_auth_id(pid_t pid, uint64_t *auth_id);
int kern_set_ucred_auth_id(pid_t pid, uint64_t auth_id);

int kern_get_ucred_caps(pid_t pid, uint8_t caps[16]);
int kern_set_ucred_caps(pid_t pid, const uint8_t caps[16]);

int kern_overlap_sockets(pid_t pid, int master_sock, int victim_sock);
