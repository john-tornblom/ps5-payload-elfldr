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

/**
 * Execute an ELF inside the process with the given name, and pipe outout
 * to the given stdout file descriptor.
 **/
int elfldr_exec(const char* procname, int stdout, uint8_t *elf, size_t size);


/**
 * Launch a socket server that accapts ELF files that are executed in the
 * process with given name, where stdout is piped to the connecting socket.
 **/
int elfldr_socksrv(const char* procname);

