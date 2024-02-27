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

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>


int
klog_printf(const char *fmt, ...) {
  char sargs[0x2000];
  char buf[0x2010];
  va_list args;

  bzero(&sargs, sizeof sargs);
  va_start(args, fmt);
  vsnprintf(sargs, sizeof sargs, fmt, args);
  va_end(args);

  snprintf(buf, sizeof buf, "<118>[elfldr.elf] %s", sargs);

  return (int)syscall(0x259, 7, buf, 0);
}


int
klog_puts(const char *s) {
  char buf[0x2000];

  snprintf(buf, sizeof buf, "<118>[elfldr.elf] %s\n", s);

  return (int)syscall(0x259, 7, buf, 0);
}


int
klog_perror(const char *s) {
  char buf[0x2000];

  snprintf(buf, sizeof buf, "<118>[elfldr.elf] %s: %s\n", s, strerror(errno));

  return (int)syscall(0x259, 7, buf, 0);
}
