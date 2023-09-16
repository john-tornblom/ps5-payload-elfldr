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

#include "payload.h"


extern int libc_init(const payload_args_t *args);
extern int kern_init(const payload_args_t *args);
extern int main(const payload_args_t *args);


void
_start(payload_args_t *args) {
  if((*args->payloadout=libc_init(args))) {
    return;
  }
  if((*args->payloadout=kern_init(args))) {
    return;
  }

  *args->payloadout = main(args);
}
