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


typedef void* pthread_t;
typedef void* pthread_attr_t;


typedef struct payload_ctx {
  payload_entry_t *entry;
  payload_args_t  *args;
  int              stdout;
} payload_ctx_t;


static void* (*malloc)(unsigned long);
static void  (*free)(void*);
static void* (*memcpy)(void*, const void*, unsigned long);
static int   (*close)(int);
static int   (*dup)(int);
static int   (*dup2)(int, int);
static int   (*pthread_create)(pthread_t*, pthread_attr_t*,
			       void*(*f)(void*), void*);


static void*
payload_thread(void* args) {
  payload_ctx_t *ctx = (payload_ctx_t*)args;
  int stdout = dup(1);
  int stderr = dup(2);

  dup2(ctx->stdout, 1);
  dup2(ctx->stdout, 2);

  ctx->entry(ctx->args);
  free(args);

  dup2(stdout, 1);
  dup2(stderr, 2);
  close(ctx->stdout);

  return 0;
}


int main(payload_ctx_t *ctx) {
  pthread_t trd;
  void* trd_args = malloc(sizeof(payload_ctx_t));

  memcpy(trd_args, ctx, sizeof(payload_ctx_t));
  pthread_create(&trd, 0, payload_thread, trd_args);

  return 0;
}


static int
init(payload_args_t *args) {
  int error;

  if((error=args->sceKernelDlsym(0x2001, "pthread_create", &pthread_create))) {
    return error;
  }
  if((error=args->sceKernelDlsym(0x2001, "dup", &dup))) {
    return error;
  }
  if((error=args->sceKernelDlsym(0x2001, "dup2", &dup2))) {
    return error;
  }
  if((error=args->sceKernelDlsym(0x2001, "close", &close))) {
    return error;
  }
  if((error=args->sceKernelDlsym(0x2, "malloc", &malloc))) {
    return error;
  }
  if((error=args->sceKernelDlsym(0x2, "free", &free))) {
    return error;
  }
  if((error=args->sceKernelDlsym(0x2, "memcpy", &memcpy))) {
    return error;
  }

  return 0;
}


void
_start(payload_entry_t *entry, payload_args_t *args, int stdout) {
  payload_ctx_t ctx = {
    .entry = entry,
    .args = args,
    .stdout = stdout
  };

  if(!(*args->payloadout=init(args))) {
    *args->payloadout = main(&ctx);
  }

  __builtin_debugtrap();
}
