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


#define ET_EXEC           2
#define ET_DYN            3
#define PT_LOAD           1
#define SHT_RELA          4
#define R_X86_64_RELATIVE 8
#define PF_X              1
#define PF_W              2
#define PF_R              4


typedef struct {
  unsigned int st_name;
  unsigned char st_info;
  unsigned char st_other;
  unsigned short st_shndx;
  unsigned long st_value;
  unsigned long st_size;
} Elf64_Sym;


typedef struct {
  unsigned char e_ident[16];
  unsigned short e_type;
  unsigned short e_machine;
  unsigned int e_version;
  unsigned long e_entry;
  unsigned long e_phoff;
  unsigned long e_shoff;
  unsigned int e_flags;
  unsigned short e_ehsize;
  unsigned short e_phentsize;
  unsigned short e_phnum;
  unsigned short e_shentsize;
  unsigned short e_shnum;
  unsigned short e_shstrndx;
} Elf64_Ehdr;


typedef struct {
  unsigned int p_type;
  unsigned int p_flags;
  unsigned long p_offset;
  unsigned long p_vaddr;
  unsigned long p_paddr;
  unsigned long p_filesz;
  unsigned long p_memsz;
  unsigned long p_align;
} Elf64_Phdr;


typedef struct {
  unsigned int sh_name;
  unsigned int sh_type;
  unsigned long sh_flags;
  unsigned long sh_addr;
  unsigned long sh_offset;
  unsigned long sh_size;
  unsigned int sh_link;
  unsigned int sh_info;
  unsigned long sh_addralign;
  unsigned long sh_entsize;
} Elf64_Shdr;


typedef struct {
  unsigned long r_offset;
  unsigned long r_info;
  long r_addend;
} Elf64_Rela;

