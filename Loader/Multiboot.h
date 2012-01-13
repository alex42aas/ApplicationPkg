/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

/*
 *  MultiBoot Info description
 *
 *  This is the struct passed to the boot image.  This is done by placing
 *  its address in the EAX register.
 */

#ifndef MULTIBOOT_H
#define MULTIBOOT_H

#pragma pack(1)
/*
 *  MultiBoot Header description
 */

struct multiboot_header
{
  /* Must be MULTIBOOT_MAGIC - see below.  */
  UINT32 magic;

  /* Feature flags - see below.  */
  UINT32 flags;

  /*
   * Checksum
   *
   * The above fields plus this one must equal 0 mod 2^32.
   */
  UINT32 checksum;

  /* These are only valid if MULTIBOOT_AOUT_KLUDGE is set.  */
  UINT32 header_addr;
  UINT32 load_addr;
  UINT32 load_end_addr;
  UINT32 bss_end_addr;
  UINT32 entry_addr;

  /* These are only valid if MULTIBOOT_VIDEO_MODE is set.  */
  UINT32 mode_type;
  UINT32 width;
  UINT32 height;
  UINT32 depth;
};

typedef struct multiboot_header MULTIBOOT_HEADER;
/*
 * The entire multiboot_header must be contained
 * within the first MULTIBOOT_SEARCH bytes of the kernel image.
 */
#define MULTIBOOT_SEARCH                8192
#define MULTIBOOT_FOUND(addr, len) \
  (! ((addr) & 0x3) \
   && (len) >= 12 \
   && *((int *) (addr)) == MULTIBOOT_MAGIC \
   && ! (*((unsigned *) (addr)) + *((unsigned *) (addr + 4)) \
         + *((unsigned *) (addr + 8))) \
   && (! (MULTIBOOT_AOUT_KLUDGE & *((int *) (addr + 4))) || (len) >= 32) \
   && (! (MULTIBOOT_VIDEO_MODE & *((int *) (addr + 4))) || (len) >= 48))

/* Magic value identifying the multiboot_header.  */
#define MULTIBOOT_MAGIC                 0x1BADB002

/*
 * Features flags for 'flags'.
 * If a boot loader sees a flag in MULTIBOOT_MUSTKNOW set
 * and it doesn't understand it, it must fail.
 */
#define MULTIBOOT_MUSTKNOW              0x0000FFFF

/* currently unsupported flags...  this is a kind of version number.  */
#define MULTIBOOT_UNSUPPORTED           0x0000FFF8

/* Align all boot modules on i386 page (4KB) boundaries.  */
#define MULTIBOOT_PAGE_ALIGN            0x00000001

/* Must pass memory information to OS.  */
#define MULTIBOOT_MEMORY_INFO           0x00000002

/* Must pass video information to OS.  */
#define MULTIBOOT_VIDEO_MODE            0x00000004

/* This flag indicates the use of the address fields in the header.  */
#define MULTIBOOT_AOUT_KLUDGE           0x00010000
/*
 *  The structure type "mod_list" is used by the "multiboot_info" structure.
 */


struct mod_list
{
  /* the memory used goes from bytes 'mod_start' to 'mod_end-1' inclusive */
  UINT32 mod_start;
  UINT32 mod_end;

  /* Module command line */
  UINT32 cmdline;

  /* padding to take it to 16 bytes (must be zero) */
  UINT32 pad;
};

typedef struct mod_list MULTIBOOT_MODULES_LIST;
#define MULTIBOOT_MAX_MODULES 256

struct multiboot_info
{
  /* MultiBoot info version number */
  UINT32 flags;

  /* Available memory from BIOS */
  UINT32 mem_lower;
  UINT32 mem_upper;

  /* "root" partition */
  UINT32 boot_device;

  /* Kernel command line */
  UINT32 cmdline;

  /* Boot-Module list */
  UINT32 mods_count;
  UINT32 mods_addr;

  union
  {
    struct
    {
      /* (a.out) Kernel symbol table info */
      UINT32 tabsize;
      UINT32 strsize;
      UINT32 addr;
      UINT32 pad;
    }
    a;

    struct
    {
      /* (ELF) Kernel section header table */
      UINT32 num;
      UINT32 size;
      UINT32 addr;
      UINT32 shndx;
    }
    e;
  }
  syms;

  /* Memory Mapping buffer */
  UINT32 mmap_length;
  UINT32 mmap_addr;

  /* Drive Info buffer */
  UINT32 drives_length;
  UINT32 drives_addr;

  /* ROM configuration table */
  UINT32 config_table;

  /* Boot Loader Name */
  UINT32 boot_loader_name;

  /* APM table */
  UINT32 apm_table;

  /* Video */
  UINT32 vbe_control_info;
  UINT32 vbe_mode_info;
  UINT16 vbe_mode;
  UINT16 vbe_interface_seg;
  UINT16 vbe_interface_off;
  UINT16 vbe_interface_len;

  /* EFI systab and acpi tab */
  UINT32 efi_systab;
  UINT32 acpi_tab;
  UINT32 efi_mmap;
  UINT32 efi_mmap_size;
  UINT32 efi_desc_size;
};
#pragma pack()

typedef struct multiboot_info MULTIBOOT_INFO;
/*
 *  Flags to be set in the 'flags' parameter above
 */

/* is there basic lower/upper memory information? */
#define MB_INFO_MEMORY                  0x00000001
/* is there a boot device set? */
#define MB_INFO_BOOTDEV                 0x00000002
/* is the command-line defined? */
#define MB_INFO_CMDLINE                 0x00000004
/* are there modules to do something with? */
#define MB_INFO_MODS                    0x00000008

/* These next two are mutually exclusive */

/* is there a symbol table loaded? */
#define MB_INFO_AOUT_SYMS               0x00000010
/* is there an ELF section header table? */
#define MB_INFO_ELF_SHDR                0x00000020

/* is there a full memory map? */
#define MB_INFO_MEM_MAP                 0x00000040

/* Is there drive info?  */
#define MB_INFO_DRIVE_INFO              0x00000080

/* Is there a config table?  */
#define MB_INFO_CONFIG_TABLE            0x00000100

/* Is there a boot loader name?  */
#define MB_INFO_BOOT_LOADER_NAME        0x00000200

/* Is there a APM table?  */
#define MB_INFO_APM_TABLE               0x00000400

/* Is there video information?  */
#define MB_INFO_VIDEO_INFO              0x00000800

/* EFI info present and valid   */
#define MB_INFO_EFI                     0x00001000

/*
 *  The following value must be present in the EAX register.
 */

#define MULTIBOOT_VALID                 0x2BADB002
#endif

