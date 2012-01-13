/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/



#ifndef _EFI_LINUX_H__
#define _EFI_LINUX_H__

#define LINUX_MAGIC_SIGNATURE                   0x53726448      /* "HdrS" */
#define LINUX_DEFAULT_SETUP_SECTS               4
#define LINUX_INITRD_MAX_ADDRESS                0x37FFFFFF
#define LINUX_MAX_SETUP_SECTS                   64
#define LINUX_BOOT_LOADER_TYPE                  0x72
#define LINUX_HEAP_END_OFFSET                   (0x9000 - 0x200)

#define LINUX_BZIMAGE_ADDR                      0x100000
#define LINUX_ZIMAGE_ADDR                       0x10000
#define LINUX_OLD_REAL_MODE_ADDR                0x90000
#define LINUX_SETUP_STACK                       0x9000

#define LINUX_FLAG_BIG_KERNEL                   0x01
#define LINUX_FLAG_QUIET                        0x20
#define LINUX_FLAG_KEEP_SEGMENTS                0x40
#define LINUX_FLAG_CAN_USE_HEAP                 0x80

/* Linux's video mode selection support. Actually I hate it!  */
#define LINUX_VID_MODE_NORMAL                   0xFFFF
#define LINUX_VID_MODE_EXTENDED                 0xFFFE
#define LINUX_VID_MODE_ASK                      0xFFFD
#define LINUX_VID_MODE_VESA_START               0x0300

#define LINUX_SETUP_MOVE_SIZE                   0x9100
#define LINUX_CL_MAGIC                          0xA33F
#define LINUX_CL_OFFSET                         0xC000
#define LINUX_CL_END_OFFSET                     0xE000
#define LINUX_MAX_SETUP_SECTORS                 64
#define LINUX_DEFAULT_SETUP_SIZE                (4*512)

// 0000 - Heap
// 8DFF - HeapEnd
// 8E00 - Stack
// 9000 - Stack
// 10000 - Setup

#define LINUX_EFI_SIGNATURE64   \
  ('4' << 24 | '6' << 16 | 'L' << 8 | 'E')


#define LINUX_EFI_SIGNATURE32   \
  ('2' << 24 | '3' << 16 | 'L' << 8 | 'E')


#define LINUX_EFI_SIGNATURE_0204           \
  ('L' << 24 | 'I' << 16 | 'F' << 8 | 'E')

#define LINUX_OFW_SIGNATURE                \
  (' ' << 24 | 'W' << 16 | 'F' << 8 | 'O')


#pragma pack(1)
/* For the Linux/i386 boot protocol version 2.03.  */
struct linux_kernel_header
{
  UINT8 code1[0x0020];
  UINT16 cl_magic;                              /* Magic number 0xA33F */
  UINT16 cl_offset;                             /* The offset of command line */
  UINT8 code2[0x01F1 - 0x0020 - 2 - 2];
  UINT8 setup_sects;                            /* The size of the setup in sectors */
  UINT16 root_flags;                            /* If the root is mounted readonly */
  UINT16 syssize;                               /* obsolete */
  UINT16 swap_dev;                              /* obsolete */
  UINT16 ram_size;                              /* obsolete */
  UINT16 vid_mode;                              /* Video mode control */
  UINT16 root_dev;                              /* Default root device number */
  UINT16 boot_flag;                             /* 0xAA55 magic number */
  UINT16 jump;                                  /* Jump instruction */
  UINT32 header;                                /* Magic signature "HdrS" */
  UINT16 version;                               /* Boot protocol version supported */
  UINT32 realmode_swtch;                        /* Boot loader hook */
  UINT16 start_sys;                             /* The load-low segment (obsolete) */
  UINT16 kernel_version;                        /* Points to kernel version string */
  UINT8 type_of_loader;                         /* Boot loader identifier */
#define LINUX_LOADER_ID_LILO                    0x0
#define LINUX_LOADER_ID_LOADLIN                 0x1
#define LINUX_LOADER_ID_BOOTSECT                0x2
#define LINUX_LOADER_ID_SYSLINUX                0x3
#define LINUX_LOADER_ID_ETHERBOOT               0x4
#define LINUX_LOADER_ID_ELILO                   0x5
#define LINUX_LOADER_ID_GRUB                    0x7
#define LINUX_LOADER_ID_UBOOT                   0x8
#define LINUX_LOADER_ID_XEN                     0x9
#define LINUX_LOADER_ID_GUJIN                   0xa
#define LINUX_LOADER_ID_QEMU                    0xb
  UINT8  loadflags;                             /* Boot protocol option flags */
  UINT16 setup_move_size;                       /* Move to high memory size */
  UINT32 code32_start;                          /* Boot loader hook */
  UINT32 ramdisk_image;                         /* initrd load address */
  UINT32 ramdisk_size;                          /* initrd size */
  UINT32 bootsect_kludge;                       /* obsolete */
  UINT16 heap_end_ptr;                          /* Free memory after setup end */
  UINT16 pad1;                                  /* Unused */
  UINT8  *cmd_line_ptr;                         /* Points to the kernel command line */
  UINT32 initrd_addr_max;                       /* Highest address for initrd */
};

typedef struct _LINUX_E820_ENTRY {
                UINT64 BaseAddress;             /* start of memory segment */
                UINT64 Length;                  /* size of memory segment  */
                UINT32 Type;                    /* type of memory segment  */
} LINUX_E820_ENTRY;

/* Boot parameters for Linux based on 2.6.12. This is used by the setup
   sectors of Linux, and must be simulated by GRUB on EFI, because
   the setup sectors depend on BIOS.  */
struct linux_kernel_params
{
  UINT8 video_cursor_x;                         /* 0 */
  UINT8 video_cursor_y;

  UINT16 ext_mem;                               /* 2 */

  UINT16 video_page;                            /* 4 */
  UINT8 video_mode;                             /* 6 */
  UINT8 video_width;                            /* 7 */

  UINT8 padding1[0xa - 0x8];

  UINT16 video_ega_bx;                          /* a */

  UINT8 padding2[0xe - 0xc];

  UINT8 video_height;                           /* e */
  UINT8 have_vga;                               /* f */
  UINT16 font_size;                             /* 10 */

  UINT16 lfb_width;                             /* 12 */
  UINT16 lfb_height;                            /* 14 */
  UINT16 lfb_depth;                             /* 16 */
  UINT32 lfb_base;                              /* 18 */
  UINT32 lfb_size;                              /* 1c */

  UINT16 cl_magic;                              /* 20 */
  UINT16 cl_offset;

  UINT16 lfb_line_len;                          /* 24 */
  UINT8 red_mask_size;                          /* 26 */
  UINT8 red_field_pos;
  UINT8 green_mask_size;
  UINT8 green_field_pos;
  UINT8 blue_mask_size;
  UINT8 blue_field_pos;
  UINT8 reserved_mask_size;
  UINT8 reserved_field_pos;
  UINT16 vesapm_segment;                        /* 2e */
  UINT16 vesapm_offset;                         /* 30 */
  UINT16 lfb_pages;                             /* 32 */
  UINT16 vesa_attrib;                           /* 34 */
  UINT32 capabilities;                          /* 36 */

  UINT8 padding3[0x40 - 0x3a];

  UINT16 apm_version;                           /* 40 */
  UINT16 apm_code_segment;                      /* 42 */
  UINT32 apm_entry;                             /* 44 */
  UINT16 apm_16bit_code_segment;                /* 48 */
  UINT16 apm_data_segment;                      /* 4a */
  UINT16 apm_flags;                             /* 4c */
  UINT32 apm_code_len;                          /* 4e */
  UINT16 apm_data_len;                          /* 52 */

  UINT8 padding4[0x60 - 0x54];

  UINT32 ist_signature;                         /* 60 */
  UINT32 ist_command;                           /* 64 */
  UINT32 ist_event;                             /* 68 */
  UINT32 ist_perf_level;                        /* 6c */

  UINT8 padding5[0x80 - 0x70];

  UINT8 hd0_drive_info[0x10];                   /* 80 */
  UINT8 hd1_drive_info[0x10];                   /* 90 */
  UINT16 rom_config_len;                        /* a0 */

  UINT8 padding6[0xb0 - 0xa2];

  UINT32 ofw_signature;                         /* b0 */
  UINT32 ofw_num_items;                         /* b4 */
  UINT32 ofw_cif_handler;                       /* b8 */
  UINT32 ofw_idt;                               /* bc */

  UINT8 padding7[0x1b8 - 0xc0];

  union
    {
      struct
        {
          UINT32 system_table;              /* 1b8 */
          UINT32 padding7_1;                /* 1bc */
          UINT32 signature;                 /* 1c0 */
          UINT32 mem_desc_size;             /* 1c4 */
          UINT32 mem_desc_version;          /* 1c8 */
          UINT32 mmap_size;                 /* 1cc */
          UINT32 mmap;                      /* 1d0 */
        } v0204;
      struct
        {
          UINT32 padding7_1;                /* 1b8 */
          UINT32 padding7_2;                /* 1bc */
          UINT32 signature;                 /* 1c0 */
          UINT32 system_table;              /* 1c4 */
          UINT32 mem_desc_size;             /* 1c8 */
          UINT32 mem_desc_version;          /* 1cc */
          UINT32 mmap;                      /* 1d0 */
          UINT32 mmap_size;                 /* 1d4 */
          UINT32 system_table_hi;           /* 1d8 */
          UINT32 mmap_hi;                   /* 1dc */
        } v0206;
    } efi;

  UINT32 alt_mem;                               /* 1e0 */

  UINT8 padding8[0x1e8 - 0x1e4];

  UINT8 mmap_size;                              /* 1e8 */

  UINT8 padding9[0x1f1 - 0x1e9];

  UINT8 setup_sects;                            /* The size of the setup in sectors */
  UINT16 root_flags;                            /* If the root is mounted readonly */
  UINT16 syssize;                               /* obsolete */
  UINT16 swap_dev;                              /* obsolete */
  UINT16 ram_size;                              /* obsolete */
  UINT16 vid_mode;                              /* Video mode control */
  UINT16 root_dev;                              /* Default root device number */

  UINT8 padding10;                              /* 1fe */
  UINT8 ps_mouse;                               /* 1ff */

  UINT16 jump;                                  /* Jump instruction */
  UINT32 header;                                /* Magic signature "HdrS" */
  UINT16 version;                               /* Boot protocol version supported */
  UINT32 realmode_swtch;                        /* Boot loader hook */
  UINT16 start_sys;                             /* The load-low segment (obsolete) */
  UINT16 kernel_version;                        /* Points to kernel version string */
  UINT8 type_of_loader;                         /* Boot loader identifier */
  UINT8 loadflags;                              /* Boot protocol option flags */
  UINT16 setup_move_size;                       /* Move to high memory size */
  UINT32 code32_start;                          /* Boot loader hook */
  UINT32 ramdisk_image;                         /* initrd load address */
  UINT32 ramdisk_size;                          /* initrd size */
  UINT32 bootsect_kludge;                       /* obsolete */
  UINT16 heap_end_ptr;                          /* Free memory after setup end */
  UINT16 pad1;                                  /* Unused */
  UINT32 cmd_line_ptr;                          /* Points to the kernel command line */

  UINT8 pad2[164];                              /* 22c */
#define LINUX_E820_MAX_ENTRY 1024
  LINUX_E820_ENTRY e820_map[LINUX_E820_MAX_ENTRY];              /* 2d0 */

}; 

typedef struct linux_kernel_header LINUX_HEADER;
typedef struct linux_kernel_params LINUX_PARAMS;

#pragma pack()
#endif

