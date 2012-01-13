/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __COMMON__DEFS__H
#define __COMMON__DEFS__H


#define MULTIBOOT_MAX_STRING            255
#define MULTIBOOT_DATA_SIGNATURE        SIGNATURE_32 ('m', 'b', 't', ' ')
#define _CR(Record, TYPE, Field)        ((TYPE *) ((CHAR8 *) (Record) - (CHAR8 *) &(((TYPE *) 0)->Field)))

#define BIOS_PLATFORM_GUID_STR 		"65F29454-0371-415f-A06B-DAFC6CEE5058"

#define MAIN_FV_GUID_STR                "40E12513-14D1-4208-AB28-55634FD73416"
#define DXEUP_FV_GUID_STR               "40E12513-14D1-4208-AB28-55634FD73417"
#define SYSTEM_FV_GUID_STR              "9EDB353A-DEFC-4F52-B2A4-8773F7166155"

#define BIOS_PASS_GUID                  "9FF5F12F-CE84-4271-9CC3-548205D49B01"
#define FAIL_SAVE_PASS_GUID             "E5619A8E-309B-40d4-BD29-795D722268BE"
#define DEFAULT_LANG                    "en-US"
#define MULTIBOOT_MAX_FILE_PATH         256
#define MULTIBOOT_MAX_ARGS_LEN          256

#define FRONT_PAGE_GUID                 { 0xf76e0a70, 0xb5ed, 0x4c38, \
  { 0xac, 0x9a, 0xe5, 0xf5, 0x4b, 0xf1, 0x6e, 0x35 } } /// F76E0A70-B5ED-4C38-AC9A-E5F54BF16E35


#endif	/* #ifndef __COMMON__DEFS__H */
