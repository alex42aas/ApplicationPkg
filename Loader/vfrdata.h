/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef MB_IFR_DATA_H
#define MB_IFR_DATA_H
#define MULTIBOOT_MAX_STRING 255

#pragma pack(1)
typedef struct {
    UINT16       Timeout;
    UINT16       DevPath[MULTIBOOT_MAX_STRING];
    UINT16       Args[MULTIBOOT_MAX_STRING]; 
} MULTIBOOT_MODULE_VFR;
#pragma pack()

#pragma pack(1)
typedef struct {
    UINT16       Name[MULTIBOOT_MAX_STRING];
} MULTIBOOT_ENTRY_VFR;
#pragma pack()

#define MULTIBOOT_MAIN_PAGE_FORM_ID        0x4000
#define MULTIBOOT_ENTRY_EDIT_FORM_ID       0x4001
#define MULTIBOOT_MODULE_EDIT_FORM_ID      0x4002
#define MULTIBOOT_STRING_REFERENCE_FORM_ID 0x40FF

#define MULTIBOOT_ENTRY_EDIT_NAME_ID  0xD001


#define FORMSET_GUID  { 0x543cd5fe, 0x1276, 0x443d, 0x41, 0x42, 0x34, 0xc2, 0x32, 0xef, 0xa1, 0xe4 }

#define LABEL_BOOT_OPTION           0x00
#define LABEL_BOOT_OPTION_END       0x01
#define LABEL_MODULE_LIST_START     0x02
#define LABEL_MODULE_LIST_END       0x03

#define USBKEY_PROVIDER_CLASS       0x00
#define USBKEY_PROVIDER_SUBCLASS    0x00
#endif
