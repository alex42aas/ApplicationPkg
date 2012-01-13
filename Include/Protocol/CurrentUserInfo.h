/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __CURRENT__USER__INFO__H
#define __CURRENT__USER__INFO__H

#include <Uefi.h>
#include <Library/BaseLib.h>

#define CURRENT_USER_INFO_PROTOCOL_GUID \
  { \
    0xc1218f9e, 0xd7c, 0x4f37, { 0xaa, 0xcd, 0x67, 0xdc, 0xb5, 0x47, 0x2f, 0xdb } \
  }

typedef struct _CURRENT_USER_INFO_PROTOCOL  CURRENT_USER_INFO_PROTOCOL;

typedef struct _CURRENT_USER_INFO {
   CHAR16  *Username; 
   CHAR16  *Pass; 
   CHAR16  *Domain OPTIONAL;
   BOOLEAN UsePassAsSmartCardPin; 
   CHAR16  *ServerNameOrIP OPTIONAL; 
   UINT16  ServerPort OPTIONAL;
} CURRENT_USER_INFO;

typedef struct _CURRENT_USER_INFO_PROTOCOL {
  CURRENT_USER_INFO *CurrentUserInfo;
};

extern EFI_GUID gCurrentUserInfoProtocolGuid;

#endif // #ifndef __CURRENT__USER__INFO__H
