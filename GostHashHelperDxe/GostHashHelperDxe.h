/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __GOST__HASH__HELPER__DXE__H

#include <Protocol/GostHashHelperProtocol.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>

typedef struct _GOST_HASH_HELPER_PRIVATE_DATA {
  EFI_HANDLE DriverHandle;
  GOST_HASH_HELPER_PROTOCOL HandlerProtocol;
} GOST_HASH_HELPER_PRIVATE_DATA;

#endif /* #ifndef __GOST__HASH__HELPER__DXE__H */
