/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __SETUP__VAR__DXE__H
#define __SETUP__VAR__DXE__H


#include <Library/CommonUtils.h>
#include <Library/PcdLib.h>
#include <Protocol/SetupVarProto.h>


typedef struct _SETUP_VAR_PRIVATE_DATA {
  EFI_HANDLE         DriverHandle;
  SETUP_VAR_PROTOCOL SetupVarProtocol;
} SETUP_VAR_PRIVATE_DATA;


#endif /* #ifndef __SETUP__VAR__DXE__H */

