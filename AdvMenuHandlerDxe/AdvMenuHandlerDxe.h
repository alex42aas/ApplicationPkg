/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __ADV__MENU__HANDLER__DXE__H
#define __ADV__MENU__HANDLER__DXE__H

#include <Protocol/AdvMenuHandlerProto.h>
#include <Protocol/HiiConfigAccess.h>
#include <Protocol/HiiDatabase.h>
#include <Library/DebugLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/MultibootDescUtils.h>
#include <Library/BIOSLib/vfrdata.h>
#include <Library/VfrCommon.h>


typedef struct _ADV_MENU_HANDLER_PRIVATE_DATA {
  EFI_HANDLE DriverHandle;
  MULTIBOOT_CONFIG *CurrentCfg;
  EFI_HII_HANDLE CurrentHiiHandle;
  ADV_MENU_HANDLER_PROTOCOL AdvMenuHandlerProtocol;
  ADV_MENU_CALLBACK StartCallback;
  ADV_MENU_CALLBACK ActionCallback;
  ADV_MENU_CALLBACK ExitCallback;
  BOOLEAN bFormExit;
  BOOLEAN bGotoAction;
  EFI_GUID AdvMenuFormGuid;
} ADV_MENU_HANDLER_PRIVATE_DATA;


#endif /* #ifndef __ADV__MENU__HANDLER__DXE__H */

