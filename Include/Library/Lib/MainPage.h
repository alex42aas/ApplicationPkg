/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __MAIN__PAGE__H
#define __MAIN__PAGE__H


#include <CommonDefs.h>
#include <Library/Messages.h>
#include <Guid/MdeModuleHii.h>
#include <Protocol/HiiConfigAccess.h>
#include <Library/MultibootDescUtils.h>
#include <Library/VfrCommon.h>
#include <Library/Lib/History.h>
#include <Library/Lib/Users.h>
#include "vfrdata.h"
#include "Locks.h"



#define MP_ADMIN_MODE_GUID        "37933FC7-ACF6-48c8-8539-EC3573952EFF"
#define MP_FAILURE_MODE_GUID      "BA6D9BE6-32E8-4bdc-912A-C27B9D6B3DEC"
#define MP_TIME_OUT_GUID          "805E541F-3895-4274-898B-5347957ADB16"
#define MP_LOADING_FROM_USB_GUID  "CD6A8D16-4A4E-4691-BE34-6B8868D81AF9"
#define MP_DEFAULT_TIME_OUT       7


VOID
MainPageSetAdminModeRdOnly (
  IN BOOLEAN bFlag
  );


EFI_STATUS
MainPageCallback(
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  );
  
  
VOID
MainPageSetCurrentConfig(
  IN MULTIBOOT_CONFIG *Cfg
  );

VOID
MainPageBlockingMode(
  IN BOOLEAN Enable
  );  
  
VOID
MainPageFailureMode(
  IN BOOLEAN Enable
  );
  
  
UINTN
MainPageStart(
  IN EFI_HANDLE DriverHandle,
  IN CHAR8 *Language
  );


#endif  /* #ifndef __MAIN__PAGE__H */
