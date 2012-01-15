/** @file
  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php
  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/

#ifndef __RECOVER__MODE__PAGE__H
#define __RECOVER__MODE__PAGE__H


#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/UefiLib.h>
#include <Library/HiiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Guid/MdeModuleHii.h>
#include <Protocol/HiiConfigAccess.h>
#include <Library/VfrCommon.h>
#include <Library/MultibootDescUtils.h>
#include "vfrdata.h"


#define MAX_RMP_STRING_LEN            255


EFI_STATUS
RMPCallback(
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  );


int
RMPGetSelectionNum(
  VOID
  );


EFI_STATUS
RMPStart(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR16 **ParamStrings,
  IN UINTN ParamStringsAmount
  );


#endif /* #ifndef __RECOVER__MODE__PAGE__H */
