/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __MII__H
#define __MII__H


#include <CommonDefs.h>
#include <Library/Messages.h>
#include <Guid/MdeModuleHii.h>
#include <Protocol/HiiConfigAccess.h>
#include <Library/MultibootDescUtils.h>
#include <Library/ExtHdrUtils.h>
#include "DateTimePage.h"
#include "vfrdata.h"
#include "Users.h"



VOID
MIISetCurrentConfig(
  IN MULTIBOOT_CONFIG *Cfg
  );

VOID
MIIStart(
  IN EFI_HII_HANDLE HiiHandle,
  IN MULTIBOOT_CONFIG *Config,
  IN struct tMainFvInfo *pmfvi,
  IN CHAR8 *Language
  );

EFI_STATUS
MIIPageCallback(
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  );  


#endif  /* #ifndef __MII__H */
