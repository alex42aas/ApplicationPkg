/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __ADMIN__MAIN__PAGE__H
#define __ADMIN__MAIN__PAGE__H


#include <CommonDefs.h>
#include <Library/Messages.h>
#include <Guid/MdeModuleHii.h>
#include <Protocol/HiiConfigAccess.h>
#include <Library/MultibootDescUtils.h>
#include <Library/ExtHdrUtils.h>
#include "vfrdata.h"
#include "Users.h"
#include "SuperUser.h"
#include "UsersStorage.h"
#include "DateTimePage.h"
#include "History.h"
#include "Locks.h"
#include "PciDevList.h"
#include <Library/FwUpdate.h>
#include <Protocol/AdvMenuHandlerProto.h>
#include "IntegrityChecking.h"


#define ADMIN_LOCK_ALL_BUT_HISTORY ((UINT32)-1 & \
  (~(1 << (ADM_MAIN_PAGE_BIOS_LOG_CTRL_ID & 0xFF))))


BOOLEAN
IsNeedAmt (
  VOID
  ); 

VOID
AmtHelper (
  VOID
  );


VOID
AdminSetCurrentConfig(
  IN MULTIBOOT_CONFIG *Cfg
  );

EFI_STATUS
AdminMainPageStart(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  );

EFI_STATUS
AdminMainPageCallback(
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  );  

EFI_STATUS
AdminCheckCurrentUserPassExpiration(
  IN EFI_HII_HANDLE HiiHandle
  );


#endif  /* #ifndef __ADMIN__MAIN__PAGE__H */

