/** @file
  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php
  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/

#ifndef __SYSTEM__INFO__H
#define __SYSTEM__INFO__H


#include <Library/CommonUtils.h>
#include <Guid/MdeModuleHii.h>
#include <Protocol/HiiConfigAccess.h>
#include <Library/ExtHdrUtils.h>
#include <Library/VarStorageUtils.h>
#include <Library/VfrCommon.h>
#include <Library/FsUtils.h>
#include <Library/MultibootDescUtils.h>
#include <Library/Lib/vfrdata.h>
#include <Library/Lib/CertificatesControl.h>
#include <Library/Lib/History.h>
#include <Library/Lib/UsersStorage.h>
#include <Library/Lib/Users.h>


extern struct tMainFvInfo MainFvInfo;


EFI_STATUS
SystemInfoPageStart(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  );

EFI_STATUS
SystemInfoPageCallback(
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  );


#endif  /* #ifndef __SYSTEM__INFO__H */

