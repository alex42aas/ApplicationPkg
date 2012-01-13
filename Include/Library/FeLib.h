/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __FE__LIB__H
#define __FE__LIB__H


#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiLib.h>
#include <Library/HiiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Guid/MdeModuleHii.h>
#include <Protocol/HiiConfigAccess.h>
#include <Library/VfrCommon.h>
#include <Library/FsUtils.h>
#include <Library/PrintLib.h>
#include <Library/CommonUtils.h>


enum FE_MODES {
  FE_MODE_BROWSE, FE_MODE_DEV_SELECT, FE_MODE_USB_DRIVE_SELECT
};

#define MAX_FE_STRING_LEN                   255


EFI_STATUS
FeCallback(
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  );

EFI_STATUS
FeLibSetDevicePath(
  IN CHAR16 *Path
  );

CHAR16 *
FeGetSelectedString(
  VOID
  );
  
EFI_DEVICE_PATH_PROTOCOL*
FeGetCurDevPath(
  VOID
  );

EFI_STATUS
FeLibTest(
  IN EFI_HII_HANDLE HiiHandle,
  IN EFI_GUID *FormSetGuid,
  IN EFI_FORM_ID FormId,
  IN EFI_QUESTION_ID FeQuidStart,
  IN UINT16 FeStartLabel,
  IN UINT16 FeEndLabel
  );

EFI_STATUS
FeLibTestWithDevPath(
  IN CHAR16 *DevicePath,
  IN EFI_HII_HANDLE HiiHandle,
  IN EFI_GUID *FormSetGuid,
  IN EFI_FORM_ID FormId,
  IN EFI_QUESTION_ID FeQuidStart,
  IN UINT16 FeStartLabel,
  IN UINT16 FeEndLabel
  );

EFI_STATUS
FeLibSelectFromDevice(
  IN EFI_HII_HANDLE HiiHandle,
  IN EFI_GUID *FormSetGuid,
  IN EFI_FORM_ID FormId,
  IN EFI_QUESTION_ID FeQuidStart,
  IN UINT16 FeStartLabel,
  IN UINT16 FeEndLabel
  );

EFI_STATUS	FeDevicesListPrint(VOID);
BOOLEAN
FeGetSaveParamsFlag(
  VOID
  );

VOID
FeSetSaveParamsFlag(
  BOOLEAN flag
  );

#endif	/* #ifndef __FE__LIB__H */
