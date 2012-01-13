/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __VFR__COMON__H
#define __VFR__COMON__H


#include <PiDxe.h>
#include <Library/PcdLib.h>
#include <Library/Messages.h>
#include <Guid/GlobalVariable.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Protocol/HiiConfigAccess.h>
#include <Protocol/HiiDatabase.h>
#include <Library/DebugLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/CommonUtils.h>
//#include <Library/HiiLib.h>


EFI_STATUS
SetFormBrowserRefreshFlag(
  VOID
  );


EFI_STATUS
EFIAPI
HiiRetriveFormData (
  IN EFI_HII_HANDLE HiiHandle,           
  IN EFI_GUID *FormSetGuid,
  IN EFI_FORM_ID FormId,
  IN VOID *StartOpcodeHandle,
  IN VOID *EndOpcodeHandle
  );

UINT8 *
VfrGetBufferPtr(
  VOID *StartOpCodeHandle
  );

UINTN
VfrGetBufferSize(
  VOID *StartOpCodeHandle
  );

UINTN
VfrGetPosition(
  VOID *StartOpCodeHandle
  );


UINT8 *
EFIAPI
VfrCreatePasswordOpCode(
  IN VOID *OpCodeHandle,
  IN UINT16 MinSize,
  IN UINT16 MaxSize,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_VARSTORE_ID VarStoreId,
  IN UINT16 VarOffset,
  IN EFI_STRING_ID Prompt,
  IN EFI_STRING_ID Help
);

UINT8 *
VfrCreateRefreshNumericTimeOut(
  IN VOID *StartOpCodeHandle,
  IN UINT8 ToVal,
  EFI_QUESTION_ID Qid,
  EFI_STRING_ID Prompt,
  EFI_STRING_ID Help
  );

EFI_STATUS
SetupBestLanguage(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *CurrentLang);

VOID
TestForLanguage(
  IN EFI_HII_HANDLE HiiHandle
  );


VOID
VfrFwVersionString(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR16 *StrBeforeVer,
  IN EFI_STRING_ID FwVersionStringId,
  IN CHAR16 *StrAfterVer
  );
  
  
VOID
VfrShowAction(
  IN EFI_BROWSER_ACTION Action
  );

EFI_STATUS
VfrCreateOneOfFromString(
  IN EFI_HII_HANDLE HiiHandle,
  IN VOID *StartOpCodeHandle,
  IN EFI_STRING_ID Caption,
  IN EFI_QUESTION_ID QuestionId,
  IN CHAR16 *ListStr,
  IN OPTIONAL CHAR16 *HelpStr
  );


EFI_STATUS
VfrCreateGrayIfNotSecurityOpCode (
  IN VOID *OpCodeHandle,
  IN EFI_GUID *PermissionGuid
  );

EFI_STATUS
VfrCreateGraySecAction (
  IN VOID *OpCodeHandle,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_STRING_ID Token, 
  IN EFI_STRING_ID HelpToken,  
  IN EFI_GUID *PermissionGuid
  );

EFI_STATUS
VfrCreateGraySecCheckBox (
  IN VOID *OpCodeHandle,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_STRING_ID Token, 
  IN EFI_STRING_ID HelpToken,
  IN UINT8 CheckBoxFlags,
  IN EFI_GUID *PermissionGuid
  );


#endif  /* #ifndef __VFR__COMON__H */
