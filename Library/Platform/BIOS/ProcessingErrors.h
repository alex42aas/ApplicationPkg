/** @file
  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php
  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/

#ifndef PROCESSING_ERRORS_H_
#define PROCESSING_ERRORS_H_

#include <Library/Lib/OpensslFunctions.h>

VOID
ShowLdapErrorAndSaveHistory (
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8  *Language,
  IN UINT8 UsrId,
  IN BOOLEAN messageIfError,
  IN UINTN chkStatus
  );

VOID
ShowVerifyErrorAndSaveHistory(
  IN EFI_HII_HANDLE CurrentHiiHandle,
  IN CHAR8  *CurrentLanguage,
  IN UINT8 UsrId,
  IN BOOLEAN messageIfError,
  IN OSSL_STATUS verifyStatus
  );

VOID
SaveErrorToHistory(
  IN EFI_HII_HANDLE CurrentHiiHandle,
  IN CHAR8  *CurrentLanguage,
  IN UINT8 UsrId,
  IN OSSL_STATUS verifyStatus
  );

VOID
ShowVerifyError(
  IN EFI_HII_HANDLE CurrentHiiHandle,
  IN CHAR8  *CurrentLanguage,
  IN OSSL_STATUS verifyStatus
  );

VOID
LogBiosMessage (
  IN UINTN logLevel,
  IN const CHAR8 *subsystem,
  IN const CHAR8 *format,
  ...
);

const CHAR16*
GetLdapErrorStr(
  IN EFI_HII_HANDLE CurrentHiiHandle,
  IN UINTN chkStatus
);

#endif // PROCESSING_ERRORS_H_
