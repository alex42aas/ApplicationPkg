/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __SUPER__USER__H
#define __SUPER__USER__H


#include <Library/ExtHdrUtils.h>
#include <InternalErrDesc.h>
#include "UsersStorage.h"
#include "vfrdata.h"


#define SU_PASS_VAR_NAME                    L"SuPass"
#define SU_NAME                             "super"
#define SU_NAME16                           L"super"



extern EFI_GUID gSuPassVarGuid;


VOID
ScanCodesTest(
  VOID
  );

BOOLEAN
SuCheckName(
  IN CHAR8 *Name
  );

BOOLEAN
SuPassVarPresent(
  VOID
  );

static EFI_STATUS
SuCheckPass(
  IN CHAR8 *InputStr,
  IN UINTN InputStrLen
  );

EFI_STATUS
SuVerify(
  IN CHAR8 *InputStr,
  IN UINTN InputStrLen
  );

EFI_STATUS
SuPassUpdate(
  IN CHAR8 *PassStr,
  IN UINTN PassStrLen
  );

EFI_STATUS
SuGetHash(
  IN OUT UINT8 *Data
  );



#endif /* #ifndef __SUPER__USER__H */

