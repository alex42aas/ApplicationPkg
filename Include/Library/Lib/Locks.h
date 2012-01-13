/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __LOCKS__H
#define __LOCKS__H


#include <CommonDefs.h>
#include <Library/Messages.h>
#include <Guid/MdeModuleHii.h>
#include <Protocol/HiiConfigAccess.h>
#include <Library/MultibootDescUtils.h>
#include <InternalErrDesc.h>
#include "UsersStorage.h"
#include "vfrdata.h"


#define LOCKS_VAR_COUNTER_NAME              L"LocksVar"
#define LOCKS_MAX_LOGIN_FAIL                20
#define MAIN_MENU_LOCKED_ADMIN_MODE         (1 << 0)

#define LOCK_VAR_WRONG_PIN_CNT_IDX          0
#define LOCK_VAR_WRONG_PIN_TRESHOLD_IDX     1
#define LOCK_VAR_WRONG_PIN_TRESHOLD_DEF     10
#define LOCK_VAR_WRONG_PIN_TRESHOLD_MIN     1
#define LOCK_VAR_WRONG_PIN_TRESHOLD_MAX     100



extern GUID gLocksCounterVarGuid;


BOOLEAN
IsTokenDisabled(
  VOID
  );

VOID
DisableToken(
  IN BOOLEAN bDisable
  );

BOOLEAN
TokenLoginOnly(
  VOID
  );

VOID
SetTokenLoginOnly(
  VOID
  );

BOOLEAN
TokenUserLoginLocked(
  VOID
  );


VOID
LockForTokenUserLogin(
  VOID
  );

VOID
UnlockForTokenUserLogin(
  VOID
  );


BOOLEAN
MainMenuAdmModeLocked(
  VOID
  );


VOID
MainMenuLockOff(
  VOID
  );

VOID
MainMenuLockAdmMode(
  VOID
  );

EFI_STATUS
LoginFailCntClean(
  VOID
  );


EFI_STATUS
LocksInit(
  IN EFI_HII_HANDLE HiiHandle
  );

BOOLEAN 
CheckForSuPasswordFail(
  VOID
  );

BOOLEAN 
CheckForUserNameFail(
  VOID
  );

VOID 
ResetUserNameFailCounter(
  VOID
  );


VOID 
UpdateUserNameFailCounter(
  VOID
  );

VOID 
ResetUserPasswordFailCounter(
  VOID
  );

BOOLEAN 
CheckForUserPasswordFail(
  VOID
  );


EFI_STATUS
LoginFailCntUpdate(
  VOID
  );



VOID 
UpdateUserPasswordFailCounter(
  VOID
  );

BOOLEAN
GetMiiMode(
  VOID
  );

VOID
SetMiiMode(
  IN BOOLEAN bVal
  );

BOOLEAN
GetTokenInserted(
  VOID
  );

VOID
SetTokenInserted(
  VOID
  );

VOID
ResetTokenInserted(
  VOID
  );

VOID
LockAdminMenu(
  IN UINT32 LockMask
  );


UINT32
GetAdminMenuLockMask(
  VOID
  );

VOID
SetAdminAdditionalFunction(
  IN int Func
  );

int GetAdminAdditionalFunction(
  VOID
  );

VOID
SetSuOnlyMode(
  VOID
  );

BOOLEAN
SuOnlyMode(
  VOID
  );

EFI_STATUS
LocksUpdateWrongPinCnt (
  VOID
  );

EFI_STATUS
LocksGetWrongPinCnt (
  IN OUT UINT32 *Cnt
  );

EFI_STATUS
LocksResetWrongPinCnt (
  VOID
  );

EFI_STATUS
LocksResetWrongPinCnt (
  VOID
  );

EFI_STATUS
LocksGetWrongPinTreshold (
  IN OUT UINT32 *Val
  );

EFI_STATUS
LocksGetWrongPinCnt (
  IN OUT UINT32 *Cnt
  );

EFI_STATUS
LocksUpdateWrongPinCnt (
  VOID
  );

EFI_STATUS
LocksSetWrongPinTreshold (
  IN UINT32 Val
  );


#endif  /* #ifndef __LOCKS__H */

