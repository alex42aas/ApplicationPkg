/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/Lib/Locks.h>
#include <Library/Lib/Users.h>
#include <Library/Lib/History.h>


static BOOLEAN bMiiMode;
static UINT32 AdminMenuLockedMask;
static int AdminAdditionalFunc;
static BOOLEAN TokenWasInserted, bTokenLoginLocked, bTokenLoginOnly;
STATIC BOOLEAN bTokenDisable;
static int UserNameFailCounter;
static int UserPasswordFailCounter;
static EFI_HII_HANDLE CurrentHiiHandle;
static UINT32 MainMenuLockedMask;
static BOOLEAN bSuOnlyMode;


BOOLEAN
IsTokenDisabled(
  VOID
  )
{
  return bTokenDisable;
}

VOID
DisableToken(
  IN BOOLEAN bDisable
  )
{
  bTokenDisable = bDisable;
}

BOOLEAN
TokenLoginOnly(
  VOID
  )
{
  return bTokenLoginOnly;
}


VOID
SetTokenLoginOnly(
  VOID
  )
{
  bTokenLoginOnly = TRUE;
}


BOOLEAN
TokenUserLoginLocked(
  VOID
  )
{
  return bTokenLoginLocked;  
}


VOID
LockForTokenUserLogin(
  VOID
  )
{
  bTokenLoginLocked = TRUE;  
}

VOID
UnlockForTokenUserLogin(
  VOID
  )
{
  bTokenLoginLocked = FALSE;  
}



BOOLEAN
MainMenuAdmModeLocked(
  VOID
  )
{
  if (MainMenuLockedMask & MAIN_MENU_LOCKED_ADMIN_MODE) {
    return TRUE;
  }
  return FALSE;
}

VOID
MainMenuLockOff(
  VOID
  )
{
  MainMenuLockedMask = 0;
}


VOID
MainMenuLockAdmMode(
  VOID
  )
{
  MainMenuLockedMask |= MAIN_MENU_LOCKED_ADMIN_MODE;
}

EFI_STATUS
LoginFailCntClean(
  VOID
  )
{
  USER_INFO *pUserInfo;
  
  pUserInfo = UserGetLastFoundedInfo();
  if (pUserInfo == NULL) {
    return EFI_ABORTED;
  }

  DEBUG((EFI_D_ERROR, "%a.%d pUserInfo->LoginFailCnt=%d\n",
    __FUNCTION__, __LINE__, pUserInfo->LoginFailCnt));
  
  pUserInfo->LoginFailCnt = 0;
  return UsersStorageUpdate();
}

EFI_STATUS
LocksGetCntByIdx (
  IN OUT UINT32 *Cnt,
  IN UINTN Idx
  )
{
  UINTN Size;
  UINT32 Vars[16];
  EFI_STATUS Status;

  if (Cnt == NULL || Idx >= 16) {
    return EFI_INVALID_PARAMETER;
  }
  
  Size = sizeof(Vars);
  Status = gRT->GetVariable(LOCKS_VAR_COUNTER_NAME, &gLocksCounterVarGuid,
      NULL, &Size, Vars);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  *Cnt = Vars[Idx];
  return EFI_SUCCESS;
}

EFI_STATUS
LocksSetCntByIdx (
  IN UINT32 Cnt,
  IN UINTN Idx
  )
{
  UINTN Size;
  UINT32 Vars[16];
  EFI_STATUS Status;

  if (Idx >= 16) {
    return EFI_INVALID_PARAMETER;
  }
  Size = sizeof (Vars);
  Status = gRT->GetVariable (
        LOCKS_VAR_COUNTER_NAME, 
        &gLocksCounterVarGuid,
        NULL, 
        &Size, 
        Vars);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  
  Vars[Idx] = Cnt;

  gRT->SetVariable(
        LOCKS_VAR_COUNTER_NAME, 
        &gLocksCounterVarGuid,
        (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS), 
        Size, 
        Vars);
  return EFI_SUCCESS;
}

EFI_STATUS
LocksResetWrongPinCnt (
  VOID
  )
{
  return LocksSetCntByIdx(0, LOCK_VAR_WRONG_PIN_CNT_IDX);
}


EFI_STATUS
LocksGetWrongPinTreshold (
  IN OUT UINT32 *Val
  )
{
  return LocksGetCntByIdx(Val, LOCK_VAR_WRONG_PIN_TRESHOLD_IDX);
}


EFI_STATUS
LocksGetWrongPinCnt (
  IN OUT UINT32 *Cnt
  )
{
  return LocksGetCntByIdx(Cnt, LOCK_VAR_WRONG_PIN_CNT_IDX);
}

EFI_STATUS
LocksUpdateWrongPinCnt (
  VOID
  )
{
  EFI_STATUS Status;
  UINT32 Cnt;
  
  Status = LocksGetWrongPinCnt (&Cnt);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  Cnt++;
  return LocksSetCntByIdx(Cnt, LOCK_VAR_WRONG_PIN_CNT_IDX);
}

EFI_STATUS
LocksSetWrongPinTreshold (
  IN UINT32 Val
  )
{
  return LocksSetCntByIdx(Val, LOCK_VAR_WRONG_PIN_TRESHOLD_IDX);
}


EFI_STATUS
LocksInit(
  IN EFI_HII_HANDLE HiiHandle
  )
{
  UINTN Size;
  UINT32 Vars[16];
  EFI_STATUS Status;
  
  CurrentHiiHandle = HiiHandle;
  
  Size = sizeof(Vars);
  Status = gRT->GetVariable(LOCKS_VAR_COUNTER_NAME, &gLocksCounterVarGuid,
      NULL, &Size, Vars);
  if (Status == EFI_NOT_FOUND || Size != sizeof(Vars)) {
    Size = sizeof(Vars);
    ZeroMem(Vars, Size);
    Vars[LOCK_VAR_WRONG_PIN_TRESHOLD_IDX] = LOCK_VAR_WRONG_PIN_TRESHOLD_DEF;
    return gRT->SetVariable(LOCKS_VAR_COUNTER_NAME, &gLocksCounterVarGuid,
      (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS), 
      Size, Vars);
  } 

  if (Size != sizeof(Vars)) {
    return EFI_INVALID_PARAMETER;
  }
  return EFI_SUCCESS;
}

EFI_STATUS
LoginFailCntUpdate(
  VOID
  )
{
  USER_INFO *pUserInfo;

  pUserInfo = UserGetLastFoundedInfo();
  if (pUserInfo == NULL) {
    return EFI_ABORTED;
  }

  DEBUG((EFI_D_ERROR, "%a.%d pUserInfo->LoginFailCnt=%d\n",
    __FUNCTION__, __LINE__, pUserInfo->LoginFailCnt));
  pUserInfo->LoginFailCnt++;
  if (pUserInfo->LoginFailCnt >= LOCKS_MAX_LOGIN_FAIL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    pUserInfo->LoginFailCnt = 0;
    return EFI_ABORTED;
  }
  return UsersStorageUpdate();
}


BOOLEAN 
CheckForUserNameFail(
  VOID
  )
{
  switch (UserNameFailCounter) {
  case 0:
    return FALSE;

  case 1:
    ShowLockPopup(CurrentHiiHandle, 
      HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_BIOS_LOCK1), NULL),
      10, FALSE);  
    break;

  case 2:
    ShowLockPopup(CurrentHiiHandle, 
      HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_BIOS_LOCK1), NULL),
      30, FALSE);
    break;

  default:
    ShowLockPopup(CurrentHiiHandle, 
      HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_BIOS_LOCK1), NULL),
      60, TRUE);
  }
    
  return TRUE;
}

VOID 
ResetUserNameFailCounter(
  VOID
  )
{
  UserNameFailCounter = 0;
}

VOID 
UpdateUserNameFailCounter(
  VOID
  )
{
  UserNameFailCounter++;
}

VOID 
ResetUserPasswordFailCounter(
  VOID
  )
{
  UserPasswordFailCounter = 0;
}


VOID 
UpdateUserPasswordFailCounter(
  VOID
  )
{
  UserPasswordFailCounter++;
}

BOOLEAN 
CheckForSuPasswordFail(
  VOID
  )
{
  USER_INFO *pUserInfo;
    
  if (UserPasswordFailCounter >= 2) {
    ShowLockPopup(CurrentHiiHandle, 
      HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_BIOS_LOCK1), NULL),
      100, FALSE);
    UserPasswordFailCounter = 2;
    return TRUE;
  }
  pUserInfo = UserGetLastFoundedInfo();
  if (pUserInfo == NULL) {
    return FALSE;
  }
  if (pUserInfo->LoginFailCnt >= 2) {
    ShowLockPopup(CurrentHiiHandle, 
      HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_BIOS_LOCK1), NULL),
      100, FALSE);
    pUserInfo->LoginFailCnt = 2;
    return TRUE;
  }
    
  return FALSE;
}


BOOLEAN 
CheckForUserPasswordFail(
  VOID
  )
{
  switch (UserPasswordFailCounter) {
  case 3:
    ShowLockPopup(CurrentHiiHandle, 
      HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_BIOS_LOCK1), NULL),
      60, FALSE);  
    break;

  case 6:
    ShowLockPopupWithTimedSound (
      CurrentHiiHandle, 
      HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_BIOS_LOCK1), NULL),
      120, 
      10
      );
    break;

  case 9:
    {
      CHAR16 *BlockedStr16;
      BlockedStr16 = HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(STR_BIOS_LOCK1), NULL);
      BeepOn(1000);
      ShowErrorPopup(CurrentHiiHandle, BlockedStr16);
      CpuDeadLoop();
    }
    break;

  case 20:
    {
      CHAR16 TmpStr16[1024], *UsrTypeStr16, *BlockedStr16;
      USER_INFO *pUserInfo;

      pUserInfo = UserGetLastFoundedInfo();
      if (NULL == pUserInfo) {
        DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
        MsgInternalError(INT_ERR_WHILE_READ_USERS_STORAGE);
      }
      if (pUserInfo->Flags & USER_ADMIN_FLAG) {
        UsrTypeStr16 = HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(STR_USERS_TYPE_ADMIN), NULL);
      } else {      
        UsrTypeStr16 = HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(STR_USERS_TYPE_USER), NULL);        
      }

      BlockedStr16 = HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(STR_BLOCK_FLAG_ON), NULL);
      pUserInfo->Flags |= USER_BLOCKED_FLAG;
      UsersStorageUpdate();
      HistoryAddRecord (
        HEVENT_USER_BLOCKED, 
        pUserInfo->UserId, 
        SEVERITY_LVL_ERROR, 
        HISTORY_RECORD_FLAG_RESULT_OK
        );
      UnicodeSPrint(TmpStr16, sizeof(TmpStr16), L"%s %s %s", 
          UsrTypeStr16, pUserInfo->UserName, BlockedStr16);
      BeepOn(1000);
      ShowErrorPopup(CurrentHiiHandle, TmpStr16);      
      CpuDeadLoop();
    }
    break;

  default:
    if (UserPasswordFailCounter > 20) {
      UserPasswordFailCounter = 20;
    }
    return FALSE;
  }
    
  return TRUE;
}



BOOLEAN
GetMiiMode(
  VOID
  )
{
  return bMiiMode;
}

VOID
SetMiiMode(
  IN BOOLEAN bVal
  )
{
  bMiiMode = bVal;
}


BOOLEAN
GetTokenInserted(
  VOID
  )
{
  return TokenWasInserted;
}

VOID
SetTokenInserted(
  VOID
  )
{
  TokenWasInserted = TRUE;
}


VOID
ResetTokenInserted(
  VOID
  )
{
  TokenWasInserted = FALSE;
}


VOID
LockAdminMenu(
  IN UINT32 LockMask
  )
{
  AdminMenuLockedMask = LockMask;
}

UINT32
GetAdminMenuLockMask(
  VOID
  )
{
  return AdminMenuLockedMask;
}

VOID
SetAdminAdditionalFunction(
  IN int Func
  )
{
  AdminAdditionalFunc = Func;
}

int GetAdminAdditionalFunction(
  VOID
  )
{
  return AdminAdditionalFunc;
}

VOID
SetSuOnlyMode(
  VOID
  )
{
  bSuOnlyMode = TRUE;
}

BOOLEAN
SuOnlyMode(
  VOID
  )
{
  return bSuOnlyMode;
}


