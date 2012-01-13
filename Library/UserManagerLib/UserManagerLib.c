/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/UserManagerLib.h>

#if 1
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif



STATIC USERS_ACCESS_STORAGE *gUsersAccessStorage;
STATIC EFI_GUID gUsersAccessInfoGuid = USERS_ACCESS_INFO_GUID;
STATIC USERS_ACCESS_INFO *pLastFoundedAccessInfo;


STATIC
EFI_STATUS
SaveUsersAccessInfo (
  VOID
  )
{
  EFI_STATUS Status;

  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if (gUsersAccessStorage == NULL) {
    LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  Status = gRT->SetVariable(USERS_ACCESS_INFO_NAME, &gUsersAccessInfoGuid, 
    EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS, 
    sizeof(*gUsersAccessStorage) - 1 + gUsersAccessStorage->DataLen, 
    gUsersAccessStorage);
  LOG ((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}

STATIC
EFI_STATUS
ObtainUsersAccessInfo (
  VOID
  )
{
  EFI_STATUS Status;
  UINTN Size;

  if (gUsersAccessStorage) {
    FreePool (gUsersAccessStorage);
    gUsersAccessStorage = NULL;
  }

  Size = 0;
  Status = gRT->GetVariable(USERS_ACCESS_INFO_NAME, &gUsersAccessInfoGuid, 
    NULL, &Size, NULL);
  if (!EFI_ERROR(Status)) {
    LOG ((EFI_D_ERROR, "%a.%d Error!Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return EFI_ABORTED;
  }
  if (Status != EFI_BUFFER_TOO_SMALL) {
    LOG ((EFI_D_ERROR, "%a.%d Error!Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  if (Size == 0 || Size < (sizeof(*gUsersAccessStorage) - 1)) {
    LOG ((EFI_D_ERROR, "%a.%d Error!Size=%d\n", __FUNCTION__, __LINE__, Size));
    return EFI_NOT_FOUND;
  }
  
  gUsersAccessStorage = AllocateZeroPool(Size);
  if (NULL == gUsersAccessStorage) {
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  LOG ((EFI_D_ERROR, "%a.%d Size=%d\n", __FUNCTION__, __LINE__, Size));
  Status = gRT->GetVariable(USERS_ACCESS_INFO_NAME, &gUsersAccessInfoGuid,
        NULL, &Size, gUsersAccessStorage);
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_ERROR, "%a.%d Error!Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    FreePool (gUsersAccessStorage);
    gUsersAccessStorage = NULL;    
  }
  return Status;
}

EFI_STATUS
CheckUserAccessInfoPresent (
  IN UINT8 UserId
  )
{
  EFI_STATUS Status;
  UINT32 DataLen;
  USERS_ACCESS_INFO *pAccessInfo;
  UINT8 *DataPtr;

  pLastFoundedAccessInfo = NULL;

  LOG ((EFI_D_ERROR, "%a.%d UserId=%X\n", __FUNCTION__, __LINE__, UserId));

  Status = ObtainUsersAccessInfo ();
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  DataLen = gUsersAccessStorage->DataLen;
  if (DataLen < sizeof (USERS_ACCESS_INFO)) {
    LOG ((EFI_D_ERROR, "%a.%d Error! DataLen=%X\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  LOG ((EFI_D_ERROR, "%a.%d DataLen=0x%X\n", __FUNCTION__, __LINE__, DataLen));

  DataPtr = gUsersAccessStorage->Data;
  while (DataLen) {
    pAccessInfo = (USERS_ACCESS_INFO*)DataPtr;
    LOG ((EFI_D_ERROR, "%a.%d pAccessInfo->UsrId=%X\n", 
      __FUNCTION__, __LINE__, pAccessInfo->UsrId));
    if (pAccessInfo->UsrId == UserId) {
      pLastFoundedAccessInfo = pAccessInfo;
      return EFI_SUCCESS;
    }
    DataPtr += sizeof (USERS_ACCESS_INFO);
    DataLen -= sizeof (USERS_ACCESS_INFO);
  }
  return EFI_NOT_FOUND;
}


EFI_STATUS
DeleteUserAccessInfo (
  IN UINT8 UserId
  )
{
  EFI_STATUS Status;
  UINT8 *BegPtr, *EndPtr;
  UINTN Len;
  
  Status = CheckUserAccessInfoPresent (UserId);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  BegPtr = (UINT8*)pLastFoundedAccessInfo;
  // calculate length from begin to deleting value
  Len = (UINT8*)pLastFoundedAccessInfo - gUsersAccessStorage->Data;
  EndPtr = BegPtr + sizeof(USERS_ACCESS_INFO);

  gUsersAccessStorage->DataLen -= sizeof(USERS_ACCESS_INFO);

  if (Len < gUsersAccessStorage->DataLen) {
    return EFI_ABORTED;
  }
  // calculate length of rest data
  Len = gUsersAccessStorage->DataLen - Len;

  if (Len) {
    CopyMem (BegPtr, EndPtr, Len);
  }
  Status = SaveUsersAccessInfo ();
  LOG ((EFI_D_ERROR, "%a.%d Status=0x%X\n", 
    __FUNCTION__, __LINE__, Status));
  return Status;
}


EFI_STATUS
AddUserAccessInfo (
  IN UINT8 UserId,
  IN UINT8 AccessType
  )
{
  EFI_STATUS Status;
  USERS_ACCESS_STORAGE *pAccessStorage;
  USERS_ACCESS_INFO *pUserInfo;

  LOG ((EFI_D_ERROR, "%a.%d UserId=0x%X AccessType=0x%X\n", 
    __FUNCTION__, __LINE__, UserId, AccessType));
  
  Status = ObtainUsersAccessInfo ();
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }
  Status = CheckUserAccessInfoPresent (UserId);
  if (!EFI_ERROR(Status)) {
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }

  pAccessStorage = AllocateZeroPool (sizeof (USERS_ACCESS_STORAGE) - 1 + 
    gUsersAccessStorage->DataLen + sizeof (USERS_ACCESS_INFO));
  if (pAccessStorage == NULL) {
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem (pAccessStorage, gUsersAccessStorage, 
    sizeof(*gUsersAccessStorage) - 1 + gUsersAccessStorage->DataLen);

  pUserInfo = (USERS_ACCESS_INFO*)(pAccessStorage->Data + 
    pAccessStorage->DataLen);
  pUserInfo->AccessType = AccessType;
  pUserInfo->UsrId = UserId;

  pAccessStorage->DataLen += sizeof (USERS_ACCESS_INFO);
  
  FreePool (gUsersAccessStorage);
  gUsersAccessStorage = pAccessStorage;

  Status = SaveUsersAccessInfo ();
  LOG ((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}

EFI_STATUS
ChangeUserAccessInfo (
  IN UINT8 UserId,
  IN UINT8 AccessType
  )
{
  EFI_STATUS Status;

  Status = CheckUserAccessInfoPresent (UserId);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  if (pLastFoundedAccessInfo->AccessType == AccessType) {
    return EFI_SUCCESS;
  }
  pLastFoundedAccessInfo->AccessType = AccessType;
  Status = SaveUsersAccessInfo();
  LOG ((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}

EFI_STATUS
GetUserAccessInfo (
  IN UINT8 UserId,
  IN OUT UINT8 *AccessType
  )
{
  EFI_STATUS Status;

  Status = CheckUserAccessInfoPresent (UserId);
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }
  *AccessType = pLastFoundedAccessInfo->AccessType;
  return EFI_SUCCESS;
}

EFI_STATUS
UsersInfoInit (
  VOID
  )
{
  EFI_STATUS Status;
//  USERS_ACCESS_INFO *pUserInfo;

  Status = ObtainUsersAccessInfo ();
  if (EFI_ERROR(Status)) {
    gUsersAccessStorage = AllocateZeroPool(sizeof(*gUsersAccessStorage) - 1 + 
      sizeof(USERS_ACCESS_INFO));
    if (gUsersAccessStorage == NULL) {
      LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_OUT_OF_RESOURCES;
    }
    gUsersAccessStorage->DataLen = 0;
  }

  Status = SaveUsersAccessInfo ();
  LOG ((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}


EFI_STATUS
SetCurrentUserVar (
  IN UINT8 *UserData,
  IN UINTN UserDataLen
  )
{
  EFI_GUID CurrentUserGuid = CURRENT_USER_VAR_GUID;
  EFI_STATUS Status;
  
  Status = gRT->SetVariable(CURRENT_USER_VAR_NAME, &CurrentUserGuid, 
    EFI_VARIABLE_BOOTSERVICE_ACCESS, 
    UserDataLen, 
    UserData);

  return Status;
}

EFI_STATUS
GetCurrentUserVar (
  IN OUT UINT8 **UserData,
  IN UINTN *UserDataLen
  )
{
  EFI_GUID CurrentUserGuid = CURRENT_USER_VAR_GUID;
  EFI_STATUS Status;
  UINTN Size;
  UINT8 *Data;

  if (UserData == NULL || UserDataLen == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *UserData = NULL;
  *UserDataLen = 0;
  
  Size = 0;
  Status = gRT->GetVariable(CURRENT_USER_VAR_NAME, &CurrentUserGuid, 
    NULL, &Size, NULL);
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_ERROR, "%a.%d Error!Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
  }
  if (Size == 0) {
    LOG ((EFI_D_ERROR, "%a.%d Error!Size=%d\n", __FUNCTION__, __LINE__, Size));
    return EFI_NOT_FOUND;
  }
  
  Data = AllocateZeroPool(Size);
  if (NULL == Data) {
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  LOG ((EFI_D_ERROR, "%a.%d Size=%d\n", __FUNCTION__, __LINE__, Size));
  Status = gRT->GetVariable(CURRENT_USER_VAR_NAME, &CurrentUserGuid,
        NULL, &Size, Data);
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_ERROR, "%a.%d Error!Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    FreePool (Data);
  } else {
    *UserData = Data;
    *UserDataLen = Size;
  }
  return Status;
}


EFI_STATUS
GetNextUserAccessInfo (
  IN OUT USERS_ACCESS_INFO *UsrInfo,
  IN BOOLEAN bRestart
  )
{
  EFI_STATUS Status;
  USERS_ACCESS_INFO *pAccessInfo;
  STATIC UINTN Idx;

  if (UsrInfo == NULL) {
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  Status = ObtainUsersAccessInfo ();
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  if (bRestart) {
    Idx = 0;
  }

  if (gUsersAccessStorage->DataLen < sizeof (USERS_ACCESS_INFO) * Idx) {
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  pAccessInfo = (USERS_ACCESS_INFO*)gUsersAccessStorage->Data;
  CopyMem (UsrInfo, &pAccessInfo[Idx], sizeof (USERS_ACCESS_INFO));
  Idx++;
  return EFI_SUCCESS;
}




