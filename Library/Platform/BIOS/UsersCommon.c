/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/Lib/SuperUser.h>
#include <Library/Lib/Users.h>
#include <Library/UserManagerLib.h>

#if 1
#define LOG(MSG)
#else
#define LOG(MSG)      DEBUG(MSG)
#endif

STATIC USER_INFO *pLastFoundUserInfo;
USERS_STORAGE UsrStrorage;

VOID
DumpUsersDB (
  VOID
  )
{
  EFI_STATUS Status;
  UINTN TotalLen, RecordSize;
  UINT8 *DataPtr;
  USER_INFO *pUserInfo;
  UINT8 AccessInfo;
  
  Status = UsersStorageGetData(&UsrStrorage);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return;
  }
  
  if (UsrStrorage.DataLen == 0) {
    LOG((EFI_D_ERROR, "%a.%d: UsrStrorage.DataLen=%d\n", 
      __FUNCTION__, __LINE__, UsrStrorage.DataLen));
    return;
  }
  
  TotalLen = UsrStrorage.DataLen;
  DataPtr = UsrStrorage.Data;
  
  while (TotalLen) {
    pUserInfo = (USER_INFO*)DataPtr;
    RecordSize = sizeof(USER_INFO) - 1;
    LOG((EFI_D_ERROR, "RecordSize=%d, pUserInfo->UserId: %d\n",
      RecordSize, pUserInfo->UserId));

    RecordSize += pUserInfo->ExtDataLen;

    if (TotalLen < RecordSize) {
      LOG((EFI_D_ERROR, "%a.%d: Attention!!! Users storage may be corrupted!!!!\n",
        __FUNCTION__, __LINE__));
      break;
    }

    AccessInfo = 0;
    GetUserAccessInfo (pUserInfo->UserId, &AccessInfo);
   
    TotalLen -= RecordSize;
    DataPtr += RecordSize;
  }  
}

EFI_STRING
UsersGetTypeString16 (
  IN UINT8 UsrType,
  IN EFI_HII_HANDLE HiiHandle
  )
{
  EFI_STRING_ID UsrTypeStr[] = {
    STRING_TOKEN(STR_AUTH_LOGIN_PASS),    
    STRING_TOKEN(STR_USR_NAME_UNKNOWN)
  };
  
  if (UsrType >= AUTH_TYPE_UNKNOWN) {
    UsrType = sizeof(UsrTypeStr) / sizeof(UsrTypeStr[0]) - 1;
    
  }
  return HiiGetString(HiiHandle, UsrTypeStr[UsrType], NULL);
}

USER_INFO *
GetStaticUserInfo(
  VOID
  )
{
  STATIC USER_INFO *pUserInfo;
  STATIC BOOLEAN bCreated;
  
  if (bCreated) {
    goto _done;
  }
  
  pUserInfo = AllocateZeroPool(sizeof(USER_INFO) - 1 + 
    sizeof(USER_INFO_LOG_PASS));
  if (NULL == pUserInfo) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return NULL;
  }
  
 bCreated = TRUE;
_done:
  
  return pUserInfo;
}


USER_INFO *
ObtainSuRecord(
  VOID
  )
{
  static USER_INFO *Su;
  USER_INFO_LOG_PASS *pLogPassUsr;
  
  if (Su == NULL) {
    Su = (USER_INFO*)AllocateZeroPool(sizeof(USER_INFO) - 1 + 
      sizeof(USER_INFO_LOG_PASS));
    if (Su == NULL) {
      return NULL;
    }
    Su->AuthType = AUTH_TYPE_LOG_PASS;
    Su->Flags = USER_ADMIN_FLAG | USER_SU_FLAG;
    StrCpy(Su->UserName, SU_NAME16);
    Su->UserId = USER_SU_ID;
    Su->ExtDataLen = sizeof(USER_INFO_LOG_PASS);
    pLogPassUsr = (USER_INFO_LOG_PASS*)Su->ExtData;
    pLogPassUsr->PassHashType = PASSWD_HASH_TYPE;
    SuGetHash(pLogPassUsr->PassHash);
  }
  return Su;
}


EFI_STATUS
UserFindRecordById (
  IN UINT8 UserId
  )
{
  EFI_STATUS Status;
  UINTN TotalLen, RecordSize;
  UINT8 *DataPtr;
  USER_INFO *pUserInfo;
  
  LOG((EFI_D_ERROR, "%a.%d Start UserId=0x%02X\n", 
    __FUNCTION__, __LINE__, UserId));
  
  pLastFoundUserInfo = NULL;

  if (UserId == 0) { /* special case for static user record */
    pLastFoundUserInfo = GetStaticUserInfo();
    return EFI_SUCCESS;
  }
  if (UserId == USER_SU_ID) {
    pLastFoundUserInfo = ObtainSuRecord();
    return EFI_SUCCESS;
  }
  if (UserId == USER_AMT_ID) {
    pLastFoundUserInfo = GetAmtUsrInfo();
    return EFI_SUCCESS;
  }
  
  Status = UsersStorageGetData(&UsrStrorage);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  
  if (UsrStrorage.DataLen == 0) {
    LOG((EFI_D_ERROR, "%a.%d: UsrStrorage.DataLen=%d\n", 
      __FUNCTION__, __LINE__, UsrStrorage.DataLen));
    return EFI_NOT_FOUND;
  }
  
  Status = UsersStorageCheckIntegrity();
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  
  TotalLen = UsrStrorage.DataLen;
  DataPtr = UsrStrorage.Data;
  
  while (TotalLen) {
    pUserInfo = (USER_INFO*)DataPtr;
    RecordSize = sizeof(USER_INFO) - 1;
    LOG((EFI_D_ERROR, "RecordSize=%d, pUserInfo->UserId: %d\n",
      RecordSize, pUserInfo->UserId));

    RecordSize += pUserInfo->ExtDataLen;

    if (TotalLen < RecordSize) {
      LOG((EFI_D_ERROR, "%a.%d: Attention!!! Users storage may be corrupted!!!!\n",
        __FUNCTION__, __LINE__));
      break;
    }

    if (pUserInfo->UserId == UserId) {
      pLastFoundUserInfo = pUserInfo;
      return EFI_SUCCESS;
    }
    TotalLen -= RecordSize;
    DataPtr += RecordSize;
  }
  LOG((EFI_D_ERROR, "%a.%d EFI_NOT_FOUND\n", __FUNCTION__, __LINE__));
  return EFI_NOT_FOUND;
}

