/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/Lib/UsersStorage.h>

static UINT8 *UsersData;
static UINTN UsersMaxCardsNum;
static UINTN UsersStorageMaxDataLen;
static BOOLEAN bDontCheckCardsAmount;
STATIC BOOLEAN bDummyReadStorage;


VOID
UsersStorageSetDummyReadFlag(
  IN BOOLEAN bVal
  )
{
  bDummyReadStorage = bVal;
}


VOID
UsersStorageSetSpecialFlag(
  IN BOOLEAN bVal
  )
{
  bDontCheckCardsAmount = bVal;
}


static
VOID
InitMaxCardsCountAndMaxUsersData(
  VOID
  )
{
  UsersStorageMaxDataLen = PcdGet32(PcdUsersStorageMaxSize);
  if (UsersStorageMaxDataLen < USERS_MAX_CARD_SIZE) {
    UsersMaxCardsNum = 1;
  } else {
    UsersMaxCardsNum = (UsersStorageMaxDataLen + 
      USERS_MAX_CARD_SIZE) / USERS_MAX_CARD_SIZE;
  }
  UsersStorageMaxDataLen += USERS_MAX_CARD_SIZE;
}

EFI_STATUS
UsersStoragePresent(
  VOID
  )
{
  SetStorageAttributes(STORAGE_WRITE_ONLY_ATTR);
  return StoragePresent(USERS_STORAGE_VAR_NAME, &gUsersStorageGuid);
}


EFI_STATUS
UsersStorageInitEmpty(
  VOID
  )
{
  SetStorageAttributes(STORAGE_WRITE_ONLY_ATTR);
  return StorageInitEmpty(USERS_STORAGE_VAR_NAME, &gUsersStorageGuid,
    NULL, 0, NULL, FALSE);
}


EFI_STATUS
UsersStorageGetData(
  IN OUT USERS_STORAGE *UsrStorage
  )
{
  EFI_STATUS Status;

  if (bDummyReadStorage) {
    return EFI_SUCCESS;
  }
  
  if (UsersStorageMaxDataLen == 0 || UsersMaxCardsNum == 0) {
    InitMaxCardsCountAndMaxUsersData();
  }
  if (UsrStorage->Data == NULL) {
    UsrStorage->Data = UsersData;
  }
  SetStorageAttributes(STORAGE_WRITE_ONLY_ATTR);  
  Status = StorageGetData2(&gUsersStorageGuid, USERS_STORAGE_VAR_NAME, 
    (STORAGE_DATA*)UsrStorage, UsersStorageMaxDataLen);
  if (UsersData == NULL) {
    UsersData = UsrStorage->Data;
  }
  return Status;
}

EFI_STATUS
UsersStorageCheckIntegrity(
  VOID
  )
{
  USERS_STORAGE UsrStorage;
  
  ZeroMem(&UsrStorage, sizeof(USERS_STORAGE));
  return UsersStorageGetData(&UsrStorage);
}

EFI_STATUS
UsersStorageSetRawData(
  IN UINT8 *RawData,
  IN UINTN RawDataLen
  )
{
  if (UsersStorageMaxDataLen == 0 || UsersMaxCardsNum == 0) {
    InitMaxCardsCountAndMaxUsersData();
  }
  SetStorageAttributes(STORAGE_WRITE_ONLY_ATTR);
  return StorageSetRawData2(&gUsersStorageGuid, USERS_STORAGE_VAR_NAME,
    RawData, RawDataLen, UsersMaxCardsNum, UsersStorageMaxDataLen,
    USERS_MAX_CARD_SIZE, bDontCheckCardsAmount);
}


