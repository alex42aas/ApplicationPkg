/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __USERS__STORAGE__H
#define __USERS__STORAGE__H


#include <Library/CommonUtils.h>
#include <Library/ExtHdrUtils.h>
#include <Library/VarStorageUtils.h>
#include <Library/PcdLib.h>
#include <Guid/VariableFormat.h>


#define USERS_STORAGE_VAR_NAME              L"UsersStorage"
#define USERS_STORAGE_VAR_NAME_WITH_NUM     L"UsersStorage_00000000"
#define USERS_STORAGE_MAX_NAME_LEN          (sizeof(USERS_STORAGE_VAR_NAME_WITH_NUM))
#define USERS_CARDS_MAX_NUMBER              (1)
#define USERS_MAX_CARD_SIZE                 (PcdGet32(PcdMaxVariableSize) - sizeof (VARIABLE_HEADER) - USERS_STORAGE_MAX_NAME_LEN)
#define USERS_STORAGE_MAX_DATA_LEN          (PcdGet32(PcdUsersStorageMaxSize) + USERS_MAX_CARD_SIZE)
#define DEFAULT_USERS_STORAGE_VAR_ATTR      (EFI_VARIABLE_NON_VOLATILE | \
                                             EFI_VARIABLE_BOOTSERVICE_ACCESS)
#define USERS_STORAGE_CS_TYPE               (CS_TYPE_CRC32)


#pragma pack(1)
typedef struct T_USR_CARD_DESC {
  UINT32 DataLen;  
  UINT8 CsType;
  UINT8 CsData[MAX_HASH_LEN];
  UINT8 Data[1];
} USR_CARD_DESC;

typedef struct T_USERS_STORAGE {  
  UINT32 DataLen;
  UINT8 *Data;
} USERS_STORAGE;
#pragma pack()


extern GUID gUsersStorageGuid;


VOID
UsersStorageSetDummyReadFlag(
  IN BOOLEAN bVal
  );

VOID
UsersStorageSetSpecialFlag(
  IN BOOLEAN bVal
  );


EFI_STATUS
UsersStoragePresent(
  VOID
  );


EFI_STATUS
UsersStorageGetData(
  IN OUT USERS_STORAGE *UsrStrorage
  );


EFI_STATUS
UsersStorageSetRawData(
  IN UINT8 *RawData,
  IN UINTN RawDataLen
  );


EFI_STATUS
UsersStorageInitEmpty(
  VOID
  );


EFI_STATUS
UsersStorageCheckIntegrity(
  VOID
  );


#endif /* #ifndef __USERS__STORAGE__H */

