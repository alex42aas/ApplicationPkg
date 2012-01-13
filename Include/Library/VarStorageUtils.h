/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __VAR__STORAGE__UTILS__H
#define __VAR__STORAGE__UTILS__H


#define STORAGE_WRITE_ONLY_ATTR                   (EFI_VARIABLE_NON_VOLATILE | \
          EFI_VARIABLE_BOOTSERVICE_ACCESS)
#define STORAGE_RDWR_ATTR                         (EFI_VARIABLE_NON_VOLATILE | \
          EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS)

extern EFI_GUID gEfiVarStorageGuid;


#pragma pack(1)

typedef struct T_STORAGE_DESC {
  EFI_GUID StorageGuid;
  UINT32 Count;
  UINT32 TotalLen;
} STORAGE_DESC;

typedef struct T_STORAGE_CARD_DESC {
  UINT32 DataLen;  
  UINT8 CsType;
  UINT8 CsData[MAX_HASH_LEN];
  UINT8 Data[1];
} STORAGE_CARD_DESC;

typedef struct T_STORAGE_DATA {  
  UINT32 DataLen;
  UINT8 *Data;
} STORAGE_DATA;

#pragma pack()


VOID
SetStorageAttributes(
  IN UINT32 Attr
  );

EFI_STATUS
SetStorageRawDataByNum(
  IN UINT32 Num,
  IN EFI_GUID *pStorageGuid,
  IN CHAR16 *StorageName,
  IN UINT8 *Data,
  IN UINT32 DataLen
  );

EFI_STATUS
GetStorageRawDataByNum(
  IN UINT32 Num,
  IN EFI_GUID *pStorageGuid,
  IN CHAR16 *StorageName,
  IN OUT UINT8 **Data,
  IN OUT UINT32 *DataLen
  );

EFI_STATUS
GetStorageCardsCountAndTotalLen(
  IN EFI_GUID *pStorageGuid,
  IN CHAR16 *StorageName,
  IN OUT UINT32 *CardsCount,
  IN OUT UINT32 *TotalLen
  );

EFI_STATUS
SetStorageCardsCountAndTotalLen(
  IN EFI_GUID *pStorageGuid,
  IN CHAR16 *StorageName,
  IN UINT32 CardsCount,
  IN UINT32 TotalLen
  );


EFI_STATUS
StoragePresent(
  IN CHAR16 *StorageVarName,
  IN GUID *pStorageGuid
  );

BOOLEAN
IsStorageEmpty (
  IN CHAR16 *StorageVarName,
  IN GUID *pStorageGuid
  );

EFI_STATUS
StorageInitEmpty(
  IN CHAR16 *StorageVarName,
  IN GUID *pStorageGuid,
  IN UINT8 *pData,
  IN UINTN DataLen,
  IN UINT8 *pCsTypeField,
  IN BOOLEAN bSaveNow
  );


EFI_STATUS
StorageGetData(
  IN CHAR16 *StorageVarName,
  IN GUID *pStorageGuid,
  IN UINT8 *pData,
  IN UINTN DataLen
  );

EFI_STATUS
StorageGetData2(
  IN EFI_GUID *pStorageGuid,
  IN CHAR16 *StorageName,
  IN STORAGE_DATA *StorageData,
  IN UINTN StorageMaxLen
  );  

EFI_STATUS
StorageCheckIntegrity(
  IN CHAR16 *StorageVarName,
  IN GUID *pStorageGuid,
  IN UINT8 *pData,
  IN UINTN DataLen,
  IN UINT32 *pDataLenField,
  IN UINT8 *pCsTypeField
  );


EFI_STATUS
StorageSetRawData(
  IN CHAR16 *StorageVarName,
  IN GUID *pStorageGuid,
  IN UINT8 *pData,
  IN UINTN DataLen,
  IN UINT32 *pDataLenField,
  IN UINT8 *pCsTypeField,
  IN UINT8 *RawData,
  IN UINTN RawDataLen
  );

EFI_STATUS
StorageSetRawData2(
  IN EFI_GUID *pStorageGuid,
  IN CHAR16 *StorageName,
  IN UINT8 *RawData,
  IN UINTN RawDataLen,
  IN UINTN StorageMaxCardsNum,
  IN UINTN StorageMaxDataLen,
  IN UINT32 MaxVarSize,
  IN BOOLEAN bDontCheckCardsAmount
  );



#endif  /* #ifndef __VAR__STORAGE__UTILS__H */
