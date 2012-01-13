/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/CommonUtils.h>
#include <Library/ExtHdrUtilsLite.h>
#include <Library/VarStorageUtils.h>


static UINT32 CurAttributes = STORAGE_WRITE_ONLY_ATTR;


VOID
SetStorageAttributes(
  IN UINT32 Attr
  )
{
  CurAttributes = Attr;
}


EFI_STATUS
SetStorageRawDataByNum(
  IN UINT32 Num,
  IN EFI_GUID *pStorageGuid,
  IN CHAR16 *StorageName,
  IN UINT8 *Data,
  IN UINT32 DataLen
  )
{
  CHAR16 VarName[255];
  STORAGE_CARD_DESC *pDesc = NULL;
  EFI_STATUS Status;
  EFI_GUID ThisGuid;

  if (Data == NULL || DataLen == 0 || pStorageGuid == NULL || 
      StorageName == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  CopyMem(&ThisGuid, pStorageGuid, sizeof(EFI_GUID));
  ThisGuid.Data1 += Num + 1;

  UnicodeSPrint(VarName, sizeof(VarName), L"%s_%08X", StorageName, Num);
  DEBUG((EFI_D_ERROR, "%a.%d VarName=%s\n", 
    __FUNCTION__, __LINE__, VarName));

  pDesc = (STORAGE_CARD_DESC*)AllocateZeroPool(
    sizeof(STORAGE_CARD_DESC) - 1 + DataLen);
  if (NULL == pDesc) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem(pDesc->Data, Data, DataLen);
  pDesc->DataLen = DataLen;
  pDesc->CsType = CS_TYPE_CRC32;

  Status = CalcHashCs(CS_TYPE_CRC32, pDesc->Data, pDesc->DataLen, 
    CALC_CS_RESET | CALC_CS_FINALIZE, pDesc->CsData);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    goto _exit;
  }

  Status = gRT->SetVariable(VarName, &ThisGuid, CurAttributes, 
    sizeof(STORAGE_CARD_DESC) - 1 + DataLen, pDesc);
  
_exit:  
  if (pDesc != NULL) {
    FreePool(pDesc);
  }
  DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
  return Status;
}


EFI_STATUS
GetStorageRawDataByNum(
  IN UINT32 Num,
  IN EFI_GUID *pStorageGuid,
  IN CHAR16 *StorageName,
  IN OUT UINT8 **Data,
  IN OUT UINT32 *DataLen
  )
{
  CHAR16 VarName[255];
  STORAGE_CARD_DESC *pDesc = NULL;
  EFI_STATUS Status;
  EFI_GUID ThisGuid;
  UINTN Size;

  if (DataLen == NULL || StorageName == NULL || pStorageGuid == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  CopyMem(&ThisGuid, pStorageGuid, sizeof(EFI_GUID));
  ThisGuid.Data1 += Num + 1;
  //DEBUG((EFI_D_ERROR, "%a.%d %g %g\n", pStorageGuid));

  UnicodeSPrint(VarName, sizeof(VarName), L"%s_%08X", 
    StorageName, Num);
  DEBUG((EFI_D_ERROR, "%a.%d VarName=%s\n", 
    __FUNCTION__, __LINE__, VarName));
  Size = 0;
  Status = gRT->GetVariable(VarName, &ThisGuid, NULL, &Size, NULL);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
  }
  if (Size == 0 || Size < sizeof(STORAGE_CARD_DESC)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!Size=%d\n", __FUNCTION__, __LINE__, Size));
    return EFI_NOT_FOUND;
  }
  
  pDesc = (STORAGE_CARD_DESC*)AllocateZeroPool(Size);
  if (NULL == pDesc) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  DEBUG((EFI_D_ERROR, "%a.%d Size=%d\n", __FUNCTION__, __LINE__, Size));
  Status = gRT->GetVariable(VarName, &ThisGuid,
        NULL, &Size, pDesc);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    goto _exit;
  }
  DEBUG((EFI_D_ERROR, "%a.%d pDesc->DataLen=%d\n", 
    __FUNCTION__, __LINE__, pDesc->DataLen));
  if (pDesc->CsType != CS_TYPE_CRC32 || pDesc->DataLen == 0 ||
      pDesc->DataLen < Size - sizeof(STORAGE_CARD_DESC) + 1) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    Status = EFI_ABORTED;
    goto _exit;
  }
  if (-1 == CheckDataWithHash(CS_TYPE_CRC32, pDesc->Data,
      pDesc->DataLen, pDesc->CsData)) {
    Status = EFI_CRC_ERROR;
    DEBUG((EFI_D_ERROR, "%a.%d Error!Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    goto _exit;
  }

  *Data = AllocateZeroPool(pDesc->DataLen);
  if (*Data == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    DEBUG((EFI_D_ERROR, "%a.%d Error!Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    goto _exit;
  }
  DEBUG((EFI_D_ERROR, "%a.%d pDesc->DataLen=%d\n",
    __FUNCTION__, __LINE__, pDesc->DataLen));
  *DataLen = pDesc->DataLen;

  CopyMem(*Data, pDesc->Data, *DataLen);
  
_exit:  
  if (pDesc != NULL) {
    FreePool(pDesc);
  }
  DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
  return Status;
}


EFI_STATUS
GetStorageCardsCountAndTotalLen(
  IN EFI_GUID *pStorageGuid,
  IN CHAR16 *StorageName,
  IN OUT UINT32 *CardsCount,
  IN OUT UINT32 *TotalLen
  )
{
  UINTN Size;
  EFI_STATUS Status;
  STORAGE_DESC StorageDesc;

  if (CardsCount == NULL || TotalLen == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  *CardsCount = 0;
  *TotalLen = 0;
  
  Size = 0;
  Status = gRT->GetVariable(StorageName, pStorageGuid,
      NULL, &Size, NULL);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n",
      __FUNCTION__, __LINE__, Status));
  }
  if (Size == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }
  if (Size != sizeof(STORAGE_DESC)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  Status = gRT->GetVariable(StorageName, pStorageGuid,
      NULL, &Size, &StorageDesc);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n",
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
    
  *CardsCount = StorageDesc.Count;
  *TotalLen = StorageDesc.TotalLen;
  return EFI_SUCCESS;
}


EFI_STATUS
SetStorageCardsCountAndTotalLen(
  IN EFI_GUID *pStorageGuid,
  IN CHAR16 *StorageName,
  IN UINT32 CardsCount,
  IN UINT32 TotalLen
  )
{
  UINTN Size;
  EFI_STATUS Status;
  STORAGE_DESC StorageDesc;

  Size = sizeof(STORAGE_DESC);
  Status = gRT->GetVariable(StorageName, pStorageGuid,
      NULL, &Size, &StorageDesc);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n",
      __FUNCTION__, __LINE__, Status));
  }
  if (Size == 0 || Size != sizeof(STORAGE_DESC)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    Size = sizeof(STORAGE_DESC);
  }
  if (CompareMem(&StorageDesc.StorageGuid, &gEfiVarStorageGuid, 
        sizeof(EFI_GUID))) {
    CopyMem(&StorageDesc.StorageGuid, &gEfiVarStorageGuid, sizeof(EFI_GUID));
  }
  
  StorageDesc.Count = CardsCount;
  StorageDesc.TotalLen = TotalLen;
  return gRT->SetVariable(StorageName, pStorageGuid,
    CurAttributes, Size, &StorageDesc);
}


EFI_STATUS
StoragePresent(
  IN CHAR16 *StorageVarName,
  IN GUID *pStorageGuid
  )
{
#if 0
  UINTN Size = 0;
  
  return gRT->GetVariable(StorageVarName, pStorageGuid, NULL, &Size, NULL);
#else
  EFI_STATUS Status;
  UINT32 CardsCount, TotalLen;

  Status = GetStorageCardsCountAndTotalLen(pStorageGuid, StorageVarName,
    &CardsCount, &TotalLen);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n",
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  if (CardsCount == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }
  if (TotalLen == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }
  return EFI_SUCCESS;
#endif
}


EFI_STATUS
StorageInitEmpty(
  IN CHAR16 *StorageVarName,
  IN GUID *pStorageGuid,
  IN UINT8 *pData,
  IN UINTN DataLen,
  IN UINT8 *pCsTypeField,
  IN BOOLEAN bSaveNow
  )
{
#if 0
  UINTN Size;
  EFI_STATUS Status;
  UINT32 Attributes;
  
  Size = DataLen;
  Status = gRT->GetVariable(StorageVarName, pStorageGuid,
      NULL, &Size, pData);
  
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  }
  
  ZeroMem(pData, DataLen);
  *pCsTypeField = CS_TYPE_CRC32;

  if (!bSaveNow) {
    return EFI_SUCCESS;
  }
  
  Attributes = STORAGE_WRITE_ONLY_ATTR;
  
  return gRT->SetVariable(StorageVarName, pStorageGuid,
    Attributes, DataLen, pData);
#else
  EFI_STATUS Status;

  Status = SetStorageCardsCountAndTotalLen(pStorageGuid, StorageVarName, 0, 0);
  DEBUG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n",
      __FUNCTION__, __LINE__, Status));
  return Status;
#endif
}


EFI_STATUS
AllocateStorageData(
  IN STORAGE_DATA *StorageData,
  IN UINTN MaxLen
  )
{
  if (MaxLen == 0 || StorageData == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  StorageData->Data = AllocateZeroPool(MaxLen);
  if (StorageData->Data == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }  
  return EFI_SUCCESS;
}


EFI_STATUS
StorageGetData2(
  IN EFI_GUID *pStorageGuid,
  IN CHAR16 *StorageName,
  IN STORAGE_DATA *StorageData,
  IN UINTN StorageMaxLen
  )  
{
  UINT32 CardsCount, TotalLen, DataLen, i;
  EFI_STATUS Status;
  UINT8 *TmpData = NULL, *BufPtr = NULL;

  if (StorageData == NULL || StorageName == NULL || pStorageGuid == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  
  if (StorageData->Data == NULL) {
    Status = AllocateStorageData(StorageData, StorageMaxLen);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return Status;
    }    
  }

  StorageData->DataLen = 0;

  Status = GetStorageCardsCountAndTotalLen(pStorageGuid, StorageName,
    &CardsCount, &TotalLen);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n",
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  DEBUG((EFI_D_ERROR, "%a.%d CardsCount=%d TotalLen=%d\n", 
    __FUNCTION__, __LINE__, CardsCount, TotalLen));
  if (CardsCount == 0 && TotalLen == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_SUCCESS;
  }
  if (TotalLen == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  StorageData->DataLen = TotalLen;

  DEBUG((EFI_D_ERROR, "%a.%d CardsCount=%d\n", 
    __FUNCTION__, __LINE__, CardsCount));

  TmpData = NULL;

  for (i = 0, BufPtr = StorageData->Data; i < CardsCount; i++) {    
    Status = GetStorageRawDataByNum(i, pStorageGuid, StorageName,
      &TmpData, &DataLen);
    if (EFI_ERROR(Status)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n",
      __FUNCTION__, __LINE__, Status));
      break;
    }
    DEBUG((EFI_D_ERROR, "TotalLen=%d DataLen=%d\n", TotalLen, DataLen));
    if (TotalLen < DataLen) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));      
      break;
    }
    
    CopyMem(BufPtr, TmpData, DataLen);
    BufPtr += DataLen;
    TotalLen -= DataLen;
    if (TmpData != NULL) {
      DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      FreePool(TmpData);
      DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      TmpData = NULL;
    }    
  }

  if (TmpData != NULL) {
    FreePool(TmpData);
  }
  if (EFI_ERROR(Status)) {
    StorageData->DataLen = 0;
  }
  return Status;
}


EFI_STATUS
StorageGetData(
  IN CHAR16 *StorageVarName,
  IN GUID *pStorageGuid,
  IN UINT8 *pData,
  IN UINTN DataLen
  )
{
  UINTN Size = DataLen;
  
  return gRT->GetVariable(StorageVarName, pStorageGuid, NULL, &Size, pData);
}


EFI_STATUS
StorageCheckIntegrity(
  IN CHAR16 *StorageVarName,
  IN GUID *pStorageGuid,
  IN UINT8 *pData,
  IN UINTN DataLen,
  IN UINT32 *pDataLenField,
  IN UINT8 *pCsTypeField
  )
{
#if 0
  EFI_STATUS Status;
  
  Status = StorageGetData(StorageVarName, pStorageGuid, pData, DataLen);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  if (*pDataLenField == 0) {
    return EFI_CRC_ERROR;
  }
  if (*pCsTypeField != CS_TYPE_CRC32) {
    return EFI_CRC_ERROR;
  }
  
  if (-1 == CheckDataWithHash(CS_TYPE_CRC32, pData,
      *pDataLenField, pCsTypeField + 1)) {
    return EFI_CRC_ERROR;
  }
#endif  
  return EFI_SUCCESS;
}

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
  )
{
  DEBUG((EFI_D_ERROR, "%a.%d StorageVarName={%s}\n", 
    __FUNCTION__, __LINE__, StorageVarName));
  DEBUG((EFI_D_ERROR, "%a.%d RawDataLen=%d DataLen=%d!\n", 
    __FUNCTION__, __LINE__, RawDataLen, DataLen));

  if (RawData == NULL || RawDataLen >= DataLen) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  CopyMem(pData, RawData, RawDataLen);
  *pDataLenField = (UINT32) RawDataLen;
  *pCsTypeField = CS_TYPE_CRC32;


  if (RawDataLen && EFI_SUCCESS != CalcHashCs(CS_TYPE_CRC32, pData, 
      *pDataLenField, CALC_CS_RESET | CALC_CS_FINALIZE, 
      pCsTypeField + 1)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error while calc CS!\n", __FUNCTION__, __LINE__));
    return EFI_CRC_ERROR;
  }

  return gRT->SetVariable(StorageVarName, pStorageGuid,
    CurAttributes, DataLen, pData);
}

/*
  pStorageGuid - Storage guid
  StorageName - name of storage (Variable name)
  RawData - pointer to data for store
  RawDataLen - length of data for store
  StorageMaxCardsNum - maximum allowed cards number in this storage
  StorageMaxDataLen - maximum data size
  MaxVarSize - maximum size of one variable
 */
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
  )
{
  UINT32 CardMaxSize;
  UINT32 RestLen, ChunkSize, i;
  EFI_STATUS Status;

  DEBUG((EFI_D_ERROR, "%a.%d RawDataLen=%d StorageMaxDataLen=%d\n",
    __FUNCTION__, __LINE__, RawDataLen, StorageMaxDataLen));

  if (RawDataLen > StorageMaxDataLen) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n",
      __FUNCTION__, __LINE__));
    return EFI_BUFFER_TOO_SMALL;
  }

  if (RawData == NULL || RawDataLen == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  if (MaxVarSize < sizeof(STORAGE_CARD_DESC)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  CardMaxSize = MaxVarSize - sizeof(STORAGE_CARD_DESC);
  DEBUG((EFI_D_ERROR, "%a.%d CardMaxSize=%d\n", 
    __FUNCTION__, __LINE__, CardMaxSize));
  RestLen = (UINT32)(RawDataLen & 0xFFFFFFFF);
  i = (RestLen + CardMaxSize) / CardMaxSize;
  if (!bDontCheckCardsAmount && i > StorageMaxCardsNum) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  i = 0;
  while (RestLen) {
    UINT8 *PrevData;
    UINT32 PrevDataLen;
    BOOLEAN bNeedUpdate = TRUE;

    PrevData = NULL;
    PrevDataLen = 0;
    
    ChunkSize = RestLen > CardMaxSize ? CardMaxSize : RestLen;
    Status = GetStorageRawDataByNum(i, pStorageGuid, StorageName,
      &PrevData, &PrevDataLen);
    if (EFI_ERROR(Status)) {
      /* may be card not present */
      bNeedUpdate = TRUE;
    } else if (PrevDataLen == ChunkSize) {
      if (CompareMem(PrevData, RawData, ChunkSize) == 0) {
        bNeedUpdate = FALSE;
      }
    }
    if (PrevData != NULL) {
      FreePool(PrevData);
    }

    if (bNeedUpdate) {
      Status = SetStorageRawDataByNum(
        i, pStorageGuid, StorageName, RawData,ChunkSize);
      if (EFI_ERROR(Status)) {
        DEBUG((EFI_D_ERROR, "%a.%d Error!Status=%X\n", 
          __FUNCTION__, __LINE__, Status));
        goto _exit;
      }
    }
    i++;
    
    RestLen -= ChunkSize;
    RawData += ChunkSize;
  }

  if (i == 0) {
    return EFI_ABORTED;
  }
  DEBUG((EFI_D_ERROR, "%a.%d Count of cards=%d\n",
    __FUNCTION__, __LINE__, i));
  Status = SetStorageCardsCountAndTotalLen(pStorageGuid, StorageName, i,
    (UINT32)(RawDataLen & 0xFFFFFFFF));
  
_exit:  
  DEBUG((EFI_D_ERROR, "%a.%d Status=%X\n", 
        __FUNCTION__, __LINE__, Status));
  return Status;
}



