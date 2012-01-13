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
#include <Library/ExtHdrUtils.h>
#include <Library/VarStorageUtils.h>


static UINT32 CurAttributes = STORAGE_WRITE_ONLY_ATTR;

#if 0
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif



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
    LOG ((EFI_D_INFO, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  CopyMem(&ThisGuid, pStorageGuid, sizeof(EFI_GUID));
  ThisGuid.Data1 += Num + 1;

  UnicodeSPrint(VarName, sizeof(VarName), L"%s_%08X", StorageName, Num);
  LOG ((EFI_D_INFO, "%a.%d StorageName:%ls.VarName:%s\n", 
    __FUNCTION__, __LINE__, StorageName, VarName));

  pDesc = (STORAGE_CARD_DESC*)AllocateZeroPool(
    sizeof(STORAGE_CARD_DESC) - 1 + DataLen);
  if (NULL == pDesc) {
    LOG ((EFI_D_INFO, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem(pDesc->Data, Data, DataLen);
  pDesc->DataLen = DataLen;
  pDesc->CsType = CS_TYPE_GOST;

  Status = CalcHashCs(CS_TYPE_GOST, pDesc->Data, pDesc->DataLen, 
    CALC_CS_RESET | CALC_CS_FINALIZE, pDesc->CsData);
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_INFO, "%a.%d Error!Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    goto _exit;
  }

  Status = gRT->SetVariable(VarName, &ThisGuid, CurAttributes, 
    sizeof(STORAGE_CARD_DESC) - 1 + DataLen, pDesc);
  
_exit:  
  if (pDesc != NULL) {
    FreePool(pDesc);
  }
  LOG ((EFI_D_INFO, "%a.%d Status=0x%X\n", 
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
    LOG ((EFI_D_INFO, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  CopyMem(&ThisGuid, pStorageGuid, sizeof(EFI_GUID));
  ThisGuid.Data1 += Num + 1;
  //LOG ((EFI_D_INFO, "%a.%d %g %g\n", pStorageGuid));

  UnicodeSPrint(VarName, sizeof(VarName), L"%s_%08X", 
    StorageName, Num);
  LOG ((EFI_D_INFO, "%a.%d VarName=%s\n", 
    __FUNCTION__, __LINE__, VarName));
  Size = 0;
  Status = gRT->GetVariable(VarName, &ThisGuid, NULL, &Size, NULL);
  if (Status != EFI_BUFFER_TOO_SMALL) {
    LOG ((EFI_D_INFO, "%a.%d Error!Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
  }
  if (Size == 0 || Size < sizeof(STORAGE_CARD_DESC)) {
    LOG ((EFI_D_INFO, "%a.%d Error!Size=%d\n", __FUNCTION__, __LINE__, Size));
    return EFI_NOT_FOUND;
  }
  
  pDesc = (STORAGE_CARD_DESC*)AllocateZeroPool(Size);
  if (NULL == pDesc) {
    LOG ((EFI_D_INFO, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }
  LOG ((EFI_D_INFO, "%a.%d Size=%d\n", __FUNCTION__, __LINE__, Size));
  Status = gRT->GetVariable(VarName, &ThisGuid,
        NULL, &Size, pDesc);
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_INFO, "%a.%d Error!Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    goto _exit;
  }
  LOG ((EFI_D_INFO, "%a.%d pDesc->DataLen=%d\n", 
    __FUNCTION__, __LINE__, pDesc->DataLen));
  if (pDesc->CsType != CS_TYPE_GOST || pDesc->DataLen == 0 ||
      pDesc->DataLen < Size - sizeof(STORAGE_CARD_DESC) + 1) {
    LOG ((EFI_D_INFO, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    Status = EFI_ABORTED;
    goto _exit;
  }
  if (-1 == CheckDataWithHash(CS_TYPE_GOST, pDesc->Data,
      pDesc->DataLen, pDesc->CsData)) {
    Status = EFI_CRC_ERROR;
    LOG ((EFI_D_INFO, "%a.%d Error!Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    goto _exit;
  }

  *Data = AllocateZeroPool(pDesc->DataLen);
  if (*Data == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    LOG ((EFI_D_INFO, "%a.%d Error!Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    goto _exit;
  }
  LOG ((EFI_D_INFO, "%a.%d pDesc->DataLen=%d\n",
    __FUNCTION__, __LINE__, pDesc->DataLen));
  *DataLen = pDesc->DataLen;

  CopyMem(*Data, pDesc->Data, *DataLen);
  
_exit:  
  if (pDesc != NULL) {
    FreePool(pDesc);
  }
  LOG ((EFI_D_INFO, "%a.%d Status=0x%X\n", 
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
    LOG ((EFI_D_INFO, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  *CardsCount = 0;
  *TotalLen = 0;
  
  Size = 0;
  Status = gRT->GetVariable(StorageName, pStorageGuid,
      NULL, &Size, NULL);
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_INFO, "%a.%d Status=0x%X\n",
      __FUNCTION__, __LINE__, Status));
  }
  if (Size == 0) {
    LOG ((EFI_D_INFO, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }
  if (Size != sizeof(STORAGE_DESC)) {
    LOG ((EFI_D_INFO, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  Status = gRT->GetVariable(StorageName, pStorageGuid,
      NULL, &Size, &StorageDesc);
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_INFO, "%a.%d Status=0x%X\n",
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
    LOG ((EFI_D_INFO, "%a.%d Status=0x%X\n",
      __FUNCTION__, __LINE__, Status));
  }
  if (Size == 0 || Size != sizeof(STORAGE_DESC)) {
    LOG ((EFI_D_INFO, "%a.%d Error!\n", __FUNCTION__, __LINE__));
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
  UINTN Size;
  EFI_STATUS Status;

  if (StorageVarName == NULL || pStorageGuid == NULL) {
    DEBUG((EFI_D_INFO, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  Size = 0;
  Status = gRT->GetVariable(StorageVarName, 
pStorageGuid,
      NULL, &Size, NULL);
  DEBUG((EFI_D_INFO, "%a.%d Status=0x%X Size=%d\n",
      __FUNCTION__, __LINE__, Status, Size));
  if (Status == EFI_BUFFER_TOO_SMALL && Size != 0) {
    return EFI_SUCCESS;
  }
  return EFI_NOT_FOUND;

}

BOOLEAN
IsStorageEmpty (
  IN CHAR16 *StorageVarName,
  IN GUID *pStorageGuid
  )
{
  EFI_STATUS Status;
  UINT32 CardsCount, TotalLen;

  Status = StoragePresent (StorageVarName, pStorageGuid);
  if (Status == EFI_NOT_FOUND) {
    return TRUE;
  }

  Status = GetStorageCardsCountAndTotalLen(pStorageGuid, StorageVarName,
    &CardsCount, &TotalLen);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_INFO, "%a.%d Error! Status=0x%X\n",
      __FUNCTION__, __LINE__, Status));
    return FALSE;
  }
  DEBUG((EFI_D_INFO, "%a.%d CardsCount=%d TotalLen=%d\n", 
    __FUNCTION__, __LINE__, CardsCount, TotalLen));
  if (CardsCount == 0 && TotalLen == 0) {
    DEBUG((EFI_D_INFO, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return TRUE;
  }
  return FALSE;
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
  EFI_STATUS Status;

  Status = SetStorageCardsCountAndTotalLen(pStorageGuid, StorageVarName, 0, 0);
  LOG ((EFI_D_INFO, "%a.%d Error! Status=0x%X\n",
      __FUNCTION__, __LINE__, Status));
  return Status;
}


EFI_STATUS
AllocateStorageData(
  IN STORAGE_DATA *StorageData,
  IN UINTN MaxLen
  )
{
  if (MaxLen == 0 || StorageData == NULL) {
    LOG ((EFI_D_INFO, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  StorageData->Data = AllocateZeroPool(MaxLen);
  if (StorageData->Data == NULL) {
    LOG ((EFI_D_INFO, "%a.%d Error!\n", __FUNCTION__, __LINE__));
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
    LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  if (StorageData->Data == NULL) {
    Status = AllocateStorageData(StorageData, StorageMaxLen);
    if (EFI_ERROR(Status)) {
      LOG ((EFI_D_INFO, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return Status;
    }    
  }  

  Status = GetStorageCardsCountAndTotalLen(pStorageGuid, StorageName,
    &CardsCount, &TotalLen);
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_INFO, "%a.%d Error! Status=0x%X\n",
      __FUNCTION__, __LINE__, Status));
    return Status;
  }
  
  StorageData->DataLen = TotalLen;
  
  LOG ((EFI_D_INFO, "%a.%d CardsCount=%d TotalLen=%d\n", 
    __FUNCTION__, __LINE__, CardsCount, TotalLen));
  if (CardsCount == 0 && TotalLen == 0) {
    LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_SUCCESS;
  }
  if (TotalLen == 0) {
    LOG ((EFI_D_INFO, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }  

  LOG ((EFI_D_INFO, "%a.%d CardsCount=%d\n", 
    __FUNCTION__, __LINE__, CardsCount));

  TmpData = NULL;

  for (i = 0, BufPtr = StorageData->Data; i < CardsCount; i++) {    
    Status = GetStorageRawDataByNum(i, pStorageGuid, StorageName,
      &TmpData, &DataLen);
    if (EFI_ERROR(Status)) {
      LOG ((EFI_D_INFO, "%a.%d Error! Status=0x%X\n",
      __FUNCTION__, __LINE__, Status));
      break;
    }
    LOG ((EFI_D_INFO, "TotalLen=%d DataLen=%d\n", TotalLen, DataLen));
    if (TotalLen < DataLen) {
      LOG ((EFI_D_INFO, "%a.%d Error!\n", __FUNCTION__, __LINE__));      
      break;
    }
    
    CopyMem(BufPtr, TmpData, DataLen);
    BufPtr += DataLen;
    TotalLen -= DataLen;
    if (TmpData != NULL) {
      LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
      FreePool(TmpData);
      LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
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
  if (*pCsTypeField != CS_TYPE_GOST) {
    return EFI_CRC_ERROR;
  }
  
  if (-1 == CheckDataWithHash(CS_TYPE_GOST, pData,
      *pDataLenField, pCsTypeField + 1)) {
    return EFI_CRC_ERROR;
  }
#endif  
  return EFI_SUCCESS;
}


EFI_STATUS
StorageUpdateData (  
  IN EFI_GUID *pStorageGuid,
  IN CHAR16 *StorageName,
  IN UINT8 *RawData,
  IN UINT32 DataIdx,
  IN UINT32 ChunkSize
  )
{
  EFI_STATUS Status;
  UINT8 *StorageData;
  UINT32 StorageDataLen, Idx;

  StorageData = NULL;
  StorageDataLen = 0;
  Idx = 0;

  do {
    Status = SetStorageRawDataByNum(
      DataIdx, pStorageGuid, StorageName, RawData, ChunkSize);
    
    Idx++;
    
    if (EFI_ERROR(Status)) {
      LOG ((EFI_D_INFO, "%a.%d Error!Status=%X\n", 
        __FUNCTION__, __LINE__, Status));
      continue;
    }
    
    Status = GetStorageRawDataByNum(DataIdx, pStorageGuid, StorageName,
                                      &StorageData, &StorageDataLen);
    if (!EFI_ERROR(Status) && 
        CompareMem(StorageData, RawData, StorageDataLen) == 0) {
      goto _exit; 
    }
  } while (Idx < PcdGet32 (PcdStorageUtilsNumAttempts));
  
_exit:  
  if (StorageData != NULL) {
    FreePool(StorageData);
  }
  return Status;
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

  LOG ((EFI_D_INFO, "%a.%d RawDataLen=%d StorageMaxDataLen=%d\n",
    __FUNCTION__, __LINE__, RawDataLen, StorageMaxDataLen));

  if (RawDataLen > StorageMaxDataLen) {
    LOG ((EFI_D_INFO, "%a.%d Error!\n",
      __FUNCTION__, __LINE__));
    return EFI_BUFFER_TOO_SMALL;
  }

  if (RawData == NULL) {
    LOG ((EFI_D_INFO, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  if (RawDataLen == 0) {
    return StorageInitEmpty(StorageName, pStorageGuid, NULL, 0, NULL, FALSE);
  }

  if (MaxVarSize < sizeof(STORAGE_CARD_DESC)) {
    LOG ((EFI_D_INFO, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  CardMaxSize = MaxVarSize - sizeof(STORAGE_CARD_DESC);
  LOG ((EFI_D_INFO, "%a.%d CardMaxSize=%d\n", 
    __FUNCTION__, __LINE__, CardMaxSize));
  RestLen = (UINT32)(RawDataLen & 0xFFFFFFFF);
  i = (RestLen + CardMaxSize) / CardMaxSize;
  if (!bDontCheckCardsAmount && i > StorageMaxCardsNum) {
    LOG ((EFI_D_INFO, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  i = 0;
  while (RestLen) {
    UINT8 *StorageData;
    UINT32 StorageDataLen;
    BOOLEAN bNeedUpdate = TRUE;

    StorageData = NULL;
    StorageDataLen = 0;
    
    ChunkSize = RestLen > CardMaxSize ? CardMaxSize : RestLen;
    Status = GetStorageRawDataByNum(i, pStorageGuid, StorageName,
      &StorageData, &StorageDataLen);
    if (EFI_ERROR(Status)) {
      /* may be card not present */
      bNeedUpdate = TRUE;
    } else if (StorageDataLen == ChunkSize) {
      if (CompareMem(StorageData, RawData, ChunkSize) == 0) {
        bNeedUpdate = FALSE;
      }
    }
    if (StorageData != NULL) {
      FreePool(StorageData);
    }
    

    if (bNeedUpdate) {
      Status = StorageUpdateData(pStorageGuid, StorageName, 
        RawData, i, ChunkSize);
      if (EFI_ERROR (Status)) {
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
  LOG ((EFI_D_INFO, "%a.%d StorageName=%s Count of cards=%d\n",
    __FUNCTION__, __LINE__, StorageName, i));
  Status = SetStorageCardsCountAndTotalLen(pStorageGuid, StorageName, i,
    (UINT32)(RawDataLen & 0xFFFFFFFF));
  
_exit:  
  LOG ((EFI_D_INFO, "%a.%d Status=%X\n", 
        __FUNCTION__, __LINE__, Status));
  return Status;
}
