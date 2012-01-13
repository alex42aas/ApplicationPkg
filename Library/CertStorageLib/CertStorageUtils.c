/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/CertStorageLib.h>

EFI_STATUS
CertStorageLibGetData(
  IN CHAR16 *StorageName,
  IN GUID *pStorageGuid,
  IN UINT8 CsType,
  OUT CERTIFICATE_STORAGE **pCertStorage
  )
{  
  EFI_STATUS Status;
  STORAGE_DATA StorageData;
  CERTIFICATE_STORAGE *pTmpStorage = NULL;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  
  if (StorageName == NULL || pStorageGuid == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));  
    return EFI_INVALID_PARAMETER;
  }

  if (StrSize(StorageName) > CERT_STORAGE_MAX_NAME_LEN) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));  
    return EFI_INVALID_PARAMETER;
  }

  /* We need to allocate memory for our certificate data */
  ZeroMem(&StorageData, sizeof(STORAGE_DATA));
  Status = StorageGetData2(pStorageGuid, StorageName,
    &StorageData, 
    sizeof(CERTIFICATE_STORAGE) - 1 + CERT_STORAGE_MAX_DATA_LEN);
  if (EFI_ERROR(Status) || 
      StorageData.DataLen < (sizeof(CERTIFICATE_STORAGE) - 1)) {
    if (StorageData.Data != NULL) {
      FreePool(StorageData.Data);
    }
    return EFI_ABORTED;
  }

  pTmpStorage = (CERTIFICATE_STORAGE*)StorageData.Data;
  if (StorageData.DataLen != 
      pTmpStorage->DataLen + sizeof(CERTIFICATE_STORAGE) - 1) {
    DEBUG((EFI_D_ERROR, "StorageData.DataLen=%d pTmpStorage->DataLen=%d\n",
      StorageData.DataLen, pTmpStorage->DataLen));
  }
  DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  DEBUG((EFI_D_ERROR, "%a.%d pTmpStorage->DataLen=%d\n", 
    __FUNCTION__, __LINE__, pTmpStorage->DataLen));
  if (pTmpStorage->DataLen == 0) {
    goto Done;
  }
  if (-1 == CheckDataWithHash(CsType, pTmpStorage->Data,
      pTmpStorage->DataLen, pTmpStorage->CsData)) {
    FreePool(StorageData.Data);
    return EFI_CRC_ERROR;
  }
Done:  
  *pCertStorage = pTmpStorage;
  return EFI_SUCCESS;
}

EFI_STATUS
CertStorageLibSetDataFromFile(
  IN CHAR16 *FullPath,
  IN CHAR16 *StorageName,
  IN GUID *pStorageGuid,
  IN UINT8 CsType,
  IN UINT32 Attributes
  )
{
  CHAR16 *FileName;
  UINTN Len;
  EFI_FILE_HANDLE File = NULL;
  EFI_STATUS Status = EFI_INVALID_PARAMETER;
  CERTIFICATE_STORAGE *pStorage = NULL;
  
  if (NULL == FullPath) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!!!\n", __FUNCTION__, __LINE__));
    goto _exit;
  }
  Len = StrLen(FullPath);
  if (Len == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!!!\n", __FUNCTION__, __LINE__));
    goto _exit;
  }
  DEBUG((EFI_D_ERROR, "%a.%d FullPath=%a\n", __FUNCTION__, __LINE__, FullPath));
  
  FileName = FullPath + Len - 1;
  while (FileName > FullPath && *FileName != L'\\') {
    FileName--;
  }
  if (FileName != FullPath) {
    FileName++;
  }

  DEBUG((EFI_D_ERROR, "%a.%d FileName=%s\n", __FUNCTION__, __LINE__, FileName));

  File = LibFsOpenFile16(FullPath, EFI_FILE_MODE_READ, 0);
  if (File == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error while LibFsOpenFile!!!!\n", 
      __FUNCTION__, __LINE__));
    goto _exit;
  }
  
  Len = LibFsSizeFile(File);
  
  if (Len == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!!!\n", __FUNCTION__, __LINE__));
    goto _exit;
  }
  
  pStorage = (CERTIFICATE_STORAGE*) AllocateZeroPool(
    sizeof(CERTIFICATE_STORAGE) - 1 + Len);
  if (NULL == pStorage) {
    Status = EFI_OUT_OF_RESOURCES;
    goto _exit;
  }
  pStorage->CsType = CsType;
  pStorage->DataLen = (UINT32) Len;

  DEBUG((EFI_D_ERROR, "%a.%d pStorage->DataLen=%d\n", 
    __FUNCTION__, __LINE__, pStorage->DataLen));
  
  Status = LibFsReadFile(File, &Len, pStorage->Data);
  if (EFI_ERROR(Status)) {
    goto _exit;
  }
  
  /* Calculate and save checksum */
  Status = CalcHashCs(CsType, pStorage->Data, 
      pStorage->DataLen, CALC_CS_RESET | CALC_CS_FINALIZE, 
      pStorage->CsData);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error while calc CS!\n", __FUNCTION__, __LINE__));
    Status = EFI_CRC_ERROR;
    goto _exit;
  }

  DEBUG((EFI_D_ERROR, "%a.%d pStorage->DataLen=%d\n", 
    __FUNCTION__, __LINE__, pStorage->DataLen));
  
  StrnCpy(pStorage->FileName, FileName, sizeof(pStorage->FileName) / 2 - 1);
  DEBUG((EFI_D_ERROR, "%a.%d pStorage->DataLen=%d\n", 
    __FUNCTION__, __LINE__, pStorage->DataLen));
  SetStorageAttributes(Attributes);
  Status = StorageSetRawData2(pStorageGuid,
    StorageName, (UINT8*)pStorage,
    sizeof(CERTIFICATE_STORAGE) - 1 + pStorage->DataLen,
    (sizeof(CERTIFICATE_STORAGE) - 1 + CERT_STORAGE_MAX_DATA_LEN + 
      CERT_MAX_CARD_SIZE) / CERT_MAX_CARD_SIZE, 
    sizeof(CERTIFICATE_STORAGE) - 1 + CERT_STORAGE_MAX_DATA_LEN,
    CERT_MAX_CARD_SIZE, FALSE);

  DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  DEBUG((EFI_D_ERROR, "%a.%d FileName=%s\n", __FUNCTION__, __LINE__, 
    pStorage->FileName));
  
_exit:
  if (pStorage) {
    FreePool(pStorage);
  }
  if (File != NULL) {
    LibFsCloseFile(File);
  }
  
  return Status;
}

EFI_STATUS
CertStorageLibSetRawData(
  IN CHAR16 *FileName,
  IN CHAR16 *StorageName,
  IN GUID *pStorageGuid,
  IN UINT8 CsType,
  IN UINT32 Attributes,
  IN UINT8 *RawData,
  IN UINTN RawDataLen
  )
{
  EFI_STATUS Status = EFI_INVALID_PARAMETER;
  CERTIFICATE_STORAGE *pStorage = NULL;
  
  if (NULL == RawData || NULL == StorageName || RawDataLen == 0 || pStorageGuid == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!!!\n", __FUNCTION__, __LINE__));
    goto _exit;
  }

  if (StrSize(StorageName) > CERT_STORAGE_MAX_NAME_LEN) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));  
    return EFI_INVALID_PARAMETER;
  }
    
  pStorage = (CERTIFICATE_STORAGE*) AllocateZeroPool(
    sizeof(CERTIFICATE_STORAGE) - 1 + RawDataLen);
  if (NULL == pStorage) {
    Status = EFI_OUT_OF_RESOURCES;
    goto _exit;
  }
  pStorage->CsType = CsType;
  pStorage->DataLen = (UINT32) RawDataLen;
  CopyMem(pStorage->Data, RawData, RawDataLen);
  
  /* Calculate and save checksum */
  Status = CalcHashCs(CsType, pStorage->Data, 
      pStorage->DataLen, CALC_CS_RESET | CALC_CS_FINALIZE, 
      pStorage->CsData);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error while calc CS!\n", __FUNCTION__, __LINE__));
    Status = EFI_CRC_ERROR;
    goto _exit;
  }
  
  StrnCpy(pStorage->FileName, FileName, sizeof(pStorage->FileName) / 2 - 1);
  
  SetStorageAttributes(Attributes);
  Status = StorageSetRawData2(pStorageGuid,
    StorageName, (UINT8*)pStorage,
    sizeof(CERTIFICATE_STORAGE) - 1 + pStorage->DataLen,
    (sizeof(CERTIFICATE_STORAGE) - 1 + CERT_STORAGE_MAX_DATA_LEN + 
      CERT_MAX_CARD_SIZE) / CERT_MAX_CARD_SIZE, 
    sizeof(CERTIFICATE_STORAGE) - 1 + CERT_STORAGE_MAX_DATA_LEN,
    CERT_MAX_CARD_SIZE, FALSE);

  DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  DEBUG((EFI_D_ERROR, "%a.%d FileName=%s\n", __FUNCTION__, __LINE__, 
    pStorage->FileName));
  
_exit:
  if (pStorage) {
    FreePool(pStorage);
  }  
  return Status;
}

EFI_STATUS
CertStorageLibInitEmpty(
  IN CHAR16 *StorageName,
  IN GUID *pStorageGuid,
  IN UINT8 CsType
  )
{
  EFI_STATUS Status;
  CERTIFICATE_STORAGE TmpStorage;

  DEBUG((EFI_D_ERROR, "%a.%d: Start\n", __FUNCTION__, __LINE__));
  if (StorageName == NULL || pStorageGuid == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));  
    return EFI_INVALID_PARAMETER;
  }

  if (StrSize(StorageName) > CERT_STORAGE_MAX_NAME_LEN) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));  
    return EFI_INVALID_PARAMETER;
  }

  Status = StorageInitEmpty(StorageName, pStorageGuid, NULL, 0, NULL, FALSE);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d: Status=0x%X\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }
  ZeroMem(&TmpStorage, sizeof(CERTIFICATE_STORAGE));    
  Status = StorageSetRawData2(pStorageGuid,
    StorageName, (UINT8*)&TmpStorage,
    sizeof(CERTIFICATE_STORAGE) - 1,
    (sizeof(CERTIFICATE_STORAGE) - 1 + CERT_STORAGE_MAX_DATA_LEN + 
      CERT_MAX_CARD_SIZE) / CERT_MAX_CARD_SIZE, 
    sizeof(CERTIFICATE_STORAGE) - 1 + CERT_STORAGE_MAX_DATA_LEN,
    CERT_MAX_CARD_SIZE, FALSE);

  return Status;
}

