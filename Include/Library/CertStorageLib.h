/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __CERT__STORAGE__LIB__H
#define __CERT__STORAGE__LIB__H

#include <Library/ExtHdrUtils.h>
#include <Library/VarStorageUtils.h>
#include <Library/FsUtils.h>
#include <Guid/VariableFormat.h>


#define MAX_CERTIFICATE_FILE_NAME_LEN     255
#define CERT_STORAGE_MAX_NAME_LEN         100
#define CERT_MAX_CARD_SIZE                (PcdGet32(PcdMaxVariableSize) - sizeof (VARIABLE_HEADER) - CERT_STORAGE_MAX_NAME_LEN)
#define CERT_STORAGE_MAX_DATA_LEN          (PcdGet32(PcdCertificateStorageMaxSize))


#pragma pack(1)
typedef struct T_CERTIFICATE_STORAGE {
  CHAR16 FileName[MAX_CERTIFICATE_FILE_NAME_LEN];
  UINT32 DataLen;
  UINT8 CsType;
  UINT8 CsData[MAX_HASH_LEN];
  UINT8 Data[1];
} CERTIFICATE_STORAGE;
#pragma pack()


EFI_STATUS
CertStorageLibGetData(
  IN CHAR16 *StorageName,
  IN GUID *pStorageGuid,
  IN UINT8 CsType,
  OUT CERTIFICATE_STORAGE **pCertStorage
  );

EFI_STATUS
CertStorageLibSetDataFromFile(
  IN CHAR16 *FullPath,
  IN CHAR16 *StorageName,
  IN GUID *pStorageGuid,
  IN UINT8 CsType,
  IN UINT32 Attributes
  );

EFI_STATUS
CertStorageLibSetRawData(
  IN CHAR16 *FileName,
  IN CHAR16 *StorageName,
  IN GUID *pStorageGuid,
  IN UINT8 CsType,
  IN UINT32 Attributes,
  IN UINT8 *RawData,
  IN UINTN RawDataLen
  );

EFI_STATUS
CertStorageLibInitEmpty(
  IN CHAR16 *StorageName,
  IN GUID *pStorageGuid,
  IN UINT8 CsType
  );

  
#endif /* #ifndef __CERT__STORAGE__LIB__H */
