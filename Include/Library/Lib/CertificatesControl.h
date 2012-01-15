/** @file
  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php
  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/

#ifndef __CERTIFICATES__CONTROL__H
#define __CERTIFICATES__CONTROL__H


#include <Library/CommonUtils.h>
#include <Guid/MdeModuleHii.h>
#include <Protocol/HiiConfigAccess.h>
#include <Library/ExtHdrUtils.h>
#include <Library/VarStorageUtils.h>
#include <Library/VfrCommon.h>
#include <Library/FsUtils.h>
#include <Library/MultibootDescUtils.h>
#include "vfrdata.h"
#include <Library/FeLib.h>
#include <Library/PcdUtilsLib.h>
#include <Library/CertStorageLib.h>

#define FW_CHAIN_INIT_FLAG_VAR_NAME       L"InitFwCa" 
#define FW_CHAIN_NAME                     L"FirmwareCA"
#define CHAIN_STORAGE_CS_TYPE             (CS_TYPE_GOST_2012)
#define CHAIN_STORAGE_VAR_NAME            L"CertChainStorage"
#define TLS_CLIENT_CERT_STORAGE_CS_TYPE   (CS_TYPE_GOST_2012)
#define TLS_CLIENT_CERT_STORAGE_VAR_NAME  L"TlsClientCertStorage"
#define TLS_PKEY_STORAGE_CS_TYPE          (CS_TYPE_GOST_2012)
#define TLS_PKEY_STORAGE_VAR_NAME         L"TlsPkeyStorage"
#define LICENSE_STORAGE_CS_TYPE           (CS_TYPE_GOST_2012)
#define LICENSE_STORAGE_VAR_NAME          L"LicenseStorage"
#define CERT_STORAGE_VAR_NAME_WITH_NUM    L"CertChainStorage_00000000"
#define CERT_MAX_CARD_SIZE                (PcdUtilsGet32PcdMaxVariableSize() - sizeof (VARIABLE_HEADER) - CERT_STORAGE_MAX_NAME_LEN)
#define CERT_STORAGE_MAX_DATA_LEN          (PcdGet32(PcdCertificateStorageMaxSize))



VOID
CertTimeBufConvToEfiTime(
  IN UINT8 *Buf,
  IN EFI_TIME *pEfiTime
  );

BOOLEAN
IsChainEmpty (
  VOID
  );

BOOLEAN
IsCRLEmpty (
  VOID
  );

EFI_STATUS
ChainInitEmpty(
  VOID
  );

EFI_STATUS
TlsClientCertLoad(
  VOID
  );

EFI_STATUS
TlsClientPKeyLoad(
  VOID
  );

EFI_STATUS
TlsClientCertInitEmpty(
  VOID
  );

EFI_STATUS
TlsPkeyInitEmpty(
  VOID
  );

CERTIFICATE_STORAGE *
TlsClientCertGetData(
  VOID
  );

CERTIFICATE_STORAGE *
TlsClientPKeyGetData(
  VOID
  );

EFI_STATUS
CertificatePageCallback(
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  );

VOID
CertificateCtrlInit(
  IN MULTIBOOT_CONFIG *Cfg
  );


EFI_STATUS 
StartCertificatesControlForm(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  );

EFI_STATUS
CertificatesControlFormConstructor(
  VOID
  );

EFI_STATUS
CertStorageSaveFromFile(
  IN CHAR16 *FullPath,
  IN CHAR16 *StorageName,
  IN GUID *pStorageGuid,
  IN UINT8 CsType
  );

EFI_STATUS
CertStorageSaveFromRawData(
  IN CHAR16 *FileName,
  IN CHAR16 *StorageName,
  IN GUID *pStorageGuid,
  IN UINT8 CsType,
  IN UINT8 *RawData,
  IN UINTN RawDataLen
  );

EFI_STATUS
SetCertificateCache (
  IN UINT8 *Data,
  IN UINTN DataLen
  );

EFI_STATUS
GetCertificateCache (
  IN OUT UINT8 **Data,
  IN OUT UINTN *DataLen
  );

EFI_STATUS
EFIAPI
CertCtrlUpdateFromFileLicense (
  IN CHAR16 *FullPath
  );

 STATIC EFI_STATUS
EFIAPI
CertCtrlLoadUpdateLicense (
  VOID
  );

EFI_STATUS
EFIAPI
CertCtrlInitEmptyLicense (
  VOID
  );
  
EFI_STATUS
EFIAPI
CertCtrlLoadLicense (
	VOID
	);
	
BOOLEAN
EFIAPI
CertCtrlIsEmptyLicense (
	VOID
	);
	
CERTIFICATE_STORAGE*
EFIAPI
CertCtrlGetDataLicense (
	VOID
  );


EFI_STATUS
EFIAPI
CertCtrlUpdateFromFileLicense (
  IN CHAR16 *FullPath
  );

EFI_STATUS
CheckStorageData (
  IN CHAR16 *StorageName,
  IN CHAR8 *Data,
  IN UINTN DataLen
  );

EFI_STATUS
UpdateChainFromFw (
  VOID
  );


EFI_STATUS
CertControlSetupFileExplorerStartPath (
  VOID
  );

#endif /* #ifndef __CERTIFICATES__CONTROL__H */

