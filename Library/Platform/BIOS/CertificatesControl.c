/** @file
  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php
  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/

#include <Library/Lib/CertificatesControl.h>
#include <Library/Lib/TokenFunctions.h>
#include <Library/Lib/OpensslFunctions.h>
#include <Library/RevokeChkConfigLib/RevokeChkConfig.h>
#include <Library/CDPSupportLib/CDPSupport.h>
#include <Library/CertViewerLib/CertViewer.h>
#include <Library/TokenViewerLib/TokenViewer.h>


#if 1
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

#define ALLOW_EXPORT_CA_FROM_TOKEN 0

STATIC MULTIBOOT_CONFIG *CurrentConfig;
STATIC EFI_FORM_BROWSER2_PROTOCOL *gFormBrowser2;
STATIC EFI_HII_HANDLE CurrentHiiHandle;
STATIC VOID *StartOpCodeHandle, *EndOpCodeHandle;

//STATIC HISTORY_RECORD *pLastFoundHistoryRecord;
//STATIC HISTORY_STORAGE gHistoryStorage;
STATIC BOOLEAN bFormExitFlag, bRefreshForm;
STATIC int CurrentEvent;
STATIC CERTIFICATE_STORAGE badPtr;
STATIC CERTIFICATE_STORAGE *gChainStoragePtr = &badPtr,
                           *gCRLStoragePtr = &badPtr,
                           *gTlsCertStoragePtr = &badPtr,
                           *gClientPKeyStoragePtr = &badPtr;

STATIC CHAR16 *gStrDevPath;

STATIC enum {
  OSSL_ERROR,
  CDP_ERROR
} errorCode;

STATIC
VOID
ProcessingSaveCertErrors (
  OSSL_STATUS Status
  );

STATIC
VOID
ProcessingCDPErrors (
  CDP_STATUS Status
);

VOID
CertTimeBufConvToEfiTime(
  IN UINT8 *Buf,
  IN EFI_TIME *pEfiTime
  )
{
  ZeroMem(pEfiTime, sizeof(EFI_TIME));
  pEfiTime->Day = 10 * (Buf[6] - '0') + Buf[7] - '0';
  pEfiTime->Month = 10 * (Buf[4] - '0') + Buf[5] - '0';
  pEfiTime->Year = (Buf[3] - '0') + (Buf[2] - '0') * 10 +
     (Buf[1] - '0') * 100 + (Buf[0] - '0') * 1000;
}

BOOLEAN
IsChainEmpty (
  VOID
  )
{
  if (ChainGetData()->Data != NULL && ChainGetData()->DataLen > 0)
    return FALSE;
  else
    return TRUE;
}

BOOLEAN
IsCRLEmpty (
  VOID
  )
{
  if (CRLGetData()->Data != NULL && CRLGetData()->DataLen > 0)
    return FALSE;
  else
    return TRUE;
}

STATIC
BOOLEAN
IsTlsClientCertEmpty (
  VOID
  )
{
  if (TlsClientCertGetData()->Data != NULL && TlsClientCertGetData()->DataLen > 0)
    return FALSE;
  else
    return TRUE;
}

STATIC
BOOLEAN
IsTlsClientPKeyEmpty (
  VOID
  )
{
  if (TlsClientPKeyGetData()->Data != NULL && TlsClientPKeyGetData()->DataLen > 0)
    return FALSE;
  return TRUE;
}

STATIC
EFI_STATUS
CheckStorageData (
  IN CHAR16 *StorageName,
  IN CHAR8 *Data,
  IN UINTN DataLen
  )
{
  if (StrCmp(StorageName, CHAIN_STORAGE_VAR_NAME) == 0) {
    // Perform a check for PKCS7 chain data
    if (CheckChainFormat(Data, DataLen) != OSSL_SUCCESS_CONVERT_TO_ASN)
      return EFI_ABORTED;

    if (VerifyCAChain(Data, DataLen) != OSSL_VERIFY_SUCCESS)
      return EFI_ABORTED;

    if (IsCRLEmpty() == FALSE) {
      if (CheckCRLWithCA(CRLGetData()->Data, 
                         CRLGetData()->DataLen,
                         Data, DataLen) != OSSL_VERIFY_SUCCESS)
        //goto _OSSL_ERROR;
        errorCode = OSSL_ERROR;
    }
    if (IsTlsClientCertEmpty() == FALSE) {
      if (VerifyCertificateWithCRLandCA(TlsClientCertGetData()->Data,
                                      TlsClientCertGetData()->DataLen,
                                      Data, DataLen,
                                      NULL, 0) != OSSL_VERIFY_SUCCESS)
        //goto _OSSL_ERROR;
        errorCode = OSSL_ERROR;
    }

  } else if (StrCmp(StorageName, TLS_CERT_STORAGE_VAR_NAME) == 0) {
    // Perform a check for certificate
    if (CheckCertificateFormat(Data, DataLen) != OSSL_SUCCESS_CONVERT_TO_ASN)
      goto _OSSL_ERROR;

    // Update Local CRL stack before verify if needed
    if (GetLocalCdpUsageFlag() == USE) {
      CDP_STATUS cdpStatus = RefreshLocalCRL(Data, DataLen);
      if (cdpStatus == CDP_REFRESH_SUCCESSFUL)
        ChainLoad();
      else if (cdpStatus == CDP_NO_NEED_TO_REFRESH)
        ; // NOP
      else if (cdpStatus == CDP_ERROR_TO_SAVE_NEW_CRL)
        goto _OSSL_ERROR;
      else
        goto _CDP_ERROR;
    }

    // Verify certificate
    if (VerifyCertificateWithCRLandCA(Data, DataLen,
          ChainGetData()->Data, ChainGetData()->DataLen,
          CRLGetData()->Data, CRLGetData()->DataLen)
          != OSSL_VERIFY_SUCCESS)
      goto _OSSL_ERROR;

  } else if (StrCmp(StorageName, CRL_STORAGE_VAR_NAME) == 0) {
    // Perform a check for CRL
    if (CheckCRLWithCA(Data, DataLen, 
          ChainGetData()->Data, ChainGetData()->DataLen
          ) != OSSL_VERIFY_SUCCESS)
      goto _OSSL_ERROR;

  }

  return EFI_SUCCESS;

_OSSL_ERROR:
  errorCode = OSSL_ERROR;
  return EFI_ABORTED;

_CDP_ERROR:
  errorCode = CDP_ERROR;
  return EFI_ABORTED;
}

STATIC
VOID
ProcessingCertificateStorageError (
  VOID
)
{
  if (errorCode == OSSL_ERROR)
    ProcessingSaveCertErrors(GetOsslLastError());
  else if (errorCode == CDP_ERROR)
    ProcessingCDPErrors(GetCDPLastError());
  return;
}

//------------------------------------------------------------------------------
/*! \brief Show an error message, which depends of a CDP error code */
/*! You can add HistoryAddRecord() here to log these errors */
//------------------------------------------------------------------------------
STATIC
VOID
ProcessingCDPErrors (
  CDP_STATUS Status
)
{
  LOG((EFI_D_ERROR, "%a.%d CDP Error: %d\n", __FUNCTION__, __LINE__, Status));
  switch(Status) {
    case CDP_URL_IS_EMPTY:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(MSG_CDP_URL_IS_EMPTY),NULL));
      break;
    case CDP_CANT_PARSE_URL:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(MSG_CDP_CANT_PARSE_URL),NULL));
      break;
    case CDP_UNSUPPORTED_PROTOCOL:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(MSG_CDP_UNSUPPORTED_PROTOCOL),NULL));
      break;
    case CDP_LDAP_SEARCH_ERROR:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(STR_LDAP_SEARCH_ERROR),NULL));
      break;
    case CDP_LDAP_CANT_PROC_OPT:
    case CDP_LDAP_CANT_INIT_SESSION:      
    case CDP_LDAP_ROOT_ERR_CREDENTIALS:
    case CDP_LDAP_SERVER_DENY:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(STR_BAD_LDAP_CONF_SETTINGS),NULL));
      break;
    case CDP_LDAP_TOO_MANY_ENTRIES:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(STR_CDP_LDAP_TOO_MANY_ENTRIES),NULL));
      break;
    case CDP_CANT_CONNECT_TO_LDAP:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(STR_LDAP_CONNECT_ERROR),NULL));
      break;
    case CDP_CANT_GET_CA_CHAIN:
    case CDP_LDAP_INTERNAL_ERROR:
    case CDP_LDAP_CANT_MAKE_REQUEST:
    case CDP_OUT_OF_MEMORY:
    case CDP_INVALID_PARAMETER:
    default:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(STR_ERR_INTERNAL),NULL));
      break;
  }
  ShowErrorPopup(CurrentHiiHandle,
    HiiGetString(CurrentHiiHandle,
      STRING_TOKEN(MSG_ERR_WHILE_SAVE_CERT),NULL));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Show an error message, which depends of a OSSL error code */
/*! You can add HistoryAddRecord() here to log these errors */
//------------------------------------------------------------------------------
STATIC
VOID
ProcessingSaveCertErrors (
  OSSL_STATUS Status
  )
{
  LOG((EFI_D_ERROR, "%a.%d OSSL Error: %d\n", __FUNCTION__, __LINE__, Status));
  switch(Status) {
    case OSSL_UNKNOWN_CRL_FORMAT:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(MSG_UNKNOWN_FORMAT_OF_CRL),NULL));
      break;
    case OSSL_UNKNOWN_CERT_FORMAT:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(STR_UNKNOWN_FORMAT_OF_CERTIFICATE),NULL));
      break;
    case OSSL_UNKNOWN_KEY_FORMAT:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(MSG_UNKNOWN_FORMAT_OF_KEY),NULL));
      break;
    case OSSL_UNKNOWN_PKCS7_FORMAT:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_UNKNOWN_FORMAT_OF_CHAIN),NULL));
      break;
    case OSSL_INVALID_SIGNATURE:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(STR_ERR_CA_SIGN),NULL));
      break;
    case OSSL_CERT_REVOKED:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_ERR_CERT_REVOKED),NULL));
      break;
    case OSSL_CANT_GET_PKEY_FROM_CERT:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_ERR_GET_CA_PUBKEY),NULL));
      break;
    case OSSL_INVALID_CRL_SIGNATURE:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_ERR_CRL_VERIFY),NULL));
      break;
    case OSSL_PKCS7_NOT_SIGNED:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_PKCS7_NOT_SIGNED),NULL));
      break;
    case OSSL_VERIFY_ERROR:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(MSG_VERIFY_ERROR),NULL));
      break;
    case OSSL_ERROR_TO_LOAD_CRL:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_ERROR_TO_LOAD_CRL),NULL));
      break;
    case OSSL_ERROR_TO_LOAD_ISSUER_CERT:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_ERROR_TO_LOAD_ISSUER_CERT),NULL));
      break;
    case OSSL_ERROR_TO_LOAD_ISSUER_CERT_LOCALLY:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_ERROR_TO_LOAD_ISSUER_CERT_LOCALLY),NULL));
      break;
    case OSSL_CANT_GET_TRUSTED_CERTS:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_CANT_GET_TRUSTED_CERTS),NULL));
      break;
    case OSSL_CERT_NOT_YET_VALID:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_CERT_NOT_YET_VALID),NULL));
      break;
    case OSSL_CERT_HAS_EXPIRED:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_CERT_HAS_EXPIRED),NULL));
      break;
    case OSSL_CRL_NOT_YET_VALID:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_CRL_NOT_YET_VALID),NULL));
      break;
    case OSSL_CRL_HAS_EXPIRED:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_CRL_HAS_EXPIRED),NULL));
      break;
    case OSSL_ERR_UNABLE_TO_GET_CRL:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_UNABLE_TO_GET_CRL),NULL));
      break;
    case OSSL_OCSP_URL_ERROR:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_OCPS_URL_ERROR),NULL));
      break;
    case OSSL_OCSP_RESPONSE_VERIFICATION:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_OCSP_RESPONSE_VERIFICATION),NULL));
      break;
    case OSSL_OCSP_RESPONDER_QUERY_FAILED:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_OCSP_RESPONDER_QUERY_FAILED),NULL));
      break;
    case OSSL_OCSP_CERT_UNKNOWN:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_OCSP_CERT_UNKNOWN),NULL));
      break;
    case OSSL_ERROR_TO_SAVE_CRL_TO_LOCAL_STACK:
    case OSSL_ERROR_TO_SAVE_BIO:
    case OSSL_ERROR_TO_SAVE_CRL_TO_CA_CHAIN:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_CDP_ERROR),NULL));
      break;
    default:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(STR_ERR_INTERNAL),NULL));
      break;
  }

#if 0
  ShowErrorPopup(CurrentHiiHandle,
    HiiGetString(CurrentHiiHandle,
      STRING_TOKEN(MSG_ERR_WHILE_SAVE_CERT),NULL));
#endif

  return;
}
//------------------------------------------------------------------------------

STATIC VOID
FreeGlobalStoragePointer(
  IN CHAR16 *StorageName
  )
{
  if (StrCmp(StorageName, CHAIN_STORAGE_VAR_NAME) == 0) {
    if (gChainStoragePtr != &badPtr) {
      FreePool(gChainStoragePtr);
      gChainStoragePtr = &badPtr;
    }
  } else if (StrCmp(StorageName, CRL_STORAGE_VAR_NAME) == 0) {
    if (gCRLStoragePtr != &badPtr) {
      FreePool(gCRLStoragePtr);
      gCRLStoragePtr = &badPtr;
    }
  } else if (StrCmp(StorageName, TLS_CERT_STORAGE_VAR_NAME) == 0) {
    if (gTlsCertStoragePtr != &badPtr) {
      FreePool(gTlsCertStoragePtr);
      gTlsCertStoragePtr = &badPtr;
    }
  } else if (StrCmp(StorageName, TLS_PKEY_STORAGE_VAR_NAME) == 0) {
    if (gClientPKeyStoragePtr != &badPtr) {
      FreePool(gClientPKeyStoragePtr);
      gClientPKeyStoragePtr = &badPtr;
    }
  } else {
    LOG((EFI_D_ERROR, "%a.%d Error! %s\n", __FUNCTION__, __LINE__, StorageName));
  }
}


STATIC VOID
UpdateGlobalStoragePointer(
  IN CHAR16 *StorageName,
  IN CERTIFICATE_STORAGE **Pointer
  )
{
  if (StrCmp(StorageName, CHAIN_STORAGE_VAR_NAME) == 0) {
    if (gChainStoragePtr != &badPtr) {
      FreePool(gChainStoragePtr);
      //gChainStoragePtr = NULL;
    }
    gChainStoragePtr = *Pointer;
  } else if (StrCmp(StorageName, CRL_STORAGE_VAR_NAME) == 0) {
    if (gCRLStoragePtr != &badPtr) {
      FreePool(gCRLStoragePtr);
      //gCRLStoragePtr = NULL;
    }
    gCRLStoragePtr = *Pointer;    
  } else if (StrCmp(StorageName, TLS_CERT_STORAGE_VAR_NAME) == 0) {
    if (gTlsCertStoragePtr != &badPtr) {
      FreePool(gTlsCertStoragePtr);
      //gTlsCertStoragePtr = NULL;
    }
    gTlsCertStoragePtr = *Pointer;
  } else if (StrCmp(StorageName, TLS_PKEY_STORAGE_VAR_NAME) == 0) {
    if (gClientPKeyStoragePtr != &badPtr) {
      FreePool(gClientPKeyStoragePtr);
      //gClientPKeyStoragePtr = NULL;
    }
    gClientPKeyStoragePtr = *Pointer;
  } else {
    LOG((EFI_D_ERROR, "%a.%d Error! %s\n", __FUNCTION__, __LINE__, StorageName));
  }
}



/* common storage functions */
STATIC EFI_STATUS
CertStorageInitEmpty(
  IN CHAR16 *StorageName,
  IN GUID *pStorageGuid,
  IN UINT8 CsType
  )
{
#if 0
  UINTN Size;
  EFI_STATUS Status;
  CERTIFICATE_STORAGE TmpStorage;
  UINT32 Attributes;
  
  if (NULL == StorageName || NULL == pStorageGuid) {
    return EFI_INVALID_PARAMETER;
  }
  
  Size = 0;
  Status = gRT->GetVariable(StorageName, pStorageGuid,
      NULL, &Size, &TmpStorage);

  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  }

  ZeroMem(&TmpStorage, sizeof(CERTIFICATE_STORAGE) - 1);
  TmpStorage.CsType = CsType;

  if (StrCmp(StorageName, CHAIN_STORAGE_VAR_NAME) == 0) {
    Attributes = STORAGE_RDWR_ATTR;
  } else if (StrCmp(StorageName, TLS_CERT_STORAGE_VAR_NAME) == 0) {
    Attributes = STORAGE_RDWR_ATTR;
  } else {
    Attributes = STORAGE_WRITE_ONLY_ATTR;
  }

  return gRT->SetVariable(StorageName, pStorageGuid,
    Attributes, sizeof(CERTIFICATE_STORAGE) - 1, &TmpStorage);
#else
  EFI_STATUS Status;
  CERTIFICATE_STORAGE TmpStorage;

  LOG((EFI_D_INFO, "%a.%d: Start\n", __FUNCTION__, __LINE__));
  Status = StorageInitEmpty(StorageName, pStorageGuid, NULL, 0, NULL, FALSE);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d: Status=0x%X\n", __FUNCTION__, __LINE__, Status));
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
#endif  
}

STATIC EFI_STATUS
CertStorageLoad(
  IN CHAR16 *StorageName,
  IN GUID *pStorageGuid
  )
{  
  EFI_STATUS Status;
  STORAGE_DATA StorageData;
  CERTIFICATE_STORAGE *pTmpStorage = NULL;
  
  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));  
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
    LOG((EFI_D_INFO, "StorageData.DataLen=%d pTmpStorage->DataLen=%d\n",
      StorageData.DataLen, pTmpStorage->DataLen));
  }
  LOG((EFI_D_INFO, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  LOG((EFI_D_INFO, "%a.%d pTmpStorage->DataLen=%d\n", 
    __FUNCTION__, __LINE__, pTmpStorage->DataLen));
  if (pTmpStorage->DataLen == 0) {
    goto _update_ptr;
  }
  if (-1 == CheckDataWithHash(CHAIN_STORAGE_CS_TYPE, pTmpStorage->Data,
      pTmpStorage->DataLen, pTmpStorage->CsData)) {
    FreePool(StorageData.Data);
    return EFI_CRC_ERROR;
  }
_update_ptr:
  UpdateGlobalStoragePointer(StorageName, &pTmpStorage);
  return EFI_SUCCESS;
}


EFI_STATUS
CertStorageSaveFromFile(
  IN CHAR16 *FullPath,
  IN CHAR16 *StorageName,
  IN GUID *pStorageGuid,
  IN UINT8 CsType
  )
{
  CHAR16 *FileName;
  UINTN Len;
  EFI_FILE_HANDLE File = NULL;
  EFI_STATUS Status = EFI_INVALID_PARAMETER;
  CERTIFICATE_STORAGE *pStorage = NULL;
  UINT32 Attributes;
  
  if (NULL == FullPath) {
    LOG((EFI_D_INFO, "%a.%d Error\n", __FUNCTION__, __LINE__));
    goto _exit;
  }
  Len = StrLen(FullPath);
  if (Len == 0) {
    LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    goto _exit;
  }
  LOG((EFI_D_INFO, "%a.%d FullPath=%s\n", __FUNCTION__, __LINE__, FullPath));
  
  FileName = FullPath + Len - 1;
  while (FileName > FullPath && *FileName != L'\\') {
    FileName--;
  }
  if (FileName != FullPath) {
    FileName++;
  }

  LOG((EFI_D_INFO, "%a.%d FileName=%s\n", __FUNCTION__, __LINE__, FileName));

  File = LibFsOpenFile16(FullPath, EFI_FILE_MODE_READ, 0);
  if (File == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error while LibFsOpenFile!!!!\n", 
      __FUNCTION__, __LINE__));
    goto _exit;
  }
  
  Len = LibFsSizeFile(File);
  
  if (Len == 0) {
    LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
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

  LOG((EFI_D_INFO, "%a.%d pStorage->DataLen=%d\n", 
    __FUNCTION__, __LINE__, pStorage->DataLen));
  
  Status = LibFsReadFile(File, &Len, pStorage->Data);
  if (EFI_ERROR(Status)) {
    goto _exit;
  }

  Status = CheckStorageData(StorageName, pStorage->Data, pStorage->DataLen);
  if (EFI_ERROR(Status))
    goto _exit;

  /* Calculate and save checksum */
  Status = CalcHashCs(CHAIN_STORAGE_CS_TYPE, pStorage->Data, 
      pStorage->DataLen, CALC_CS_RESET | CALC_CS_FINALIZE, 
      pStorage->CsData);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error while calc CS!\n", __FUNCTION__, __LINE__));
    Status = EFI_CRC_ERROR;
    goto _exit;
  }

  LOG((EFI_D_INFO, "%a.%d pStorage->DataLen=%d\n", 
    __FUNCTION__, __LINE__, pStorage->DataLen));
  
#if 0  
  if (-1 == CheckDataWithHash(CHAIN_STORAGE_CS_TYPE, pStorage->Data,
      pStorage->DataLen, pStorage->CsData)) {
    Status = EFI_CRC_ERROR;
  }
#endif
  StrnCpy(pStorage->FileName, FileName, sizeof(pStorage->FileName) / 2 - 1);
  if (StrCmp(StorageName, CHAIN_STORAGE_VAR_NAME) == 0) {
    Attributes = STORAGE_RDWR_ATTR;
  } else {
    Attributes = STORAGE_WRITE_ONLY_ATTR;
  }
#if 0  
  Status = gRT->SetVariable(StorageName, pStorageGuid, Attributes, 
    sizeof(CERTIFICATE_STORAGE) - 1 + pStorage->DataLen, pStorage);
#else
  LOG((EFI_D_INFO, "%a.%d pStorage->DataLen=%d\n", 
    __FUNCTION__, __LINE__, pStorage->DataLen));
  SetStorageAttributes(Attributes);
  Status = StorageSetRawData2(pStorageGuid,
    StorageName, (UINT8*)pStorage,
    sizeof(CERTIFICATE_STORAGE) - 1 + pStorage->DataLen,
    (sizeof(CERTIFICATE_STORAGE) - 1 + CERT_STORAGE_MAX_DATA_LEN + 
      CERT_MAX_CARD_SIZE) / CERT_MAX_CARD_SIZE, 
    sizeof(CERTIFICATE_STORAGE) - 1 + CERT_STORAGE_MAX_DATA_LEN,
    CERT_MAX_CARD_SIZE, FALSE);
#endif
  LOG((EFI_D_INFO, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  LOG((EFI_D_INFO, "%a.%d FileName=%s\n", __FUNCTION__, __LINE__, 
    pStorage->FileName));
  
_exit:
  if (EFI_ERROR(Status)) {
    if (pStorage) {
      FreePool(pStorage);
    }
  } else {
    UpdateGlobalStoragePointer(StorageName, &pStorage);
  }
  if (File) {
    LibFsCloseFile(File);
  }
  
  return Status;
}

EFI_STATUS
CertStorageSaveFromRawData(
  IN CHAR16 *FileName,
  IN CHAR16 *StorageName,
  IN GUID *pStorageGuid,
  IN UINT8 CsType,
  IN UINT8 *RawData,
  IN UINTN RawDataLen
  )
{
  EFI_STATUS Status = EFI_INVALID_PARAMETER;
  CERTIFICATE_STORAGE *pStorage = NULL;
  UINT32 Attributes;
  
  if (NULL == RawData || NULL == StorageName || RawDataLen == 0) {
    LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    goto _exit;
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

  Status = CheckStorageData(StorageName, pStorage->Data, pStorage->DataLen);
  if (EFI_ERROR(Status)) {
    LOG((DEBUG_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    goto _exit;
  }

  /* Calculate and save checksum */
  Status = CalcHashCs(CHAIN_STORAGE_CS_TYPE, pStorage->Data, 
      pStorage->DataLen, CALC_CS_RESET | CALC_CS_FINALIZE, 
      pStorage->CsData);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error while calc CS!\n", __FUNCTION__, __LINE__));
    Status = EFI_CRC_ERROR;
    goto _exit;
  }
  
  StrnCpy(pStorage->FileName, FileName, sizeof(pStorage->FileName) / 2 - 1);
  if (StrCmp(StorageName, CHAIN_STORAGE_VAR_NAME) == 0) {
    Attributes = STORAGE_RDWR_ATTR;
  } else {
    Attributes = STORAGE_WRITE_ONLY_ATTR;
  }
#if 0  
  Status = gRT->SetVariable(StorageName, pStorageGuid, Attributes, 
    sizeof(CERTIFICATE_STORAGE) - 1 + pStorage->DataLen, pStorage);
#else
  SetStorageAttributes(Attributes);
  Status = StorageSetRawData2(pStorageGuid,
    StorageName, (UINT8*)pStorage,
    sizeof(CERTIFICATE_STORAGE) - 1 + pStorage->DataLen,
    (sizeof(CERTIFICATE_STORAGE) - 1 + CERT_STORAGE_MAX_DATA_LEN + 
      CERT_MAX_CARD_SIZE) / CERT_MAX_CARD_SIZE, 
    sizeof(CERTIFICATE_STORAGE) - 1 + CERT_STORAGE_MAX_DATA_LEN,
    CERT_MAX_CARD_SIZE, FALSE);
#endif
  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  LOG((EFI_D_ERROR, "%a.%d FileName=%s\n", __FUNCTION__, __LINE__, 
    pStorage->FileName));
  
_exit:
  if (EFI_ERROR(Status)) {
    if (pStorage) {
      FreePool(pStorage);
    }
  } else {
    UpdateGlobalStoragePointer(StorageName, &pStorage);
  }
  
  return Status;
}

EFI_STATUS
SaveCRLToStorage(
  IN CHAR8 *crlData,
  IN UINTN crlDataLen
  )
{
  EFI_STATUS Status;
  Status = CertStorageSaveFromRawData(L"binaryCrl", CRL_STORAGE_VAR_NAME, &gCRLStorageGuid, CRL_STORAGE_CS_TYPE, 
    crlData, crlDataLen);
  LOG((EFI_D_INFO, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}

/* CA storage functions */
EFI_STATUS
ChainInitEmpty(
  VOID
  )
{
  SetStorageAttributes (STORAGE_RDWR_ATTR);
  return CertStorageInitEmpty(
    CHAIN_STORAGE_VAR_NAME,
    &gChainStorageGuid,
    CHAIN_STORAGE_CS_TYPE);
}

EFI_STATUS
CAUpdateFromFile(
  IN CHAR16 *FullPath
  )
{
  LOG((EFI_D_INFO, "%a.%d Start\n", __FUNCTION__, __LINE__));
  return CertStorageSaveFromFile(FullPath,
    CHAIN_STORAGE_VAR_NAME, &gChainStorageGuid, CHAIN_STORAGE_CS_TYPE);
}

EFI_STATUS
ChainLoad(
  VOID
  )
{
  LOG((EFI_D_INFO, "%a.%d Start\n", __FUNCTION__, __LINE__));
  return CertStorageLoad(CHAIN_STORAGE_VAR_NAME, &gChainStorageGuid);
}

EFI_STATUS
CASave(
  VOID
  )
{
  return EFI_UNSUPPORTED;
}

CERTIFICATE_STORAGE *
ChainGetData(
  VOID
  )
{
  return gChainStoragePtr;
}

/* TLS Client cert storage functions */
EFI_STATUS
TlsCertInitEmpty(
  VOID
  )
{
  SetStorageAttributes (STORAGE_WRITE_ONLY_ATTR);
  return CertStorageInitEmpty(
    TLS_CERT_STORAGE_VAR_NAME,
    &gClientCertStorageGuid,
    TLS_CERT_STORAGE_CS_TYPE);
}

EFI_STATUS
TlsClientCertUpdateFromFile(
  IN CHAR16 *FullPath
  )
{
  LOG((EFI_D_INFO, "%a.%d Start\n", __FUNCTION__, __LINE__));
  return CertStorageSaveFromFile(FullPath,
    TLS_CERT_STORAGE_VAR_NAME, &gClientCertStorageGuid, TLS_CERT_STORAGE_CS_TYPE);
}

EFI_STATUS
TlsClientCertLoad(
  VOID
  )
{
  LOG((EFI_D_INFO, "%a.%d Start\n", __FUNCTION__, __LINE__));
  return CertStorageLoad(TLS_CERT_STORAGE_VAR_NAME, &gClientCertStorageGuid);
}

CERTIFICATE_STORAGE *
TlsClientCertGetData(
  VOID
  )
{
  return gTlsCertStoragePtr;
}

/* TLS Client pkey storage functions */
EFI_STATUS
TlsPkeyInitEmpty(
  VOID
  )
{
  return CertStorageInitEmpty(
    TLS_PKEY_STORAGE_VAR_NAME,
    &gClientPKeyStorageGuid,
    TLS_PKEY_STORAGE_CS_TYPE);
}

EFI_STATUS
TlsClientPkeyUpdateFromFile(
  IN CHAR16 *FullPath
  )
{
  LOG((EFI_D_INFO, "%a.%d Start\n", __FUNCTION__, __LINE__));
  return CertStorageSaveFromFile(FullPath,
    TLS_PKEY_STORAGE_VAR_NAME, &gClientPKeyStorageGuid, TLS_PKEY_STORAGE_CS_TYPE);
}

EFI_STATUS
TlsClientPKeyLoad(
  VOID
  )
{
  LOG((EFI_D_INFO, "%a.%d Start\n", __FUNCTION__, __LINE__));
  return CertStorageLoad(TLS_PKEY_STORAGE_VAR_NAME, &gClientPKeyStorageGuid);
}

CERTIFICATE_STORAGE *
TlsClientPKeyGetData(
  VOID
  )
{
  return gClientPKeyStoragePtr;
}

/* CRL storage functions */
EFI_STATUS
CRLInitEmpty(
  VOID
  )
{
  SetStorageAttributes (STORAGE_WRITE_ONLY_ATTR);
  return CertStorageInitEmpty(
    CRL_STORAGE_VAR_NAME,
    &gCRLStorageGuid,
    CRL_STORAGE_CS_TYPE);
}

EFI_STATUS
CRLUpdateFromFile(
  IN CHAR16 *FullPath
  )
{
  LOG((EFI_D_INFO, "%a.%d Start\n", __FUNCTION__, __LINE__));
  return CertStorageSaveFromFile(FullPath,
    CRL_STORAGE_VAR_NAME, &gCRLStorageGuid, CRL_STORAGE_CS_TYPE);
}

EFI_STATUS
CRLLoad(
  VOID
  )
{
  LOG((EFI_D_INFO, "%a.%d Start\n", __FUNCTION__, __LINE__));
  return CertStorageLoad(CRL_STORAGE_VAR_NAME, &gCRLStorageGuid);;
}

EFI_STATUS
CRLSave(
  VOID
  )
{
  return EFI_UNSUPPORTED;
}

CERTIFICATE_STORAGE *
CRLGetData(
  VOID
  )
{
  return gCRLStoragePtr;
}


EFI_STATUS
CertificatePageCallback(
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  )
{
  //EFI_STATUS Status;

  if (ActionRequest == NULL) {
    return EFI_INVALID_PARAMETER;
  }

#if 1
  LOG((EFI_D_INFO, "%a.%d: Action=0x%x, QuestionId=0x%x\n", 
    __FUNCTION__, __LINE__, Action, QuestionId));
#endif
  
  if (EFI_BROWSER_ACTION_FORM_CLOSE == Action) {
    bFormExitFlag = TRUE;
    return EFI_SUCCESS;
  }
  if (EFI_BROWSER_ACTION_FORM_OPEN == Action) {
    
    return EFI_SUCCESS;
  }
  if (Action != EFI_BROWSER_ACTION_CHANGING) {
    return EFI_SUCCESS;
  }

  CurrentEvent = QuestionId;

  switch (QuestionId) {
  case CERT_CTRL_LOAD_UPDATE_CA_ID:
    LOG((EFI_D_INFO, "%a.%d --> CERT_CTRL_LOAD_UPDATE_CA_ID!!!\n",
      __FUNCTION__, __LINE__));
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    break;
    
  case CERT_CTRL_LOAD_UPDATE_CA_STATUS_ID:
    LOG((EFI_D_INFO, "%a.%d -->CERT_CTRL_LOAD_UPDATE_CA_STATUS_ID\n",
      __FUNCTION__, __LINE__));
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    break;
    
  case CERT_CTRL_DELETE_CA_ID:
    LOG((EFI_D_INFO, "%a.%d --> CERT_CTRL_DELETE_CA_ID!!!\n",
      __FUNCTION__, __LINE__));
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    break;
    
  case CERT_CTRL_LOAD_UPDATE_CRL_ID:
    LOG((EFI_D_INFO, "%a.%d --> CERT_CTRL_LOAD_UPDATE_CRL_ID!!!\n",
      __FUNCTION__, __LINE__));
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    break;
    
  case CERT_CTRL_LOAD_UPDATE_CRL_STATUS_ID:
    LOG((EFI_D_INFO, "%a.%d --> CERT_CTRL_LOAD_UPDATE_CRL_STATUS_ID"
      " Unexpected!!!\n", __FUNCTION__, __LINE__));
    break;
    
  case CERT_CTRL_DELETE_CRL_ID:
    LOG((EFI_D_INFO, "%a.%d --> CERT_CTRL_DELETE_CRL_ID!!!\n",
      __FUNCTION__, __LINE__));
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    break;
    
  case CERT_CTRL_LOAD_UPDATE_CERT_ID:
    LOG((EFI_D_INFO, "%a.%d --> CERT_CTRL_LOAD_UPDATE_CERT_ID!!!\n",
      __FUNCTION__, __LINE__));
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    break;
    
  case CERT_CTRL_LOAD_UPDATE_CERT_STATUS_ID:
    LOG((EFI_D_INFO, "%a.%d --> CERT_CTRL_LOAD_UPDATE_CERT_STATUS_ID \n",
      __FUNCTION__, __LINE__));
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    break;
    
  case CERT_CTRL_DELETE_CERT_ID:
    LOG((EFI_D_INFO, "%a.%d --> CERT_CTRL_DELETE_CERT_ID!!!\n",
      __FUNCTION__, __LINE__));
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    break;
    
  case CERT_CTRL_LOAD_UPDATE_PKEY_ID:
    LOG((EFI_D_INFO, "%a.%d --> CERT_CTRL_LOAD_UPDATE_PKEY_ID!!!\n",
      __FUNCTION__, __LINE__));
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    break;
    
  case CERT_CTRL_LOAD_UPDATE_PKEY_STATUS_ID:
    LOG((EFI_D_INFO, "%a.%d --> CERT_CTRL_LOAD_UPDATE_PKEY_STATUS_ID"
      " Unexpected!!!\n", __FUNCTION__, __LINE__));
    break;
    
  case CERT_CTRL_DELETE_PKEY_ID:
    LOG((EFI_D_INFO, "%a.%d --> CERT_CTRL_DELETE_PKEY_ID!!!\n",
      __FUNCTION__, __LINE__));
    *ActionRequest = EFI_BROWSER_ACTION_REQUEST_EXIT;
    break;

  default:
    LOG((EFI_D_ERROR, "%a.%d Unexpected QuestionId=0x%X!!!\n",
      __FUNCTION__, __LINE__, QuestionId));
    break;
  }
  return EFI_SUCCESS;
}




STATIC VOID
DestroyHiiResources(
  VOID
  )
{
  if (StartOpCodeHandle != NULL) {
    HiiFreeOpCodeHandle (StartOpCodeHandle);
    StartOpCodeHandle = NULL;
  }
  if (EndOpCodeHandle != NULL) {
    HiiFreeOpCodeHandle (EndOpCodeHandle);
    EndOpCodeHandle = NULL;
  }
}


STATIC EFI_STATUS
AllocateHiiResources(
  VOID
  )
{
  EFI_IFR_GUID_LABEL *StartLabel;
  EFI_IFR_GUID_LABEL *EndLabel;
  EFI_GUID FormSetGuid = FORMSET_CERT_CTRL_GUID;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  EFI_FORM_ID FormId = CERT_CTRL_PAGE_ID;

  DestroyHiiResources();

  StartOpCodeHandle = HiiAllocateOpCodeHandle ();
  if (StartOpCodeHandle == NULL) {
    goto _exit;
  }

  EndOpCodeHandle = HiiAllocateOpCodeHandle ();
  if (EndOpCodeHandle == NULL) {
    goto _exit;
  }

  StartLabel = (EFI_IFR_GUID_LABEL *) HiiCreateGuidOpCode (
      StartOpCodeHandle, &gEfiIfrTianoGuid, NULL, sizeof (EFI_IFR_GUID_LABEL));

  StartLabel->ExtendOpCode = EFI_IFR_EXTEND_OP_LABEL;
  StartLabel->Number       = LABEL_CERT_CTRL_LIST_START;

  EndLabel = (EFI_IFR_GUID_LABEL *) HiiCreateGuidOpCode (
      EndOpCodeHandle, &gEfiIfrTianoGuid, NULL, sizeof (EFI_IFR_GUID_LABEL));

  EndLabel->ExtendOpCode = EFI_IFR_EXTEND_OP_LABEL;
  EndLabel->Number       = LABEL_CERT_CTRL_LIST_END;

  Status = EFI_SUCCESS;

  HiiUpdateForm(CurrentHiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);

_exit:
  return Status;
}


EFI_STATUS
CertificateCommonInit(
  IN EFI_HII_HANDLE HiiHandle
  )
{
  bRefreshForm = FALSE;
  return EFI_SUCCESS;
}


STATIC EFI_STATUS
LoadUpdateCA(
  VOID
  )
{
  CHAR16 *FullPath;
  
  FullPath = FeGetSelectedString();
  if (StrLen(FullPath) == 0) {
    return EFI_NOT_FOUND;
  }
  LOG((EFI_D_INFO, "%a.%d FullPath=%s\n", __FUNCTION__, __LINE__, FullPath));
  return CAUpdateFromFile(FullPath);
}

STATIC EFI_STATUS
LoadUpdateCRL(
  VOID
  )
{
  CHAR16 *FullPath;

  FullPath = FeGetSelectedString();
  if (StrLen(FullPath) == 0) {
    return EFI_NOT_FOUND;
  }

  FullPath = FeGetSelectedString();
  return CRLUpdateFromFile(FullPath);
}

STATIC EFI_STATUS
LoadUpdateTlsClientCertificate(
  VOID
  )
{
  CHAR16 *FullPath;
  
  FullPath = FeGetSelectedString();
  if (StrLen(FullPath) == 0) {
    return EFI_NOT_FOUND;
  }
  LOG((EFI_D_INFO, "%a.%d FullPath=%s\n", __FUNCTION__, __LINE__, FullPath));
  return TlsClientCertUpdateFromFile(FullPath);
}

STATIC EFI_STATUS
LoadUpdateTlsClientPKey(
  VOID
  )
{
  CHAR16 *FullPath;
  
  FullPath = FeGetSelectedString();
  if (StrLen(FullPath) == 0) {
    return EFI_NOT_FOUND;
  }
  LOG((EFI_D_INFO, "%a.%d FullPath=%s\n", __FUNCTION__, __LINE__, FullPath));
  return TlsClientPkeyUpdateFromFile(FullPath);
}

STATIC
EFI_STATUS
SaveCertificateFromTokenById (
  IN CHAR16 *CertName,
  IN GUID *pStorageGuid,
  IN UINT8 CsType,
  IN UINT8 *IdVal,
  IN UINTN IdLen
  )
{
  UINT8 *CertData;
  UINTN CertDataLen;
  EFI_STATUS Status;
  CHAR16 FileName[300];

  Status = TokenGetCertificateById(IdVal, IdLen, 
    &CertData, &CertDataLen);
  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }
  LOG((EFI_D_ERROR, "%a.%d CertDataLen=%d\n", 
    __FUNCTION__, __LINE__, CertDataLen));

  UnicodeSPrint(FileName, sizeof(FileName), L"CertId_%X", IdVal);

  Status = CertStorageSaveFromRawData(FileName, CertName, pStorageGuid, CsType, 
    CertData, CertDataLen);
  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}

STATIC EFI_STATUS
LoadUpdateFromToken(
  IN CHAR16 *CertName,
  IN GUID *pStorageGuid,
  IN UINT8 CsType
  )
{
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut;
  UINTN PosX, PosY, IdLen, Columns, Rows, Ncols, Nlines;
  CHAR8 IdBuf[256];
  UINT8 IdVal[256];
  EFI_SIMPLE_TEXT_OUTPUT_MODE ConsoleMode;
  CHAR16 *HiiString;
  EFI_STATUS Status;  

  LOG((EFI_D_INFO, "%a.%d Start\n", __FUNCTION__, __LINE__));
  
  ConOut = gST->ConOut;
  ConOut->ClearScreen(ConOut);  
  HiiString = HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_INPUT_CERT_ID),
        NULL);

  CreatePopUp(EFI_LIGHTGRAY | EFI_BACKGROUND_BLUE, NULL, L"", HiiString,
    L"", L"", NULL);

  CopyMem(&ConsoleMode, ConOut->Mode, sizeof(ConsoleMode));
  ConOut->QueryMode (ConOut, ConsoleMode.Mode, &Columns, &Rows);
  Nlines = 5; // currently 5 lines in popup
  Nlines = MIN (Nlines, Rows - 3);
  Ncols = StrLen(HiiString);
  Ncols = MIN (Ncols, Columns - 2);

  // Calc starting row and starting column for the popup
  PosY = (Rows - (Nlines + 3)) / 2;
  PosX = (Columns - (Ncols + 2)) / 2;
  
  PosY += 4;
  PosX += 2;

  PrepareInputLine(PosX, PosY, Ncols - 2);
#if 0  
  IdLen = ReadLineHexAndHide((UINT8*)IdBuf, sizeof(IdBuf) - 1, Ncols - 2, FALSE);
  if (IdLen == 0) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  IdBuf[IdLen] = L'\0';
#else
{
  CHAR16 String[255];
  UINTN Idx; 

  //for (Idx = 0; Idx < )
  (VOID)Idx;
  String[0] = 0;
  
  Status = ReadInputStringWithCheck (String, 0, 255,
          Ncols - 2,
          Ncols,
          PosY,
          PosX,
          FALSE,
          TRUE,
          GetTokenInserted
          );
  AsciiSPrint(IdBuf, sizeof(IdBuf), "%s", String);
  IdLen = AsciiStrLen(IdBuf);
  if (EFI_ERROR(Status)) {
    return Status;
  }
}
#endif  
  
  
  LOG((EFI_D_INFO, "%a.%d %a\n", __FUNCTION__, __LINE__, IdBuf));  

  //IdVal = StrHexToUintn(IdBuf);
  Status = HexStringToByteBuf(IdBuf,  IdVal, sizeof(IdVal));
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!%r\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }
  
  ConOut->ClearScreen(ConOut);

  Status = SaveCertificateFromTokenById (
              CertName, 
              pStorageGuid,
              CsType,
              IdVal, 
              (IdLen + 1) / 2
              );
  LOG((EFI_D_INFO, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}

STATIC
EFI_STATUS
SetupFileExplorerStartPath (
  VOID
  )
{
  EFI_STATUS Status = EFI_SUCCESS;
  STATIC CHAR16 TmpPtr16[255];
  
  if (gStrDevPath == NULL) {
    Status = FindUsbPath();
    if (!EFI_ERROR(Status)) {
      gStrDevPath = USB_PATH_SHORT_NAME;
    }
  }
  if (EFI_ERROR(Status) || gStrDevPath == NULL) {
    return EFI_NOT_FOUND;
  }
  if (!CheckFsPathPresent(gStrDevPath, NULL)) {
    Status = FindSpecialDevPath(L"Pci(0x16,0x2)/Ata");
    if (!EFI_ERROR(Status)) {
      UnicodeSPrint(TmpPtr16, sizeof(TmpPtr16), L"%s:\\", 
        SPEC_PATH_SHORT_NAME);
      gStrDevPath = TmpPtr16;
    } else {
      return EFI_NOT_FOUND;
    }
  }
  
  FeLibSetDevicePath(gStrDevPath);
  return EFI_SUCCESS;
}


EFI_STATUS
CertificateControlPage(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  )
{
  EFI_GUID FormSetGuid = FORMSET_CERT_CTRL_GUID;
  EFI_FORM_ID FormId = CERT_CTRL_PAGE_ID;
  EFI_BROWSER_ACTION_REQUEST ActionRequest;
  EFI_STATUS Status = EFI_OUT_OF_RESOURCES;
  EFI_STRING_ID HelpToken;
  UINT8 QuestionChainIdFlag, QuestionTlsIdFlag;
  CHAR16 Str16[255];
  //CHAR8 Str8[255];

  do {
    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

    if (EFI_SUCCESS != CertificateCommonInit(HiiHandle)) {
      return EFI_INVALID_PARAMETER;
    }

    if (EFI_SUCCESS != AllocateHiiResources()) {
      return EFI_OUT_OF_RESOURCES;
    }

    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

    HiiCreateSubTitleOpCode (StartOpCodeHandle, STRING_TOKEN(STR_CERT_CTRL_SUBTITLE), 0, 0, 1);

    HelpToken = HiiSetString (HiiHandle, 0, L"", NULL);
/* Load update CA */
    HiiCreateActionOpCode(StartOpCodeHandle,
      (EFI_QUESTION_ID)CERT_CTRL_LOAD_UPDATE_CA_ID,
      STRING_TOKEN(STR_CA_LOAD_UPDATE),
      HelpToken, EFI_IFR_FLAG_CALLBACK, 0);
    HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);
/* Load update Status (Current CA) */

    if (IsChainEmpty() == TRUE)
      QuestionChainIdFlag = EFI_IFR_FLAG_READ_ONLY;
    else
      QuestionChainIdFlag = EFI_IFR_FLAG_CALLBACK;

    if (IsTlsClientCertEmpty() == TRUE)
      QuestionTlsIdFlag = EFI_IFR_FLAG_READ_ONLY;
    else
      QuestionTlsIdFlag = EFI_IFR_FLAG_CALLBACK;

    UnicodeSPrint(Str16, sizeof(Str16), L"%s : < %s >", 
      HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_CA_CURRENT),
        NULL), gChainStoragePtr == &badPtr || gChainStoragePtr->FileName[0] == 0 ? 
          L"..." : gChainStoragePtr->FileName);
    LOG((EFI_D_INFO, "%a.%d: Str16=%s\n", __FUNCTION__, __LINE__, Str16));
    HiiCreateActionOpCode(StartOpCodeHandle,
      (EFI_QUESTION_ID)CERT_CTRL_LOAD_UPDATE_CA_STATUS_ID,
      //STRING_TOKEN(STR_CA_CURRENT),
      HiiSetString(CurrentHiiHandle, 0, Str16, NULL),
      HelpToken, QuestionChainIdFlag, 0);
    HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
      StartOpCodeHandle, EndOpCodeHandle);

    if (IsChainEmpty() == FALSE) {
      /* Delete CA */
      HiiCreateActionOpCode(StartOpCodeHandle,
        (EFI_QUESTION_ID)CERT_CTRL_DELETE_CA_ID,
        STRING_TOKEN(STR_CA_DELETE),
        HelpToken, EFI_IFR_FLAG_CALLBACK, 0);
      HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
        StartOpCodeHandle, EndOpCodeHandle);

      /* Load update CRL */    
      LOG((EFI_D_INFO, "%a.%d: Str16=%s\n", __FUNCTION__, __LINE__, Str16));
      HiiCreateActionOpCode(StartOpCodeHandle,
        (EFI_QUESTION_ID)CERT_CTRL_LOAD_UPDATE_CRL_ID,
        STRING_TOKEN(STR_CRL_LOAD_UPDATE),
        HelpToken, EFI_IFR_FLAG_CALLBACK, 0);
      HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
        StartOpCodeHandle, EndOpCodeHandle);
      /* Load update Status (Current CRL) */
      UnicodeSPrint(Str16, sizeof(Str16), L"%s : < %s >", 
        HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_CRL_CURRENT),
          NULL), gCRLStoragePtr == &badPtr || gCRLStoragePtr->FileName[0] == 0 ? 
            L"..." : gCRLStoragePtr->FileName);
      HiiCreateActionOpCode(StartOpCodeHandle,
        (EFI_QUESTION_ID)CERT_CTRL_LOAD_UPDATE_CRL_STATUS_ID,
        //STRING_TOKEN(STR_CRL_CURRENT),
        HiiSetString(CurrentHiiHandle, 0, Str16, NULL),
        HelpToken, EFI_IFR_FLAG_READ_ONLY, 0);
      HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
        StartOpCodeHandle, EndOpCodeHandle);

      if (IsCRLEmpty() == FALSE) {
        /* Delete CRL */
        HiiCreateActionOpCode(StartOpCodeHandle,
          (EFI_QUESTION_ID)CERT_CTRL_DELETE_CRL_ID,
          STRING_TOKEN(STR_CRL_DELETE),
          HelpToken, EFI_IFR_FLAG_CALLBACK, 0);
        HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
          StartOpCodeHandle, EndOpCodeHandle);
      }

      /* Load update TLS client certificate */
      HiiCreateActionOpCode(StartOpCodeHandle,
        (EFI_QUESTION_ID)CERT_CTRL_LOAD_UPDATE_CERT_ID,
        STRING_TOKEN(STR_CERT_LOAD_UPDATE),
        HelpToken, EFI_IFR_FLAG_CALLBACK, 0);
      HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
        StartOpCodeHandle, EndOpCodeHandle);
      /* Load update Status (Current TLS client certificate) */
      UnicodeSPrint(Str16, sizeof(Str16), L"%s : < %s >", 
        HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_CERT_CURRENT),
          NULL), gTlsCertStoragePtr == &badPtr || gTlsCertStoragePtr->FileName[0] == 0 ? 
            L"..." : gTlsCertStoragePtr->FileName);
      LOG((EFI_D_INFO, "%a.%d: Str16=%s\n", __FUNCTION__, __LINE__, Str16));
      HiiCreateActionOpCode(StartOpCodeHandle,
        (EFI_QUESTION_ID)CERT_CTRL_LOAD_UPDATE_CERT_STATUS_ID,
        //STRING_TOKEN(STR_CA_CURRENT),
        HiiSetString(CurrentHiiHandle, 0, Str16, NULL),
        HelpToken, QuestionTlsIdFlag, 0);
      HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
        StartOpCodeHandle, EndOpCodeHandle);

      if (IsTlsClientCertEmpty() == FALSE) {
        /* Delete TLS client certificate */
        HiiCreateActionOpCode(StartOpCodeHandle,
          (EFI_QUESTION_ID)CERT_CTRL_DELETE_CERT_ID,
          STRING_TOKEN(STR_CERT_DELETE),
          HelpToken, EFI_IFR_FLAG_CALLBACK, 0);
        HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
          StartOpCodeHandle, EndOpCodeHandle);
      }

      /* Load update TLS client pkey */
      HiiCreateActionOpCode(StartOpCodeHandle,
        (EFI_QUESTION_ID)CERT_CTRL_LOAD_UPDATE_PKEY_ID,
        STRING_TOKEN(STR_PKEY_LOAD_UPDATE),
        HelpToken, EFI_IFR_FLAG_CALLBACK, 0);
      HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
        StartOpCodeHandle, EndOpCodeHandle);
      /* Load update Status (Current TLS client pkey) */
      UnicodeSPrint(Str16, sizeof(Str16), L"%s : < %s >", 
        HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_PKEY_CURRENT),
          NULL), gClientPKeyStoragePtr == &badPtr || gClientPKeyStoragePtr->FileName[0] == 0 ? 
            L"..." : gClientPKeyStoragePtr->FileName);
      LOG((EFI_D_INFO, "%a.%d: Str16=%s\n", __FUNCTION__, __LINE__, Str16));
      HiiCreateActionOpCode(StartOpCodeHandle,
        (EFI_QUESTION_ID)CERT_CTRL_LOAD_UPDATE_PKEY_STATUS_ID,
        //STRING_TOKEN(STR_CA_CURRENT),
        HiiSetString(CurrentHiiHandle, 0, Str16, NULL),
        HelpToken, EFI_IFR_FLAG_READ_ONLY, 0);
      HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
        StartOpCodeHandle, EndOpCodeHandle);

      if (IsTlsClientPKeyEmpty() == FALSE) {
        /* Delete TLS client pkey */
        HiiCreateActionOpCode(StartOpCodeHandle,
          (EFI_QUESTION_ID)CERT_CTRL_DELETE_PKEY_ID,
          STRING_TOKEN(STR_PKEY_DELETE),
          HelpToken, EFI_IFR_FLAG_CALLBACK, 0);
        HiiUpdateForm(HiiHandle, &FormSetGuid, FormId,
          StartOpCodeHandle, EndOpCodeHandle);
      }
    }

    LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

    Status = gBS->LocateProtocol (&gEfiFormBrowser2ProtocolGuid, NULL,
      (VOID **) &gFormBrowser2);
    if (EFI_ERROR (Status)) {
      LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
      goto _exit;
    }

    ActionRequest = EFI_BROWSER_ACTION_REQUEST_NONE;
    Status = EFI_SUCCESS;

    do {
      Status = gFormBrowser2->SendForm(gFormBrowser2, &HiiHandle, 1,
        &FormSetGuid, FormId, NULL, &ActionRequest);
      
      LOG((EFI_D_INFO, "%a.%d CurrentEvent=0x%X\n", 
        __FUNCTION__, __LINE__, CurrentEvent));
      
      switch (CurrentEvent) {
      case CERT_CTRL_LOAD_UPDATE_CA_ID:
        //DestroyHiiResources();
        CurrentEvent = 0;
        bRefreshForm = TRUE;

        if (IsCRLEmpty() == FALSE || IsTlsClientCertEmpty() == FALSE) {
          // show warning popup
          CHAR16 *WarnStr;
          
          WarnStr = HiiGetString (
                CurrentHiiHandle, 
                STRING_TOKEN (STR_MSG_WARN_TLS_AND_CRL), 
                NULL
                );          
          ShowWarningPopup (
            CurrentHiiHandle,
            HiiGetString (
                CurrentHiiHandle, 
                STRING_TOKEN (STR_MSG_WARN_TLS_AND_CRL), 
                NULL
                )
            );          
        }
#if ALLOW_EXPORT_CA_FROM_TOKEN //export CA from token        
        if (GetTokenInserted()) {
          UINT8 IdVal[256];
          UINTN IdLen;

          if (!GetExtractTokenCert()) {
            ShowErrorPopup(CurrentHiiHandle,
              HiiGetString(CurrentHiiHandle,
                  STRING_TOKEN(STR_TOKEN_DATA_ERROR), NULL));
            Status = EFI_SUCCESS;
            break;       
          }
          
          IdLen = sizeof(IdVal);
          Status = ProcessTokenViewer(CurrentHiiHandle, 
            CurrentConfig, IdVal, &IdLen);
          if (EFI_UNSUPPORTED == Status) {
            Status = LoadUpdateFromToken (
                        CHAIN_STORAGE_VAR_NAME, 
                        &gChainStorageGuid,
                        CHAIN_STORAGE_CS_TYPE
                        );
          } else if (EFI_SUCCESS == Status) {
            Status = SaveCertificateFromTokenById (
              CHAIN_STORAGE_VAR_NAME,
              &gChainStorageGuid,
              CHAIN_STORAGE_CS_TYPE,
              IdVal,
              1 //IdLen = 2 and C_GetAttributeValue return 1
              );
          }
          if (EFI_ERROR(Status)) {
            LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
            if (Status == EFI_NOT_STARTED) {
              Status = EFI_SUCCESS;
              break;
            } else {            
              ShowErrorPopup(CurrentHiiHandle,
                HiiGetString(CurrentHiiHandle,
                  GetTokenInserted() ? 
                    STRING_TOKEN(MSG_ERR_WHILE_SAVE_CERT) :
                    STRING_TOKEN(STR_ERR_TOKEN_WAS_REMOVED), NULL));
            }
          }
          HistoryAddRecord(HEVENT_LOAD_CA, 
            GetCurrentUserId(), SEVERITY_LVL_INFO, 
            EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
          Status = EFI_SUCCESS;
          break;
        }
#else
        if (GetTokenInserted()) {
          ShowWarningPopup(CurrentHiiHandle,
            HiiGetString(CurrentHiiHandle,
              STRING_TOKEN(STR_TOKEN_ERROR_CA), NULL));
        }
#endif //ALLOW_EXPORT_CA_FROM_TOKEN

        Status = SetupFileExplorerStartPath();
        if (EFI_ERROR(Status)) {
          ShowErrorPopup(CurrentHiiHandle,
            HiiGetString(CurrentHiiHandle,
              STRING_TOKEN(STR_PLEASE_INSERT_FLASH_IN_PROPER_PORT), NULL));
          Status = EFI_SUCCESS;
          break;
        }
        
        Status = FeLibTest(NULL, NULL, 0, 0, 0, 0);
        Status = LoadUpdateCA();
        if (Status == EFI_NOT_FOUND) {
          /* no error popup */
        } else if (EFI_ERROR(Status)) {
          ProcessingCertificateStorageError();
        }
        HistoryAddRecord(HEVENT_LOAD_CA, 
            GetCurrentUserId(), SEVERITY_LVL_INFO, 
            EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
        Status = EFI_SUCCESS;        
        break;

      case CERT_CTRL_LOAD_UPDATE_CA_STATUS_ID:
        // Launch Certificate viewer
        ProcessCertViewer(CurrentHiiHandle,
                          CurrentConfig,
                          P7B_CHAIN,
                          ChainGetData()->Data,
                          ChainGetData()->DataLen);
        CurrentEvent = 0;
        bRefreshForm = TRUE;
        Status = EFI_SUCCESS;
        break;

      case CERT_CTRL_DELETE_CA_ID:
        if (IsCRLEmpty() == TRUE &&
            IsTlsClientCertEmpty() == TRUE) {
          // delete CA if storage is empty (except CRL key)
          Status = ChainInitEmpty();
          if (EFI_ERROR(Status)) {
            LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
          }
          Status = ChainLoad();
          if (EFI_ERROR(Status)) {
            LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
          }
          FlushCRLLocalStack();
        } else {
          ShowErrorPopup(CurrentHiiHandle,
            HiiGetString(CurrentHiiHandle, 
              STRING_TOKEN(MSG_CERT_STORAGE_NOT_EMPTY),NULL));
        }
        CurrentEvent = 0;
        bRefreshForm = TRUE;
        break;

      case CERT_CTRL_DELETE_CRL_ID:
        Status = CRLInitEmpty();
        if (EFI_ERROR(Status)) {
          LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
        }
        Status = CRLLoad();
        if (EFI_ERROR(Status)) {
          LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
        }
        CurrentEvent = 0;
        bRefreshForm = TRUE;
        break;

      case CERT_CTRL_DELETE_CERT_ID:
        Status = TlsCertInitEmpty();
        if (EFI_ERROR(Status)) {
          LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
        }
        Status = TlsClientCertLoad();
        if (EFI_ERROR(Status)) {
          LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
        }
        CurrentEvent = 0;
        bRefreshForm = TRUE;
        break;
        
      case CERT_CTRL_DELETE_PKEY_ID:
          Status = TlsPkeyInitEmpty();
          if (EFI_ERROR(Status)) {
            LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
          }
          Status = TlsClientPKeyLoad();
          if (EFI_ERROR(Status)) {
            LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
          }
        CurrentEvent = 0;
        bRefreshForm = TRUE;
        break;
        
      case CERT_CTRL_LOAD_UPDATE_CRL_ID:
        CurrentEvent = 0;
        bRefreshForm = TRUE;
/*
        if (GetTokenInserted()) {
          Status = LoadUpdateFromToken(CRL_STORAGE_VAR_NAME, &gCRLStorageGuid,
            CHAIN_STORAGE_CS_TYPE);
          if (EFI_ERROR(Status)) {
            LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
            if (Status == EFI_NOT_STARTED) {
              Status = EFI_SUCCESS;
              break;
            } else {            
              ShowErrorPopup(CurrentHiiHandle,
                HiiGetString(CurrentHiiHandle, 
                  GetTokenInserted() ? 
                    STRING_TOKEN(MSG_ERR_WHILE_SAVE_CERT) :
                    STRING_TOKEN(STR_ERR_TOKEN_WAS_REMOVED), NULL));
            }
          }
          HistoryAddRecord(HEVENT_LOAD_CRL, 
            GetCurrentUserId(), SEVERITY_LVL_INFO, 
            EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
          Status = EFI_SUCCESS;
          break;
        }
*/
        Status = SetupFileExplorerStartPath();
        if (EFI_ERROR(Status)) {
          ShowErrorPopup(CurrentHiiHandle,
            HiiGetString(CurrentHiiHandle, 
              STRING_TOKEN(STR_PLEASE_INSERT_FLASH_IN_PROPER_PORT), NULL));
          Status = EFI_SUCCESS;
          break;
        }
        Status = FeLibTest(NULL, 0, 0, 0, 0, 0);
        LOG((EFI_D_INFO, "%a.%d Status: %d\n", __FUNCTION__, __LINE__, Status));
        Status = LoadUpdateCRL();
        if (Status == EFI_NOT_FOUND) {
          /* no error popup */
        } else if (EFI_ERROR(Status)) {
          ProcessingCertificateStorageError();
        }
        HistoryAddRecord(HEVENT_LOAD_CRL, 
            GetCurrentUserId(), SEVERITY_LVL_INFO, 
            EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
        Status = EFI_SUCCESS;        
        break;

      case CERT_CTRL_LOAD_UPDATE_CERT_STATUS_ID:
        // Launch Certificate viewer
        ProcessCertViewer(CurrentHiiHandle,
                          CurrentConfig,
                          CERT_OBJ,
                          TlsClientCertGetData()->Data,
                          TlsClientCertGetData()->DataLen);
        CurrentEvent = 0;
        bRefreshForm = TRUE;
        Status = EFI_SUCCESS;
        break;

      case CERT_CTRL_LOAD_UPDATE_CERT_ID:
        CurrentEvent = 0;
        bRefreshForm = TRUE;
        Status = SetupFileExplorerStartPath();
        if (EFI_ERROR(Status)) {
          ShowErrorPopup(CurrentHiiHandle,
            HiiGetString(CurrentHiiHandle, 
              STRING_TOKEN(STR_PLEASE_INSERT_FLASH_IN_PROPER_PORT), NULL));
          Status = EFI_SUCCESS;
          break;
        }
        Status = FeLibTest(NULL, NULL, 0, 0, 0, 0);
        Status = LoadUpdateTlsClientCertificate();
        if (Status == EFI_NOT_FOUND) {
          /* no error popup */
        } else if (EFI_ERROR(Status)) {
          ProcessingCertificateStorageError();
        }
        Status = EFI_SUCCESS;    
        break;
        
      case CERT_CTRL_LOAD_UPDATE_PKEY_ID:
        CurrentEvent = 0;
        bRefreshForm = TRUE;
        Status = SetupFileExplorerStartPath();
        if (EFI_ERROR(Status)) {
          ShowErrorPopup(CurrentHiiHandle,
            HiiGetString(CurrentHiiHandle, 
              STRING_TOKEN(STR_PLEASE_INSERT_FLASH_IN_PROPER_PORT), NULL));
          Status = EFI_SUCCESS;
          break;
        }
        Status = FeLibTest(NULL, NULL, 0, 0, 0, 0);
        Status = LoadUpdateTlsClientPKey();
        if (Status == EFI_NOT_FOUND) {
          /* no error popup */
        } else if (EFI_ERROR(Status)) {
          LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
          ShowErrorPopup(CurrentHiiHandle,
            HiiGetString(CurrentHiiHandle, 
              STRING_TOKEN(STR_ERR_WHILE_SAVE_DATA),NULL));
        }
        Status = EFI_SUCCESS;    
        break;
      
      default:
        break;
      }

      if (bRefreshForm) {
        break;
      }
      if (bFormExitFlag) {
        Status = EFI_SUCCESS;
        break;
      }
    } while (1);

  _exit:
    DestroyHiiResources();
    if (EFI_ERROR(Status)) {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      break;
    }
  } while (bRefreshForm);

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  return Status;
}

EFI_STATUS
ObtainDevPathForLoadCert(
  VOID
  )
{
  gStrDevPath = GetDevicePathFromCfg(CurrentConfig, ADM_MAIN_PAGE_SERT_CTRL_ID);
  return gStrDevPath ? EFI_SUCCESS : EFI_INVALID_PARAMETER;
}

const CHAR16*
GetStrDevPath(
  VOID
  )
{
  if (gStrDevPath == NULL) {
    ObtainDevPathForLoadCert();
  }
  
  return gStrDevPath;
}


VOID
CertificateCtrlInit(
  IN MULTIBOOT_CONFIG *Cfg
  )
{
  CurrentConfig = Cfg;
}


EFI_STATUS
CertificateCtrlMenuStart(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  )
{
  EFI_STATUS Status;

  LOG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  CurrentHiiHandle = HiiHandle;
  bRefreshForm = FALSE;

  ObtainDevPathForLoadCert();

  Status = CertificateControlPage(HiiHandle, Language);
  LOG((EFI_D_INFO, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));
  return Status;
}

STATIC UINT8 *CertCacheData;
STATIC UINTN CertCacheDataLen;


EFI_STATUS
SetCertificateCache (
  IN UINT8 *Data,
  IN UINTN DataLen
  )
{
  if (Data == NULL || DataLen == 0) {
    return EFI_INVALID_PARAMETER;
  }

  if (CertCacheData != NULL) {
    FreePool (CertCacheData);
    CertCacheData = NULL;
    CertCacheDataLen = 0;
  }

  CertCacheData = AllocateZeroPool (DataLen);
  if (CertCacheData == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  CopyMem (CertCacheData, Data, DataLen);
  CertCacheDataLen = DataLen;
  return EFI_SUCCESS;
}


EFI_STATUS
GetCertificateCache (
  IN OUT UINT8 **Data,
  IN OUT UINTN *DataLen
  )
{
  if (Data == NULL || DataLen == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (CertCacheData != NULL) {
    *Data = CertCacheData;
    *DataLen = CertCacheDataLen;
    return EFI_SUCCESS;
  }
  return EFI_NOT_READY;
}


