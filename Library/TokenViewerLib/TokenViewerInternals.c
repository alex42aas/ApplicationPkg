/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Uefi.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BIOSLib/TokenFunctions.h>

#include <Protocol/OpensslProtocol.h>

#include "TokenViewerInternals.h"

#if 0
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

#define ARRAY_ITEMS(Array_) \
  (sizeof (Array_) / sizeof (*Array_))


STATIC OPENSSL_PROTOCOL *pOpenSSLProtocol;
STATIC CK_BBOOL bFalse = CK_FALSE;
STATIC CK_BBOOL bTrue = CK_TRUE;
STATIC CK_OBJECT_CLASS cClass = CKO_CERTIFICATE;
STATIC CK_CERTIFICATE_TYPE cType = CKC_X_509;


//------------------------------------------------------------------------------
/*! \brief Convert certificate data to the TokenViewer format */
/*! \param[out] *certificate A certificate in a TokenViewer format
    \param[in] *CertData A certificate in a binary form
    \param[in] CertDataLen A length of the binary
    \param[in] CertID ID of a certificate on the token */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
ConvertCertStruct(
  OUT CERT_T *certificate,
  IN  UINT8  *certData,
  IN  UINTN   certDataLen,
  IN  UINT16  certID
)
{
  EFI_STATUS Status;

  if (pOpenSSLProtocol == NULL) {
    Status = gBS->LocateProtocol (
                    &gOpenSSLProtocolGuid,
                    NULL,
                    (VOID **) &pOpenSSLProtocol
                    );
    if (Status != EFI_SUCCESS) {
      DEBUG ((EFI_D_ERROR, "%a.%d Status: %d\n", __FUNCTION__, __LINE__, Status));
      return Status;
    }
  }

  Status = pOpenSSLProtocol->GetCertificateInfoFromCertBinary(certData, certDataLen, &(certificate->certInfo));
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_ERROR, "%a.%d Status: %d\n", __FUNCTION__, __LINE__, Status));
    return EFI_NOT_FOUND;
  }

   certificate->certId = AllocateZeroPool(sizeof(certID));
   if (certificate->certId != NULL ) {
     CopyMem(certificate->certId, &certID, sizeof(certID));
     certificate->lenId = sizeof(certID);
   } else
     Status = EFI_OUT_OF_RESOURCES;

  LOG((EFI_D_ERROR, "%a.%d Status: %d\n", __FUNCTION__, __LINE__, Status));

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get all certificates from the inserted eToken */
/*! \param[out] **certList A list of certificates from the eToken
    \param[out] *certCount A count of certificates in the list */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
GetCertListFromEToken(
  OUT CERT_T **certList,
  OUT UINTN   *certCount
)
{
  EFI_STATUS Status;

  ET_OBJ_DESC *Objects   = NULL;
  CERT_T      *beginList = NULL;

  SMART_CARD_PROTOCOL *pSmartCardProtocol;

  UINTN ObjCnt, i;
  UINTN DataLen;

  pSmartCardProtocol = TokenGetSmartCardProtocol();
  if (pSmartCardProtocol == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  Status = pSmartCardProtocol->GetObjectsList(
                                pSmartCardProtocol,
                                (UINT8**)&Objects,
                                &DataLen
                                );
  if (EFI_ERROR(Status) || (Objects == NULL) || (DataLen == 0) ) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  // Calculate a number of certificates
  ObjCnt = DataLen / sizeof(struct _ET_OBJ_DESC);

  LOG((EFI_D_ERROR, "%a.%d ObjCnt=%d\n", __FUNCTION__, __LINE__, ObjCnt));

  *certCount = 0;
  for(i = 0; i < ObjCnt; i++ ) {
    if (Objects[i].Type == CERT_ID_TYPE)
      (*certCount)++;
  }

  if (*certCount == 0) {
    Status = EFI_NOT_FOUND;
    goto _exit;
  }

  *certList = AllocateZeroPool(*certCount * sizeof(CERT_T));
  if (*certList == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    Status = EFI_OUT_OF_RESOURCES;
    goto _exit;
  }

  // Backup a pointer to the start of the list
  beginList = *certList;

  for (i = 0; i < ObjCnt; i++) {
    if (Objects[i].Type == CERT_ID_TYPE) {

      UINT8 *CertData = NULL;
      UINTN CertDataLen;

      LOG((EFI_D_ERROR, "%a.%d certID: %d\n", __FUNCTION__, __LINE__, Objects[i].Id));

      Status = pSmartCardProtocol->GetObjectValById(
                                     pSmartCardProtocol,
                                     (UINT8*)&(Objects[i].Id),
                                     sizeof(Objects[i].Id),
                                     &CertData,
                                     &CertDataLen);
      if (!EFI_ERROR(Status) && (CertData != NULL) && (CertDataLen > 0)) {
        Status = ConvertCertStruct(*certList, CertData, CertDataLen, Objects[i].Id);
        (*certList)++;
      } else
        LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));

      if (CertData != NULL)
        FreePool(CertData);

    }
  }

_exit:

  if (Objects != NULL)
    FreePool(Objects);

  // Restore the start of the list
  *certList = beginList;

  LOG((EFI_D_ERROR, "%a.%d Status: %d\n", __FUNCTION__, __LINE__, Status));

  return Status;
}
//------------------------------------------------------------------------------

STATIC
EFI_STATUS
GetCertificateData (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE hCert,
  IN OUT UINT8 **Cdata,
  IN OUT UINTN *CdataLen
  )
{
  CK_RV rv;
  CK_ATTRIBUTE aCertVal = {CKA_VALUE, NULL, 0};

  rv = C_GetAttributeValue (hSession, hCert, &aCertVal, 1);
  if (rv != CKR_OK) {
    DEBUG((EFI_D_ERROR, "%a.%d Error 0x%X\n", __FUNCTION__, __LINE__, rv));
    return EFI_ABORTED;
  }
  DEBUG((EFI_D_ERROR, "aCertVal.ulValueLen=%d\n", aCertVal.ulValueLen));
  if (aCertVal.ulValueLen == 0) {
    return EFI_INVALID_PARAMETER;
  }
  
  *Cdata = AllocateZeroPool(aCertVal.ulValueLen);
  if (*Cdata == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!!!\n", __FUNCTION__, __LINE__));
    return EFI_OUT_OF_RESOURCES;
  }

  aCertVal.pValue = *Cdata;

  rv = C_GetAttributeValue (hSession, hCert, &aCertVal, 1);
  if (rv != CKR_OK) {
    DEBUG((EFI_D_ERROR, "%a.%d Error 0x%X\n", __FUNCTION__, __LINE__, rv));
    FreePool(*Cdata);
    *Cdata = 0;
    return EFI_ABORTED;
  }
  *CdataLen = aCertVal.ulValueLen;
  //DumpBytes(*Cdata, *CdataLen);
  return EFI_SUCCESS;
}


STATIC
EFI_STATUS
GetCertListFromRuToken(
  OUT CERT_T **certList,
  OUT UINTN   *certCount
  )
{
  CK_SESSION_HANDLE hSession  = CK_INVALID_HANDLE;
  CK_OBJECT_HANDLE hCert = CK_INVALID_HANDLE;  
  CK_ATTRIBUTE aClientCertTokenFindAttrs[] = {
    { CKA_TOKEN,            &bTrue,  sizeof bTrue  },
    { CKA_CLASS,            &cClass, sizeof cClass },
    { CKA_CERTIFICATE_TYPE, &cType,  sizeof cType  }
  };
  CK_BYTE Id[256];
  CK_ATTRIBUTE aCertId = {CKA_ID, NULL_PTR, 0};  
  CK_RV rv;
  CK_ULONG Count;
  CERT_T *beginList = NULL;
  EFI_STATUS Status;
  UINT8 *CertData = NULL;
  UINTN CertDataLen;
  UINT16 CertId;

  rv = C_Initialize(NULL_PTR);
  if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {    
    return EFI_ABORTED;
  }
  
  rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
         NULL_PTR, NULL_PTR, &hSession);
  if (rv != CKR_OK) {
    LOG ((EFI_D_ERROR, "%a.%d Error while open session! {%X}\n", 
      __FUNCTION__, __LINE__, rv));
    if (rv == CKR_SESSION_COUNT) {
      rv = Pkcs11_GetSlotSession (0, &hSession);
      if (rv != CKR_OK) {
        return EFI_ABORTED;
      }
    }    
  }

  rv = C_FindObjectsInit (hSession, aClientCertTokenFindAttrs,
    ARRAY_ITEMS(aClientCertTokenFindAttrs));
  if (rv != CKR_OK) {
    LOG ((EFI_D_ERROR, "%a.%d Error! rv = %d\n", __FUNCTION__, __LINE__, rv));
    return EFI_ABORTED;
  }

  *certCount = 0;

  while (1) {
    Count = 0;
    rv = C_FindObjects (hSession, &hCert, 1, &Count);    
    LOG((EFI_D_ERROR, "%a.%d Count=%d\n", __FUNCTION__, __LINE__, Count));
    if (rv != CKR_OK || Count != 1) {
      LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));      
      break;
    }
    (*certCount)++;
    ZeroMem(Id, sizeof(Id));
    aCertId.pValue = Id;
    aCertId.ulValueLen = sizeof(Id);
    if (C_GetAttributeValue (hSession, hCert, &aCertId, 1) != CKR_OK) {
      LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
      continue;
    }    
  }
  C_FindObjectsFinal(hSession);

  *certList = AllocateZeroPool(*certCount * sizeof(CERT_T));
  if (*certList == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  // Backup a pointer to the start of the list
  beginList = *certList;

  LOG ((EFI_D_ERROR, "%a.%d beginList->certInfo=%p\n", 
    __FUNCTION__, __LINE__, beginList->certInfo));

  rv = C_FindObjectsInit (hSession, aClientCertTokenFindAttrs,
    ARRAY_ITEMS(aClientCertTokenFindAttrs));
  if (rv != CKR_OK) {
    LOG ((EFI_D_ERROR, "%a.%d Error! rv = %d\n", __FUNCTION__, __LINE__, rv));
    return EFI_ABORTED;
  }
  
  while (1) {
    Count = 0;
    rv = C_FindObjects (hSession, &hCert, 1, &Count);    
    LOG((EFI_D_ERROR, "%a.%d Count=%d\n", __FUNCTION__, __LINE__, Count));
    if (rv != CKR_OK || Count != 1) {
      LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));      
      break;
    }
    ZeroMem(Id, sizeof(Id));
    aCertId.pValue = Id;
    aCertId.ulValueLen = sizeof(Id);
    if (C_GetAttributeValue (hSession, hCert, &aCertId, 1) != CKR_OK) {
      LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
      continue;
    }
    Status = GetCertificateData(hSession, hCert, &CertData, &CertDataLen);
    if (EFI_ERROR (Status)) {
      continue;
    }    
    CertId = *(UINT16*)Id;
    LOG((EFI_D_ERROR, "%a.%d CertId=0x%X\n", 
      __FUNCTION__, __LINE__, CertId));
    LOG((EFI_D_ERROR, "%a.%d CertDataLen=%d\n", 
      __FUNCTION__, __LINE__, CertDataLen));
    DumpBytes (CertData, CertDataLen);
    
    Status = ConvertCertStruct(*certList, CertData, CertDataLen, CertId);
    if (CertData != NULL) {
      FreePool(CertData);
      CertData = NULL;
    }
    if (EFI_ERROR (Status)) {
      continue;
    }
    (*certList)++;
  }
  C_FindObjectsFinal(hSession);
  // Restore the start of the list
  *certList = beginList;
  return EFI_SUCCESS;
}


//------------------------------------------------------------------------------
/*! \brief Get a list of certificates from the token */
/*! \param[out] **certList A list of certificates
    \param[out] *certCount A number of certificates in the list */
//------------------------------------------------------------------------------
EFI_STATUS
GetTestCertListFromToken(
  OUT CERT_T **certList,
  OUT UINTN   *certCount
)
{

  return EFI_ABORTED;

}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a list of certificates from the token */
/*! \param[out] **certList A list of certificates
    \param[out] *certCount A number of certificates in the list */
//------------------------------------------------------------------------------
EFI_STATUS
GetCertListFromToken(
  OUT CERT_T **certList,
  OUT UINTN   *certCount
)
{
  EFI_STATUS Status = EFI_ABORTED;

  if (eTokenLikeSmartCard() == TRUE) {
    // Get a list from eToken
    Status = GetCertListFromEToken(certList, certCount);
  } else {
    // Get a list from RuToken
    return GetCertListFromRuToken (certList, certCount);
  }

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Delete a list of certificates */
//------------------------------------------------------------------------------
VOID
FreeCertList(
  CERT_T *certList,
  UINTN   certCount
)
{
  UINTN count = 0;

  if ((certList != NULL) || (certCount == 0))
    return;

  if (pOpenSSLProtocol == NULL)
    gBS->LocateProtocol (&gOpenSSLProtocolGuid,
                         NULL,
                         (VOID **) &pOpenSSLProtocol
                         );

  for(count = 0; count < certCount; count++) {
    if (certList != NULL) {

      if (pOpenSSLProtocol != NULL)
        pOpenSSLProtocol->FreeCertInfo(certList->certInfo);

      if (certList->certId != NULL) {
        FreePool(certList->certId);
        certList->certId = NULL;
      }

      FreePool(certList);
      certList = NULL;
    }

    
    certList++;
  }

  return;
}
//------------------------------------------------------------------------------

