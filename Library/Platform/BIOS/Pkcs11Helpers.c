/** @file
  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php
  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/

#include "Pkcs11Helpers.h"
#include <Library/CDPSupportLib/CDPSupport.h>
#include <Library/Lib/OpensslFunctions.h>
#include <Library/RevokeChkConfigLib/RevokeChkConfig.h>
#include "ProcessingErrors.h"



STATIC CK_SESSION_HANDLE hSession  = CK_INVALID_HANDLE;
STATIC CK_OBJECT_HANDLE hCACertSession = CK_INVALID_HANDLE;
STATIC CK_OBJECT_HANDLE hCAKeySession = CK_INVALID_HANDLE;
STATIC CK_OBJECT_HANDLE hClientCertSession = CK_INVALID_HANDLE;
STATIC CK_BBOOL bFalse = CK_FALSE;
STATIC CK_BBOOL bTrue = CK_TRUE;
STATIC CK_OBJECT_CLASS kClass = CKO_PUBLIC_KEY;
STATIC CK_OBJECT_CLASS kClassPriv = CKO_PRIVATE_KEY;
STATIC CK_OBJECT_CLASS cClass = CKO_CERTIFICATE;
STATIC CK_CERTIFICATE_TYPE cType = CKC_X_509;
STATIC CK_BYTE aSessionCACertId[] = {
  0x55, 0x01
};
STATIC CK_UTF8CHAR aSessionCACertLabel[] = {
  'F', 'X', 'F'
};
STATIC CK_UTF8CHAR aTokenClientCertLabel[] = {
  'C', 'e', 'r', 't', 'i', 'f', 'i', 'c', 'a', 't', 'e'
};
STATIC CK_ATTRIBUTE aCACertCreateAttrs[] = {
  {CKA_TOKEN, &bFalse, sizeof bFalse},
  {CKA_CLASS, &cClass, sizeof cClass},
  {CKA_CERTIFICATE_TYPE, &cType, sizeof cType},
  {CKA_VALUE, NULL, 0},
  {CKA_ID, &aSessionCACertId, sizeof aSessionCACertId},
  {CKA_LABEL, &aSessionCACertLabel, sizeof aSessionCACertLabel}
};

CK_RV 
GetStartEndDate (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN CK_BYTE_PTR       pStartDate,
  IN CK_ULONG_PTR      pulStartDate,
  IN CK_BYTE_PTR       pEndDate,
  IN CK_ULONG_PTR      pulEndDate
  )
{
  CK_ATTRIBUTE aStartDate = { CKA_START_DATE, NULL_PTR, 0 };
  CK_ATTRIBUTE aEndDate = { CKA_END_DATE, NULL_PTR, 0 };
  CK_RV rv;

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  aStartDate.pValue     = pStartDate;
  aStartDate.ulValueLen = *pulStartDate;

  aEndDate.pValue     = pEndDate;
  aEndDate.ulValueLen = *pulEndDate;

  if ((rv = C_GetAttributeValue (hSession, hCert, &aStartDate, 1)) != CKR_OK) {
    return rv;
  }
  *pulStartDate = aStartDate.ulValueLen;
  if ((rv = C_GetAttributeValue (hSession, hCert, &aEndDate, 1)) == CKR_OK) {
    *pulEndDate = aEndDate.ulValueLen;  
  }  
  return rv;
}


EFI_STATUS
CheckForCertExpire (
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hCert
  )
{
  CK_RV rv;
  UINT8 StartDateBuf[8], EndDateBuf[8];
  CK_ULONG EndDateBufLen = sizeof EndDateBuf;
  CK_ULONG StartDateBufLen = sizeof StartDateBuf;
  EFI_TIME EfiTimeStart, EfiTimeEnd, EfiTimeNow;
  UINT32 DaysNow, DaysCmp;

  rv = GetStartEndDate (hSession, hCert, 
        StartDateBuf, &StartDateBufLen, 
        EndDateBuf, &EndDateBufLen);
  if (rv != CKR_OK) {
    DEBUG((EFI_D_ERROR, "%a.%d Error while Validate!\n", 
      __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  
  DEBUG((EFI_D_ERROR, "Obtained Start Date:\n"));
  DumpBytes(StartDateBuf, StartDateBufLen);
  DEBUG((EFI_D_ERROR, "Obtained End Date:\n"));
  DumpBytes(EndDateBuf, EndDateBufLen);
  if (EndDateBufLen != 8) {
    DEBUG((EFI_D_ERROR, "%a.%d Error while Validate!\n", 
      __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  CertTimeBufConvToEfiTime(StartDateBuf, &EfiTimeStart);
  CertTimeBufConvToEfiTime(EndDateBuf, &EfiTimeEnd);

  gRT->GetTime(&EfiTimeNow, NULL);

  DEBUG((EFI_D_ERROR, "EfiTimeStart: Day=%d Month=%d Year=%d\n",
    EfiTimeStart.Day, EfiTimeStart.Month, EfiTimeStart.Year));
  DEBUG((EFI_D_ERROR, "EfiTimeEnd: Day=%d Month=%d Year=%d\n",
    EfiTimeEnd.Day, EfiTimeEnd.Month, EfiTimeEnd.Year));
  DEBUG((EFI_D_ERROR, "EfiTimeNow: Day=%d Month=%d Year=%d\n",
    EfiTimeNow.Day, EfiTimeNow.Month, EfiTimeNow.Year));
  
  DaysNow = EfiTimeNow.Day + EfiTimeNow.Month * 31 +
    (EfiTimeNow.Year - START_YEAR) * 31 * 12;
  
  DaysCmp = EfiTimeStart.Day + EfiTimeStart.Month * 31 +
    (EfiTimeStart.Year - START_YEAR) * 31 * 12;
  
  if (DaysNow < DaysCmp) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", 
      __FUNCTION__, __LINE__));
    DEBUG((EFI_D_ERROR, "DaysNow=%d DaysCmp=%d\n", DaysNow, DaysCmp));
    return EFI_ABORTED;
  }
  DaysCmp = EfiTimeEnd.Day + EfiTimeEnd.Month * 31 +
    (EfiTimeEnd.Year - START_YEAR) * 31 * 12;
  if (DaysNow > DaysCmp) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", 
      __FUNCTION__, __LINE__));
    DEBUG((EFI_D_ERROR, "DaysNow=%d DaysCmp=%d\n", DaysNow, DaysCmp));
    return EFI_TIMEOUT;
  }
  return EFI_SUCCESS;
}


CK_RV 
GetSubjectUid (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR  pUid
  )
{
  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return C_AuxGetSubjectUid (hSession, hCert, pUid);
}


CK_RV 
GetSubjectEmail (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR  pEmail
  )
{
  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return C_AuxGetSubjectEmail (hSession, hCert, pEmail);
}


CK_RV 
GetSubjectTitle (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR pTitle
  )
{
  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return C_AuxGetSubjectTitle (hSession, hCert, pTitle);
}


CK_RV 
GetSubjectCommonName (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR  pCN
  )
{
  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return C_AuxGetSubjectCommonName (hSession, hCert, pCN);
}

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
  DumpBytes(*Cdata, *CdataLen);
  return EFI_SUCCESS;
}


CK_RV 
Verify (
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE  hCert    /* Certificate to verify */
  )
{
  CK_RV rv;
  UINT8 *Data = NULL;
  UINTN DataLen = 0;
  CERTIFICATE_STORAGE *pCA;
  EFI_STATUS Status;

  Status = GetCertificateData(hSession, hCert, &Data, &DataLen);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error while verify signature!\n", 
    __FUNCTION__, __LINE__));
    return CKR_CANCEL;
  }

  if (GetLocalCdpUsageFlag() == USE) {
      CDP_STATUS cdpStatus = RefreshLocalCRL(Data, DataLen);
      if (cdpStatus == CDP_REFRESH_SUCCESSFUL)
        ChainLoad();
  }

  pCA = ChainGetData();
  if (NULL == pCA || pCA->DataLen == 0) {
    return CKR_CANCEL;
  }

  if (VerifyCertificateWithCRLandCA(Data, DataLen, 
        pCA->Data, pCA->DataLen, 
        CRLGetData()->Data, CRLGetData()->DataLen)
        != OSSL_VERIFY_SUCCESS) {
    DEBUG((EFI_D_ERROR, "%a.%d Error while verify signature!\n", 
    __FUNCTION__, __LINE__));
    rv = CKR_CANCEL;
  } else
    rv = CKR_OK;

  if (Data != NULL)
    FreePool(Data);

  return rv;
}



CK_RV 
GetCertificateDigest (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE hCert,
  IN CK_OBJECT_HANDLE hCACert,
  IN OUT CK_BYTE_PTR pDigest,
  IN CK_ULONG_PTR pulDigestLen
  )
{
  CK_RV        rv;
  CK_ATTRIBUTE C = {0,0,0}, C1 = {0,0,0}; /* Certificate Content storage */
  EFI_STATUS Status;
  UINT8 *CertData = NULL;

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));


  /* Extract Certificate Content from the Certificate supplied */
  if ((rv = C_AuxGetCertContent (hSession, hCert, &C1)) == CKR_OK) {
    CK_ATTRIBUTE T[] = { /* Signature Algorithm parameters storage */
      { CKA_TOKEN, &bTrue,   sizeof bTrue },
      { 0,         NULL_PTR, 0            },
      { 0,         NULL_PTR, 0            }
    };

    Status = GetCertificateData(hSession, hCert, &CertData, &C.ulValueLen);
    DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    if (EFI_ERROR(Status)) {
      return CKR_FUNCTION_FAILED;
    }

    C.pValue = (VOID*)CertData;
    C.type = C1.type;
    
    DEBUG((EFI_D_ERROR, "%a.%d Certificate content {%d}:\n", 
      __FUNCTION__, __LINE__, C.ulValueLen));
    DumpBytes(C.pValue, C.ulValueLen);
    
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    /* Extract Signature Algorithm parameters from the CA Certificate */
    if ((rv = C_AuxGetSignatureAlgorithmParamSet (
                hSession,
                hCACert,
                &T[1]
                )) == CKR_OK) {
      CK_ULONG     I;
      //CHECK IT: ?
      CK_MECHANISM M = { CKM_GOSTR3411, NULL_PTR, 0 };      
      //CK_MECHANISM M = { CKM_GOSTR3411_2012, NULL_PTR, 0 };

      DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      
      M.pParameter     = &T[0];
      M.ulParameterLen = 2;

      for (I = 1; I < ARRAY_ITEMS (T); I++) {
        if (T[I].type == CKA_GOSTR3411_PARAMS) {
          T[1].type       = CKA_OBJECT_ID;
          T[1].pValue     = T[I].pValue;
          T[1].ulValueLen = T[I].ulValueLen;
          break;
        }
      }
      DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      
      if (!(I < ARRAY_ITEMS (T))) {
        DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
        DEBUG ((EFI_D_ERROR, "Filed to find digest parameter set\n"));
        FreePool(C1.pValue);
        FreePool(C.pValue);
        return CKR_FUNCTION_FAILED;
      }

      /* Compute the digest */
      if ((rv = C_DigestInit (hSession, &M)) == CKR_OK) {
        DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
        rv = C_Digest (
               hSession,
               C.pValue,     /* Certificate Content */
               C.ulValueLen,
               pDigest,      /* Computed Digest     */
               pulDigestLen
               );
        DEBUG((EFI_D_ERROR, "%a.%d RV=0x%X\n", __FUNCTION__, __LINE__, rv));
      }
    }
  }

  if (CertData != NULL) {
    FreePool(CertData);
  }

  return rv;
}

CK_RV 
GetCertificateDigest2 (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE hCert,
  IN CK_OBJECT_HANDLE hCACert,
  IN OUT CK_BYTE_PTR pDigest,
  IN CK_ULONG_PTR pulDigestLen
  )
{
  CK_RV        rv;
  CK_ATTRIBUTE C = {0,0,0}, C1 = {0,0,0}; /* Certificate Content storage */
  EFI_STATUS Status;
  UINT8 *CertData = NULL;
  CERTIFICATE_STORAGE *pCA;
  UINT8 *SignBuf = NULL;
  UINTN SignLen;
  
  pCA = ChainGetData();
  if (NULL == pCA || pCA->DataLen == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));    
    return EFI_INVALID_PARAMETER;
  }

  DEBUG((EFI_D_ERROR, "%a.%d pCA->DataLen=%d\n", 
    __FUNCTION__, __LINE__, pCA->DataLen));

  DumpBytes(pCA->Data, pCA->DataLen);

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));


  /* Extract Certificate Content from the Certificate supplied */
  if ((rv = C_AuxGetCertContent (hSession, hCert, &C1)) == CKR_OK) {
    
    Status = GetCertificateData(hSession, hCert, &CertData, &C.ulValueLen);
    DEBUG((EFI_D_ERROR, "%a.%d Status=0x%X\n", 
      __FUNCTION__, __LINE__, Status));
    if (EFI_ERROR(Status)) {
      return CKR_FUNCTION_FAILED;
    }

    C.pValue = (VOID*)CertData;
    C.type = C1.type;
    
    DEBUG((EFI_D_ERROR, "%a.%d Certificate content {%d}:\n", 
      __FUNCTION__, __LINE__, C.ulValueLen));
    DumpBytes(C.pValue, C.ulValueLen);
    
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    Status = CalcDataDigest (
              (UINT8*)pCA->Data, 
              (UINTN)pCA->DataLen,
              (UINT8*)C.pValue,
              (UINTN)C.ulValueLen,
              &SignBuf,
              &SignLen);
    if (!EFI_ERROR(Status)) {
      CopyMem(pDigest, SignBuf, SignLen);
      *pulDigestLen = (CK_ULONG)SignLen;
      rv = CKR_OK;
    } else {
      rv = CKR_CANCEL;
    }
      
  }

  if (CertData != NULL) {
    FreePool(CertData);
  }
  if (SignBuf != NULL) {
    FreePool(SignBuf);
  }
  
  return rv;
}



VOID
Pkcs11_DestroySession (
  VOID
  )  
{
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if (hSession != CK_INVALID_HANDLE) {    
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    if (hCACertSession != CK_INVALID_HANDLE) {
      DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      C_DestroyObject(hSession, hCACertSession);
      hCACertSession = CK_INVALID_HANDLE;
    }
    if (hCAKeySession != CK_INVALID_HANDLE) {
      DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      C_DestroyObject(hSession, hCAKeySession);
      hCAKeySession = CK_INVALID_HANDLE;
    }
    if (hClientCertSession != CK_INVALID_HANDLE) {
      DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      C_DestroyObject(hSession, hClientCertSession);
      hClientCertSession = CK_INVALID_HANDLE;
    }
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));    
    C_Finalize(NULL);
    hSession  = CK_INVALID_HANDLE;
  }
}

EFI_STATUS
Pkcs11_CreateSessionAndLogin (
  VOID
  )
{
  EFI_STATUS Status = EFI_ABORTED;
  CK_RV rv;
  CK_SLOT_INFO SlotInfo;
  CK_UTF8CHAR UserPIN[8];
  UINTN UserPIN_Len;
  BOOLEAN bLocalLogin = TRUE;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  UserPIN_Len = sizeof(UserPIN);

  DEBUG((EFI_D_ERROR, "%a.%d Call TokenDestroySession\n", 
    __FUNCTION__, __LINE__));
  Pkcs11_DestroySession();

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  rv = C_Initialize(&bLocalLogin);
  if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
    DEBUG((EFI_D_ERROR, "%a.%d Error rv=%x\n", __FUNCTION__, __LINE__, rv));
    switch (rv) {
    case CKR_GENERAL_ERROR:
      MsgInternalError(INT_ERR_C_INITIALIZE_CKR_GENERAL_ERROR);
      break;
      
    case CKR_FUNCTION_FAILED:
      MsgInternalError(INT_ERR_C_INITIALIZE_CKR_FUNCTION_FAILED);
      break;

    default:
      MsgInternalError(INT_ERR_C_INITIALIZE_OTHER);
      break;
    }
    return EFI_ABORTED;
  }

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  rv = C_GetSlotInfo(0, &SlotInfo);
  if (rv != CKR_OK) {
    DEBUG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    MsgInternalError(INT_ERR_C_GETSLOTINFO);
    return EFI_ABORTED;
  }

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, 
      NULL_PTR, NULL_PTR, &hSession);
  if (rv != CKR_OK) {
    DEBUG((EFI_D_ERROR, "%a.%d Error while open session! {%X}\n", 
      __FUNCTION__, __LINE__, rv));    
    MsgInternalError(INT_ERR_C_OPENSESSION);
    goto _exit;
  }

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  /* Fake login, only for correct pkcs11 further usage */
  C_Login(hSession, CKU_USER, UserPIN, UserPIN_Len);
  
  Status = EFI_SUCCESS;
_exit:
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    Pkcs11_DestroySession();
  }
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return Status;
}

CK_SESSION_HANDLE
Pkcs11_GetCurrentSessionHandler (
  VOID
  )
{
  return hSession;
}

VOID
Pkcs11_FindObjectsFinish (
  IN CK_SESSION_HANDLE    hSession
  )
{
  C_FindObjectsFinal(hSession);
}



EFI_STATUS
Pkcs11_CreateClientCertObjFromData (
  IN UINT8 *CertData,
  IN UINTN CertDataLen,
  IN OUT CK_OBJECT_HANDLE *hCert
  )
{
  EFI_STATUS Status = EFI_SUCCESS;
  UINT8 CertId[2] = {0x30, 0x00};
  STATIC CK_OBJECT_HANDLE hClientCert = CK_INVALID_HANDLE;
  CK_ATTRIBUTE CertCreateAttrs[] = {
    {CKA_TOKEN, &bFalse, sizeof bFalse},
    {CKA_CLASS, &cClass, sizeof cClass},
    {CKA_CERTIFICATE_TYPE, &cType, sizeof cType},
    {CKA_VALUE, NULL, 0},  
    {CKA_ID, NULL, 0},
    {CKA_LABEL, NULL, 0}
  };
  CK_UTF8CHAR aTokenClientCertLabel[] = {
    'C', 'e', 'r', 't', 'i', 'f', 'i', 'c', 'a', 't', 'e'
  };
  
  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (hClientCert != CK_INVALID_HANDLE) {    
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    C_DestroyObject (hSession, hClientCert);
    hClientCert = CK_INVALID_HANDLE;
  }

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  CertCreateAttrs[3].pValue = CertData;
  CertCreateAttrs[3].ulValueLen = CertDataLen;

  CertCreateAttrs[4].pValue = &CertId; //aSessionClientCertId; //
  CertCreateAttrs[4].ulValueLen = (CK_ULONG)sizeof(CertId); //sizeof(aSessionClientCertId); //

  CertCreateAttrs[5].pValue = aTokenClientCertLabel; //aSessionCACertLabel;
  CertCreateAttrs[5].ulValueLen = sizeof(aTokenClientCertLabel); //sizeof(aSessionCACertLabel);

  DEBUG((EFI_D_ERROR, "%a.%d C_CreateObject\n", __FUNCTION__, __LINE__));
  if (CKR_OK != C_CreateObject (hSession, CertCreateAttrs, 
      ARRAY_ITEMS(CertCreateAttrs), hCert)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    Status = EFI_ABORTED;
    goto _exit;
  }

  hClientCert = *hCert;

_exit:  
  return Status;
}


STATIC
EFI_STATUS
Pkcs11_CheckCA (
  VOID
  )
{  
  CERTIFICATE_STORAGE *pCA;
  USER_INFO *pUsrInfo;
  //EFI_STATUS Status;
  
  DEBUG((EFI_D_ERROR, "%a.%d Start\n", __FUNCTION__, __LINE__));
  DEBUG((EFI_D_ERROR, "hCACertSession=0x%X\n", hCACertSession));

  if (hCACertSession != CK_INVALID_HANDLE) {
    DEBUG((EFI_D_ERROR, "%a.%d Allready Processed!!!\n", 
      __FUNCTION__, __LINE__));
    return EFI_SUCCESS;
  }
  
  pUsrInfo = GetCurrentUser();
  if (pUsrInfo && pUsrInfo->AuthType == AUTH_TYPE_TOKEN) {
    DEBUG((EFI_D_ERROR, "%a.%d Token-user allready present!\n",
      __FUNCTION__, __LINE__));
    return EFI_SUCCESS;
  }
  
  pCA = ChainGetData();
  if (NULL == pCA || pCA->DataLen == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));    
    return EFI_INVALID_PARAMETER;
  }

  DEBUG((EFI_D_ERROR, "%a.%d pCA->DataLen=%d\n", 
    __FUNCTION__, __LINE__, pCA->DataLen));

  DumpBytes(pCA->Data, pCA->DataLen);
#if 0
  aCACertCreateAttrs[3].pValue = pCA->Data;
  aCACertCreateAttrs[3].ulValueLen = pCA->DataLen;

  DEBUG((EFI_D_ERROR, "aSessionCACertLabel [0]=0x%02X [1]=0x%02X [2]=0x%02X\n",
    aSessionCACertLabel[0], aSessionCACertLabel[1], aSessionCACertLabel[2]));
  
  if (CKR_OK != C_CreateObject (hSession, aCACertCreateAttrs, 
      ARRAY_ITEMS(aCACertCreateAttrs), &hCACertSession)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    goto _exit;
  }

  DEBUG((EFI_D_ERROR, "%a.%d hCACertSession=0x%X!!!\n", 
    __FUNCTION__, __LINE__, hCACertSession));
#endif
  if (OSSL_SUCCESS_CONVERT_TO_ASN != CheckChainFormat(pCA->Data, pCA->DataLen)) {
    if (OSSL_SUCCESS_CONVERT_TO_ASN != CheckCertificateFormat(pCA->Data, pCA->DataLen)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));    
      goto _exit;
    }
  }
#if 0  
/* Check for CA expired */
  Status = CheckForCertExpire(hSession, hCACertSession);
  if (EFI_SUCCESS != Status) {
    DEBUG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    goto _exit;
  }
#endif
  return EFI_SUCCESS;

_exit:
  DEBUG((EFI_D_ERROR, "%a.%d ===EXIT===\n", __FUNCTION__, __LINE__));
  if (hCACertSession != CK_INVALID_HANDLE) {
    if (CKR_OK != C_DestroyObject (hSession, hCACertSession)) {
      DEBUG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    }
    hCACertSession = CK_INVALID_HANDLE;
  }
  return EFI_ABORTED;
}

STATIC
VOID
ProcessVerifyError(
  IN UINTN verifyStatus
  )
{
  USER_INFO *pUsrInfo;
  UINT8 UsrId;

  pUsrInfo = GetCurrentUser();
  UsrId = USER_UNKNOWN_ID;
  if (pUsrInfo && pUsrInfo->UserId) {
    UsrId = pUsrInfo->UserId;
  }

  ShowVerifyErrorAndSaveHistory(NULL, NULL,
    UsrId, FALSE, verifyStatus);

  return;
}



EFI_STATUS
Pkcs11_ComparisonDataByCertData (
  IN VOID *pCertData,
  IN UINTN CertDataLen,
  IN OUT UINT8 **Data,
  IN OUT UINTN *DataLen
  )
{
  CK_RV rv;
  CK_OBJECT_HANDLE hCert;
  EFI_STATUS Status = EFI_SUCCESS;
  static CK_ATTRIBUTE aCertFindAttrs[] = {
    {CKA_TOKEN, &bTrue, sizeof bTrue},
    {CKA_CLASS, &cClass, sizeof cClass},
    {CKA_CERTIFICATE_TYPE, &cType, sizeof cType}
  };
  STATIC UINT8 DigestBuf[64];
  CK_ULONG DigestLen;
  UINTN i, TotalLen, Offset, TypeNameLen;
  STATIC CK_ATTRIBUTE CompAttributes[MAX_COMPARISON_NUM];
  UINTN GostYear;


  Status = Pkcs11_CreateClientCertObjFromData(
    pCertData, 
    CertDataLen, 
    &hCert);
  if (EFI_ERROR(Status)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", 
      __FUNCTION__, __LINE__));
    return Status;
  }

  rv = Verify (hSession, hCert);
  if (rv != CKR_OK) {
    DEBUG((EFI_D_ERROR, "%a.%d Verify error!\n", 
      __FUNCTION__, __LINE__));
    ProcessVerifyError (GetOsslLastError());
    return EFI_CRC_ERROR;
  } 

  rv = GetSubjectCommonName (hSession, hCert, 
    &CompAttributes[CT_FLAG_CN]);
  if (rv != CKR_OK) {
    DEBUG((EFI_D_ERROR, "%a.%d Error while obtain common name!\n", 
      __FUNCTION__, __LINE__));
  } else {
  }

  rv = GetSubjectTitle(hSession, hCert, 
    &CompAttributes[CT_FLAG_SUBJECT]);
  if (rv != CKR_OK) {
    DEBUG((EFI_D_ERROR, "%a.%d Error while obtain title!\n", 
      __FUNCTION__, __LINE__));
  } else {
  }

  rv = GetSubjectUid(hSession, hCert, 
    &CompAttributes[CT_FLAG_UID]);
  if (rv != CKR_OK) {
    DEBUG((EFI_D_ERROR, "%a.%d Error while obtain uid!\n", 
      __FUNCTION__, __LINE__));
  } else {
  }

  rv = GetSubjectEmail(hSession, hCert, 
    &CompAttributes[CT_FLAG_MAIL]);
  if (rv != CKR_OK) {
    DEBUG((EFI_D_ERROR, "%a.%d Error while obtain Email!\n", 
      __FUNCTION__, __LINE__));
  } else {
  }

  Status = Pkcs11_CheckCA();
  if (EFI_ERROR(Status)) {
    return EFI_ABORTED;  
  }
  
  DigestLen = sizeof(DigestBuf);
  rv = GetCertificateDigest2 (hSession, hCert, hCACertSession,
    (CK_BYTE_PTR)DigestBuf, &DigestLen);
  if (rv != CKR_OK) {
    DEBUG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));     
  } else {
    DEBUG((EFI_D_ERROR, "%a.%d DigestLen=%d\n", 
      __FUNCTION__, __LINE__, DigestLen));
    DumpBytes(DigestBuf, DigestLen);
    CompAttributes[CT_FLAG_DIGEST].pValue = DigestBuf;
    CompAttributes[CT_FLAG_DIGEST].ulValueLen = DigestLen;
  }

  for (i = 0, TotalLen = 0; i < MAX_COMPARISON_NUM; i++) {
    if (CompAttributes[i].pValue == NULL) {
      continue;
    }
    TypeNameLen = StrLen(GetComparisonDataName16((UINT8)(i & 0xFF)));
    if (i == CT_FLAG_DIGEST) {
      TotalLen += (CompAttributes[i].ulValueLen * 2 + TypeNameLen + 3) << 1;
    } else {
      TotalLen += (CompAttributes[i].ulValueLen + TypeNameLen + 3) << 1;
    }
  }
  if (TotalLen == 0) {
    return EFI_INVALID_PARAMETER;
  }
  TotalLen += 2;

  *Data = AllocateZeroPool(TotalLen);
  if (*Data == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  Offset = 0;

  for (i = 0; i <= CT_FLAG_MAIL; i++) {
    if (CompAttributes[i].pValue && 
        CompAttributes[i].ulValueLen) {
      TypeNameLen = StrLen(GetComparisonDataName16((UINT8)(i & 0xFF)));
      *DataLen += (CompAttributes[i].ulValueLen + TypeNameLen + 3) << 1;
      Offset = StrLen((CHAR16*)*Data);
      Offset <<= 1;
      if (CompAttributes[i].type == CKA_BMP_STRING) {
        UINTN j;
        UINT8 Tmp8, *DataPtr;
        CHAR16 *Utf16Str;
        Utf16Str = AllocateZeroPool(CompAttributes[i].ulValueLen + 2);
        if (NULL == Utf16Str) {
          return EFI_OUT_OF_RESOURCES;
        }
        CopyMem(Utf16Str, CompAttributes[i].pValue, 
          CompAttributes[i].ulValueLen);
        Utf16Str[CompAttributes[i].ulValueLen] = L'\0';
        for (j = 0, DataPtr = (UINT8*)Utf16Str; 
             j < CompAttributes[i].ulValueLen; j += 2) {
          Tmp8 = DataPtr[j];
          DataPtr[j] = DataPtr[j + 1];
          DataPtr[j + 1] = Tmp8;
        }
              
        UnicodeSPrint((CHAR16*)(*Data + Offset), *DataLen - Offset, 
          L"%s=%s\n", GetComparisonDataName16((UINT8)(i & 0xFF)), Utf16Str);
        FreePool(Utf16Str);
      } else {
        CHAR8 *AsciiStr;
        AsciiStr = AllocateZeroPool(CompAttributes[i].ulValueLen + 1);
        if (NULL == AsciiStr) {
          return EFI_OUT_OF_RESOURCES;
        }
        CopyMem(AsciiStr, CompAttributes[i].pValue, 
          CompAttributes[i].ulValueLen);
        AsciiStr[CompAttributes[i].ulValueLen] = '\0';      
        UnicodeSPrint((CHAR16*)(*Data + Offset), *DataLen - Offset, 
          L"%s=%a\n", GetComparisonDataName16((UINT8)(i & 0xFF)), AsciiStr);
        FreePool(AsciiStr);
      }
    }
  }

  if (CompAttributes[CT_FLAG_DIGEST].pValue &&
      CompAttributes[CT_FLAG_DIGEST].ulValueLen) {
    CHAR8 TmpStr8[255];
    struct tHashRecord *pTmpRec;
    pTmpRec = AllocateZeroPool(sizeof(struct tHashRecord) - 1 + MAX_HASH_LEN);
    if (NULL == pTmpRec) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_OUT_OF_RESOURCES;
    }
    
    pTmpRec->Size = (UINT16)CompAttributes[CT_FLAG_DIGEST].ulValueLen;
    if (IsGostDigest(GetCalcDataDigest_MdType(), &GostYear) == TRUE) {
      DEBUG((EFI_D_INFO, "%a.%d it's GOST\n",__FUNCTION__, __LINE__));
      if (GostYear == 2012) {
        pTmpRec->HashType = CS_TYPE_GOST_2012;  
      } else {
        pTmpRec->HashType = CS_TYPE_GOST;
      }

    } else {
      DEBUG((EFI_D_INFO, "%a.%d it's not GOST\n",__FUNCTION__, __LINE__));
      pTmpRec->HashType = (UINT8)(-1); // default 
    }
   
    CopyMem(pTmpRec->HashData, CompAttributes[CT_FLAG_DIGEST].pValue, 
      CompAttributes[CT_FLAG_DIGEST].ulValueLen);

    GetDigestStr(TmpStr8, pTmpRec);
    FreePool(pTmpRec);
    
    TypeNameLen = StrLen(GetComparisonDataName16(CT_FLAG_DIGEST));
    *DataLen += (CompAttributes[CT_FLAG_DIGEST].ulValueLen * 2 + 
      TypeNameLen + 3) << 1;
    Offset = StrLen((CHAR16*)*Data);
    Offset <<= 1;
    UnicodeSPrint((CHAR16*)(*Data + Offset), *DataLen - Offset, 
      L"%s=%a\n", GetComparisonDataName16(CT_FLAG_DIGEST), TmpStr8);
  }

  DEBUG((EFI_D_ERROR, "%a.%d TotalLen=%d\n", __FUNCTION__, __LINE__, TotalLen));  
  return Status;
}



