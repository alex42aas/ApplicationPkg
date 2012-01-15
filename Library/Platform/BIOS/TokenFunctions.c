/** @file
  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php
  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/

#include <Library/AuthModeConfig/AuthModeConfig.h>
#include <Library/Lib/TokenFunctions.h>
#include <Library/Lib/OpensslFunctions.h>
#include <Library/Lib/OpensslCnfFv.h>
#include <TlsConfigStruct.h>

#include <Protocol/LdapAuthDxe.h>
#include <Protocol/RawKeyboardInput.h>
#include "Pkcs11Helpers.h"
#include "ProcessingErrors.h"
#include <openssl/engine.h>

#if 1
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

#define JC_HARDWARE_CHECK_ECP 0 //использовать аппаратную проверку подписи для Jacarta

#define NUM_OF_ISSUER_ATTRs  6  //!< A number of attributes in the certificate ISSUER field
#define MAX_TRY_COUNT        2

STATIC CHAR8 *attrTitle[NUM_OF_ISSUER_ATTRs] = {"email=", "CN=", "OU=", "O=", "L=", "ST="};
enum {AttrEmail, AttrCN, AttrOU, AttrO, AttrL, AttrST};

STATIC LDAP_AUTH_PROTOCOL *pLdapAuthProtocol;

STATIC MULTIBOOT_CONFIG *CurrentConfig;


STATIC EFI_EVENT gTokenEvent;
STATIC VOID *gTokenEventReg;
STATIC SMART_CARD_PROTOCOL *gSmartCardProtocol;
extern EFI_GUID gSmartCardProtocolGuid;

STATIC CK_SESSION_HANDLE hSession  = CK_INVALID_HANDLE;
STATIC CK_OBJECT_HANDLE hCACertSession = CK_INVALID_HANDLE;
STATIC CK_OBJECT_HANDLE hCAKeySession = CK_INVALID_HANDLE;
STATIC CK_OBJECT_HANDLE hClientCertSession = CK_INVALID_HANDLE;
STATIC USER_INFO *gCurUserInfo;
STATIC USER_INFO_TOKEN **gpTokenUser;

STATIC EFI_HII_HANDLE CurrentHiiHandle;
STATIC CHAR8 CurrentLanguage[255];
STATIC CK_UTF8CHAR UserPIN[255];
STATIC UINTN UserPIN_Len;
STATIC CK_BBOOL bFalse = CK_FALSE;
STATIC CK_BBOOL bTrue = CK_TRUE;
STATIC CK_OBJECT_CLASS kClass = CKO_PUBLIC_KEY;
STATIC CK_OBJECT_CLASS kClassPriv = CKO_PRIVATE_KEY;
STATIC CK_OBJECT_CLASS cClass = CKO_CERTIFICATE;
STATIC CK_CERTIFICATE_TYPE cType = CKC_X_509;
STATIC OSSL_STATUS VerifyLastStatus = OSSL_VERIFY_SUCCESS; 

STATIC  BOOLEAN bTokenUpdateLogin = FALSE;

STATIC CK_BYTE aSessionCACertId[] = {
  0x55, 0x01
};
STATIC CK_BYTE aSessionClientCertId[] = {
  0x55, 0x01
};

STATIC CK_UTF8CHAR aSessionCACertLabel[] = {
  'F', 'X', 'F'
};
STATIC CK_BYTE aTokenClientCertId[] = {
  0x03
};
STATIC CK_UTF8CHAR aTokenClientCertLabel[] = {
  //'C', 'l', 'i', 'e', 'n', 't', ' ', 'G', 'O', 'S', 'T', ' ',
  'C', 'e', 'r', 't', 'i', 'f', 'i', 'c', 'a', 't', 'e'
};


VOID
DumpBytes_(
  IN UINT8 *Bytes,
  IN UINTN Len
  )
{
  UINTN i;

  for (i = 0; i < Len; i++) {
    if (i && !(i & 0xF)) {
      LOG(( EFI_D_ERROR, "\n"));
    }
    LOG(( EFI_D_ERROR, "%02x ", Bytes[i]));
  }
  LOG(( EFI_D_ERROR, "\n"));
}



STATIC CK_ATTRIBUTE aCACertCreateAttrs[] = {
  {CKA_TOKEN, &bFalse, sizeof bFalse},
  {CKA_CLASS, &cClass, sizeof cClass},
  {CKA_CERTIFICATE_TYPE, &cType, sizeof cType},
  {CKA_VALUE, NULL, 0},
  {CKA_ID, &aSessionCACertId, sizeof aSessionCACertId},
  {CKA_LABEL, &aSessionCACertLabel, sizeof aSessionCACertLabel}
};

STATIC CK_ATTRIBUTE aClientCertCreateAttrs[] = {
  {CKA_TOKEN, &bFalse, sizeof bFalse},
  {CKA_CLASS, &cClass, sizeof cClass},
  {CKA_CERTIFICATE_TYPE, &cType, sizeof cType},
  {CKA_VALUE, NULL, 0},  
  {CKA_ID, &aSessionClientCertId, sizeof aSessionClientCertId},
  //{CKA_LABEL, &aTokenClientCertLabel, sizeof aTokenClientCertLabel}
  {CKA_LABEL, &aSessionCACertLabel, sizeof aSessionCACertLabel}
};


STATIC CK_ATTRIBUTE aCAKeySessionFindAttrs[] = {
  { CKA_TOKEN,            &bFalse,              sizeof bFalse              },
  { CKA_CLASS,            &kClass,              sizeof kClass              },
  { CKA_ID,               &aSessionCACertId,    sizeof aSessionCACertId    },
  { CKA_LABEL,            &aSessionCACertLabel, sizeof aSessionCACertLabel }
};

STATIC CK_ATTRIBUTE aClientCertTokenFindAttrs[] = {
  { CKA_TOKEN,            &bTrue,                 sizeof bTrue                 },
  { CKA_CLASS,            &cClass,                sizeof cClass                },
  { CKA_CERTIFICATE_TYPE, &cType,                 sizeof cType                 }//,
  //{ CKA_ID,               &aTokenClientCertId,    sizeof aTokenClientCertId    }//,
  //{ CKA_LABEL,            &aTokenClientCertLabel, sizeof aTokenClientCertLabel }
};

STATIC CK_ATTRIBUTE CompAttributes[MAX_COMPARISON_NUM];
STATIC UINT8 gMatchedFlags;
STATIC BOOLEAN bResetAfterLogOff = TRUE;
STATIC BOOLEAN eTokenRstSearch = FALSE;

EFI_STATUS
TokenEjectCallback(
  IN SMART_CARD_PROTOCOL *This
  );

VOID
eTokenLikeSmartCardResetSearch (
  VOID
  )
{
  eTokenRstSearch = TRUE;
}


VOID
SetResetAfterLogOff (
  IN BOOLEAN bFlag
  )
{
  bResetAfterLogOff = bFlag;
}
 
STATIC
VOID
TokenDestroySession (
  VOID
  );
  
STATIC
EFI_STATUS
TokenCreateSession (
  CK_UTF8CHAR *pinCode
  );
  
STATIC
EFI_STATUS
CreateRuTokenSession(
  CK_UTF8CHAR *pinCode
  );
  
STATIC
EFI_STATUS
CreateSimpleTokenSession(
  CK_UTF8CHAR *pinCode
  );
  
STATIC
EFI_STATUS
CreateSimpleTokenGuestSession(
  VOID
  );
  
STATIC
EFI_STATUS
CreateRuTokenGuestSession(
  VOID
  );

STATIC
CHAR8*
MakeUserCertificateMatchingValue (
  UINTN  certSerialNum,
  CHAR8  **issuerAttributeList
  );
  
STATIC 
CHAR8*
MakeUserCertificateMatchingValueByIssuerField (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert
  );

STATIC 
CHAR8*
MakeUserCertificateMatchingValueByIssuerFieldOssl (
  IN CK_SESSION_HANDLE hTokenSession,
  IN CK_OBJECT_HANDLE  hClientCertObjectHandle
  );
  
STATIC
CHAR8*
MakeUserCertificateMatchingValueByBinary (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert
  );

STATIC
USER_AUTH_PERMISSION
CheckLoginPermissionWithUserDN (
  IN CHAR8 *userDN,
  OUT UINTN *retval
  );

 STATIC CK_RV GetIssuerEmail (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR  pEmail
  );

STATIC CK_RV GetIssuerCommonName (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR  pCN
  );
  
STATIC CK_RV GetSubjectOrganizationUnitName (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR  pOrganizationUnitName
  );
  
STATIC CK_RV GetIssuerOrganizationUnitName (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR  pOrganizationUnitName
  );
  
STATIC CK_RV GetSubjectOrganizationName (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR  pOrganizationName
  );
  
STATIC CK_RV GetIssuerOrganizationName (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR  pOrganizationName
  );
  
STATIC CK_RV GetSubjectLocalityName (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR  pLocalityName
  );
  
STATIC CK_RV GetIssuerLocalityName (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR  pLocalityName
  );
  
STATIC CK_RV GetSubjectStateOrProvinceName (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR  pStateOrProvinceName
  );
  
STATIC CK_RV GetIssuerStateOrProvinceName (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR  pStateOrProvinceName
  );
  
EFI_STATUS
eTokenGetNextObject(
  IN BOOLEAN bRestart,
  IN OUT UINT16 *Id,
  IN OUT UINT16 *Type
  );
  
EFI_STATUS
eTokenGetClientCertById(
  IN VOID *pInId,
  IN UINTN InIdLen,
  IN OUT CK_OBJECT_HANDLE *hCert,
  IN BOOLEAN bNoDestroy,
  IN BOOLEAN bCheckExist
  );
  
EFI_STATUS
ProcessingCA(
  VOID
  );

STATIC
VOID
ProcessingOsslCertErrors (
  OSSL_STATUS Status
  )
{
  LOG((EFI_D_ERROR, "%a.%d Error: %d\n", __FUNCTION__, __LINE__, Status));
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
    case OSSL_CRL_HAS_EXPIRED:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_CRL_HAS_EXPIRED),NULL));
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
    case OSSL_ERR_UNABLE_TO_GET_CRL:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(STR_UNABLE_TO_GET_CRL_ERROR),NULL));
      break;
    case OSSL_ERR_VERIFY_WITH_USER_PKEY:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_CANT_VERIFY_USER_WITH_PKEY),NULL));
      break;
	  case OSSL_ERR_RUTOKEN_SUPPORT_ERR:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(MSG_RUTOKEN_SUPPORT_ERR),NULL));
      break;
    default:
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle,
          STRING_TOKEN(STR_ERR_INTERNAL),NULL));
      break;
  }
  return;
}

//------------------------------------------------------------------------------
/*! \brief Compare certificate with token certificate */
/*! Compare an user certificate with certificate retreived from the token */
/*! \param[in] hSession 
    \param[in] hCert
    \param[om] caData User certificate to compare */
//------------------------------------------------------------------------------
STATIC
BOOLEAN
CompareWithTokenCert(
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  const UserCertificateData_t *caData
  )
{
  BOOLEAN      matchedCertificate = FALSE;
  EFI_STATUS   Status    = EFI_SUCCESS;
  UINTN        caBodyLen = 0;
  CHAR8       *caBody    = NULL;
  
  LOG((EFI_D_ERROR, "ldap caData: \n"));
  DumpBytes_(caData->data, caData->dataLen);
  LOG((EFI_D_ERROR, "\n"));
  
  Status = GetCertificateData (hSession, hCert,
                               &caBody, &caBodyLen);
                     
  if (EFI_SUCCESS == Status) {
    LOG((EFI_D_ERROR, "token caBody: \n"));
    DumpBytes_(caBody, caBodyLen);
    LOG((EFI_D_ERROR, "\n"));
              
    // Compare objects
    if (caData->dataLen != caBodyLen) {
      LOG((EFI_D_ERROR, "Lengths are different! \n"));
    } else if (CompareMem(caData->data, caBody, caBodyLen) == 0) {
      LOG((EFI_D_ERROR, "Equal certificates!: \n"));
      matchedCertificate = TRUE;
    } else
      LOG((EFI_D_ERROR, "Not equal certificates!\n"));
  } else
    LOG((EFI_D_ERROR, "Error! \n"));
               
  if (caBody != NULL) {
    FreePool(caBody);
    caBody = NULL;
  }
  
  LOG((EFI_D_ERROR, "%a.%d:\n", __FUNCTION__, __LINE__));
  
  return matchedCertificate;
}
//------------------------------------------------------------------------------
  
BOOLEAN
eTokenLikeSmartCard(
  VOID
  )
{
  if (gSmartCardProtocol == NULL) {
    return FALSE;
  }
  if (gSmartCardProtocol->VendorId == ETOKEN_VENDOR_ID &&
      gSmartCardProtocol->ProdId == ETOKEN_PROD_ID) {
    return TRUE;
  }
  if (gSmartCardProtocol->VendorId == ATHENA_VENDOR_ID &&
      gSmartCardProtocol->ProdId == ATHENA_PROD_ID) {
    return TRUE;
  }
  return FALSE;
}

STATIC EFI_STATUS
TokenEnterPIN(
  IN OUT CK_UTF8CHAR *UserPIN,
  IN OUT UINTN *UserPIN_Len
  )
{
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut;
  UINTN PassLen;
  CHAR8 PassBuf[MAX_PIN_CODE_LEN + 1];
  CHAR16 *HiiString;

  *UserPIN_Len = 0;
  
  ConOut = gST->ConOut;
  HiiString = HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_ENTER_PIN_PROMPT),
          NULL);
  
  while (1) {
	  ShowPassWindow(HiiGetString(CurrentHiiHandle, 
	    STRING_TOKEN(STR_CHECKING_FOR_PIN), NULL), HiiString);
	  
	  PassLen = ReadLineAndHideWithCheck(PassBuf, MAX_PIN_CODE_LEN, TRUE, 
	    GetTokenInserted, FALSE);

    if (!GetTokenInserted()) {
      return EFI_ABORTED;
    }

    if (PassLen == 0) {
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(STR_PINSIZE_NULL), NULL));
      ConOut->ClearScreen(ConOut);
      continue;
    }
    break;
  }

  LOG((EFI_D_ERROR, "%a.%d: PassLen=%d\n", __FUNCTION__, __LINE__, PassLen));
  CopyMem(UserPIN, PassBuf, PassLen);
  *UserPIN_Len = PassLen;
  
  LOG((EFI_D_ERROR, "%a.%d: UserPIN", __FUNCTION__, __LINE__));
  DumpBytes_((UINT8 *)UserPIN, *UserPIN_Len);

  ConOut->ClearScreen(ConOut);

  return EFI_SUCCESS;
}

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
TokenCreateGuestSession(
  VOID
  )
{
  EFI_STATUS Status;
  if (eTokenLikeSmartCard() == TRUE) {
    Status = CreateSimpleTokenGuestSession();
  } else {
    Status = CreateRuTokenGuestSession();
  }
  
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Create a session to exchange with RuToken in guest mode */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
CreateRuTokenGuestSession(
  VOID
  )
{
  CK_RV      rv;
  EFI_STATUS Status; 
  
  Status = CreateSimpleTokenGuestSession();
  if (EFI_SUCCESS == Status) {
    rv = C_FindObjectsInit (hSession, aClientCertTokenFindAttrs,
    ARRAY_ITEMS(aClientCertTokenFindAttrs));
  
    if (rv != CKR_OK) {
      LOG((EFI_D_ERROR, "%a.%d Error! rv = %d\n", __FUNCTION__, __LINE__, rv));
      TokenDestroySession();
      MsgInternalError(INT_ERR_C_INITIALIZE_OTHER);
      return EFI_ABORTED;
    }
  }
  
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  return Status;
}

//------------------------------------------------------------------------------
/*! \brief Create a session to exchange with token in guest mode */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
CreateSimpleTokenGuestSession(
  VOID
  )
{
  EFI_STATUS Status = EFI_ABORTED;
  CK_RV      rv;
  
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  // Have to destroy old session
  TokenDestroySession();

  LOG((DEBUG_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  rv = C_Initialize(NULL_PTR);
  if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
    LOG((EFI_D_ERROR, "%a.%d Error rv=%x\n", __FUNCTION__, __LINE__, rv));
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

  LOG((DEBUG_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
         NULL_PTR, NULL_PTR, &hSession);
  if (rv != CKR_OK) {
    LOG((EFI_D_ERROR, "%a.%d Error while open session! {%X}\n", 
      __FUNCTION__, __LINE__, rv));    
    MsgInternalError(INT_ERR_C_OPENSESSION);
    goto _exit;
  }

  LOG((DEBUG_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  Status = ProcessingCA();
  if (EFI_ERROR(Status)) {
    goto _exit;
  }
  
  Status =  EFI_SUCCESS;
  
_exit:
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    TokenDestroySession();
  }
  
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  return Status;
}

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
TokenCreateSession(
  CK_UTF8CHAR *pinCode
  )
{
  EFI_STATUS Status;
  
  if (eTokenLikeSmartCard() == TRUE) {
    Status = CreateSimpleTokenSession(pinCode);
  } else {
    Status = CreateRuTokenSession(pinCode);
  }
  
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Create a session to exchange with eToken */
/*! \param[in] *pinCode A pin code has been entered by the user */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
CreateSimpleTokenSession(
  CK_UTF8CHAR *pinCode
  )
{
  EFI_STATUS Status = EFI_ABORTED;
  CK_RV      rv;
  
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  // Have to destroy old session
  TokenDestroySession();
  
  rv = C_Initialize(NULL_PTR);
  if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
    LOG((EFI_D_ERROR, "%a.%d Error rv=%x\n", __FUNCTION__, __LINE__, rv));
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
  
  rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION,
         NULL_PTR, NULL_PTR, &hSession);
  if (rv != CKR_OK) {
    LOG((EFI_D_ERROR, "%a.%d Error while open session! {%X}\n", 
      __FUNCTION__, __LINE__, rv));    
    MsgInternalError(INT_ERR_C_OPENSESSION);
    goto _exit;
  }
  
  // UserPIN has been specified previously
  rv = C_Login(hSession, CKU_USER, pinCode, AsciiStrLen(pinCode));
  if (rv != CKR_OK) {
    USER_INFO *pUsrInfo;
    UINT8 UsrId;
    
    pUsrInfo = GetCurrentUser();
    UsrId = USER_UNKNOWN_ID;
    if (pUsrInfo && pUsrInfo->UserId) {
      UsrId = pUsrInfo->UserId;
    }    
    LOG((EFI_D_ERROR, "%a.%d UserLogin Error! {%X} {%p} {%X}\n", 
      __FUNCTION__, __LINE__, rv, pUsrInfo, UsrId));
    HistoryAddRecord(HEVENT_WRONG_PIN, UsrId, SEVERITY_LVL_ERROR, 0);
    if (UsrId == USER_UNKNOWN_ID) {
      LocksUpdateWrongPinCnt ();
    }
    ShowErrorPopup(CurrentHiiHandle,
      HiiGetString(CurrentHiiHandle, 
        STRING_TOKEN(STR_WRONG_PIN), NULL));

    goto _exit;
  }
  
  Status = ProcessingCA();
  if (EFI_ERROR(Status)) {
    goto _exit;
  }
  
  Status =  EFI_SUCCESS;
  
_exit:
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    TokenDestroySession();
  }
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Create a session to exchange with RuToken */
/*! \param[in] *pinCode A pin code has been entered by the user */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
CreateRuTokenSession(
  CK_UTF8CHAR *pinCode
  )
{
  CK_RV      rv;
  EFI_STATUS Status;
  
  Status = CreateSimpleTokenSession(pinCode);
  if (EFI_SUCCESS == Status) {
    rv = C_FindObjectsInit (hSession, aClientCertTokenFindAttrs,
    ARRAY_ITEMS(aClientCertTokenFindAttrs));
  
    if (rv != CKR_OK) {
      LOG((EFI_D_ERROR, "%a.%d Error! rv = %d\n", __FUNCTION__, __LINE__, rv));
      TokenDestroySession();
      MsgInternalError(INT_ERR_C_INITIALIZE_OTHER);
      return EFI_ABORTED;
    }
  }

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
STATIC
VOID
TokenDestroySession(
  VOID
  )  
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if (hSession != CK_INVALID_HANDLE) {    
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    if (hCACertSession != CK_INVALID_HANDLE) {
      LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      C_DestroyObject(hSession, hCACertSession);
      hCACertSession = CK_INVALID_HANDLE;
    }
    if (hCAKeySession != CK_INVALID_HANDLE) {
      LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      C_DestroyObject(hSession, hCAKeySession);
      hCAKeySession = CK_INVALID_HANDLE;
    }
    if (hClientCertSession != CK_INVALID_HANDLE) {
      LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      C_DestroyObject(hSession, hClientCertSession);
      hClientCertSession = CK_INVALID_HANDLE;
    }
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));    
    C_Finalize(NULL);
    hSession  = CK_INVALID_HANDLE;
  }
  eTokenLikeSmartCardResetSearch ();
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
STATIC
CK_RV
FindNextETokenSertificate (
  OUT CK_OBJECT_HANDLE_PTR phObject
  )
{
  UINT16 Id;
  UINT16 Type;
  EFI_STATUS Status;
  STATIC BOOLEAN bRestart = TRUE;

  if (eTokenRstSearch) {
    bRestart = TRUE;
    eTokenRstSearch = FALSE;
  }
  
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  while(1) {  
    Status = eTokenGetNextObject(bRestart, &Id, &Type);
    bRestart = FALSE;
    if (EFI_ERROR(Status)) {
      bRestart = TRUE;
      LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return CKR_CANCEL;
    }
    if (Type != CERT_ID_TYPE) { // it is not certificate
      LOG((EFI_D_ERROR, "%a.%d it is not certificate\n", __FUNCTION__, __LINE__));
      continue;
    }
    LOG((EFI_D_ERROR, "%a.%d Id=%X\n", __FUNCTION__, __LINE__, Id));
    Status = eTokenGetClientCertById(&Id, sizeof(UINT16), phObject,
               phObject == CK_INVALID_HANDLE ? TRUE : FALSE, FALSE);
    if (EFI_ERROR(Status)) {
      LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      bRestart = TRUE;
      return CKR_CANCEL;
    }
    break;
  }
  
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return CKR_OK;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
STATIC
CK_RV
SearchTokenObjects (
  CK_SESSION_HANDLE    hSession,
  CK_OBJECT_HANDLE_PTR phObject,
  CK_ULONG             ulMaxObjectCount,
  CK_ULONG_PTR         pulObjectCount
  )
{
  CK_RV rv = CKR_OK;
  
  if (eTokenLikeSmartCard() == TRUE) {
    rv = FindNextETokenSertificate(phObject);
    *pulObjectCount = 1;
  } else {
    rv = C_FindObjects (hSession, phObject, ulMaxObjectCount, pulObjectCount); 
  }
  
  return rv;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Search token object - certificate */
//------------------------------------------------------------------------------
STATIC
CK_RV
SearchTokenObject (
  CK_SESSION_HANDLE    hSession,
  CK_OBJECT_HANDLE_PTR phObject,
  CK_ULONG             ulMaxObjectCount,
  CK_ULONG_PTR         pulObjectCount
)
{
  CK_RV     rv;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  rv = SearchTokenObjects(hSession, phObject, 1, pulObjectCount);
  if (*pulObjectCount != 1) {
    LOG((EFI_D_ERROR, "%a.%d pulObjectCount: %d\n", __FUNCTION__, __LINE__, *pulObjectCount));
    return CKR_GENERAL_ERROR;
  }

  LOG((EFI_D_ERROR, "%a.%d rv: 0x%X\n", __FUNCTION__, __LINE__, rv));

  return rv;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Verify token object - certificate */
//------------------------------------------------------------------------------
STATIC
CK_RV
VerifyTokenObject (
  CK_SESSION_HANDLE    hSession,
  CK_OBJECT_HANDLE phObject
)
{
  CK_RV rv;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  rv = Verify(hSession, phObject);
  if (rv != CKR_OK) {
    LOG((EFI_D_ERROR, "%a.%d Verify OSSL Error! : %d\n",
      __FUNCTION__, __LINE__, GetOsslLastError()));
    return rv;
  }
  if (CheckForCertExpire(hSession, phObject) != EFI_SUCCESS) {
    LOG((EFI_D_ERROR, "%a.%d CheckForCertExpire Fail!\n", 
      __FUNCTION__, __LINE__));
    SetOsslLastError(OSSL_CERT_HAS_EXPIRED);
    return CKR_GENERAL_ERROR;
  }

  return rv;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
STATIC
CK_RV
SearchTokenVerifyObject (
  CK_SESSION_HANDLE    hSession,
  CK_OBJECT_HANDLE_PTR phObject,
  CK_ULONG             ulMaxObjectCount,
  CK_ULONG_PTR         pulObjectCount
  )
{
  CK_RV     rv;
  
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  while(1) {
    rv = SearchTokenObjects(hSession, phObject, 1, pulObjectCount);
    if (rv != CKR_OK || *pulObjectCount != 1) {
      break;
    }
    
    rv = Verify(hSession, *phObject);
    if (rv != CKR_OK) {
      LOG((EFI_D_ERROR, "%a.%d Verify OSSL Error! : %d\n",
        __FUNCTION__, __LINE__, GetOsslLastError()));
      continue;
    }
    if (CheckForCertExpire(hSession, *phObject) != EFI_SUCCESS) {
      LOG((EFI_D_ERROR, "%a.%d CheckForCertExpire Fail!\n", 
        __FUNCTION__, __LINE__));
      continue;
    }
    break;
  }
  
  LOG((EFI_D_ERROR, "%a.%d rv: 0x%X\n", __FUNCTION__, __LINE__, rv, *pulObjectCount));
  return rv;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
STATIC
VOID
SearchTokenObjectsFinish (
  CK_SESSION_HANDLE    hSession
  )
{
  if (eTokenLikeSmartCard() == TRUE) {
    eTokenLikeSmartCardResetSearch ();
  } else {
    C_FindObjectsFinal(hSession);
  }
  
  return;
}
//------------------------------------------------------------------------------

EFI_STATUS
eTokenGetNextObject(
  IN BOOLEAN bRestart,
  IN OUT UINT16 *Id,
  IN OUT UINT16 *Type
  )
{
  EFI_STATUS Status;
  STATIC ET_OBJ_DESC *Objects = NULL;
  STATIC UINTN ObjCnt, Idx;
  UINTN DataLen;

  LOG((EFI_D_ERROR, "%a.%d bRestart=%a\n", __FUNCTION__, __LINE__,
    bRestart ? "TRUE" : "FALSE"));

  if (bRestart) {
    if (Objects) {
      FreePool(Objects);
      Objects = NULL;
    }
    Idx = 0;
    Status = gSmartCardProtocol->GetObjectsList(
                                  gSmartCardProtocol,
                                  (UINT8**)&Objects,
                                  &DataLen
                                  );
    if (EFI_ERROR(Status)) {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_NOT_FOUND;
    }
    ObjCnt = DataLen / sizeof(struct _ET_OBJ_DESC);
    LOG((EFI_D_ERROR, "%a.%d ObjCnt=%d\n", __FUNCTION__, __LINE__, ObjCnt));
  }
  if (ObjCnt == 0 || Objects == NULL) {
    return EFI_NOT_FOUND;
  }
  if (Idx >= ObjCnt) {
    FreePool(Objects);
    Objects = NULL;
    return EFI_NOT_FOUND;
  }

  *Id = Objects[Idx].Id;
  *Type = Objects[Idx].Type;

  LOG((EFI_D_ERROR, "%a.%d ObjCnt=%d Idx=%d {id=%X type=%X}\n", 
    __FUNCTION__, __LINE__, ObjCnt, Idx, *Id, *Type));
  LOG((EFI_D_ERROR, "%a.%d Objects=%p\n", 
    __FUNCTION__, __LINE__, Objects));  

  Idx++;
  return EFI_SUCCESS;
}


EFI_STATUS
eTokenCheckCertIdExist(
  IN VOID *pInId,
  IN UINTN InIdLen
  )
{
  EFI_STATUS Status;
  BOOLEAN bRestart;
  UINT16 SearchId;
  ET_OBJ_DESC Obj;
  
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (pInId == NULL || pInId == 0) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  SearchId = ((UINT8*)pInId)[0] | ((UINT8*)pInId)[1] << 8;
  bRestart = TRUE;
  while (1) {
    Status = eTokenGetNextObject(bRestart, &Obj.Id, &Obj.Type);        
    if (EFI_ERROR(Status)) {
      break;
    }
    bRestart = FALSE;
    if (Obj.Type != CERT_ID_TYPE) {
      continue;
    }
    if (Obj.Id == SearchId) {
      break;
    }    
  }
  return Status;
}


EFI_STATUS
GetCertificateDataFromEtoken(
  IN VOID *pInId,
  IN UINTN InIdLen,
  IN OUT UINT8 **Cdata,
  IN OUT UINTN *CdataLen,
  IN BOOLEAN bCheckExist
  )
{
  EFI_STATUS Status;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if (bCheckExist) {
    Status = eTokenCheckCertIdExist(pInId, InIdLen);
    if (EFI_ERROR(Status)) {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return Status;
    }
  }
  
  Status = gSmartCardProtocol->GetObjectValById(
                          gSmartCardProtocol,
                          pInId,
                          InIdLen,
                          Cdata,
                          CdataLen);
  return Status;
}

EFI_STATUS
eTokenGetClientCertById(
  IN VOID *pInId,
  IN UINTN InIdLen,
  IN OUT CK_OBJECT_HANDLE *hCert,
  IN BOOLEAN bNoDestroy,
  IN BOOLEAN bCheckExist
  )
{
  EFI_STATUS Status;
  STATIC UINT8 *CertData = NULL;
  STATIC UINTN CertDataLen;
  STATIC CK_OBJECT_HANDLE hClientCert = CK_INVALID_HANDLE;
  CK_ATTRIBUTE CertCreateAttrs[] = {
    {CKA_TOKEN, &bFalse, sizeof bFalse},
    {CKA_CLASS, &cClass, sizeof cClass},
    {CKA_CERTIFICATE_TYPE, &cType, sizeof cType},
    {CKA_VALUE, NULL, 0},  
    {CKA_ID, NULL, 0},
    {CKA_LABEL, NULL, 0}
  };
  
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (pInId == NULL || InIdLen == 0 || InIdLen > 2) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
#if 0  
  if (bCheckExist) {
    Status = eTokenCheckCertIdExist(pInId, InIdLen);
    if (EFI_ERROR(Status)) {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return Status;
    }
  }
#endif
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if (hClientCert != CK_INVALID_HANDLE) {    
    LOG((EFI_D_ERROR, "%a.%d C_DestroyObject { %X %X }\n", 
      __FUNCTION__, __LINE__, hClientCert, hClientCertSession));
    if (!bNoDestroy) {
      LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      C_DestroyObject (hSession, hClientCert);
    }
    hClientCert = CK_INVALID_HANDLE;
  }

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
/*  if (CertData) {
    FreePool(CertData);
    CertData = NULL;
  }*/
  
  Status = GetCertificateDataFromEtoken(pInId, InIdLen, &CertData, 
    &CertDataLen, bCheckExist);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return Status;
  }

#if 0
  LOG((EFI_D_ERROR, "%a.%d Certificate:\n", __FUNCTION__, __LINE__));
  DumpBytes_(CertData, CertDataLen);
#endif

#if 1
  CertCreateAttrs[3].pValue = CertData;
  CertCreateAttrs[3].ulValueLen = CertDataLen;

  CertCreateAttrs[4].pValue = pInId; //aSessionClientCertId; //
  CertCreateAttrs[4].ulValueLen = (CK_ULONG)InIdLen; //sizeof(aSessionClientCertId); //

  CertCreateAttrs[5].pValue = aTokenClientCertLabel; //aSessionCACertLabel;
  CertCreateAttrs[5].ulValueLen = sizeof(aTokenClientCertLabel); //sizeof(aSessionCACertLabel);
#else
{
  CERTIFICATE_STORAGE *pCA;
  pCA = ChainGetData();
  DumpBytes_(pCA->Data, pCA->DataLen);

  aCACertCreateAttrs[3].pValue = pCA->Data;
  aCACertCreateAttrs[3].ulValueLen = pCA->DataLen;
}
#endif
  LOG((EFI_D_ERROR, "%a.%d C_CreateObject\n", __FUNCTION__, __LINE__));
  if (CKR_OK != C_CreateObject (hSession, CertCreateAttrs, 
      ARRAY_ITEMS(CertCreateAttrs), hCert)) {
    LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    Status = EFI_ABORTED;
    goto _exit;
  }

  hClientCert = *hCert;

_exit:  
  return Status;
}

VOID
GetCertificateIssuerAtrributeList(
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE hCert,
  IN OUT CHAR8** issuerAttributeList
  )
{
  CK_ATTRIBUTE email, CN, OU, O, L, ST;
  CK_RV        rv;
  CHAR8        *printableStr;
  UINTN        offset;
  
  rv = GetIssuerEmail(hSession, hCert, &email);
  if (CKR_OK == rv) {
    offset = AsciiStrLen(attrTitle[AttrEmail]);
    printableStr = AllocateZeroPool(email.ulValueLen + offset);
    AsciiStrCpy(&printableStr[0], attrTitle[AttrEmail]);
    CopyMem(&printableStr[offset], email.pValue, email.ulValueLen);
    printableStr[offset + email.ulValueLen] = '\0';
    LOG((EFI_D_ERROR, "%a.%d printableStr: %a\n", __FUNCTION__, __LINE__, printableStr));
    issuerAttributeList[AttrEmail] = &printableStr[0];
  } else
    LOG((EFI_D_ERROR, "%a.%d rv=%d\n", __FUNCTION__, __LINE__, rv));
     
  rv = GetIssuerCommonName(hSession, hCert, &CN);
  if (CKR_OK == rv) {
    offset = AsciiStrLen(attrTitle[AttrCN]);
    printableStr = AllocateZeroPool(CN.ulValueLen + offset);
    AsciiStrCpy(&printableStr[0], attrTitle[AttrCN]);
    CopyMem(&printableStr[offset], CN.pValue, CN.ulValueLen);
    printableStr[offset + CN.ulValueLen] = '\0';
    LOG((EFI_D_ERROR, "%a.%d printableStr: %a\n", __FUNCTION__, __LINE__, printableStr));
    issuerAttributeList[AttrCN] = &printableStr[0];
  } else
    LOG((EFI_D_ERROR, "%a.%d rv=%d\n", __FUNCTION__, __LINE__, rv));
    
  rv = GetIssuerOrganizationUnitName(hSession, hCert, &OU);
  if (CKR_OK == rv) {
    offset = AsciiStrLen(attrTitle[AttrOU]);
    printableStr = AllocateZeroPool(OU.ulValueLen + offset);
    AsciiStrCpy(&printableStr[0], attrTitle[AttrOU]);
    CopyMem(&printableStr[offset], OU.pValue, OU.ulValueLen);
    printableStr[offset + OU.ulValueLen] = '\0';
    LOG((EFI_D_ERROR, "%a.%d printableStr: %a\n", __FUNCTION__, __LINE__, printableStr));
    issuerAttributeList[AttrOU] = &printableStr[0];
  } else
    LOG((EFI_D_ERROR, "%a.%d rv=%d\n", __FUNCTION__, __LINE__, rv));
    
  rv = GetIssuerOrganizationName(hSession, hCert, &O);
  if (CKR_OK == rv) {
    offset = AsciiStrLen(attrTitle[AttrO]);
    printableStr = AllocateZeroPool(O.ulValueLen + offset);
    AsciiStrCpy(&printableStr[0], attrTitle[AttrO]);
    CopyMem(&printableStr[offset], O.pValue, O.ulValueLen);
    printableStr[offset + O.ulValueLen] = '\0';
    LOG((EFI_D_ERROR, "%a.%d printableStr: %a\n", __FUNCTION__, __LINE__, printableStr));
    issuerAttributeList[AttrO] = &printableStr[0];
  } else
    LOG((EFI_D_ERROR, "%a.%d rv=%d\n", __FUNCTION__, __LINE__, rv));

  rv = GetIssuerLocalityName(hSession, hCert, &L);
  if (CKR_OK == rv) {
    offset = AsciiStrLen(attrTitle[AttrL]);
    printableStr = AllocateZeroPool(L.ulValueLen + offset);
    AsciiStrCpy(&printableStr[0], attrTitle[AttrL]);
    CopyMem(&printableStr[offset], L.pValue, L.ulValueLen);
    printableStr[offset + L.ulValueLen] = '\0';
    LOG((EFI_D_ERROR, "%a.%d printableStr: %a\n", __FUNCTION__, __LINE__, printableStr));
    issuerAttributeList[AttrL] = &printableStr[0];
  } else
    LOG((EFI_D_ERROR, "%a.%d rv=%d\n", __FUNCTION__, __LINE__, rv));
    
  rv = GetIssuerStateOrProvinceName(hSession, hCert, &ST);
  if (CKR_OK == rv) {
    offset = AsciiStrLen(attrTitle[AttrST]);
    printableStr = AllocateZeroPool(ST.ulValueLen + offset);
    AsciiStrCpy(&printableStr[0], attrTitle[AttrST]);
    CopyMem(&printableStr[offset], ST.pValue, ST.ulValueLen);
    printableStr[offset + ST.ulValueLen] = '\0';
    LOG((EFI_D_ERROR, "%a.%d printableStr: %a\n", __FUNCTION__, __LINE__, printableStr));
    issuerAttributeList[AttrST] = &printableStr[0];
  } else
    LOG((EFI_D_ERROR, "%a.%d rv=%d\n", __FUNCTION__, __LINE__, rv));
  
  return;
}

EFI_STATUS
GetCertificateSerialNumber(
  IN  CK_SESSION_HANDLE hSession,
  IN  CK_OBJECT_HANDLE hCert,
  OUT UINTN *serialNumber
  )
{
  CK_RV rv;
  CK_BYTE      Id[256];
  CK_ATTRIBUTE aCertId = {CKA_SERIAL_NUMBER, NULL_PTR, 0};
  
  ZeroMem(Id, sizeof(Id));
  aCertId.pValue = Id;
  aCertId.ulValueLen = sizeof(Id);
  
  rv = C_GetAttributeValue (hSession, hCert,
         &aCertId, 1);
  if (CKR_OK == rv) {
    LOG((EFI_D_ERROR, "%a.%d serial number: ", __FUNCTION__, __LINE__));
    DumpBytes_(aCertId.pValue, aCertId.ulValueLen);
    LOG((EFI_D_ERROR, "\n"));
  }
  else {
    LOG((EFI_D_ERROR, "%a.%d rv=%d\n", __FUNCTION__, __LINE__, rv));
    return EFI_ABORTED;
  }
  
  *serialNumber = ByteBufToUINTN(aCertId.pValue, aCertId.ulValueLen);
  
  return EFI_SUCCESS;
}


BOOLEAN
CheckCertId(
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN CK_VOID_PTR pInId,
  IN CK_ULONG InIdLen  
  )
{
  CK_BYTE Id[256];
  CK_ATTRIBUTE aCertId = {CKA_ID, NULL_PTR, 0};
  //CK_RV rv;

  LOG((EFI_D_ERROR, "%a.%d start\n", __FUNCTION__, __LINE__));
  DumpBytes_(pInId, InIdLen);

  ZeroMem(Id, sizeof(Id));
  aCertId.pValue = Id;
  aCertId.ulValueLen = sizeof(Id);
  
  if (C_GetAttributeValue (hSession, hCert, &aCertId, 1) != CKR_OK) {
    LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    return FALSE;
  }

  LOG((EFI_D_ERROR, "%a.%d aCertId.ulValueLen=%d\n", 
    __FUNCTION__, __LINE__, aCertId.ulValueLen));
  DumpBytes_(aCertId.pValue, aCertId.ulValueLen);
  
  if (aCertId.ulValueLen != InIdLen) {
    LOG((EFI_D_ERROR, "%a.%d false\n", __FUNCTION__, __LINE__));
    return FALSE;
  }
  if (CompareMem(aCertId.pValue, pInId, InIdLen)) {
    LOG((EFI_D_ERROR, "%a.%d false\n", __FUNCTION__, __LINE__));
    return FALSE;
  }

  LOG((EFI_D_ERROR, "%a.%d ok!\n", __FUNCTION__, __LINE__));
  return TRUE;
}

EFI_STATUS
TokenGetCertificateById(
  IN VOID *pInId,
  IN UINTN InIdLen,
  IN OUT UINT8 **Cdata,
  IN OUT UINTN *CdataLen
  )
{
  CK_ULONG Count;
  CK_RV rv;
  CK_OBJECT_HANDLE hCert;
  EFI_STATUS Status;
  STATIC CK_ATTRIBUTE aCertFindAttrs[] = {
    {CKA_TOKEN, &bTrue, sizeof bTrue},
    {CKA_CLASS, &cClass, sizeof cClass},
    {CKA_CERTIFICATE_TYPE, &cType, sizeof cType}
  };

  if (!TokenPresent()) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }

  if (hSession == CK_INVALID_HANDLE) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }

  if (eTokenLikeSmartCard()) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return GetCertificateDataFromEtoken(pInId, InIdLen, Cdata, CdataLen, TRUE);
  }

  rv = C_FindObjectsInit (hSession, aCertFindAttrs, 
    ARRAY_ITEMS(aCertFindAttrs));

  while (1) {
    Count = 0;
    rv = C_FindObjects (hSession, &hCert, 1, &Count);    
    LOG((EFI_D_ERROR, "%a.%d Count=%d\n", __FUNCTION__, __LINE__, Count));
    if (rv != CKR_OK || Count != 1) {
      LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
      C_FindObjectsFinal(hSession);
      return EFI_NOT_FOUND;
    }
    if (!CheckCertId(hSession, hCert, pInId, InIdLen)) {
      continue;
    }
    Status = GetCertificateData(hSession, hCert, Cdata, CdataLen);
    break;
  }
  C_FindObjectsFinal(hSession);
  return Status;
}

//------------------------------------------------------------------------------
/*! \brief Get the SUBJECT attribute, decoded to the string */
/*! This function allocates a memory for a pSubject.pValue, so you have to free it. */
/*! Result is a decoded string: e.x. "mail=tester@company.ry,CN=tester,OU=company" */
//------------------------------------------------------------------------------
STATIC CK_RV GetSubjectDecodedN (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN CK_ATTRIBUTE      *pSubject
  )
{
  CK_ATTRIBUTE email = {CKA_VALUE, NULL, 0};
  CK_ATTRIBUTE CN    = {CKA_VALUE, NULL, 0};
  CK_ATTRIBUTE OU    = {CKA_VALUE, NULL, 0};
  CK_ATTRIBUTE O     = {CKA_VALUE, NULL, 0};
  CK_ATTRIBUTE L     = {CKA_VALUE, NULL, 0};
  CK_ATTRIBUTE ST    = {CKA_VALUE, NULL, 0};
  
  CK_RV   rv;
  UINTN   totalLen = 0;
  
  //-----------------------------------------------------------------------------------------
  // Prevent to corrupt a data, previous has been stored. But we dont need to free this data,
  // because CK_ATTRIBUTE is used as a pointer to some data usualy.
  //-----------------------------------------------------------------------------------------
  pSubject->pValue = NULL;
  pSubject->ulValueLen = 0;
  
  rv = GetSubjectEmail(hSession, hClientCertSession, &email);
  if (CKR_OK == rv) {
    LOG((EFI_D_ERROR, "%a.%d email: %a\n", __FUNCTION__, __LINE__, email.pValue));
    totalLen += (email.ulValueLen + AsciiStrLen(attrTitle[AttrEmail]) + sizeof(CHAR8));
  } else {
    LOG((EFI_D_ERROR, "%a.%d rv=%d\n", __FUNCTION__, __LINE__, rv));
    return rv;
  }
     
  rv = GetSubjectCommonName(hSession, hClientCertSession, &CN);
  if (CKR_OK == rv) {
    LOG((EFI_D_ERROR, "%a.%d CN: %a\n", __FUNCTION__, __LINE__, CN.pValue));
    totalLen += (CN.ulValueLen + AsciiStrLen(attrTitle[AttrCN]) + sizeof(CHAR8));
  } else {
    LOG((EFI_D_ERROR, "%a.%d rv=%d\n", __FUNCTION__, __LINE__, rv));
    return rv;
  }
    
  rv = GetSubjectOrganizationUnitName(hSession, hClientCertSession, &OU);
  if (CKR_OK == rv) {
    LOG((EFI_D_ERROR, "%a.%d OU: %a\n", __FUNCTION__, __LINE__, OU.pValue));
    totalLen += (OU.ulValueLen + AsciiStrLen(attrTitle[AttrOU]) + sizeof(CHAR8));
  } else {
    LOG((EFI_D_ERROR, "%a.%d rv=%d\n", __FUNCTION__, __LINE__, rv));
    return rv;
  }
    
  rv = GetSubjectOrganizationName(hSession, hClientCertSession, &O);
  if (CKR_OK == rv) {
    LOG((EFI_D_ERROR, "%a.%d O: %a\n", __FUNCTION__, __LINE__, O.pValue));
    totalLen += (O.ulValueLen + AsciiStrLen(attrTitle[AttrO]) + sizeof(CHAR8));
  } else {
    LOG((EFI_D_ERROR, "%a.%d rv=%d\n", __FUNCTION__, __LINE__, rv));
    return rv;
  }

  rv = GetSubjectLocalityName(hSession, hClientCertSession, &L);
  if (CKR_OK == rv) {
    LOG((EFI_D_ERROR, "%a.%d L: %a\n", __FUNCTION__, __LINE__, L.pValue));
    totalLen += (L.ulValueLen + AsciiStrLen(attrTitle[AttrL]) + sizeof(CHAR8));
  } else {
    LOG((EFI_D_ERROR, "%a.%d rv=%d\n", __FUNCTION__, __LINE__, rv));
    return rv;
  }
    
  rv = GetSubjectStateOrProvinceName(hSession, hClientCertSession, &ST);
  if (CKR_OK == rv) {
    LOG((EFI_D_ERROR, "%a.%d ST: %a\n", __FUNCTION__, __LINE__, ST.pValue));
    totalLen += (ST.ulValueLen + AsciiStrLen(attrTitle[AttrST]) + sizeof(CHAR8));
  } else {
    LOG((EFI_D_ERROR, "%a.%d rv=%d\n", __FUNCTION__, __LINE__, rv));
    return rv;
  }
  
  if (totalLen > 0){
    CHAR8 *pSubjectData;
    
    pSubject->pValue = AllocateZeroPool(totalLen + sizeof(CHAR8));
    pSubject->ulValueLen = totalLen;
    
    pSubjectData = (CHAR8*)pSubject->pValue;
    
    if (email.ulValueLen > 0) {
      AsciiStrCpy(pSubjectData, attrTitle[AttrEmail]);
      pSubjectData += AsciiStrLen(attrTitle[AttrEmail]);
      CopyMem(pSubjectData, email.pValue, email.ulValueLen);
      pSubjectData += email.ulValueLen;
      AsciiStrCpy(pSubjectData, ",");
      pSubjectData += sizeof(CHAR8);
    }
    
    if (CN.ulValueLen > 0) {
      AsciiStrCpy(pSubjectData, attrTitle[AttrCN]);
      pSubjectData += AsciiStrLen(attrTitle[AttrCN]);
      CopyMem(pSubjectData, CN.pValue, CN.ulValueLen);
      pSubjectData += CN.ulValueLen;
      AsciiStrCpy(pSubjectData, ",");
      pSubjectData += sizeof(CHAR8);
    }
    
    if (OU.ulValueLen > 0) {
      AsciiStrCpy(pSubjectData, attrTitle[AttrOU]);
      pSubjectData += AsciiStrLen(attrTitle[AttrOU]);
      CopyMem(pSubjectData, OU.pValue, OU.ulValueLen);
      pSubjectData += OU.ulValueLen;
      AsciiStrCpy(pSubjectData, ",");
      pSubjectData += sizeof(CHAR8);
    }
    
    if (O.ulValueLen > 0) {
      AsciiStrCpy(pSubjectData, attrTitle[AttrO]);
      pSubjectData += AsciiStrLen(attrTitle[AttrO]);
      CopyMem(pSubjectData, O.pValue, O.ulValueLen);
      pSubjectData += O.ulValueLen;
      AsciiStrCpy(pSubjectData, ",");
      pSubjectData += sizeof(CHAR8);
    }
    
    if (L.ulValueLen > 0) {
      AsciiStrCpy(pSubjectData, attrTitle[AttrL]);
      pSubjectData += AsciiStrLen(attrTitle[AttrL]);
      CopyMem(pSubjectData, L.pValue, L.ulValueLen);
      pSubjectData += L.ulValueLen;
      AsciiStrCpy(pSubjectData, ",");
      pSubjectData += sizeof(CHAR8);
    }
    
    if (ST.ulValueLen > 0) {
      AsciiStrCpy(pSubjectData, attrTitle[AttrST]);
      pSubjectData += AsciiStrLen(attrTitle[AttrST]);
      CopyMem(pSubjectData, ST.pValue, ST.ulValueLen);
      pSubjectData += ST.ulValueLen;
      AsciiStrCpy(pSubjectData, ",");
      pSubjectData += sizeof(CHAR8);
    }
    
    LOG((EFI_D_ERROR, "%a.%d SUBJECT: %a\n", __FUNCTION__, __LINE__, pSubject->pValue));
    
    return CKR_OK;
  }
  
  return CKR_CANCEL;
}


STATIC CK_RV GetSubject (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN CK_BYTE_PTR       pSubject,
  IN CK_ULONG_PTR      pulSubject
  )
{
  CK_ATTRIBUTE T = { CKA_SUBJECT, NULL_PTR, 0 };
  CK_RV        rv;

  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  T.pValue     = pSubject;
  T.ulValueLen = *pulSubject;

  if ((rv = C_GetAttributeValue (hSession, hCert, &T, 1)) == CKR_OK) {
    *pulSubject = T.ulValueLen;
  }

  return rv;
}

STATIC BOOLEAN 
CheckBasicConstraintsCAflag(
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert
  )
{
  CK_RV rv;
  CK_ATTRIBUTE BasicConstraints;

  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  rv = C_AuxGetBasicConstraints (hSession, hCert, &BasicConstraints);
  if (CKR_OK != rv) {
    LOG ((EFI_D_ERROR, "%a.%d Error! 0x%X\n", __FUNCTION__, __LINE__, rv));
    return FALSE;
  }
  
  LOG ((EFI_D_ERROR, "%a.%d BasicConstraints.ulValueLen=%d\n", 
    __FUNCTION__, __LINE__, BasicConstraints.ulValueLen));
  
  DumpBytes_(BasicConstraints.pValue, BasicConstraints.ulValueLen);
  return TRUE;
}


STATIC CK_RV GetIssuerCommonName (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR  pCN
  )
{
  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return C_AuxGetIssuerCommonName (hSession, hCert, pCN);
}

STATIC CK_RV GetIssuerEmail (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR  pEmail
  )
{
  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return C_AuxGetIssuerEmail (hSession, hCert, pEmail);
}


STATIC CK_RV GetSubjectOrganizationName (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR  pOrganizationName
  )
{
  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return C_AuxGetSubjectOrganizationName (hSession, hCert, pOrganizationName);
}


STATIC CK_RV GetIssuerOrganizationName (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR  pOrganizationName
  )
{
  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return C_AuxGetIssuerOrganizationName (hSession, hCert, pOrganizationName);
}


STATIC CK_RV GetSubjectOrganizationUnitName (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR  pOrganizationUnitName
  )
{
  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return C_AuxGetSubjectOrganizationUnitName (hSession, hCert, pOrganizationUnitName);
}


STATIC CK_RV GetIssuerOrganizationUnitName (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR  pOrganizationUnitName
  )
{
  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return C_AuxGetIssuerOrganizationUnitName (hSession, hCert, pOrganizationUnitName);
}


STATIC CK_RV GetSubjectLocalityName (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR  pLocalityName
  )
{
  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return C_AuxGetSubjectLocalityName (hSession, hCert, pLocalityName);
}


STATIC CK_RV GetIssuerLocalityName (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR  pLocalityName
  )
{
  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return C_AuxGetIssuerLocalityName (hSession, hCert, pLocalityName);
}


STATIC CK_RV GetSubjectStateOrProvinceName (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR  pStateOrProvinceName
  )
{
  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return C_AuxGetSubjectStateOrProvinceName (hSession, hCert, pStateOrProvinceName);
}


STATIC CK_RV GetIssuerStateOrProvinceName (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR  pStateOrProvinceName
  )
{
  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return C_AuxGetIssuerStateOrProvinceName (hSession, hCert, pStateOrProvinceName);
}


STATIC CK_RV FindFirstObject (
               CK_SESSION_HANDLE hSession,
               CK_ATTRIBUTE      *pAttrs,
               CK_ULONG          AttrNum,
               CK_BBOOL          *pFound,
               CK_OBJECT_HANDLE  *phObject)
{
  CK_ULONG Count = 0;
  CK_RV    rv;
  
  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  rv = C_FindObjectsInit (hSession, pAttrs, AttrNum);

  if (rv == CKR_OK) { /* Initialized successfully, so MUST be completed then */
    if ((rv = C_FindObjects (hSession, phObject, 1, &Count)) == CKR_OK) {
      *pFound =
#if _MSC_VER
        (CK_BBOOL)
#endif
          (Count == 1);
      LOG((EFI_D_ERROR, "%a.%d Count=%d\n", __FUNCTION__, __LINE__, Count));
    }

    /* Complete the Find operation (no return code check in this version) */
    C_FindObjectsFinal (hSession);
  }

  return rv;
}


STATIC EFI_STATUS
CheckComparisonData(
  IN CK_ATTRIBUTE *Attributes,
  IN UINT8 ComparisonFlags,
  IN int Index
  )
{
  STATIC UINT8 DigestCmpBuf[64];

  LOG((EFI_D_ERROR, "%a.%d Index=%d\n", __FUNCTION__, __LINE__, Index));
  
  if ((ComparisonFlags & (1 << Index)) == 0 && gpTokenUser[Index] != NULL) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  if (gpTokenUser[Index] == NULL) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  if (gpTokenUser[Index]->Data == NULL || gpTokenUser[Index]->DataLen == 0) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }

  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  LOG ((EFI_D_ERROR, 
    "gpTokenUser[Index]->DataLen=%X Attributes[Index].ulValueLen=%X\n",
    gpTokenUser[Index]->DataLen, 
    Attributes[Index].ulValueLen
    ));

  if (Index == CT_FLAG_DIGEST) {
    if ((UINTN)((gpTokenUser[Index]->DataLen & ~1) / 4) < 
        Attributes[Index].ulValueLen) {
      LOG((EFI_D_ERROR, "%a.%d Wrong length of data!\n",
        __FUNCTION__, __LINE__));
      LOG((EFI_D_ERROR, "{%d} {%d}\n",
        gpTokenUser[Index]->DataLen, Attributes[Index].ulValueLen));
      return EFI_ABORTED;
    }
    if (StrLen((UINT16*)gpTokenUser[Index]->Data) / 2 != 
        Attributes[Index].ulValueLen) {
      LOG((EFI_D_ERROR, "%a.%d Wrong length of data!\n",
        __FUNCTION__, __LINE__));
      LOG((EFI_D_ERROR, "{%d} {%d}\n",
        StrLen((UINT16*)gpTokenUser[Index]->Data) / 2, 
        Attributes[Index].ulValueLen));
      return EFI_ABORTED;
    }
    {
      CHAR16 TmpStr16[255];

      LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      LOG((EFI_D_ERROR, "GetCalcDataDigest_MdType()=%X\n", GetCalcDataDigest_MdType()));
      LOG((EFI_D_ERROR, "Attributes[Index].ulValueLen=%X\n", 
        Attributes[Index].ulValueLen));
      
      if (GetCalcDataDigest_MdType() == NID_id_GostR3411_2012_256) {
        LOG((DEBUG_ERROR, "%a.%d it's GostR3411_2012_256\n", __FUNCTION__, __LINE__));
        GetDigestWithLenStr16(TmpStr16, Attributes[Index].pValue, CS_TYPE_GOST_2012, 0);
      } else if (GetCalcDataDigest_MdType() == NID_id_GostR3411_2012_512) {
        LOG((DEBUG_ERROR, "%a.%d it's GostR3411_2012_512\n", __FUNCTION__, __LINE__));
        GetDigestWithLenStr16(TmpStr16, Attributes[Index].pValue, CS_TYPE_GOST_2012, 0);      
      } else if (GetCalcDataDigest_MdType() == NID_id_GostR3411_94) {
        LOG((DEBUG_ERROR, "%a.%d it's GostR3411_94\n", __FUNCTION__, __LINE__));
        GetDigestWithLenStr16(TmpStr16, Attributes[Index].pValue, CS_TYPE_GOST, 0);
      } else {
        LOG((DEBUG_ERROR, "%a.%d it's NOT GostR3411_94 | GetCalcDataDigest_MdType = %x\n",
          __FUNCTION__, __LINE__, GetCalcDataDigest_MdType()));
        GetDigestWithLenStr16(TmpStr16, Attributes[Index].pValue, 
          (UINT8)-1, Attributes[Index].ulValueLen);
      }
      LOG((EFI_D_ERROR, "cur=%s saved=%s\n", TmpStr16, (CHAR16*)gpTokenUser[Index]->Data));
      if (StrCmp(TmpStr16, (CHAR16*)gpTokenUser[Index]->Data) == 0) {
        return EFI_SUCCESS;
      }
      LOG((DEBUG_ERROR, "%a.%d hashs is not equal\n", __FUNCTION__, __LINE__));
    }
  } else {
    CHAR8 Str8[255], UserDataStr8[255];
    CopyMem(Str8, Attributes[Index].pValue, Attributes[Index].ulValueLen);
    Str8[Attributes[Index].ulValueLen] = '\0';
    LOG((EFI_D_ERROR, 
      "Attributes[Index].pValue={%a} gpTokenUser[Index]->Data={%s}\n",
      Str8, gpTokenUser[Index]->Data));
    AsciiSPrint(UserDataStr8, sizeof(UserDataStr8), "%s", 
      gpTokenUser[Index]->Data);
    if (AsciiStrLen(UserDataStr8) != Attributes[Index].ulValueLen) {
      LOG((EFI_D_ERROR, "%a.%d Length of data not the same!\n",
        __FUNCTION__, __LINE__));
      LOG((EFI_D_ERROR, 
        "AsciiStrLen(UserDataStr8)=%d Attributes[Index].ulValueLen=%d\n",
        AsciiStrLen(UserDataStr8), Attributes[Index].ulValueLen));
    }   
    LOG((EFI_D_ERROR, "Compare: {%a} && {%a}\n", Str8, UserDataStr8));
    if (AsciiStrCmp(Str8, UserDataStr8) == 0) {      
      return EFI_SUCCESS;
    }  
    LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    DumpBytes_ (gpTokenUser[Index]->Data, gpTokenUser[Index]->DataLen);
    LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    DumpBytes_ (Attributes[Index].pValue, Attributes[Index].ulValueLen);
    if (gpTokenUser[Index]->DataLen == Attributes[Index].ulValueLen) {      
      if (CompareMem (
        gpTokenUser[Index]->Data, 
        Attributes[Index].pValue,
        Attributes[Index].ulValueLen
        ) == 0) {
        return EFI_SUCCESS;
      }
    } else {
      if (Attributes[Index].type == CKA_BMP_STRING) {        
        UINTN Idx;
        UINT8 *Data;
        UINT8 TmpData;
        CHAR16 *BmpStr;
        INTN Res;
        LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));        
        BmpStr = AllocateZeroPool(Attributes[Index].ulValueLen + 
          sizeof (CHAR16));
        if (BmpStr == NULL) {
          return EFI_OUT_OF_RESOURCES;
        }
        CopyMem(BmpStr, Attributes[Index].pValue, Attributes[Index].ulValueLen);
        Data = (UINT8*)BmpStr;
        for (Idx = 0; Idx + 1 < Attributes[Index].ulValueLen; Idx += 2) {
          TmpData = Data[Idx];
          Data[Idx] = Data[Idx + 1];
          Data[Idx + 1] = TmpData;
        }
        LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
        Res = StrCmp((CHAR16*)gpTokenUser[Index]->Data, BmpStr);
        FreePool (BmpStr);
        if (Res == 0) {
          LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
          return EFI_SUCCESS;
        }
      }
    }
  }
  return EFI_ABORTED;
}


STATIC VOID
CheckAllOverComparisonData(
  IN CK_ATTRIBUTE *Attributes,
  IN UINT8 ComparisonFlags,
  IN int LastIndex
)
{
  int i;

  gMatchedFlags |= (1 << LastIndex);
  
  for (i = 0; i < LastIndex; i++) {
    if (EFI_SUCCESS == CheckComparisonData(Attributes, ComparisonFlags, i)) {
      gMatchedFlags |= (1 << i);
    }
  }
}

EFI_STATUS
UpdateSringForDigestWithColons(
  IN CHAR16 *Str16,
  IN UINTN StrLength,
  IN CHAR16 *DigestStr,
  IN UINTN DigestStrLen
  )
{
  UINTN i;
  

  if (Str16 == NULL || DigestStr == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  if (StrLength == 0 || DigestStrLen == 0) {
    return EFI_INVALID_PARAMETER;
  }
  
  Str16[0] = ';';
  Str16++;
  StrLength--;
#if 0  
  for (i = 0; i < DigestStrLen; i+= 2) {
    UnicodeSPrint(Str16, StrLength, L"%c%c%s", 
      DigestStr[i], DigestStr[i + 1], 
      i + 2 >= DigestStrLen ? L"" : L":");
    Str16 += 3;    
  }
#else
  for (i = DigestStrLen; i > 0; i-= 2) {
    UnicodeSPrint(Str16, StrLength, L"%c%c%s", 
      DigestStr[i - 2], DigestStr[i - 1], 
      i == 2 ? L"" : L":");
    Str16 += 3;    
  }
#endif
  return EFI_SUCCESS;
}


CHAR8 *
GetUserPIN (
  VOID
  )
{
  return UserPIN;
}

UINT16 *
GetTokenUserVarsString16(
  VOID
  )
{
  STATIC CHAR16 Str16[1024];
  int i;
  UINTN Offset;

  UnicodeSPrint(Str16, sizeof(Str16), L"%a", UserPIN);
  
  for (i = 0; i < 5; i++) {
    Offset = StrLen(Str16);
    if (Offset >= sizeof(Str16) - 1) {
      return NULL;
    }
    if ((gMatchedFlags & (1 << i)) == 0) {
      UnicodeSPrint(Str16 + Offset, sizeof(Str16) - Offset, L";");
      continue;
    }
    if ((gMatchedFlags & (1 << i)) == CT_BIT_DIGEST) {
      CHAR16 *TmpPtr16 = (CHAR16*)gpTokenUser[i]->Data;
      UpdateSringForDigestWithColons(Str16 + Offset, sizeof(Str16) - Offset,
        TmpPtr16, StrLen(TmpPtr16));
    } else {
      UnicodeSPrint(Str16 + Offset, sizeof(Str16) - Offset, L";%s", 
        gpTokenUser[i]->Data);
    }
  }
  return Str16;
}


STATIC EFI_STATUS
GetApropriateTokenUser(
  IN CK_ATTRIBUTE *Attributes,
  IN UINT8 ComparisonFlags
  )
{
  int i;
  EFI_STATUS Status;
  USER_INFO *pUserInfo;
  
  Status = UsersGetNextTokenUser(TRUE);
  if (EFI_ERROR(Status)) {
    return EFI_NOT_FOUND;
  }
  gpTokenUser = UsersGetLastFoundedTokenUser();
  while (gpTokenUser != NULL) {    
    pUserInfo = UserGetLastFoundedInfo ();
    if (!isHiddenUser(pUserInfo)) {
      for (i = 4; i >= 0; i--) {
        Status = CheckComparisonData(Attributes, ComparisonFlags, i);
        if (Status == EFI_SUCCESS) {
          gMatchedFlags |= 1 << i;
        } else if (Status == EFI_ABORTED) {
          gMatchedFlags = 0;
          break;
        }
      }
      if (gMatchedFlags) {
        return EFI_SUCCESS;
      }
    }
    Status = UsersGetNextTokenUser(FALSE);
    if (EFI_ERROR(Status)) {
      break;
    }
    gpTokenUser = UsersGetLastFoundedTokenUser();
  }
  return EFI_NOT_FOUND;
}


STATIC EFI_STATUS
GetNextCertificateData(
  IN OUT CK_ATTRIBUTE *Attributes,
  IN OUT UINT8 *ComparisonFlags
  )
{
  CK_ULONG Count;
  CK_RV rv;
  CHAR8 Str8[255];
  STATIC UINT8 DigestBuf[64];
  CK_ULONG DigestLen;
  CK_BYTE Id[256];
  CK_ATTRIBUTE aCertId = {CKA_ID, NULL_PTR, 0};
  STATIC BOOLEAN bRestart = TRUE;

  if (eTokenRstSearch) {
    bRestart = TRUE;
    eTokenRstSearch = FALSE;
  }
  
  do {
    Count = 0;

    if (eTokenLikeSmartCard()) {
      UINT16 Id;
      UINT16 Type;
      EFI_STATUS Status;
      
      Status = eTokenGetNextObject(bRestart, &Id, &Type);
      bRestart = FALSE;
      if (EFI_ERROR(Status)) {
        bRestart = TRUE;
        return EFI_NOT_FOUND;
      }
      if (Type != CERT_ID_TYPE) { // it is not certificate
        continue;
      }
      LOG((EFI_D_ERROR, "%a.%d Id=%X\n", __FUNCTION__, __LINE__, Id));
      Status = eTokenGetClientCertById(&Id, sizeof(UINT16), &hClientCertSession,
        hClientCertSession == CK_INVALID_HANDLE ? TRUE : FALSE, FALSE);
      if (EFI_ERROR(Status)) {
        return EFI_NOT_FOUND;
      }
    } else {
      LOG((EFI_D_ERROR, "%a.%d Starting C_FindObjects...\n", 
        __FUNCTION__, __LINE__));
      rv = C_FindObjects (hSession, &hClientCertSession, 1, &Count);    
      LOG((EFI_D_ERROR, "%a.%d Count=%d\n", __FUNCTION__, __LINE__, Count));
      if (rv != CKR_OK || Count != 1) {
        LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
        //C_FindObjectsFinal(hSession);
        return EFI_NOT_FOUND;
      }
      LOG((EFI_D_ERROR, "%a.%d C_FindObjects OK!!!\n", __FUNCTION__, __LINE__));
    }

    ZeroMem(Id, sizeof(Id));
    aCertId.pValue = Id;
    aCertId.ulValueLen = sizeof(Id);
    
    if (C_GetAttributeValue (hSession, hClientCertSession, 
        &aCertId, 1) == CKR_OK) {
      LOG((EFI_D_ERROR, "%a.%d ==>CERT_ID_LEN=%d\n", 
        __FUNCTION__, __LINE__, aCertId.ulValueLen));
      DumpBytes_(aCertId.pValue, aCertId.ulValueLen);  
    } else {
      LOG((EFI_D_ERROR, "%a.%d ==>CERT_ID NOT FOUND!!!\n", 
        __FUNCTION__, __LINE__, aCertId.ulValueLen));
    }

    rv = Verify(hSession, hClientCertSession);
    LOG((EFI_D_ERROR, "%a.%d RV=0x%X\n", 
        __FUNCTION__, __LINE__, rv));
    VerifyLastStatus = GetOsslLastError();
    if (CKR_OK != rv) {
      LOG((EFI_D_ERROR, "%a.%d Verify OSSL Error! : %d\n",
        __FUNCTION__, __LINE__, GetOsslLastError()));

      break;
    } else {
      LOG((EFI_D_ERROR, "%a.%d Verify signature OK!!!\n", 
        __FUNCTION__, __LINE__));

      if (CheckForCertExpire(hSession, hClientCertSession) == EFI_SUCCESS) {
        break;
      }
    }
  } while (1);
  //C_FindObjectsFinal(hSession);

  *ComparisonFlags = 0;   

  /* COMMON NAME */
  rv = GetSubjectCommonName (hSession, hClientCertSession, 
    &Attributes[CT_FLAG_CN]);
  if (rv != CKR_OK) {
    LOG((EFI_D_ERROR, "%a.%d Error while obtain common name!\n", 
      __FUNCTION__, __LINE__));
  } else {
    *ComparisonFlags |= CT_BIT_CN;
    CopyMem(Str8, Attributes[CT_FLAG_CN].pValue, 
      Attributes[CT_FLAG_CN].ulValueLen);
    Str8[Attributes[CT_FLAG_CN].ulValueLen] = '\0';
    LOG((EFI_D_ERROR, "Obtained COMMON NAME: %a\n", Str8));
    DumpBytes_(Attributes[CT_FLAG_CN].pValue, Attributes[CT_FLAG_CN].ulValueLen);
  }

  /* SUBJECT TITLE */
  rv = GetSubjectTitle(hSession, hClientCertSession, 
    &Attributes[CT_FLAG_SUBJECT]);
  if (rv != CKR_OK) {
    LOG((EFI_D_ERROR, "%a.%d Error while obtain title!\n", 
      __FUNCTION__, __LINE__));
  } else {
    *ComparisonFlags |= CT_BIT_SUBJECT;
    LOG((EFI_D_ERROR, "Obtained TITLE:\n"));
    DumpBytes_(Attributes[CT_FLAG_SUBJECT].pValue, 
      Attributes[CT_FLAG_SUBJECT].ulValueLen);
  }
  
  rv = GetSubjectUid(hSession, hClientCertSession, &Attributes[CT_FLAG_UID]);
  if (rv != CKR_OK) {
    LOG((EFI_D_ERROR, "%a.%d Error while obtain uid!\n", 
      __FUNCTION__, __LINE__));
  } else {
    *ComparisonFlags |= CT_BIT_UID;
    LOG((EFI_D_ERROR, "Obtained UID:\n"));
    DumpBytes_(Attributes[CT_FLAG_UID].pValue, Attributes[CT_FLAG_UID].ulValueLen);
  }


  /* E-mail */
  rv = GetSubjectEmail(hSession, hClientCertSession, &Attributes[CT_FLAG_MAIL]);
  if (rv != CKR_OK) {
    LOG((EFI_D_ERROR, "%a.%d Error while obtain Email!\n", 
      __FUNCTION__, __LINE__));
  } else {
    *ComparisonFlags |= CT_BIT_MAIL;
    CopyMem(Str8, Attributes[CT_FLAG_MAIL].pValue, 
      Attributes[CT_FLAG_MAIL].ulValueLen);
    Str8[Attributes[CT_FLAG_MAIL].ulValueLen] = '\0';
    LOG((EFI_D_ERROR, "Obtained Email: %a\n", Str8));
    DumpBytes_(Attributes[CT_FLAG_MAIL].pValue, 
      Attributes[CT_FLAG_MAIL].ulValueLen);
  }

  /* DIGEST */
  DigestLen = sizeof(DigestBuf);
  rv = GetCertificateDigest2 (hSession, hClientCertSession, hCACertSession,
    (CK_BYTE_PTR)DigestBuf, &DigestLen);
  if (rv != CKR_OK) {
    LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));     
  } else {
    *ComparisonFlags |= CT_BIT_DIGEST;
    LOG((EFI_D_ERROR, "%a.%d DigestLen=%d\n", 
      __FUNCTION__, __LINE__, DigestLen));
    DumpBytes_(DigestBuf, DigestLen);
    Attributes[CT_FLAG_DIGEST].pValue = DigestBuf;
    Attributes[CT_FLAG_DIGEST].ulValueLen = DigestLen;
  }

#if 0
{
  /* FIXME: test test */
  UINT8 Id[] = {0x00, 0x03};
  UINT8 *Data = NULL;
  UINTN DataLen = 0;
  
  CheckCertId(hSession, hClientCertSession, Id, sizeof(Id));
  GetCertificateData(hSession, hClientCertSession, &Data, &DataLen);
  if (Data != NULL) {
    FreePool(Data);
  }
}
#endif
  
  return EFI_SUCCESS;
}

#if JC_HARDWARE_CHECK_ECP
EFI_STATUS
JacartaCheckDataSignature (
  IN UINT8 *CertData,
  IN UINTN CertDataLen,
  IN UINT8 *Data,
  IN UINTN DataLen,
  IN UINT8 *SigData,
  IN UINTN SigDataLen,
  IN BOOLEAN IsGost2012
  ) 
{
  EFI_STATUS Status;
  UINT8 Digest[32];
  BOOLEAN RetStatus;
  INT64 Nid;

  //check pubkey
  
  if (IsGost2012) {
    Nid = 926; //NID_id_GostR3411_2012_256 defined in obj_mac.h
  } else {
    Nid = 809; //NID_id_GostR3411_94 defined in obj_mac.h
  }

  Status = GetDigestOpenSSL(Data, DataLen, Digest, Nid);
  if (EFI_ERROR(Status)) {
     DEBUG((DEBUG_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return Status;
  }

  DEBUG((DEBUG_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  Status = gSmartCardProtocol->VerifySignatureInit(
    gSmartCardProtocol, 0);
  if (EFI_ERROR(Status)) {
    return Status;
  }

  DEBUG((DEBUG_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  Status = gSmartCardProtocol->VerifySignature(
    gSmartCardProtocol,
    0,
    Digest,
    sizeof(Digest),
    SigData,
    SigDataLen,
    0,
    0,
    &RetStatus
    );
  if (EFI_ERROR (Status) || !RetStatus) {
    return EFI_CRC_ERROR;
  } 
  return EFI_SUCCESS;
}
#endif //JC_HARDWARE_CHECK_ECP


STATIC
EFI_STATUS
VerifyUserWithPkey (
  VOID
  )
{
  UINT8 MyData[32];
  UINT8 *EcpData = NULL;
  UINTN EcpDataLen = 0, Idx;
  EFI_STATUS Status;
  UINT8 *CertData = NULL;
  UINTN CertDataLen = 0;
  CK_BYTE TmpData[256];
  CK_ATTRIBUTE aPkeyId = {CKA_ID, NULL_PTR, 0};
  CK_ATTRIBUTE aPkeySessionFindAttrs[] = {
    {CKA_TOKEN, &bTrue, sizeof bTrue},
    {CKA_CLASS, &kClassPriv, sizeof kClassPriv}
  };
  CK_RV rv;
  CK_OBJECT_HANDLE  hPkey;
  CK_ULONG Count = 0;
  CK_BBOOL token = CK_TRUE;
  CK_ATTRIBUTE templateDeft = { CKA_TOKEN, NULL, 0};
  CK_MECHANISM M = { CKM_GOSTR3411, NULL, 0}; //set GOST3411-94 as default 
  UINT8 Digest[32];
  UINTN DigestLen = 0;
  OPENSSL_PROTOCOL *pOpenSSLProtocol = NULL;
  UINT8 *SigBuf = NULL;
  UINTN SigBufLen = 0, MdType;
  UINTN GostYear;

  templateDeft.pValue = &token;
  templateDeft.ulValueLen = sizeof (token);

  M.pParameter = &templateDeft;
  M.ulParameterLen = 1;

  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if (gSmartCardProtocol == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }

  Status = GetCertificateData(hSession, hClientCertSession, 
    &CertData, &CertDataLen);
  if (EFI_ERROR(Status)) {
    goto _exit;
  }

  srand ((unsigned int)AsmReadTsc());
  for (Idx = 0; Idx < sizeof (MyData); Idx++) {
    MyData[Idx] = (UINT8)(rand () & 0xFF);
  }

  Status = gBS->LocateProtocol (
                  &gOpenSSLProtocolGuid,
                  NULL,
                  (VOID **) &pOpenSSLProtocol
                  );
  if (Status != EFI_SUCCESS || pOpenSSLProtocol == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
    goto _exit;
  }

  Status = pOpenSSLProtocol->CalcDataDigest(CertData,
                                            CertDataLen,
                                            MyData,
                                            sizeof (MyData),
                                            &SigBuf,
                                            &SigBufLen
                                            );
  if (SigBuf != NULL) {
    FreePool (SigBuf);
  }
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "%a.%d Status=%X\n", __FUNCTION__, __LINE__, Status));
    goto _exit;
  }
  MdType = pOpenSSLProtocol->GetCalcDataDigest_MdType ();
  
  if(pOpenSSLProtocol->IsGostDigest(MdType, &GostYear)) {
    if (GostYear == 2012) {
      DEBUG((DEBUG_ERROR, "%a.%d Used CKM_GOSTR3411_2012!\n", __FUNCTION__, __LINE__));
      M.mechanism = CKM_GOSTR3411_2012; //redefine The Digest Mechanism on GOST2012
    }
  }

  gSmartCardProtocol->CurContext = (VOID*)&MdType;
  gSmartCardProtocol->CurContextLen = sizeof (MdType);

  if (!eTokenLikeSmartCard ()) { 
    //
    // For Rutoken and other
    //

    LOG((DEBUG_ERROR, "%a.%d This is NOT eToken!..\n", __FUNCTION__, __LINE__));
    
    // try pkcs15 for find pkey
    rv = C_FindObjectsInit (hSession, aPkeySessionFindAttrs, 
          ARRAY_ITEMS(aPkeySessionFindAttrs));
    if (rv != CKR_OK) {
      DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return EFI_UNSUPPORTED;
    }

    LOG((DEBUG_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

    rv = C_FindObjects (hSession, &hPkey, 1, &Count);

    LOG((DEBUG_ERROR, "%a.%d Count = %d\n", __FUNCTION__, __LINE__, Count));

    rv = C_FindObjectsFinal (hSession);
    if (rv != CKR_OK || Count == 0) {
      DEBUG ((EFI_D_ERROR, "%a.%d   Count = %d\n", __FUNCTION__, __LINE__,Count));
      return EFI_UNSUPPORTED;
    }

    LOG((DEBUG_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

    aPkeyId.pValue = TmpData;
    aPkeyId.ulValueLen = sizeof (TmpData);
    rv = C_GetAttributeValue(hSession, hPkey, &aPkeyId, 1);
    if (rv != CKR_OK) {
      DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return EFI_UNSUPPORTED;
    }

    LOG ((DEBUG_ERROR, "%a.%d Pkey (%x) = \n", __FUNCTION__, __LINE__, aPkeyId.ulValueLen));
    DumpBytes_ (aPkeyId.pValue, aPkeyId.ulValueLen);

    DigestLen = sizeof (Digest);
	
    //хешируем данные
    rv = C_DigestInit (hSession, &M);
    if (rv != CKR_OK) {
      
      DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

      if(rv == CKR_ALGORITM_UNSUPPORT) {
        DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
        return EFI_INCOMPATIBLE_VERSION;
      }

      LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return EFI_ABORTED;
    }
     
    LOG((DEBUG_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

    rv = C_Digest (
               hSession,
               MyData,     /* Certificate Content */
               sizeof (MyData),
               Digest,      /* Computed Digest     */
               &DigestLen
               );
    if (rv != CKR_OK) {
      DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return EFI_UNSUPPORTED;
    }    

    LOG ((EFI_D_ERROR, "%a.%d Digest (%x) = \n", __FUNCTION__, __LINE__, DigestLen));
    DumpBytes_ (Digest, DigestLen);
    LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

    rv = C_SignInit(hSession, &M, hPkey);
    if (rv != CKR_OK) {
      DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return EFI_UNSUPPORTED;
    }

    LOG((DEBUG_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

    EcpDataLen = sizeof (TmpData);
    rv = C_Sign (
              hSession,
              Digest,
              DigestLen,
              TmpData,
              &EcpDataLen
              );
    if (rv != CKR_OK) {
      DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return EFI_UNSUPPORTED;
    }   
    
    EcpData = AllocateCopyPool(EcpDataLen, TmpData);
    if (EcpData == NULL) {
      DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      return EFI_OUT_OF_RESOURCES;
    }    
  } else {
    //
    // For eToken
    //

    LOG((DEBUG_ERROR, "%a.%d This is eToken..\n", __FUNCTION__, __LINE__));

    Status = gSmartCardProtocol->EcpInit (gSmartCardProtocol);
    LOG ((DEBUG_ERROR, "%a.%d Status=%r\n", 
      __FUNCTION__, __LINE__, Status));
    if (EFI_ERROR (Status)) {
      return Status;
    }    
    
    Status = gSmartCardProtocol->Ecp (
                  gSmartCardProtocol,
                  MyData,
                  sizeof (MyData),
                  &EcpData,
                  &EcpDataLen
                  );  
    LOG ((DEBUG_ERROR, "%a.%d Status=%r\n", 
      __FUNCTION__, __LINE__, Status));
    if (EFI_ERROR (Status)) {
      return Status;
    }
  }

  LOG((DEBUG_ERROR, "%a.%d\n Ecp (%x) = ", __FUNCTION__, __LINE__, EcpDataLen));
  DumpBytes (EcpData, EcpDataLen);
  LOG((DEBUG_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  LOG((DEBUG_ERROR, "%a.%d\n CertData (%x) = ", __FUNCTION__, __LINE__, CertDataLen));
  DumpBytes (CertData, CertDataLen);
  LOG((DEBUG_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  LOG((DEBUG_ERROR, "%a.%d VendorId %x\n", __FUNCTION__, __LINE__, gSmartCardProtocol->VendorId));

#if JC_HARDWARE_CHECK_ECP
  if (gSmartCardProtocol->VendorId == JACARTA_VENDOR_ID) {
    Status = JacartaCheckDataSignature(
              CertData,
              CertDataLen,
              MyData,
              sizeof (MyData),
              EcpData,
              EcpDataLen,
              (M.mechanism == CKM_GOSTR3411_2012)
    );
    
    goto _exit;
  }
#endif //JC_HARDWARE_CHECK_ECP

  Status = CheckDataSignature (
              CertData,
              CertDataLen,
              MyData,
              sizeof (MyData),
              EcpData,
              EcpDataLen
              );
  if (EFI_ERROR (Status)) {
    Status = EFI_CRC_ERROR;
  }
_exit:
  LOG ((EFI_D_ERROR, "%a.%d Status=%r\n", 
      __FUNCTION__, __LINE__, Status));
  if (CertData) {
    FreePool (CertData);
  }
  if (EcpData) {
    FreePool (EcpData);
  }
  gSmartCardProtocol->CurContext = NULL;
  gSmartCardProtocol->CurContextLen = 0;
  return Status;
}


EFI_STATUS
ProcessingTokenUser(
  VOID
  )
{  
  EFI_STATUS Status = EFI_ABORTED;
  UINT8 ComparisonFlags = 0;
  CK_RV rv;

  if (eTokenLikeSmartCard()) {

  } else {
    rv = C_FindObjectsInit (hSession, aClientCertTokenFindAttrs, 
      ARRAY_ITEMS(aClientCertTokenFindAttrs));

    if (rv != CKR_OK) {
      LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
      /* return EFI_ABORTED; */
      goto _exit;
    }
  }

  gMatchedFlags = 0;
  
  while (1) {
    USER_INFO *pUsrInfo;
    UINT8 UsrId;
    BOOLEAN isShowMessage = TRUE;
      
    Status = GetNextCertificateData(CompAttributes, &ComparisonFlags);
    if (EFI_ERROR(Status)) {
      LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", 
        __FUNCTION__, __LINE__, Status));
      break;
    }

    Status = GetApropriateTokenUser(CompAttributes, ComparisonFlags);
    if (EFI_ERROR (Status)) {
      continue;
    }

     LOG((DEBUG_ERROR, "%a.%d GetApropriateTokenUser ret status = %x\n", __FUNCTION__, __LINE__, Status));

    pUsrInfo = UserGetLastFoundedInfo ();
    UsrId = USER_UNKNOWN_ID;
    if (pUsrInfo && pUsrInfo->UserId) {
      UsrId = pUsrInfo->UserId;
    }

    LOG((DEBUG_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    
    if (VerifyLastStatus != OSSL_VERIFY_SUCCESS) {      
      ShowVerifyErrorAndSaveHistory(CurrentHiiHandle, NULL,
        UsrId, isShowMessage, VerifyLastStatus);
      Status = EFI_ABORTED;
      break;
    }

    Status = VerifyUserWithPkey ();
    LOG ((EFI_D_ERROR, "%a.%d Status=%r\n", 
      __FUNCTION__, __LINE__, Status));
    if (EFI_ERROR(Status)) {
      if(Status == EFI_INCOMPATIBLE_VERSION)
		  SetOsslLastError(OSSL_ERR_RUTOKEN_SUPPORT_ERR);
	  else
		  SetOsslLastError(OSSL_ERR_VERIFY_WITH_USER_PKEY);
		  
	  ShowVerifyErrorAndSaveHistory(CurrentHiiHandle, NULL, UsrId, isShowMessage, VerifyLastStatus);
	  
      Status = EFI_ABORTED;     
    }
    break;
    /* if User not found, try to next certificate */
  }
_exit:

  return Status;
}

EFI_STATUS
ProcessingCA(
  VOID
  )
{  
  CERTIFICATE_STORAGE *pCA;
  USER_INFO *pUsrInfo;
  //EFI_STATUS Status;
/*
  LOG((EFI_D_ERROR, "%a.%d Start\n", __FUNCTION__, __LINE__));
  LOG((EFI_D_ERROR, "hCACertSession=0x%X\n", hCACertSession));

  if (hCACertSession != CK_INVALID_HANDLE) {
    LOG((EFI_D_ERROR, "%a.%d Allready Processed!!!\n", 
      __FUNCTION__, __LINE__));
    return EFI_SUCCESS;
  }
*/
  pUsrInfo = GetCurrentUser();
  if (pUsrInfo && pUsrInfo->AuthType == AUTH_TYPE_TOKEN) {
    LOG((EFI_D_ERROR, "%a.%d Token-user allready present!\n",
      __FUNCTION__, __LINE__));
    return EFI_SUCCESS;
  }
  
  pCA = ChainGetData();
  if (NULL == pCA || pCA->DataLen == 0) {
    LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    ShowErrorPopup(CurrentHiiHandle, 
      HiiGetString(CurrentHiiHandle, 
        STRING_TOKEN(STR_ERR_CA_NOT_LOADED), NULL));
    return EFI_INVALID_PARAMETER;
  }

  LOG((EFI_D_ERROR, "%a.%d pCA->DataLen=%d\n", 
    __FUNCTION__, __LINE__, pCA->DataLen));

  DumpBytes_(pCA->Data, pCA->DataLen);
/*
  aCACertCreateAttrs[3].pValue = pCA->Data;
  aCACertCreateAttrs[3].ulValueLen = pCA->DataLen;

  LOG((EFI_D_ERROR, "aSessionCACertLabel [0]=0x%02X [1]=0x%02X [2]=0x%02X\n",
    aSessionCACertLabel[0], aSessionCACertLabel[1], aSessionCACertLabel[2]));
  
  if (CKR_OK != C_CreateObject (hSession, aCACertCreateAttrs, 
      ARRAY_ITEMS(aCACertCreateAttrs), &hCACertSession)) {
    LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    goto _exit;
  }

  LOG((EFI_D_ERROR, "%a.%d hCACertSession=0x%X!!!\n", 
    __FUNCTION__, __LINE__, hCACertSession));
*/
  if (OSSL_SUCCESS_CONVERT_TO_ASN != CheckChainFormat(pCA->Data, pCA->DataLen)) {
    ShowErrorPopup(CurrentHiiHandle,
      HiiGetString(CurrentHiiHandle, STRING_TOKEN(MSG_UNKNOWN_FORMAT_OF_CHAIN),
        NULL));
    goto _exit;
  }

/* Check for CA expired */
/*
  Status = CheckForCertExpire(hSession, hCACertSession);
  if (EFI_SUCCESS != Status) {
    LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    ShowErrorPopup(CurrentHiiHandle,
      HiiGetString(CurrentHiiHandle, 
        Status == EFI_TIMEOUT ? 
          STRING_TOKEN(STR_ERR_CA_EXPIRE_VALIDITY) : 
          STRING_TOKEN(STR_ERR_CA_NOT_VALIDITY),
        NULL));
    goto _exit;
  }
*/
  return EFI_SUCCESS;

_exit:
  LOG((EFI_D_ERROR, "%a.%d ===EXIT===\n", __FUNCTION__, __LINE__));
/*
  if (hCACertSession != CK_INVALID_HANDLE) {
    if (CKR_OK != C_DestroyObject (hSession, hCACertSession)) {
      LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    }
    hCACertSession = CK_INVALID_HANDLE;
  }
*/
  return EFI_ABORTED;
}



EFI_STATUS
ProcessingTokenLogin(
  VOID
  ) 
{
  EFI_STATUS Status = EFI_ABORTED;
  
  LOG((EFI_D_ERROR, "%a.%d Start\n", __FUNCTION__, __LINE__));
  
  Status = ProcessingCA();
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    goto _exit;
  }

  gCurUserInfo = NULL;
  Status = ProcessingTokenUser();
 
  if (EFI_SUCCESS == Status) {
    CHAR16 TmpStr16[50];
    gCurUserInfo = UserGetLastFoundedInfo();

    if (gCurUserInfo->Flags & USER_BLOCKED_FLAG) {
      UnicodeSPrint(TmpStr16, sizeof(TmpStr16), L"%s: %s %s", 
        HiiGetString(CurrentHiiHandle, 
          gCurUserInfo->Flags & USER_ADMIN_FLAG ? 
            STRING_TOKEN(STR_USERS_TYPE_ADMIN) : 
            STRING_TOKEN(STR_USERS_TYPE_USER), NULL),
        gCurUserInfo->UserName,
        HiiGetString(CurrentHiiHandle, 
            STRING_TOKEN(STR_BLOCK_FLAG_ON), NULL));
      ShowErrorPopup(CurrentHiiHandle, TmpStr16);
      Status = EFI_ACCESS_DENIED;
      goto _exit;
    }
    
    LOG((EFI_D_ERROR, "%a.%d We are found User:\n", __FUNCTION__, __LINE__));
    LOG((EFI_D_ERROR, "UserName=\"%s\" UserFIO=\"%s\", UserId=\"%d\"\n", 
      gCurUserInfo->UserName, gCurUserInfo->UserFIO, gCurUserInfo->UserId));
    UnicodeSPrint(TmpStr16, sizeof(TmpStr16), L"%s: %s", 
      HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_CURRENT_USER), NULL),
      gCurUserInfo->UserName);

    if (/*CheckPcdDebugPropertyMask() && */
        gCurUserInfo->AuthType != AUTH_TYPE_TOKEN_AND_PASS) {
      ShowSuccessPopup(CurrentHiiHandle, TmpStr16);
    }

    return Status;
  } 

_exit:
  if (hClientCertSession != CK_INVALID_HANDLE) {
    C_FindObjectsFinal (hSession);
    eTokenLikeSmartCardResetSearch ();
  }
#if 0  
  if (hClientCertSession != CK_INVALID_HANDLE) {
    C_DestroyObject (hSession, hClientCertSession);
    hClientCertSession = CK_INVALID_HANDLE;
  }
  if (hCACertSession != CK_INVALID_HANDLE) {
    if (CKR_OK != C_DestroyObject (hSession, hCACertSession)) {
      LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    }
    hCACertSession = CK_INVALID_HANDLE;
  }
#endif
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
  } else {
    LOG((EFI_D_ERROR, "%a.%d Done!\n", __FUNCTION__, __LINE__));
  }
  return Status;
}


EFI_STATUS
TokenCheckSelfSignedCert(
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE hCert,
  IN VOID *CertId,
  IN UINTN CertIdLen  
  )
{
  EFI_STATUS Status;
  UINT8 *certData = NULL;
  UINTN certDataLen = 0;

  if (NULL == CertId || 0 == CertIdLen) {
    LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }
  if (hSession == CK_INVALID_HANDLE) {
    LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  Status = GetCertificateData (hSession, hCert,
                               &certData, &certDataLen);
  if (EFI_ERROR(Status))
    return EFI_INVALID_PARAMETER;

  if (VerifySelfSignedCertificate(certData, certDataLen) != OSSL_VERIFY_SUCCESS) {
    LOG((EFI_D_ERROR, "%a.%d Error while verify signature!\n", 
      __FUNCTION__, __LINE__));
    Status = EFI_CRC_ERROR;
  }

  if (certData != NULL)
    FreePool(certData);
  
  return Status;
}

EFI_STATUS
TokenSessionAndLogin(
  VOID
  )
{
  EFI_STATUS Status = EFI_ABORTED;
  CK_RV rv;
  CK_SLOT_INFO SlotInfo;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  ZeroMem (UserPIN, sizeof (UserPIN));
  UserPIN_Len = 0;
  
  Status = TokenEnterPIN(UserPIN, &UserPIN_Len);
  if (!EFI_ERROR(Status)) {
    SaveUserPassOrPin (UserPIN, NULL);
  }

  if (!GetTokenInserted()) {
    LOG((EFI_D_ERROR, "%a.%d Token was removed!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }

  LOG((EFI_D_ERROR, "%a.%d Call TokenDestroySession\n", 
    __FUNCTION__, __LINE__));
  TokenDestroySession();

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  rv = C_Initialize(NULL_PTR);
  if (rv != CKR_OK && rv != CKR_CRYPTOKI_ALREADY_INITIALIZED) {
    LOG((EFI_D_ERROR, "%a.%d Error rv=%x\n", __FUNCTION__, __LINE__, rv));
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

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  rv = C_GetSlotInfo(0, &SlotInfo);
  if (rv != CKR_OK) {
    LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    MsgInternalError(INT_ERR_C_GETSLOTINFO);
    return EFI_ABORTED;
  }

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  rv = C_OpenSession(0, CKF_SERIAL_SESSION | CKF_RW_SESSION, 
      NULL_PTR, NULL_PTR, &hSession);
  if (rv != CKR_OK) {
    LOG((EFI_D_ERROR, "%a.%d Error while open session! {%X}\n", 
      __FUNCTION__, __LINE__, rv));    
    MsgInternalError(INT_ERR_C_OPENSESSION);
    goto _exit;
  }

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  rv = C_Login(hSession, CKU_USER, UserPIN, UserPIN_Len);
  if (rv != CKR_OK) {
    USER_INFO *pUsrInfo;
    UINT8 UsrId;

    pUsrInfo = GetCurrentUser();
    UsrId = USER_UNKNOWN_ID;
    if (pUsrInfo && pUsrInfo->UserId) {
      UsrId = pUsrInfo->UserId;
    }    
    LOG((EFI_D_ERROR, "%a.%d UserLogin Error! {%X} {%p} {%X}\n", 
      __FUNCTION__, __LINE__, rv, pUsrInfo, UsrId));
    if (UsrId == USER_UNKNOWN_ID) {
      LocksUpdateWrongPinCnt ();
    }
    HistoryAddRecord(HEVENT_WRONG_PIN, UsrId, SEVERITY_LVL_ERROR, 0);
    
    //disable extract certificates
    SetExtractTokenCert(FALSE);

    Status = EFI_ABORTED;
    goto _exit;

  }

  SetExtractTokenCert(TRUE);

  Status = EFI_SUCCESS;
_exit:
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    TokenDestroySession();
  }
  LOG((EFI_D_ERROR, "%a.%d Status = %x\n", __FUNCTION__, __LINE__, Status));
  return Status;
}

STATIC
VOID
ErrorWhileSessionAndLogin(
  IN EFI_HII_HANDLE HiiHandle,
  IN EFI_STATUS Result
  )
{
  CHAR16 *HiiString;
  SetMouseEnableVar(FALSE);
  if (GetTokenInserted()) {
    HiiString = HiiGetString(HiiHandle, STRING_TOKEN(STR_WRONG_PIN),
      NULL);
  } else {
    HiiString = HiiGetString(HiiHandle, 
      STRING_TOKEN(STR_ERR_TOKEN_WAS_REMOVED),
      NULL);
  }
  ShowErrorPopup(HiiHandle, HiiString);
  SetMouseEnableVar(TRUE);
}


EFI_STATUS
TokenCheckPin(
  VOID
  )
{
  EFI_STATUS Status = EFI_SUCCESS;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  SetMouseEnableVar(FALSE);
  if (EFI_SUCCESS != TokenSessionAndLogin()) {
    LOG((EFI_D_ERROR, "%a.%d UserLogin Error!\n", 
      __FUNCTION__, __LINE__));    
    Status = EFI_ACCESS_DENIED;
    ErrorWhileSessionAndLogin(CurrentHiiHandle, Status);
  }
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  SetMouseEnableVar(TRUE);
  return Status;
}

/**
  This function perform login for local users
  checking for pin-code and find appropriate local user

  @param Event  - token insert event (not used now, but future ...)
  @param Context - context from caller
  @param bRestartIfNoTokenUsersCards - flag for restart if no users card at all

  @retval EFI_SUCCESS    The function complete successfully (User login).
  @return EFI_NO_MEDIA   No device found (in this case just leave callback).
  @return EFI_NOT_STARTED  Pin-code accepted, but token accepted as storage
                                        (in this case just leave callback).
  @return EFI_ACCESS_DENIED Wrong pin-code
  @return EFI_NOT_FOUND Pin-code accepted but no appropriate local user found
**/
STATIC
EFI_STATUS
ProcessingLocalUserLogin(
  IN EFI_EVENT Event,
  IN VOID      *Context,
  IN BOOLEAN   bRestartIfNoTokenUsersCards
  )  
{
  EFI_STATUS Status;

  LOG ((EFI_D_ERROR, "%a.%d Start\n", __FUNCTION__, __LINE__));
  
/* Check for token-user present */
  Status = UsersGetNextTokenUser(TRUE);
  if (EFI_ERROR(Status)) {
    if (bRestartIfNoTokenUsersCards) {
      ShowErrorPopup(CurrentHiiHandle, 
        HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(STR_NO_CARDS_FOR_TOKEN_USERS), NULL));
      gRT->ResetSystem (EfiResetCold, EFI_SUCCESS, 0, NULL);
    }
  }
  
  UserCleanLastFoundedInfo();
  
  Status = TokenCheckPin();
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    TokenDestroySession();
  } else {
    Status = ProcessingTokenLogin();
    if (EFI_ERROR(Status)) {
      Status = EFI_NOT_FOUND;
      TokenDestroySession();
    }
  }
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return Status;
}

//------------------------------------------------------------------------------
/*! \brief Processing a ldap token login error */
/*! If chkStatus is LDAP_SEARCH_SUCCESS just return */
/*! Add record to the history log and show an error popup */
/*! \param[in] messageIfError TRUE if need to show error popups, FALSE overwise
    \param[in] chkStatus Status of a login */
//------------------------------------------------------------------------------
STATIC
VOID
ProcessLdapTokenLoginError(
  IN BOOLEAN messageIfError,
  IN UINTN chkStatus
  )
{
  USER_INFO *pUsrInfo;
  UINT8 UsrId;
    
  pUsrInfo = GetCurrentUser();
  UsrId = USER_LDAP_LOG_ID;
  if (pUsrInfo && pUsrInfo->UserId) {
    UsrId = pUsrInfo->UserId;
  }
  DEBUG((DEBUG_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  ShowLdapErrorAndSaveHistory(CurrentHiiHandle, CurrentLanguage,
    UsrId, messageIfError, chkStatus);

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! brief Processing a certificate verify error */
/*! if verifyStatus is OSSL_VERIFY_SUCCESS just return */
/*! \param[in] messageIfError TRUE if need to show error popups, FALSE overwise
    \param[in] verifyStatus Status of a verification */
//------------------------------------------------------------------------------
STATIC
VOID
ProcessVerifyTokenError(
  IN BOOLEAN messageIfError,
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

  ShowVerifyErrorAndSaveHistory(CurrentHiiHandle, CurrentLanguage,
    UsrId, messageIfError, verifyStatus);

  return;
}
//------------------------------------------------------------------------------

/**
  Proccess a login of a user using ldap and token

  @param Event  Token insert event (not used now, but future ...)
  @param Context Context from caller

  @retval EFI_SUCCESS    The function complete successfully (User login)
  @retval EFI_ABORTED    If the error has occured
**/
STATIC
EFI_STATUS
ProcessingLdapTokenUserLogin (
  IN EFI_EVENT Event,
  IN VOID      *Context
  )  
{
  CHAR8 *certMatchValue = NULL, *userDN = NULL;
  
  UINTN       chkStatus = LDAP_SEARCH_ERROR, permissions = NOT_ALLOW_TO_LOGIN;
  UINTN       numOfCerts = 0, caCount;
  UINT8       userID = 0, i;
  CK_ULONG    Count  = 0;
  EFI_STATUS  Status;
  CK_RV       rv;

  BOOLEAN     matchedCertificate = FALSE;
  BOOLEAN     messageIfError     = FALSE;
  BOOLEAN     isAdmin            = FALSE;
  BOOLEAN     isCertificateValid = TRUE;

  CHAR8       *accountName = NULL;
  CHAR16      *name = NULL;
  
  UserCertificateData_t caData = {0, NULL};
  
  LOG((EFI_D_ERROR, "%a.%d \n", __FUNCTION__, __LINE__));
  
  if (CheckPcdDebugPropertyMask() == TRUE) {
    messageIfError = TRUE;
  }
  
  Status = gBS->LocateProtocol (
                  &gLdapAuthDxeProtocolGuid,
                  NULL,
                  (VOID **) &pLdapAuthProtocol
                  );
  if (Status != EFI_SUCCESS) {
    LOG((EFI_D_ERROR, "%a.%d Status=%d\n", __FUNCTION__, __LINE__, Status));
    return EFI_ABORTED;
  }
  
  if (pLdapAuthProtocol->LdapConfigOp.GetLdapAuthUsageStatus() != USE_LDAP_AUTH) {
    return EFI_ABORTED;
  }

  ShowInfoPopup(CurrentHiiHandle, 
    HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_CHECK_LDAP_USER),
      CurrentLanguage));
  
  Status = TokenCreateSession(UserPIN);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  
  if (pLdapAuthProtocol->LdapConfigOp.IsUseTLS() == TRUE) {
    //-------------------------------------------------------
    // Check an using of a TLS and try to get OpenSSL.cnf from fv and load it
    //-------------------------------------------------------
    tlsConfig_t config = MakeTlsConfig(ChainGetData()->Data, ChainGetData()->DataLen);
    Status = pLdapAuthProtocol->LdapConfigOp.SetOpensslConfig(config);
    if (Status != EFI_SUCCESS) {
       LOG((EFI_D_ERROR, "%a.%d: Can't set OpenSSL.cnf. Will be used default settings\n", __FUNCTION__, __LINE__));
    }
  }
   
  while(1) {
    rv = SearchTokenObject(hSession, &hClientCertSession, 1, &Count);
    if (rv != CKR_OK || Count != 1) {
      break;
    }
    
    for(i = 0; i < MAX_TRY_COUNT; i++) {
    
      if (certMatchValue != NULL) {
        LOG((EFI_D_ERROR, "%a.%d: Free: %a\n", __FUNCTION__, __LINE__, certMatchValue));
        FreePool(certMatchValue);
        certMatchValue = NULL;
      }
      
      if (i == 0) {// try for an Active Directory
        certMatchValue = MakeUserCertificateMatchingValueByBinary(hSession, hClientCertSession);
      } else if (i == 1) {// try for a LDAP server
        certMatchValue = MakeUserCertificateMatchingValueByIssuerFieldOssl(hSession, hClientCertSession);
      } else {
        break;
      }
        
      if (userDN != NULL) {
          LOG((EFI_D_ERROR, "%a.%d: Free: %a\n", __FUNCTION__, __LINE__, certMatchValue));
          FreePool(userDN);
          userDN = NULL;
        }
        
      //------------------------------------------------------------------------------
      // Search an user with an userCertificate, which corresponds to the certMatchValue
      //------------------------------------------------------------------------------
      userDN = pLdapAuthProtocol->SearchUserCertificateFromLdapServer(certMatchValue, &accountName, &numOfCerts, &chkStatus);
      if (chkStatus == LDAP_SEARCH_SUCCESS) {
        if (numOfCerts > 0) {
          LOG((EFI_D_ERROR, "%a.%d numOfCerts=%d\n", __FUNCTION__, __LINE__, numOfCerts));
          for(caCount = 0; caCount < numOfCerts; caCount++) {
             pLdapAuthProtocol->GetUserCertificateByNum(caCount, &caData);
             if (caData.data != NULL) {
               matchedCertificate = CompareWithTokenCert(hSession, hClientCertSession, &caData);
               if (TRUE == matchedCertificate) {
                 name = AllocatePool (AsciiStrSize(accountName) * sizeof(CHAR16));
                 if (name == NULL) {
                   LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
                   chkStatus = LDAP_OUT_OF_MEMORY;
                   Status = EFI_OUT_OF_RESOURCES;
                   matchedCertificate = FALSE;
                 } else {
                   AsciiStrToUnicodeStr (accountName, name);
                 }
                 goto _SEARCH_EXIT;
               }
             }
          }
        }
      } else if (chkStatus == LDAP_SEARCH_ERROR) {
        continue;
      } else {
        goto _SEARCH_EXIT;
      }
    }
  }
  
_SEARCH_EXIT:
  if (TRUE == matchedCertificate) {
    // Verify certificate
    rv = VerifyTokenObject(hSession, hClientCertSession);
    if (rv != CKR_OK) {
      Status = EFI_ABORTED;
      isCertificateValid = FALSE;
      permissions = NOT_ALLOW_TO_LOGIN;
    } else {
      Status = VerifyUserWithPkey ();
      DEBUG ((EFI_D_INFO, "%a.%d Status=%r\n", 
        __FUNCTION__, __LINE__, Status));
      if (EFI_ERROR (Status)) {
		if(Status == EFI_INCOMPATIBLE_VERSION)
		  SetOsslLastError(OSSL_ERR_RUTOKEN_SUPPORT_ERR);
		else
		  SetOsslLastError(OSSL_ERR_VERIFY_WITH_USER_PKEY);	

        Status = EFI_ABORTED;
        isCertificateValid = FALSE;
        permissions = NOT_ALLOW_TO_LOGIN;
      } else {
      // Check user permission
        permissions = CheckLoginPermissionWithUserDN(userDN, &Status);
        switch(permissions) {
        case ALLOW_TO_LOGIN_ADMIN_FULL:
        case ALLOW_TO_LOGIN_ADMIN_FULL_REMOTE:
        case ALLOW_TO_LOGIN_ADMIN_AUDIT:
        case ALLOW_TO_LOGIN_ADMIN_AUDIT_REMOTE:
          isAdmin = TRUE;
        case ALLOW_TO_LOGIN_USER:
        case ALLOW_TO_LOGIN_USER_REMOTE:
          break;
        case NOT_ALLOW_TO_LOGIN:
        case ALLOW_TO_LOGIN_GUEST:
        default:
          chkStatus = LDAP_SEARCH_ERROR;
          Status = EFI_ABORTED;
          break;
        }
      }
    }

    if (EFI_SUCCESS == AddLdapUser(name, userDN, isAdmin, TRUE, permissions, &userID)) {
      SetCurrentUser(UserGetLastFoundedInfo());
    } else {
      Status = EFI_ABORTED;
      ShowErrorPopup(CurrentHiiHandle,
        HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_LDAP_UNKNOWN_ERROR), CurrentLanguage));
      HistoryAddRecord(HEVENT_LDAP_USER_ADD_ERROR, USER_LDAP_LOG_ID, SEVERITY_LVL_ERROR, 1);
    }

  } else {
    Status = EFI_ABORTED;
  }

  LOG ((EFI_D_ERROR, 
    "%a.%d Status=%r isCertificateValid=%d GetOsslLastError()=%d\n", 
        __FUNCTION__, __LINE__, Status, 
        isCertificateValid, GetOsslLastError()));

  if (isCertificateValid == TRUE) {
    ProcessLdapTokenLoginError(messageIfError, chkStatus);
  } else {
    ProcessVerifyTokenError(TRUE, GetOsslLastError());
  }

  SearchTokenObjectsFinish(hSession);
  TokenDestroySession();

  if (userDN != NULL) {
    LOG((EFI_D_ERROR, "%a.%d: Free: %a\n", __FUNCTION__, __LINE__, userDN));
    FreePool(userDN);
  }

  if (certMatchValue != NULL) {
    LOG((EFI_D_ERROR, "%a.%d: Free: %a\n", __FUNCTION__, __LINE__, certMatchValue));
    FreePool(certMatchValue);
  }

  pLdapAuthProtocol->CleanLdapConnection();
  pLdapAuthProtocol->FreeReceivedUserCertificates();

  if (name != NULL) {
    FreePool (name);
  }
  if (accountName != NULL) {
    FreePool (accountName);
  }

  LOG((EFI_D_ERROR, "%a.%d: Status: %d\n", __FUNCTION__, __LINE__, Status));

  return Status;
}

//------------------------------------------------------------------------------
/*! \brief Compare attributes
/*! Compare an attribute from a setting with an attribute from the user certificate */
/*! \param[in] *attrFromSetting Attribute from the setting
    \param[in] *attrFromCerts Attribute from the user certificate */
/*! \retval TRUE If attributes are equal
    \retval FALSE If attributes aren't equal */
//------------------------------------------------------------------------------
STATIC
BOOLEAN
IsEqualAttr (
  const CHAR16 *attrFromSetting,
  CK_ATTRIBUTE *attrFromCerts
  )
{
  BOOLEAN retval = FALSE;
  CHAR8* attrToCmp = NULL;
  UINTN  attrLen;
  
  LOG((EFI_D_ERROR, "%a.%d\nattrToCmp: %s\nattrFromCA: %a\n", __FUNCTION__, __LINE__, attrFromSetting, attrFromCerts->pValue));

  if ((NULL == attrFromSetting) || (StrLen(attrFromSetting) == 0)) {
    LOG((EFI_D_ERROR, "%a.%d: attrFromSetting is empty!\n", __FUNCTION__, __LINE__));
    return FALSE;
  }
  
  attrLen = StrLen(attrFromSetting);
  
  attrToCmp = AllocateZeroPool(attrLen + sizeof(CHAR8));
  if (NULL == attrToCmp) {
    LOG((EFI_D_ERROR, "%a.%d: Out of memory!!\n", __FUNCTION__, __LINE__));
    return FALSE;
  }
  UnicodeStrToAsciiStr(attrFromSetting, attrToCmp);
  if (AsciiStrStr(attrFromCerts->pValue, attrToCmp) != NULL) {
    LOG((EFI_D_ERROR, "%a.%d: Equal!!\n", __FUNCTION__, __LINE__));
    retval = TRUE;
  } else {
    LOG((EFI_D_ERROR, "%a.%d: Not equal!!\n", __FUNCTION__, __LINE__));
    retval = FALSE;
  }

  if (attrToCmp != NULL)
    FreePool(attrToCmp);
    
  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Compare a data form certificate */
/*! \param[in] hSession
    \param[in] hCert
    \param[in] cmpType A combination of types of a comparison data */
/*! \retval TRUE If comperison data is equal
    \retval FALSE If comperison data isn't equal */
//------------------------------------------------------------------------------
STATIC
BOOLEAN
CompareCertificateData (
  IN  CK_SESSION_HANDLE hSession,
  IN  CK_OBJECT_HANDLE hCert,
  IN  UINT8 cmpType
  )
{
  CK_ATTRIBUTE attr;
  CK_RV        rv;
  BOOLEAN      equalData = FALSE;
  
  LOG((EFI_D_ERROR, "%a.%d: %d\n", __FUNCTION__, __LINE__));
  
  if (0 == cmpType)
    return FALSE;
  
  if ((cmpType & CN_CMP) == CN_CMP) {
    rv = GetSubjectCommonName(hSession, hClientCertSession, &attr);
    if (CKR_OK == rv) {
      equalData = IsEqualAttr(GetCmpDataByType(CN_CMP), &attr);
      if (FALSE == equalData)
        return FALSE;
    } else {
      LOG((EFI_D_ERROR, "%a.%d Error!! rv: %d\n", __FUNCTION__, __LINE__, rv));
      return FALSE;
    }
  }
  if ((cmpType & OU_CMP) == OU_CMP) {
    rv = GetSubjectOrganizationUnitName(hSession, hClientCertSession, &attr);
    if (CKR_OK == rv) {
      LOG((EFI_D_ERROR, "%a.%d IsEqualAttr\n", __FUNCTION__, __LINE__));
      equalData = IsEqualAttr(GetCmpDataByType(OU_CMP), &attr);
      if (FALSE == equalData)
        return FALSE;
    } else {
      LOG((EFI_D_ERROR, "%a.%d Error!! rv: %d\n", __FUNCTION__, __LINE__, rv));
      return FALSE;
    }
  }
  if ((cmpType & SUBJECT_CMP) == SUBJECT_CMP) {
    rv = GetSubjectDecodedN(hSession, hClientCertSession, &attr);
    if (CKR_OK == rv) {
      equalData = IsEqualAttr(GetCmpDataByType(SUBJECT_CMP), &attr);
      if (attr.pValue != NULL)
        FreePool(attr.pValue);
      if (FALSE == equalData) 
        return FALSE;
    } else {
      LOG((EFI_D_ERROR, "%a.%d Error!! rv: %d\n", __FUNCTION__, __LINE__, rv));
      return FALSE;
    }
   }
   
    
  return TRUE;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Auth local guest user */
/*! \retval EFI_ABORTED Authenticate is failed. See debug log for more details
    \retval EFI_SUCCESS Guest has been passed the authenticate */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
AuthLocalGuest (
  VOID
  )
{
  UINT8        cmpType;
  BOOLEAN      authPass = FALSE;
  CK_ULONG     Count  = 0;
  EFI_STATUS   Status;
  CK_RV        rv;
  
  LOG((EFI_D_ERROR, "%a.%d \n", __FUNCTION__, __LINE__));
  
  Status = TokenCreateGuestSession();
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }
  
  cmpType = GetTypeOfComparison();
  
  while(1) {
    rv = SearchTokenVerifyObject(hSession, &hClientCertSession, 1, &Count);   
    if (rv != CKR_OK || Count != 1) {
      LOG((EFI_D_ERROR, "%a.%d rv: %d\n", __FUNCTION__, __LINE__, rv));
      break;
    }
    
    authPass = CompareCertificateData(hSession, hClientCertSession, cmpType);
    if (TRUE == authPass)
      break;
  }
  
  LOG((EFI_D_ERROR, "%a.%d \n", __FUNCTION__, __LINE__));

  SearchTokenObjectsFinish(hSession);
  TokenDestroySession();
  
  if (TRUE == authPass)
    return EFI_SUCCESS;
  else
    return EFI_ABORTED;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Auth ldap guest user */
/*! \param[in] messageIfError TRUE if need to show error popups, FALSE overwise
    \param[out] Status of the operation */
/*! \return User DN for the guest user if auth is success, NULL overwise */
//------------------------------------------------------------------------------
STATIC
CHAR8*
AuthLdapGuest (
  IN BOOLEAN messageIfError,
  OUT CHAR16 **name,
  OUT EFI_STATUS *Status
  )
{
  CK_RV       rv;
  CK_ULONG    Count  = 0;
  UINT8       i;
  UINTN       attrFromCerts = 0, certCount, chkStatus = LDAP_SEARCH_ERROR;
  CHAR8       *certMatchValue = NULL, *userDN = NULL;
  CHAR8       *issuerAttributeList[NUM_OF_ISSUER_ATTRs];
  BOOLEAN     matchedCertificate = FALSE;
  UserCertificateData_t certData = {0, NULL};
  CHAR8       *accountName = NULL;
  
  LOG((EFI_D_ERROR, "%a.%d \n", __FUNCTION__, __LINE__));
  
  ZeroMem(issuerAttributeList, sizeof(issuerAttributeList));
  
  *Status = TokenCreateGuestSession();
  if (EFI_ERROR(*Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    *Status = EFI_ABORTED;
    return NULL;
  }
  
  *Status = gBS->LocateProtocol (
                  &gLdapAuthDxeProtocolGuid,
                  NULL,
                  (VOID **) &pLdapAuthProtocol
                  );
  if (*Status != EFI_SUCCESS) {
    LOG((EFI_D_ERROR, "%a.%d Status=%d\n", __FUNCTION__, __LINE__, *Status));
    SearchTokenObjectsFinish(hSession);
    TokenDestroySession();
    *Status = EFI_ABORTED;
    return NULL;
  }
  
  if (pLdapAuthProtocol->LdapConfigOp.GetLdapAuthUsageStatus() != USE_LDAP_AUTH) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    SearchTokenObjectsFinish(hSession);
    TokenDestroySession();
    *Status = EFI_ABORTED;
    return NULL;
  }
  
  if (pLdapAuthProtocol->LdapConfigOp.IsUseTLS() == TRUE) {
    //-------------------------------------------------------
    // Check an using of a TLS and try to get OpenSSL.cnf from fv and load it
    //-------------------------------------------------------
    tlsConfig_t config = MakeTlsConfig(ChainGetData()->Data, ChainGetData()->DataLen);
    *Status = pLdapAuthProtocol->LdapConfigOp.SetOpensslConfig(config);
    if (*Status != EFI_SUCCESS) {
       LOG((EFI_D_ERROR, "%a.%d: Can't set OpenSSL.cnf. Will be used default settings\n", __FUNCTION__, __LINE__));
    }
  }
  
  while(1) {
    rv = SearchTokenVerifyObject(hSession, &hClientCertSession, 1, &Count);   
    if (rv != CKR_OK || Count != 1) {
      break;
    }
  
    for(i = 0; i < MAX_TRY_COUNT; i++) {
    
      if (certMatchValue != NULL) {
        LOG((EFI_D_ERROR, "%a.%d: Free: %a\n", __FUNCTION__, __LINE__, certMatchValue));
        FreePool(certMatchValue);
        certMatchValue = NULL;
      }

      if (i == 0) { // try for an Active Directory
        certMatchValue = MakeUserCertificateMatchingValueByBinary(hSession, hClientCertSession);
      } else if (i == 1) { // try for a LDAP server
        certMatchValue = MakeUserCertificateMatchingValueByIssuerFieldOssl(hSession, hClientCertSession);
      } else {
        break;
      }

      //------------------------------------------------------------------------------
      // Search a guest attribute and an user with an userCertificate, which corresponds 
      // to the certMatchValue
      //------------------------------------------------------------------------------
      userDN = pLdapAuthProtocol->SearchUserCertificateFromLdapServer(certMatchValue, &accountName, &attrFromCerts, &chkStatus);
      if (chkStatus == LDAP_SEARCH_SUCCESS) {
        LOG((EFI_D_ERROR, "%a.%d attrFromCerts=%d\n", __FUNCTION__, __LINE__, attrFromCerts));
        if (attrFromCerts > 0) {
          for(certCount = 0; certCount < attrFromCerts; certCount++) {
             pLdapAuthProtocol->GetUserCertificateByNum(certCount, &certData);
               if (certData.data != NULL) {
                 matchedCertificate = CompareWithTokenCert(hSession, hClientCertSession, &certData);
                 if (TRUE == matchedCertificate) {
                   *name = AllocatePool (AsciiStrSize(accountName) * sizeof(CHAR16));
                   if (*name == NULL) {
                     LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
                     chkStatus = LDAP_OUT_OF_MEMORY;
                     *Status = EFI_OUT_OF_RESOURCES;
                     matchedCertificate = FALSE;
                   } else {
                     AsciiStrToUnicodeStr (accountName, *name);
                   }
                   goto _EXIT;
                 }
               }
          }
        }
      } else if (chkStatus == LDAP_SEARCH_ERROR) {
        continue;
      } else {
        goto _EXIT;
      }
    }
  }

_EXIT:

  if (TRUE == matchedCertificate) {
    *Status  = EFI_SUCCESS;
  } else {
    ProcessLdapTokenLoginError(messageIfError, chkStatus);
    *Status  = EFI_ABORTED;
  }
  
  SearchTokenObjectsFinish(hSession);
  TokenDestroySession();

  if (certMatchValue != NULL) {
    LOG((EFI_D_ERROR, "%a.%d: Free: %a\n", __FUNCTION__, __LINE__, certMatchValue));
    FreePool(certMatchValue);
  }
  
  pLdapAuthProtocol->FreeReceivedUserCertificates();
  
  return userDN;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Proccess a login of a guest user */
/*! \param[in] Event  - token insert event (not used now, but future ...)
    \param[in] Context - context from caller */
/*! \retval EFI_SUCCESS    The function complete successfully (User login)
    \retval EFI_ABORTED    If the error has occured */
//------------------------------------------------------------------------------
STATIC
EFI_STATUS
ProcessingGuestTokenUserLogin (
  IN EFI_EVENT Event,
  IN VOID      *Context
  )
{
  EFI_STATUS Status = EFI_SUCCESS;
  USER_INFO  *pUsrInfo;
  UINT8      UsrId;
  CHAR8      *userDN = NULL;
  UINTN      permissions;
  BOOLEAN    messageIfError = FALSE, isAdmin = FALSE;

  CHAR16     *name = NULL;
  
  LOG((EFI_D_ERROR, "%a.%d \n", __FUNCTION__, __LINE__));
  
  ShowInfoPopup(CurrentHiiHandle, 
    HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_CHECK_LDAP_USER),
      CurrentLanguage));
  
  if (CheckPcdDebugPropertyMask() == TRUE)
    messageIfError = TRUE;
  
  if ( PcdUtilsGetBoolUseLdapAuth() == TRUE) 
  {
    if (TRUE == IsUseLdapGuestLogin()) {
      //-------------------------------------------------------------------------
      // Auth a ldap guest user
      //-------------------------------------------------------------------------
      userDN = AuthLdapGuest(messageIfError, &name, &Status);
      if (Status == EFI_SUCCESS) {
        permissions = CheckLoginPermissionWithUserDN(userDN, &Status);
        pLdapAuthProtocol->CleanLdapConnection();
        switch(permissions) {
        case ALLOW_TO_LOGIN_GUEST:
          break;
        case ALLOW_TO_LOGIN_ADMIN_FULL:
        case ALLOW_TO_LOGIN_ADMIN_FULL_REMOTE:
        case ALLOW_TO_LOGIN_ADMIN_AUDIT:
        case ALLOW_TO_LOGIN_ADMIN_AUDIT_REMOTE:
          isAdmin = TRUE;
          if (TokenCheckPin() != EFI_SUCCESS)
            goto _error_exit;
          break;
        case NOT_ALLOW_TO_LOGIN:
        case ALLOW_TO_LOGIN_USER:
        case ALLOW_TO_LOGIN_USER_REMOTE:
        default:
          Status = EFI_ABORTED;
          break;
        }
        if (AddLdapUser(name, userDN, isAdmin, TRUE, permissions, &UsrId) == EFI_SUCCESS) {
          SetCurrentUser(UserGetLastFoundedInfo());
        
          if (userDN != NULL) {
            FreePool(userDN);
            userDN = NULL;
          }
          if (name != NULL) {
            FreePool (name);
            name = NULL;
          }
          
          if (Status == EFI_ABORTED)
            goto _error_exit;
        
          return EFI_SUCCESS;
        }
      } else {
        pLdapAuthProtocol->CleanLdapConnection();
      }
    }
  }
  
  if (TRUE == IsUseLocalGuestLogin()) {
    //-------------------------------------------------------------------------
    // Auth a token guest user
    //-------------------------------------------------------------------------
    if (AuthLocalGuest() == EFI_SUCCESS) {
      if (AddTokenGuestUser(L"token_guest_user", GetComparisonDataAsStr(), &UsrId) == EFI_SUCCESS) {
        if (CheckPcdDebugPropertyMask() == TRUE)
          LOG((EFI_D_ERROR, "%a.%d Success to aut GuestUser\n",
            __FUNCTION__, __LINE__));
        SetCurrentUser(UserGetLastFoundedInfo());
        if (name != NULL) {
          FreePool (name);
          name = NULL;
        }
        return EFI_SUCCESS;
      }
    }
  }
_error_exit:
  LOG((EFI_D_ERROR, "%a.%d Error to auth guest!\n", __FUNCTION__, __LINE__));
  ShowErrorPopup(CurrentHiiHandle,
    HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_GUEST_LOGIN_FAIL), CurrentLanguage));
    
  pUsrInfo = GetCurrentUser();
  UsrId = USER_UNKNOWN_ID;
  if (pUsrInfo && pUsrInfo->UserId) {
    UsrId = pUsrInfo->UserId;
  }
  HistoryAddRecord(HEVENT_GUEST_AUTH_FAIL, UsrId, SEVERITY_LVL_ERROR, 0);
  
  LOG((EFI_D_ERROR, "%a.%d \n", __FUNCTION__, __LINE__));
  
  if (name != NULL) {
    FreePool (name);
    name = NULL;
  }
  return EFI_ABORTED;
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
/*! \brief Get a ldap usage status */
/*! Helper function, only for this module. */
//------------------------------------------------------------------------------
STATIC
BOOLEAN
IsUseLdapAuth (
  VOID
  )
{
  if ( PcdUtilsGetBoolUseLdapAuth() == FALSE)
    return FALSE;
  else {
    EFI_STATUS          Status;
    LDAP_AUTH_PROTOCOL *pLdapAuthProtocol;

    Status = gBS->LocateProtocol (
                    &gLdapAuthDxeProtocolGuid,
                    NULL,
                    (VOID **) &pLdapAuthProtocol
                    );
    if (Status != EFI_SUCCESS) {
      LOG((EFI_D_ERROR, "%a.%d Status=%d\n", __FUNCTION__, __LINE__, Status));
      return FALSE;
    }
  
    if (pLdapAuthProtocol->LdapConfigOp.GetLdapAuthUsageStatus() != USE_LDAP_AUTH) {
      return FALSE;
    }
  
    return TRUE;
  }
}
//------------------------------------------------------------------------------

STATIC VOID TokenShowLoginForm()
{
  EFI_STATUS Status;
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));    
  SetMouseEnableVar(FALSE);
  Status = TokenSessionAndLogin();
  if (EFI_ERROR(Status)) {
    ErrorWhileSessionAndLogin(CurrentHiiHandle, Status);
  } else {
    ShowSuccessPopup(CurrentHiiHandle, 
      HiiGetString(CurrentHiiHandle,
        STRING_TOKEN(STR_PIN_OK), NULL));
  }

  
  Status = SetFormBrowserRefreshFlag();
  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", 
    __FUNCTION__, __LINE__, Status));
  
  SetMouseEnableVar(TRUE);
}

BOOLEAN VerifyOneTokenInstalled()
{
  EFI_STATUS Status;
  UINTN BufferSize;
  EFI_HANDLE *Buffer = NULL;

  // явно считаем кол-во протоколов для токенов и если их больше 1 возвращает FALSE

  BufferSize = 0;

  Status = gBS->LocateHandle(
    ByProtocol,
    &gSmartCardProtocolGuid,
    NULL,
    &BufferSize,
    Buffer
  );

  if (Status == EFI_BUFFER_TOO_SMALL) {
    DMSG("BufferSize = %x", BufferSize);
    if (BufferSize > sizeof(EFI_HANDLE) * 1) {
      DMSG("");
      return FALSE;
    }
  }
  DMSG("Status = %x", Status);
  return TRUE;
}

STATIC VOID
EFIAPI
SmartCardProtocolCallback (
  IN  EFI_EVENT Event,
  IN  VOID      *Context
  )
{
  EFI_TPL    OldTpl;
  EFI_STATUS Status;
  USER_INFO  *pUsrInfo;
  BOOLEAN    rebootFlag = FALSE;
  UINT8      UsrId;
  STATIC     BOOLEAN noReenter = FALSE;
  RAW_KEYBOARD_INPUT_PROTOCOL *RawKeyboard = NULL;
  EFI_STATUS RawKeyboardStatus = EFI_ABORTED;
  SMART_CARD_PROTOCOL* pSMArtCardProt = NULL;

  if (!VerifyOneTokenInstalled()) {
    OldTpl = EfiGetCurrentTpl();
    gBS->RestoreTPL (TPL_APPLICATION);

    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    ShowErrorPopup(CurrentHiiHandle,
      HiiGetString(CurrentHiiHandle,STRING_TOKEN(STR_TOKEN_DOUBLE_WARN),NULL));
    gRT->ResetSystem (EfiResetCold, EFI_SUCCESS, 0, NULL);
    
    gBS->RaiseTPL (OldTpl);
    return;
  }

	/* Отсекаем паразитный вызов после вызова TokenRegisterCallback */
	Status = gBS->LocateProtocol (
							&gSmartCardProtocolGuid,
							NULL,
							(VOID**)&pSMArtCardProt
							);

	if ( EFI_ERROR(Status) )return;
	gSmartCardProtocol = pSMArtCardProt;
	
	{
    /* Функциональный сброс токена/смарткарты */
		UINT8 rgbAtrString[54]; //FIXIT
		UINT16 nbLen = sizeof(rgbAtrString);

		Status = pSMArtCardProt->Reset (
										pSMArtCardProt,
										rgbAtrString,
										nbLen
										);
	}
	
  if (noReenter) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return;
  }
  noReenter = TRUE;
  
  OldTpl = EfiGetCurrentTpl();
  gBS->RestoreTPL (TPL_APPLICATION);
  
  /* cleaning signalled state of event */
  gBS->CheckEvent(Event);  

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  gSmartCardProtocol->EjectNotify = TokenEjectCallback;
  gSmartCardProtocol->EjectNotifyContext = NULL;

  HistoryAddRecord(HEVENT_TOKEN_INSERT_NOTIFY, GetCurrentUserId(), 
    SEVERITY_LVL_NOTICE, HISTORY_RECORD_FLAG_RESULT_OK);

  if (gSmartCardProtocol) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    ZeroMem(gSmartCardProtocol->SerialNumberStr8, 
      sizeof (gSmartCardProtocol->SerialNumberStr8));
    Status = gSmartCardProtocol->GetSn (
      gSmartCardProtocol
      );
    if (EFI_ERROR (Status)) {
      LOG((EFI_D_ERROR, "%a.%d Error! Status=%r\n", 
        __FUNCTION__, __LINE__, Status));
    }
  }
  
  if (IsTokenDisabled()) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    goto _restore_tpl;
  }

  Status = gBS->HandleProtocol(gST->ConsoleInHandle, &gRawKeyboardInputProtocolGuid, &RawKeyboard);
  LOG ((EFI_D_ERROR, "%a.%d HandleProtocol(RawKeyboard): Status = %r\n", __FUNCTION__, __LINE__, Status));
  if (Status == EFI_SUCCESS && RawKeyboard != NULL) {
    RawKeyboardStatus = RawKeyboard->UnLock(RawKeyboard);
    LOG ((EFI_D_ERROR, "%a.%d RawKeyboard->UnLock(): Status = %r\n", __FUNCTION__, __LINE__, RawKeyboardStatus));
  }

  if (GetTokenInserted()) {
    ShowErrorPopup(CurrentHiiHandle,
      HiiGetString(CurrentHiiHandle,STRING_TOKEN(STR_TOKEN_DOUBLE_WARN),NULL));
    gRT->ResetSystem (EfiResetCold, EFI_SUCCESS, 0, NULL);
  }  

  SetTokenInserted();

  //-------------------------------------------------------------------------
  // check for allready login or initial initialization
  //-------------------------------------------------------------------------

  if (GetMiiMode() && GetTokenDisableLogin()) {
    DEBUG((DEBUG_ERROR, "%a.%d TokenInserted= %x\n", __FUNCTION__, __LINE__, GetTokenInserted()));
    bTokenUpdateLogin = TRUE;
    goto _restore_tpl;
  }

  gST->ConOut->SetAttribute (gST->ConOut, 
    EFI_TEXT_ATTR(EFI_WHITE, EFI_BACKGROUND_BLACK));
  
  pUsrInfo = GetCurrentUser();
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));    
  
  if (((pUsrInfo != NULL) && (pUsrInfo->UserId != 0)) || GetMiiMode()) {
    TokenShowLoginForm();
    goto Done;
  }
  
  if (TokenUserLoginLocked()) {
    ShowErrorPopup(CurrentHiiHandle, 
      HiiGetString(CurrentHiiHandle,
        STRING_TOKEN(STR_TOKEN_LOGIN_NEED_RESTART), NULL));
    LOG((EFI_D_ERROR, "%a.%d Token login locked!\n", 
      __FUNCTION__, __LINE__));
    gRT->ResetSystem (EfiResetCold, EFI_SUCCESS, 0, NULL);
  }
  //-------------------------------------------------------------------------
  
  // Create a session to check CA on the next step
  Status = CreateSimpleTokenGuestSession();
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error while CA checking!\n", __FUNCTION__, __LINE__));
    goto _error;
  }
  TokenDestroySession();

  SetOsslLastError(OSSL_VERIFY_SUCCESS);
  if (GetAuthMode() == GUEST_AUTH_MODE) {
    //-------------------------------------------------------------------------
    // Login of a guest token user
    //-------------------------------------------------------------------------
    Status = ProcessingGuestTokenUserLogin(Event, Context);
    if (Status != EFI_SUCCESS)
      goto _error;
  } else {
    //-------------------------------------------------------------------------
    // Login of a local token user
    //-------------------------------------------------------------------------
    if(IsUseLdapAuth() == FALSE) {
        rebootFlag = TRUE;
    }
    Status = ProcessingLocalUserLogin(Event, Context, rebootFlag);
    if (Status == EFI_NO_MEDIA || Status == EFI_NOT_STARTED) {
      goto Done;
    } else if (EFI_NOT_FOUND == Status && 
               GetOsslLastError() != OSSL_ERR_VERIFY_WITH_USER_PKEY&&
			   GetOsslLastError() != OSSL_ERR_RUTOKEN_SUPPORT_ERR) {
      //-------------------------------------------------------------------------
      // Login of a ldap token user
      //-------------------------------------------------------------------------
      Status = ProcessingLdapTokenUserLogin(Event, Context);
      if (EFI_SUCCESS != Status) {
        SetOsslLastError(OSSL_VERIFY_SUCCESS);
        goto _error;
      }
    }
  }

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (Status == EFI_SUCCESS && ((TokenLoginOnly() && UserGetLastFoundedInfo())
      || UserTypeAdmin(UserGetLastFoundedInfo()))) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    gBS->SetWatchdogTimer (0, 0x0000, 0x00, NULL);
    SetCurrentUser(UserGetLastFoundedInfo());    
    if (TokenLoginOnly()) {
      LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      goto Done;
    }
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    AdminMainPageStart(CurrentHiiHandle, CurrentLanguage);
  }

  if (Status == EFI_SUCCESS) {
    goto Done;
  }

_error:
  pUsrInfo = GetCurrentUser();
  UsrId = USER_UNKNOWN_ID;
  if (pUsrInfo && pUsrInfo->UserId) {
    UsrId = pUsrInfo->UserId;
  }
  if (OSSL_ERR_VERIFY_WITH_USER_PKEY == GetOsslLastError()) {
  	DEBUG((DEBUG_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    HistoryAddRecord(HEVENT_CANT_VERIFY_USER_WITH_PKEY, UsrId, 
        SEVERITY_LVL_ERROR, 1);
    ShowErrorPopup(CurrentHiiHandle,
      HiiGetString(CurrentHiiHandle,
        STRING_TOKEN(MSG_CANT_VERIFY_USER_WITH_PKEY),NULL));
  }
  else if (OSSL_ERR_RUTOKEN_SUPPORT_ERR == GetOsslLastError()) {
    HistoryAddRecord(HEVENT_ERR_RUTOKEN_SUPPORT_ERR, UsrId, 
        SEVERITY_LVL_ERROR, 1);
    ShowErrorPopup(CurrentHiiHandle,
      HiiGetString(CurrentHiiHandle,
        STRING_TOKEN(MSG_RUTOKEN_SUPPORT_ERR),NULL));
  }
  HistoryAddRecord(HEVENT_USER_LOGIN, UsrId, SEVERITY_LVL_ERROR, 0);
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  ShowErrorPopup(CurrentHiiHandle, 
    HiiGetString(CurrentHiiHandle, 
      STRING_TOKEN(STR_PERMISSION_DENIED), NULL));
  
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  gST->ConOut->ClearScreen(gST->ConOut);
  gRT->ResetSystem (EfiResetCold, EFI_SUCCESS, 0, NULL);

Done:

  //если переставло что-то обновляться на экране - раскомментировать
  //и добавить if (something), что-бы не допустить повторное обновление главного меню
  //gST->ConOut->ClearScreen(gST->ConOut);
  //SetFormBrowserRefreshFlag();

_restore_tpl:
  if (RawKeyboard != NULL) {
    if (RawKeyboardStatus == EFI_SUCCESS) {
      RawKeyboardStatus = RawKeyboard->Lock(RawKeyboard);
      LOG ((EFI_D_ERROR, "%a.%d RawKeyboard->Lock(): Status = %r\n", __FUNCTION__, __LINE__, RawKeyboardStatus));
    }
  }

  noReenter = FALSE;
  gBS->RaiseTPL (OldTpl);
}


VOID TokenUpdateLogin()
{
  if (!bTokenUpdateLogin) {
    DEBUG((DEBUG_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return;
  }

  LOG((EFI_D_ERROR, "%a.%d GetTokenInserted = %x\n", __FUNCTION__, __LINE__, GetTokenInserted()));    
  if (GetMiiMode() ) {
    gST->ConOut->SetAttribute (gST->ConOut, EFI_TEXT_ATTR(EFI_WHITE, EFI_BACKGROUND_BLACK));
    TokenShowLoginForm();
  }

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));    

  bTokenUpdateLogin = FALSE;
}

SMART_CARD_PROTOCOL *
TokenGetSmartCardProtocol(
  VOID
  )
{
  return gSmartCardProtocol;
}

EFI_STATUS
TokenEjectCallback(
  IN SMART_CARD_PROTOCOL *This
  )
{
  USER_INFO *CurUsr;
  
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));  

  SetMouseEnableVar(TRUE);
  ResetTokenInserted();
  TokenDestroySession();
  bTokenUpdateLogin = FALSE;

  HistoryAddRecord(HEVENT_TOKEN_EJECTED, GetCurrentUserId(), 
      SEVERITY_LVL_NOTICE, HISTORY_RECORD_FLAG_RESULT_OK);

  
  CurUsr = GetCurrentUser();  
  if (CurUsr && (CurUsr->AuthType == AUTH_TYPE_TOKEN ||
                  CurUsr->AuthType == AUTH_TYPE_TOKEN_AND_PASS ||
                 ((CurUsr->Flags & USER_TOKEN_LDAP) && 
                  CurUsr->AuthType == AUTH_TYPE_LDAP))) {

    if (!bResetAfterLogOff) {
      SetCurrentUser(NULL);
      return EFI_SUCCESS;
    }
    ShowTimeoutPopup(CurrentHiiHandle,
      HiiGetString(CurrentHiiHandle, 
          STRING_TOKEN(STR_TOKEN_WAS_REMOVED), NULL), 5, 
          EFI_LIGHTGRAY | EFI_BACKGROUND_RED);
    HistoryAddRecord(HEVENT_RESET_SYSTEM, GetCurrentUserId(), 
      SEVERITY_LVL_DEBUG, HISTORY_RECORD_FLAG_RESULT_OK);
    gRT->ResetSystem (EfiResetCold, EFI_SUCCESS, 0, NULL);
  }
  return EFI_SUCCESS;
}

BOOLEAN
TokenPresent(
  VOID
  )
{
	EFI_STATUS Status;
	SMART_CARD_PROTOCOL* pSMArtCardProt = NULL;
  

  if (IsTokenDisabled ()) {
    return FALSE;
  }
  
  if (CurrentConfig == NULL) {
    /* TokenFunctions not initialized  */
    return FALSE;
  }

	Status = gBS->LocateProtocol (
							&gSmartCardProtocolGuid,
							NULL,
							(VOID**)&pSMArtCardProt
							);

	return (Status == EFI_SUCCESS);
}

VOID 
TokenRegisterCallback(
  VOID
  )
{
  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  gTokenEvent =
    EfiCreateProtocolNotifyEvent (
      &gSmartCardProtocolGuid,
      TPL_CALLBACK,
      SmartCardProtocolCallback,
      NULL,
      &gTokenEventReg
      );
}


EFI_STATUS
TokenFunctionsInit(
  IN EFI_HII_HANDLE HiiHandle,
  IN MULTIBOOT_CONFIG *Cfg
  )
{
  if (Cfg == NULL || HiiHandle == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  CurrentHiiHandle = HiiHandle;
  CurrentConfig = Cfg;
#ifndef BIOS_ONLY
  TokenRegisterCallback();
#endif //BIOS_ONLY
  if (Cfg->Language != NULL) {
    AsciiStrCpy(CurrentLanguage, Cfg->Language);
  } else {
    CurrentLanguage[0] = '\0';
  }
  return EFI_SUCCESS;
}


VOID
TokenNotifyTest(
  VOID
  )
{
  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  WaitForKP();
}


STATIC UINT32
CountHiiHandles(
  EFI_HII_HANDLE *Handles)
{
  UINT32 i;
  
  for (i = 0; Handles[i] != NULL; i++) ;

  return i;
}

EFI_STATUS
TokenComparisonDataById(
  IN VOID *pInId,
  IN UINTN InIdLen,
  IN OUT UINT8 **Data,
  IN OUT UINTN *DataLen
  )
{
  CK_ULONG Count;
  CK_RV rv;
  CK_OBJECT_HANDLE hCert;
  EFI_STATUS Status = EFI_SUCCESS;
  STATIC CK_ATTRIBUTE aCertFindAttrs[] = {
    {CKA_TOKEN, &bTrue, sizeof bTrue},
    {CKA_CLASS, &cClass, sizeof cClass},
    {CKA_CERTIFICATE_TYPE, &cType, sizeof cType}
  };
  STATIC UINT8 DigestBuf[GOST_DIGEST_LEN];
  CK_ULONG DigestLen;
  UINTN i, TotalLen, Offset, TypeNameLen;

  if (!TokenPresent()) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }

  LOG((DEBUG_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  if (eTokenLikeSmartCard()) {
    Status = eTokenGetClientCertById(pInId, InIdLen, &hCert, FALSE, TRUE);
    if (EFI_ERROR(Status)) {
      return Status;
    }
  } else {
    rv = C_FindObjectsInit (hSession, aCertFindAttrs, 
      ARRAY_ITEMS(aCertFindAttrs));
    
    while (1) {
      Count = 0;
      rv = C_FindObjects (hSession, &hCert, 1, &Count);    
      LOG((EFI_D_ERROR, "%a.%d Count=%d\n", __FUNCTION__, __LINE__, Count));
      if (rv != CKR_OK || Count != 1) {
        LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
        C_FindObjectsFinal(hSession);
        return EFI_NOT_FOUND;
      }
      if (!CheckCertId(hSession, hCert, pInId, InIdLen)) {
        continue;
      }    
      break;
    }
    C_FindObjectsFinal(hSession);
  }

  if (EFI_SUCCESS == TokenCheckSelfSignedCert(hSession, hCert, pInId, 
      InIdLen)) {
    LOG((EFI_D_ERROR, "%a.%d Error!!!\n", __FUNCTION__, __LINE__));
    ShowErrorPopup(CurrentHiiHandle,
      HiiGetString(CurrentHiiHandle, STRING_TOKEN(STR_ERR_SELF_SIGNED), NULL));
    return EFI_ABORTED;
  }

  rv = Verify(hSession, hCert);
  LOG((EFI_D_ERROR, "%a.%d RV=0x%X\n", 
      __FUNCTION__, __LINE__, rv));
  if (CKR_OK != rv) {
    ProcessingOsslCertErrors(GetOsslLastError());
    return EFI_CRC_ERROR;
  }

  //CheckBasicConstraintsCAflag(hSession, hCert);
  
  rv = GetSubjectCommonName (hSession, hCert, 
    &CompAttributes[CT_FLAG_CN]);
  if (rv != CKR_OK) {
    LOG((EFI_D_ERROR, "%a.%d Error while obtain common name!\n", 
      __FUNCTION__, __LINE__));
  } else {
  }

  rv = GetSubjectTitle(hSession, hCert, 
    &CompAttributes[CT_FLAG_SUBJECT]);
  if (rv != CKR_OK) {
    LOG((EFI_D_ERROR, "%a.%d Error while obtain title!\n", 
      __FUNCTION__, __LINE__));
  } else {
  }

  rv = GetSubjectUid(hSession, hCert, 
    &CompAttributes[CT_FLAG_UID]);
  if (rv != CKR_OK) {
    LOG((EFI_D_ERROR, "%a.%d Error while obtain uid!\n", 
      __FUNCTION__, __LINE__));
  } else {
  }

  rv = GetSubjectEmail(hSession, hCert, 
    &CompAttributes[CT_FLAG_MAIL]);
  if (rv != CKR_OK) {
    LOG((EFI_D_ERROR, "%a.%d Error while obtain Email!\n", 
      __FUNCTION__, __LINE__));
  } else {
  }

  Status = ProcessingCA();
  if (EFI_ERROR(Status)) {
    return EFI_ABORTED;  
  }
  
  DigestLen = sizeof(DigestBuf);
  rv = GetCertificateDigest2 (hSession, hCert, hCACertSession,
    (CK_BYTE_PTR)DigestBuf, &DigestLen);
  if (rv != CKR_OK) {
    LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));     
  } else {
    LOG((EFI_D_ERROR, "%a.%d DigestLen=%d\n", 
      __FUNCTION__, __LINE__, DigestLen));
    DumpBytes_(DigestBuf, DigestLen);
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
      //if (CompAttributes[i].type)
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
	Utf16Str[CompAttributes[i].ulValueLen / 2] = L'\0';
        for (j = 0, DataPtr = (UINT8*)Utf16Str; 
             j < CompAttributes[i].ulValueLen; j += 2) {
          Tmp8 = DataPtr[j];
          DataPtr[j] = DataPtr[j + 1];
          DataPtr[j + 1] = Tmp8;
        }
              
        UnicodeSPrint((CHAR16*)(*Data + Offset), *DataLen - Offset, 
          L"%s=%s\n", GetComparisonDataName16((UINT8)(i & 0xFF)), Utf16Str);
        FreePool(Utf16Str);
      } else  if (CompAttributes[i].type == CKA_UTF8_STRING) {
        CHAR16 *UnicodeStr;
        UINTN ActualLen;
        CK_ULONG wcsize;

        wcsize = CompAttributes[i].ulValueLen + 1;
        UnicodeStr = (CHAR16 *)AllocateZeroPool(wcsize * sizeof(CHAR16));
        if (UnicodeStr == NULL)
          return EFI_OUT_OF_RESOURCES;

        ActualLen = ConvertUtf8StrToUnicodeStr(UnicodeStr, 
          CompAttributes[i].pValue, wcsize ? wcsize - 1 : 0);
        LOG ((EFI_D_ERROR, "ActualLen=%d\n", ActualLen));
        if (ActualLen && ActualLen < wcsize) {
          UnicodeStr[ActualLen] = 0;
        }

        UnicodeSPrint((CHAR16*)(*Data + Offset), *DataLen - Offset,
          L"%s=%s\n", GetComparisonDataName16((UINT8)(i & 0xFF)), UnicodeStr);

        FreePool(UnicodeStr);

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
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return EFI_OUT_OF_RESOURCES;
    }
    CopyMem(pTmpRec->HashData, CompAttributes[CT_FLAG_DIGEST].pValue, 
      CompAttributes[CT_FLAG_DIGEST].ulValueLen);
    
    pTmpRec->Size = (UINT16)CompAttributes[CT_FLAG_DIGEST].ulValueLen;
    if (GetCalcDataDigest_MdType() == NID_id_GostR3411_2012_256 || 
      GetCalcDataDigest_MdType() == NID_id_GostR3411_2012_512) {
      pTmpRec->HashType = CS_TYPE_GOST_2012;
    } else if (GetCalcDataDigest_MdType() == NID_id_GostR3411_94) {
      pTmpRec->HashType = CS_TYPE_GOST;
    } else {
      pTmpRec->HashType = (UINT8)(-1); // default 
    }
    GetDigestStr(TmpStr8, pTmpRec);
    FreePool(pTmpRec);
    
    //AsciiStr[CompAttributes[CT_FLAG_DIGEST].ulValueLen] = '\0';
    TypeNameLen = StrLen(GetComparisonDataName16(CT_FLAG_DIGEST));
    *DataLen += (CompAttributes[CT_FLAG_DIGEST].ulValueLen * 2 + 
      TypeNameLen + 3) << 1;
    Offset = StrLen((CHAR16*)*Data);
    Offset <<= 1;
    UnicodeSPrint((CHAR16*)(*Data + Offset), *DataLen - Offset, 
      L"%s=%a\n", GetComparisonDataName16(CT_FLAG_DIGEST), TmpStr8);
  }

  LOG((EFI_D_ERROR, "%a.%d TotalLen=%d\n", __FUNCTION__, __LINE__, TotalLen));  
  return Status;
}



VOID
TokenSimpleTest(
  VOID
  )
{
  EFI_GUID SearchGuid = { 0x543cd4ff, 0x1276, 0x443d, 
    {0x41, 0x42, 0x34, 0xc2, 0x32, 0xfe, 0xb2, 0x42 } };
  EFI_HII_HANDLE *HiiHandles;
  UINT32 Count;
  EFI_STATUS Status;
  EFI_BROWSER_ACTION_REQUEST ActionRequest;
  EFI_FORM_BROWSER2_PROTOCOL *gFormBrowser2;
  
  
  LOG((EFI_D_ERROR, "%a.%d Start\n", __FUNCTION__, __LINE__));
    
  for (;;) {
    if (!TokenPresent()) {
      continue;
    }
    
    LOG((EFI_D_ERROR, "%a.%d gSmartCardProtocol located!!!\n", 
      __FUNCTION__, __LINE__));
    
    HiiHandles = HiiGetHiiHandles(&SearchGuid);
    Count = CountHiiHandles(HiiHandles);
    if (Count == 0) {
      continue;
    }
    LOG((EFI_D_ERROR, "%a.%d Count=%d\n", __FUNCTION__, __LINE__, Count));
    if (Count != 1) {
      return;
    }
    
    Status = gBS->LocateProtocol (&gEfiFormBrowser2ProtocolGuid, NULL,
      (VOID **) &gFormBrowser2);
    
    ActionRequest = EFI_BROWSER_ACTION_REQUEST_NONE;
    Status = gFormBrowser2->SendForm (gFormBrowser2,
         HiiHandles,
         1,
         NULL,
         0,
         NULL,
         &ActionRequest
         );
    
    break;
  }
  
  //HiiHandles = HiiGetHiiHandles (NULL);
}

//------------------------------------------------------------------------------
/*! \brief Make a userCertificate Matching value */
/*! Matching value is certificate_serial_number$certificate_issuer_DN. */ 
/*! You have to free a memory, containes this value, when you dont need it any more. */
/*! \param[in] aCertSerialNum A serial number of a certificate 
    \param[in] issuerAttributeList A list of attributes of ISSUER field of certificate */
/*! \return A pointer to a userCertificate Matching value */
//------------------------------------------------------------------------------
STATIC
CHAR8*
MakeUserCertificateMatchingValue(
  UINTN  certSerialNum,
  CHAR8  **issuerAttributeList
  )
{
  CHAR8 *resultStr = NULL, *startStr = NULL, *strCaSerial = NULL;
  UINTN totalSize = 0, attrCount, attrNum = 0;
  
  LOG((EFI_D_ERROR, "%a.%d \n", __FUNCTION__, __LINE__));
  
  strCaSerial = UINTNToAsciiString(certSerialNum);

  totalSize = AsciiStrLen(strCaSerial);
  
  // Count a total size of matchingValue string
  for(attrCount = 0; attrCount < NUM_OF_ISSUER_ATTRs; attrCount++) {
    if (issuerAttributeList[attrCount] != NULL) {
      totalSize += AsciiStrLen(issuerAttributeList[attrCount]);
      // Add a byte for a "," simbol
      totalSize += sizeof(CHAR8);
      attrNum++;
    }
  }
  
  resultStr = AllocateZeroPool(totalSize + 1);
  
  startStr = resultStr;
  
  //------------------------------------------------------------------------------
  // make a string of a matching value
  // e.g.: 6$email=tester@example.com,CN=test,OU=Users,O=Example,L=Com,ST=Com
  //------------------------------------------------------------------------------
  AsciiStrCpy(resultStr, strCaSerial);
  resultStr += AsciiStrLen(strCaSerial);
  
  AsciiStrCpy(resultStr, "$");
  resultStr += sizeof(CHAR8);
  
  for(attrCount = 0; attrCount < NUM_OF_ISSUER_ATTRs; attrCount++) {
    if (issuerAttributeList[attrCount]!= NULL) {
      AsciiStrCpy(resultStr, issuerAttributeList[attrCount]);
      resultStr += AsciiStrLen(issuerAttributeList[attrCount]);
      attrNum--;
      if (attrNum > 0) {
        AsciiStrCpy(resultStr, ",");
        resultStr += sizeof(CHAR8);
      }
    }
  }
  
  if (strCaSerial != NULL)
    FreePool(strCaSerial);
  
  LOG((EFI_D_ERROR, "%a.%d Cert Matching Value: %a\n", __FUNCTION__, __LINE__, startStr));
  
  return startStr;
}
//------------------------------------------------------------------------------


STATIC
CHAR8*
MakeUserCertificateMatchingValueVer2(
  UINT16  *certSerialNum,
  CHAR8  **issuerAttributeList
  )
{
  CHAR8 *resultStr = NULL, *startStr = NULL, *strCaSerial = NULL;
  UINTN totalSize = 0, attrCount, attrNum = 0, certSerialNumStrLen;

  TrimString16FromEnd (certSerialNum, TRUE);
  
  LOG((EFI_D_ERROR, "%a.%d certSerialNum=\"%s\"\n", 
    __FUNCTION__, __LINE__, certSerialNum));

  certSerialNumStrLen = (StrLen(certSerialNum)  + 1) * sizeof (CHAR8);
  strCaSerial = AllocateZeroPool (certSerialNumStrLen);
  if (strCaSerial == NULL) {
    return NULL;
  }
  AsciiSPrint(strCaSerial, certSerialNumStrLen, "%s", certSerialNum);

  totalSize = AsciiStrLen(strCaSerial);
  
  // Count a total size of matchingValue string
  for(attrCount = 0; attrCount < NUM_OF_ISSUER_ATTRs; attrCount++) {
    if (issuerAttributeList[attrCount] != NULL) {
      totalSize += AsciiStrLen(issuerAttributeList[attrCount]);
      // Add a byte for a "," simbol
      totalSize += sizeof(CHAR8);
      attrNum++;
    }
  }
  
  resultStr = AllocateZeroPool(totalSize + AsciiStrSize("{ serialNumber ' 'H, issuer rdnSequence:\" \" }"));
  
  startStr = resultStr;
  
  //------------------------------------------------------------------------------
  // make a string of a matching value
  // e.g.: { serialNumber '1234567890ABCDEF'H, issuer rdnSequence:"email=tester@example.com,CN=test,OU=Users,O=Example,L=Com,ST=Com" }
  //------------------------------------------------------------------------------
  AsciiStrCpy(resultStr, "{ serialNumber '");
  resultStr += AsciiStrLen("{ serialNumber '");

  AsciiStrCpy(resultStr, strCaSerial);
  resultStr += AsciiStrLen(strCaSerial);

  AsciiStrCpy(resultStr, "'H, issuer rdnSequence:\"");
  resultStr += AsciiStrLen("'H, issuer rdnSequence:\"");
  
  for(attrCount = 0; attrCount < NUM_OF_ISSUER_ATTRs; attrCount++) {
    if (issuerAttributeList[attrCount]!= NULL) {
      AsciiStrCpy(resultStr, issuerAttributeList[attrCount]);
      resultStr += AsciiStrLen(issuerAttributeList[attrCount]);
      attrNum--;
      if (attrNum > 0) {
        AsciiStrCpy(resultStr, ",");
        resultStr += sizeof(CHAR8);
      }
    }
  }

  AsciiStrCpy(resultStr, "\" }");
  resultStr += AsciiStrLen("\" }");
  
  if (strCaSerial != NULL)
    FreePool(strCaSerial);
  
  LOG((EFI_D_ERROR, "%a.%d Cert Matching Value: %a\n", __FUNCTION__, __LINE__, startStr));
  
  return startStr;
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
/*! \brief Make a matched value by serNum and issuer */
/*! Get a serial number and an issuer from a token certificate */
/*! \param[in] hTokenSession A session with a token 
    \param[in] hClientCertObjectHandle An object containes a certificate */
//------------------------------------------------------------------------------
STATIC 
CHAR8*
MakeUserCertificateMatchingValueByIssuerField (
  IN CK_SESSION_HANDLE hTokenSession,
  IN CK_OBJECT_HANDLE  hClientCertObjectHandle
  )
{
    CHAR8 *certMatchValue;
    CHAR8 *issuerAttributeList[NUM_OF_ISSUER_ATTRs];
    UINTN certSN = 0;
    
    EFI_STATUS Status;
    
    ZeroMem(issuerAttributeList, sizeof(issuerAttributeList));
    
    //------------------------------------------------------------------------------
    // Get Certificate Serial Number
    //------------------------------------------------------------------------------
    Status = GetCertificateSerialNumber(hTokenSession, hClientCertObjectHandle, &certSN);
    if (EFI_ERROR(Status)) {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return NULL;
    }
    
    //------------------------------------------------------------------------------
    // Get Certificate Issuer Field
    //------------------------------------------------------------------------------
    GetCertificateIssuerAtrributeList(hTokenSession, hClientCertObjectHandle, issuerAttributeList);
    if (NULL == issuerAttributeList) {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      return NULL;
    }
    
    certMatchValue = MakeUserCertificateMatchingValue(certSN, (CHAR8**)issuerAttributeList);
    
    return certMatchValue;
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
/*! \brief Make a matched value by serNum and issuer */
/*! Get a serial number and an issuer from a token certificate */
/*! \param[in] hTokenSession A session with a token 
    \param[in] hClientCertObjectHandle An object containes a certificate */
//------------------------------------------------------------------------------
STATIC 
CHAR8*
MakeUserCertificateMatchingValueByIssuerFieldOssl (
  IN CK_SESSION_HANDLE hTokenSession,
  IN CK_OBJECT_HANDLE  hClientCertObjectHandle
  )
{
  CHAR8 *certMatchValue;
  CHAR8 *issuerAttributeList[NUM_OF_ISSUER_ATTRs];
//  UINTN certSN = 0;
  CHAR16 *certSNStr16 = NULL;
  UINTN CcertLen;
  UINT8 *CcertData;
  EFI_STATUS Status;
  
  ZeroMem(issuerAttributeList, sizeof(issuerAttributeList));

  Status = GetCertificateData (hTokenSession, hClientCertObjectHandle,
                            &CcertData, &CcertLen);
  if (EFI_ERROR (Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return NULL;
  }

#if 0  
  //------------------------------------------------------------------------------
  // Get Certificate Serial Number
  //------------------------------------------------------------------------------
  Status = GetCertificateSerialNumber(hTokenSession, hClientCertObjectHandle, &certSN);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return NULL;
  }
#endif

  Status = GetCertificateSerialNumberOssl (CcertData, CcertLen, &certSNStr16); 
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return NULL;
  }
  
  //------------------------------------------------------------------------------
  // Get Certificate Issuer Field
  //------------------------------------------------------------------------------
  GetCertificateIssuerAtrributeList(hTokenSession, hClientCertObjectHandle, issuerAttributeList);
  if (NULL == issuerAttributeList) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return NULL;
  }
  
  //certMatchValue = MakeUserCertificateMatchingValue(certSN, (CHAR8**)issuerAttributeList);
  certMatchValue = MakeUserCertificateMatchingValueVer2(certSNStr16,
    (CHAR8**)issuerAttributeList);
  
  return certMatchValue;
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
/*! \brief Make a matched value by certificate bynary */
/*! A matched value is an array of bytes, where "\" symbol is followed after each byte */
/*! \param[in] hTokenSession A session with a token 
    \param[in] hClientCertObjectHandle An object containes a certificate */
/*! \return A matched value to compare binary cert data */
//------------------------------------------------------------------------------
STATIC
CHAR8*
MakeUserCertificateMatchingValueByBinary (
  IN CK_SESSION_HANDLE hTokenSession,
  IN CK_OBJECT_HANDLE  hClientCertObjectHandle
  )
{
  EFI_STATUS Status;
  unsigned char *certMatchValue = NULL, *caBody = NULL, *valueToCopy = NULL;
  UINTN caBodyLen = 0, byteCount, i, count, valueLen, lenToCopy, delimiterLen;
  CHAR8 delimiter[2] = {'\\', '\0'};
  
  Status = GetCertificateData (hTokenSession, hClientCertObjectHandle,
                               &caBody, &caBodyLen);
  if (EFI_ERROR(Status)) {
    LOG((EFI_D_ERROR, "Error!\n"));
    return NULL;
  }
                               
  valueLen = caBodyLen * 3 + sizeof(CHAR8);
                               
  certMatchValue = AllocateZeroPool(valueLen);
  if (certMatchValue == NULL) {
    LOG((EFI_D_ERROR, "Error!\n"));
    goto _EXIT;
  }
  
  byteCount = 0;
  delimiterLen = AsciiStrLen(&delimiter[0]);
  
  for(byteCount = 0, i = 0; i < caBodyLen; i++) {
    CopyMem(&certMatchValue[byteCount], &delimiter[0], delimiterLen);
    valueToCopy = UINTNToHexAsciiString(caBody[i]);
    if (valueToCopy == NULL) {
      if (certMatchValue != NULL) {
        FreePool(certMatchValue);
        certMatchValue = NULL;
      }
      goto _EXIT;
    }
    lenToCopy = AsciiStrLen(valueToCopy);
    for(count = 0; count < lenToCopy; count++) {
      CopyMem(&certMatchValue[byteCount + delimiterLen + count], &valueToCopy[count], sizeof(CHAR8));
    }
    
    byteCount += lenToCopy + delimiterLen;
      
    if (valueToCopy != NULL) {
      FreePool(valueToCopy);
      valueToCopy = NULL;
    }
  }
  
  LOG((EFI_D_ERROR, "certMatchValue: \n"));
  DumpBytes_(certMatchValue, byteCount);
  LOG((EFI_D_ERROR, "\n"));
  
_EXIT:
  if (caBody != NULL)
    FreePool(caBody);
  
  if (valueToCopy != NULL)
    FreePool(valueToCopy);
    
  return certMatchValue;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a permission for user DN */
//------------------------------------------------------------------------------
STATIC
USER_AUTH_PERMISSION
CheckLoginPermissionWithUserDN (
  IN CHAR8 *userDN,
  OUT EFI_STATUS *Status
  )
{
  UINTN retval = 0;
  USER_AUTH_PERMISSION  permission = NOT_ALLOW_TO_LOGIN;

  *Status = gBS->LocateProtocol (
                  &gLdapAuthDxeProtocolGuid,
                  NULL,
                  (VOID **) &pLdapAuthProtocol
                  );
  if (*Status != EFI_SUCCESS) {
    LOG((EFI_D_ERROR, "%a.%d Status=%d\n", __FUNCTION__, __LINE__, *Status));
    *Status = EFI_ABORTED;
    return NOT_ALLOW_TO_LOGIN;
  }

  if (pLdapAuthProtocol->LdapConfigOp.IsUseTLS() == TRUE) {
    //-------------------------------------------------------
    // Check an using of a TLS and try to get OpenSSL.cnf from fv and load it
    //-------------------------------------------------------
    tlsConfig_t config = MakeTlsConfig(ChainGetData()->Data, ChainGetData()->DataLen);
    *Status = pLdapAuthProtocol->LdapConfigOp.SetOpensslConfig(config);
    if (*Status != EFI_SUCCESS) {
       LOG((EFI_D_ERROR, "%a.%d: Can't set OpenSSL.cnf. Will be used default settings\n", __FUNCTION__, __LINE__));
    }
  }

  permission = pLdapAuthProtocol->CheckUserLoginPermission(userDN, &retval);

  return permission;
}
//------------------------------------------------------------------------------


BOOLEAN
CheckForWrongPinLocks (
  VOID
  )
{
  EFI_STATUS Status;
  UINT32 Cnt;
  UINT32 Tresh;

  LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  Status = LocksGetWrongPinCnt (&Cnt);
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return FALSE;
  }

  Status = LocksGetWrongPinTreshold(&Tresh);
  if (EFI_ERROR(Status)) {    
    LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return FALSE;
  }

  LOG ((EFI_D_ERROR, "%a.%d Cnt=%X Tresh=%X\n", 
      __FUNCTION__, __LINE__, Cnt, Tresh));
  
  if (Cnt >= Tresh) {
    LOG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return TRUE;  
  }
  return FALSE;
}



EFI_STATUS
LdapAuthWithCertData (
  IN UINT8 *UsrCertData,
  IN UINTN UsrCertDataLen
  )  
{
  CHAR8 *certMatchValue = NULL, *userDN = NULL;
  
  UINTN       chkStatus = LDAP_SEARCH_ERROR, permissions = NOT_ALLOW_TO_LOGIN;
  UINTN       numOfCerts = 0, caCount;
  UINT8       userID = 0, i;
  EFI_STATUS  Status;
  CK_RV       rv;

  BOOLEAN     matchedCertificate = FALSE;
  BOOLEAN     isAdmin            = FALSE;
  BOOLEAN     isCertificateValid = TRUE;

  CHAR8       *accountName = NULL;
  CHAR16      *name = NULL;
  LDAP_AUTH_PROTOCOL *pLdapAuthProtocol;
  CK_SESSION_HANDLE hSession;
  CK_OBJECT_HANDLE hClientCertSession;
  
  UserCertificateData_t caData = {0, NULL};
  
  LOG((EFI_D_ERROR, "%a.%d \n", __FUNCTION__, __LINE__));
  
  Status = gBS->LocateProtocol (
                  &gLdapAuthDxeProtocolGuid,
                  NULL,
                  (VOID **) &pLdapAuthProtocol
                  );
  if (Status != EFI_SUCCESS) {
    LOG((EFI_D_ERROR, "%a.%d Status=%d\n", __FUNCTION__, __LINE__, Status));
    return EFI_ABORTED;
  }
  
  if (pLdapAuthProtocol->LdapConfigOp.GetLdapAuthUsageStatus() != USE_LDAP_AUTH) {
    return EFI_ABORTED;
  }

  Status = Pkcs11_CreateSessionAndLogin ();
  if (EFI_ERROR(Status)) {
    return Status;
  }
  
  if (pLdapAuthProtocol->LdapConfigOp.IsUseTLS() == TRUE) {
    //-------------------------------------------------------
    // Check an using of a TLS and try to get OpenSSL.cnf from fv and load it
    //-------------------------------------------------------
    tlsConfig_t config = MakeTlsConfig(ChainGetData()->Data, ChainGetData()->DataLen);
    Status = pLdapAuthProtocol->LdapConfigOp.SetOpensslConfig(config);
    if (Status != EFI_SUCCESS) {
       LOG((EFI_D_ERROR, "%a.%d: Can't set OpenSSL.cnf. Will be used default settings\n", __FUNCTION__, __LINE__));
    }
  }

  hSession = Pkcs11_GetCurrentSessionHandler ();
  Status = Pkcs11_CreateClientCertObjFromData(
    UsrCertData, 
    UsrCertDataLen, 
    &hClientCertSession);
  if (EFI_ERROR(Status)) {
    return Status;
  }
   
  while(1) {
    for(i = 0; i < 2; i++) {
    
      if (certMatchValue != NULL) {
        LOG((EFI_D_ERROR, "%a.%d: Free: %a\n", __FUNCTION__, __LINE__, certMatchValue));
        FreePool(certMatchValue);
        certMatchValue = NULL;
      }
      
      if (i == 0) { // trying for an Active Directory
        certMatchValue = MakeUserCertificateMatchingValueByBinary(hSession, hClientCertSession);
      } else if (i == 1) { // try for a LDAP server
        certMatchValue = MakeUserCertificateMatchingValueByIssuerFieldOssl(hSession, hClientCertSession);
      } else {
        break;
      }
        
      if (userDN != NULL) {
          LOG((EFI_D_ERROR, "%a.%d: Free: %a\n", __FUNCTION__, __LINE__, certMatchValue));
          FreePool(userDN);
          userDN = NULL;
        }
        
      //------------------------------------------------------------------------------
      // Search an user with an userCertificate, which corresponds to the certMatchValue
      //------------------------------------------------------------------------------
      userDN = pLdapAuthProtocol->SearchUserCertificateFromLdapServer(
                                    certMatchValue, 
                                    &accountName,
                                    &numOfCerts, 
                                    &chkStatus);
      if (chkStatus == LDAP_SEARCH_SUCCESS) {
        if (numOfCerts > 0) {
          LOG((EFI_D_ERROR, "%a.%d numOfCerts=%d\n", __FUNCTION__, __LINE__, 
            numOfCerts));
          for(caCount = 0; caCount < numOfCerts; caCount++) {
             pLdapAuthProtocol->GetUserCertificateByNum(caCount, &caData);
             if (caData.data != NULL) {
               matchedCertificate = CompareWithTokenCert(hSession, 
                                        hClientCertSession, &caData);
               if (TRUE == matchedCertificate) {
                 name = AllocatePool (AsciiStrSize(accountName) * sizeof(CHAR16));
                 if (name == NULL) {
                   LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
                   chkStatus = LDAP_OUT_OF_MEMORY;
                   Status = EFI_OUT_OF_RESOURCES;
                   matchedCertificate = FALSE;
                 } else {
                   AsciiStrToUnicodeStr (accountName, name);
                 }
                 goto _SEARCH_EXIT;
               }
             }
          }
        }
      } else if (chkStatus == LDAP_SEARCH_ERROR) {
        continue;
      } else
        goto _SEARCH_EXIT;
    }
  }
  
_SEARCH_EXIT:
  if (TRUE == matchedCertificate) {
    // Verify certificate
    rv = VerifyTokenObject(hSession, hClientCertSession);
    if (rv != CKR_OK) {
      Status = EFI_ABORTED;
      isCertificateValid = FALSE;
      permissions = NOT_ALLOW_TO_LOGIN;
    } else {
      // Check user permission
      permissions = CheckLoginPermissionWithUserDN(userDN, &Status);
      switch(permissions) {
      case ALLOW_TO_LOGIN_ADMIN_FULL:
      case ALLOW_TO_LOGIN_ADMIN_FULL_REMOTE:
      case ALLOW_TO_LOGIN_ADMIN_AUDIT:
      case ALLOW_TO_LOGIN_ADMIN_AUDIT_REMOTE:
        isAdmin = TRUE;
      case ALLOW_TO_LOGIN_USER:
      case ALLOW_TO_LOGIN_USER_REMOTE:
        break;
      case NOT_ALLOW_TO_LOGIN:
      case ALLOW_TO_LOGIN_GUEST:
      default:
        chkStatus = LDAP_SEARCH_ERROR;
        Status = EFI_ABORTED;
        break;
      }
    }

    if (EFI_SUCCESS == AddLdapUser(name, userDN, isAdmin, TRUE, 
                          permissions, &userID)) {
      SetCurrentUser(UserGetLastFoundedInfo());
    } else {
      Status = EFI_ABORTED;      
      HistoryAddRecord(
          HEVENT_LDAP_USER_ADD_ERROR, 
          USER_LDAP_LOG_ID, 
          SEVERITY_LVL_ERROR, 
          1);
    }

  } else
    Status = EFI_ABORTED;

  if (isCertificateValid == TRUE)
    ProcessLdapTokenLoginError(FALSE, chkStatus);
  else
    ProcessVerifyTokenError(FALSE, GetOsslLastError());

 Pkcs11_FindObjectsFinish(hSession);
  Pkcs11_DestroySession ();

  if (userDN != NULL) {
    LOG((EFI_D_ERROR, "%a.%d: Free: %a\n", __FUNCTION__, __LINE__, userDN));
    FreePool(userDN);
  }

  if (certMatchValue != NULL) {
    LOG((EFI_D_ERROR, "%a.%d: Free: %a\n", __FUNCTION__, __LINE__, 
        certMatchValue));
    FreePool(certMatchValue);
  }

  if (name != NULL) {
    FreePool (name);
  }

  pLdapAuthProtocol->CleanLdapConnection();
  pLdapAuthProtocol->FreeReceivedUserCertificates();

  LOG((EFI_D_ERROR, "%a.%d: Status: %d\n", __FUNCTION__, __LINE__, Status));

  return Status;
}


