/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <StorageDef.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/CommonUtils.h>
#include <Library/CertStorageLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/RevokeChkConfigLib/RevokeChkConfig.h>
#include <Library/Lib/OpensslCnfFv.h>
#include <Library/Lib/OpensslFunctions.h>

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/x509_vfy_ocsp.h>
#include <openssl/ocsp_clnt.h>
#include <openssl/engine.h>

#include "OpensslFunctionsInternal.h"

#if 0
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

#define CHAIN_STORAGE_VAR_NAME            L"CertChainStorage"
extern GUID gChainStorageGuid;

STATIC OSSL_STATUS lastStatus = OSSL_INVALID_PARAM;
STATIC UINTN CalcDataDigest_MdType;

typedef enum {
             CRL1_NEWER,
             CRL2_NEWER,
             CRL_THE_SAME,
             CRL_DIFF_ISSUERS,
             CRL_CMP_ERROR
             }
  CRL_CMP_STATUS;

STATIC struct {
  STACK_OF(X509_CRL) *localCRLs;
  BOOLEAN stackIsFresh;
} localCRLStack;

STATIC
STACK_OF(X509_CRL)*
GetCRLLocalStack (
  VOID
);

STATIC
OSSL_STATUS
CheckAndSaveStackToPkcs7CAChain (
  IN STACK_OF(X509_CRL) *crlStack,
  IN OUT PKCS7 *Pkcs7,
  OUT BOOLEAN *needToResave
);

STATIC
OSSL_STATUS
SavePkcs7CAChainToFlash (
  IN OUT PKCS7 *Pkcs7
);

STATIC
OSSL_STATUS
IsCertificateRevoked (
  IN CHAR8 *certData,
  IN UINTN certDataLen,
  IN CHAR8 *crlData,
  IN UINTN crlDataLen
);

STATIC
int
MsgCallback (
  IN int ok,
  IN X509_STORE_CTX *ctx,
  OUT OSSL_STATUS *status
);

STATIC
OSSL_STATUS
Check (
  IN X509_STORE *ctx,
  IN STACK_OF(X509) *cert,
  IN STACK_OF(X509_CRL) *crls,
  IN X509 *userX509
);

STATIC
OSSL_STATUS
OCSPVerifyCert (
  X509_STORE_CTX *csc
);

STATIC
int
add_ocsp_cert (
  OCSP_REQUEST **req,
  X509 *cert,
  const EVP_MD *cert_id_md,
  X509 *issuer,
  STACK_OF(OCSP_CERTID) *ids
);

STATIC
VOID
PurgeOpenSSLErrors (
  IN CHAR8 *FuncName
  )
{
  unsigned long SslErr;
  while((SslErr = ERR_get_error()) != 0) {
    DEBUG ((EFI_D_ERROR, "%a.%d %a(): 0x%X, %a\n", __FUNCTION__, __LINE__,
      FuncName, SslErr, ERR_error_string(SslErr, NULL)));
  }
}

//------------------------------------------------------------------------------
/*! \brief Check that this certificate is selfsigned */
/*! DER format of a certificate is only supported */
/*! \param[in] *certData A pointer to certificate data 
    \param[in] certDataLen A length of a data */
/*! \retval OSSL_VERIFY_SUCCESS The signature of this certificate is valid
    \retval OSSL_UNKNOWN_CERT_FORMAT Unknown type of the certificate 
    \retval OSSL_MEMORY_ERROR Internal error (Alloc memory e.g.)
    \retval OSSL_INVALID_SIGNATURE The signature of this certificate is invalid
    \retval OSSL_INVALID_PARAM Incorrect parameters (NULL data e.g.) */
//------------------------------------------------------------------------------
OSSL_STATUS
VerifySelfSignedCertificate (
  IN CHAR8 *certData,
  IN UINTN certDataLen
  )
{
  X509    *x509 = NULL;

  lastStatus = OSSL_INVALID_SIGNATURE;

  // Lazy initializing of OpenSSL
  InitializeOpenSSL();

  if (certData == NULL || certDataLen == 0) {
    lastStatus = OSSL_INVALID_PARAM;
    return lastStatus;
  }

  x509 = GetCertificateFromBinary(certData, certDataLen, &lastStatus);
  if (lastStatus != OSSL_SUCCESS_CONVERT_TO_ASN)
    return lastStatus;

  if (X509_verify(x509, X509_get_pubkey(x509)) == 1)
    lastStatus = OSSL_VERIFY_SUCCESS;
  else
    lastStatus = OSSL_INVALID_SIGNATURE;

  if (x509 != NULL)
    X509_free(x509);

  PurgeOpenSSLErrors(__FUNCTION__);

  return lastStatus;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Check a certificate chain format */
/*! DER format of a certificate chain is only supported */
/*! \param[in] *chainData A pointer to certificate data
    \param[in] chainDataLen A length of a data */
/*! \retval OSSL_SUCCESS_CONVERT_TO_ASN Format of the chain is valid
    \retval OSSL_UNKNOWN_PKCS7_FORMAT Unknown type of the chain
    \retval OSSL_INVALID_PARAM Incorrect parameters (NULL data e.g.)
    \retval OSSL_MEMORY_ERROR Internal error (Alloc memory e.g.) */
//------------------------------------------------------------------------------
OSSL_STATUS
CheckChainFormat (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen
  )
{
  BIO   *chainBIO = NULL;
  PKCS7 *p7       = NULL;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  // Lazy initializing of OpenSSL
  InitializeOpenSSL();

  if (chainData == NULL || chainDataLen == 0) {
    lastStatus = OSSL_INVALID_PARAM;
    return OSSL_INVALID_PARAM;
  }

  chainBIO = BIO_new_mem_buf(chainData, (int)chainDataLen);
  if (chainBIO == NULL) {
    lastStatus = OSSL_MEMORY_ERROR;
    return OSSL_MEMORY_ERROR;
  }

  p7 = d2i_PKCS7_bio(chainBIO, NULL);
  BIO_free(chainBIO);
  if (p7 == NULL) {
    lastStatus = OSSL_UNKNOWN_PKCS7_FORMAT;
    return OSSL_UNKNOWN_PKCS7_FORMAT;
  }

  LOG((EFI_D_ERROR, "%a.%d: PKCS7 type: %d \n",
    __FUNCTION__, __LINE__, OBJ_obj2nid((p7)->type)));
  
  if (p7 != NULL)
    PKCS7_free(p7);

  lastStatus = OSSL_SUCCESS_CONVERT_TO_ASN;

  PurgeOpenSSLErrors(__FUNCTION__);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return OSSL_SUCCESS_CONVERT_TO_ASN;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Check a format of the certificate */
/*! DER format of a certificate is only supported */
/*! \param[in] *certData A pointer to certificate data 
    \param[in] certDataLen A length of a data */
/*! \retval OSSL_SUCCESS_CONVERT_TO_ASN Format of the certificate is valid
    \retval OSSL_UNKNOWN_CERT_FORMAT Unknown type of the certificate
    \retval OSSL_INVALID_PARAM Incorrect parameters (NULL data e.g.)
    \retval OSSL_MEMORY_ERROR Internal error (Alloc memory e.g.) */
//------------------------------------------------------------------------------
OSSL_STATUS
CheckCertificateFormat (
  IN CHAR8 *certData,
  IN UINTN certDataLen
  )
{
  BIO *Cert;
  X509 *x509 = NULL;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  // Lazy initializing of OpenSSL
  InitializeOpenSSL();

  if (certData == NULL || certDataLen == 0) {
    lastStatus = OSSL_INVALID_PARAM;
    return lastStatus;
  }

  Cert = BIO_new_mem_buf(certData, (int)certDataLen);
  if (Cert == NULL) {
    lastStatus = OSSL_MEMORY_ERROR;
    return lastStatus;
  }

  x509 = d2i_X509_bio(Cert, NULL);
  BIO_free(Cert);
  
  if (x509 == NULL) {
    x509 = PEM_read_mem_X509(certData, certDataLen, NULL, NULL, NULL);
    if (x509 == NULL)
      lastStatus = OSSL_UNKNOWN_CERT_FORMAT;
    else
      lastStatus = OSSL_SUCCESS_CONVERT_TO_ASN;
  } else
    lastStatus = OSSL_SUCCESS_CONVERT_TO_ASN;

  if (x509 != NULL)
    X509_free(x509);

  PurgeOpenSSLErrors(__FUNCTION__);

  return lastStatus;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Check certificate's revocation status */
/*! If internal error was occured, will be returned TRUE, because we can't check 
    certificate. */
/*! \param[in] *certData A pointer to certificate data 
    \param[in] certDataLen A length of a data
    \param[in] *crlData A pointer to crl
    \param[in] crlDataLen A length of a crl
    \param[out] *status Status of an operation (not a revocation status!) */
/*! \return TRUE if certificate is in CRL, FALSE otherwise */
//------------------------------------------------------------------------------
STATIC
OSSL_STATUS
IsCertificateRevoked (
  IN CHAR8 *certData,
  IN UINTN certDataLen,
  IN CHAR8 *crlData,
  IN UINTN crlDataLen
  )
{
  X509 *x509_cert = NULL;
  X509_CRL *x509_crl = NULL;
  X509_REVOKED *rev = NULL;
  OSSL_STATUS Status = OSSL_INVALID_PARAM;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  // Lazy initializing of OpenSSL
  InitializeOpenSSL();

  if (certData == NULL || certDataLen == 0) {
    return OSSL_INVALID_PARAM;
  }
  if (crlData == NULL || crlDataLen == 0) {
    return OSSL_VERIFY_SUCCESS;
  }

  x509_crl = GetCRLFromBinary(crlData, crlDataLen, &Status);
  if (x509_crl == NULL) {
    return Status;
  }

  x509_cert = GetCertificateFromBinary(certData, certDataLen, &Status);
  if (x509_cert == NULL) {
    goto _exit;
  }

  if (!X509_CRL_get0_by_serial(x509_crl, &rev, X509_get_serialNumber(x509_cert))) {
    LOG((EFI_D_ERROR, "%a.%d OSSL_VERIFY_SUCCESS\n", __FUNCTION__, __LINE__));
    Status = OSSL_VERIFY_SUCCESS;
  } else {
    LOG((EFI_D_ERROR, "%a.%d OSSL_CERT_REVOKED\n", __FUNCTION__, __LINE__));
    Status = OSSL_CERT_REVOKED;
  }

_exit:
  if (x509_crl != NULL)
    X509_CRL_free(x509_crl);

  if (x509_cert != NULL)
    X509_free(x509_cert);

  PurgeOpenSSLErrors(__FUNCTION__);

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Check CRL was signed with the CA from the chain */
/*! \param[in] *crlData A pointer to crl
    \param[in] crlDataLen A length of a crl
    \param[in] *chainData A pointer to CA chain data
    \param[in] chainDataLen A length of a CA chain data */
/*! \retval OSSL_VERIFY_SUCCESS The signature of this CRL is valid
    \retval OSSL_INVALID_PARAM Unknown type of certificate/CRL
    \retval OSSL_MEMORY_ERROR Internal error (Alloc memory e.g.)
    \retval OSSL_UNKNOWN_KEY_FORMAT Format of public key is invalid
    \retval OSSL_INVALID_CRL_SIGNATURE The signature of this CRL is invalid
    \retval OSSL_PKCS7_NOT_SIGNED PKCS7 chain structure is not signed
    \retval OSSL_CANT_GET_TRUSTED_CERTS Trusted chain of CAs is lost in PKCS7 */
//------------------------------------------------------------------------------
OSSL_STATUS
CheckCRLWithCA (
  IN CHAR8 *crlData,
  IN UINTN crlDataLen,
  IN CHAR8 *chainData,
  IN UINTN chainDataLen
  )
{
  X509      *x509_ca  = NULL;
  X509_CRL  *x509_crl = NULL;
  EVP_PKEY* ikey      = NULL;
  PKCS7     *Pkcs7    = NULL;

  STACK_OF(X509) *trustedCerts = NULL;

  INT32 error, count;

  OSSL_STATUS Status = OSSL_INVALID_CRL_SIGNATURE;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  // Lazy initializing of OpenSSL
  InitializeOpenSSL();

  if (crlData == NULL || crlDataLen == 0 || 
      chainData == NULL || chainDataLen == 0) {
    lastStatus = OSSL_INVALID_PARAM;
    return lastStatus;
  }

  x509_crl = GetCRLFromBinary(crlData, crlDataLen, &Status);
  if (x509_crl == NULL)
    goto _exit;

  LOG((EFI_D_ERROR, "%a.%d x509_crl issuer: %a\n",
    __FUNCTION__, __LINE__, X509_NAME_oneline(x509_crl->crl->issuer,NULL,0)));

  LOG((EFI_D_ERROR, "\n"));
  DumpBytes(crlData, crlDataLen);
  LOG((EFI_D_ERROR, "\n"));

  Pkcs7 = GetChainFromBinary(chainData, chainDataLen, &Status);
  if (Pkcs7 == NULL)
    goto _exit;

  if (!PKCS7_type_is_signed (Pkcs7)) {
    Status = OSSL_PKCS7_NOT_SIGNED;
    goto _exit;
  }

  trustedCerts = Pkcs7->d.sign->cert;
  if (trustedCerts == NULL) {
    Status = OSSL_CANT_GET_TRUSTED_CERTS;
    goto _exit;
  }

  Status = OSSL_INVALID_CRL_SIGNATURE;

  for(count =0; count < sk_X509_num(trustedCerts); count++) {
    x509_ca = sk_X509_value (trustedCerts, count);
    LOG((EFI_D_ERROR, "%a.%d x509_ca: %a\n",
      __FUNCTION__, __LINE__, X509_NAME_oneline(X509_get_subject_name(x509_ca),NULL,0)));
    if (ikey != NULL)
      EVP_PKEY_free(ikey);
    ikey = X509_get_pubkey(x509_ca);
    if (ikey == NULL) {
      Status = OSSL_CANT_GET_PKEY_FROM_CERT;
      goto _exit;
    }
    if(X509_CRL_verify(x509_crl, ikey) <= 0)
      continue;
    else {

      time_t currentTime32U;
      EFI_TIME   currentTime;  

      Status = gRT->GetTime (&currentTime, NULL);
      if (EFI_ERROR(Status)) {
        PurgeOpenSSLErrors(__FUNCTION__);
        return OSSL_VERIFY_ERROR;
      }

      currentTime32U = Efi2Time(&currentTime);

      LOG((EFI_D_ERROR, "%a.%d currentTime: %d\n", __FUNCTION__, __LINE__, currentTime32U));

      error = CheckCRLTime(x509_crl, &currentTime32U);
      switch(error) {
        case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
          Status = OSSL_ERR_IN_CRL_LAST_UPDATE_FIELD;
          break;
        case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
          Status = OSSL_ERR_IN_CRL_NEXT_UPDATE_FIELD;
          break;
        case X509_V_ERR_CRL_NOT_YET_VALID:
          Status = OSSL_CRL_NOT_YET_VALID;
          break;
        case X509_V_ERR_CRL_HAS_EXPIRED:
          Status = OSSL_CRL_HAS_EXPIRED;
          break;
        case X509_V_OK:
          Status = OSSL_VERIFY_SUCCESS;
          continue;
        default:
          Status = OSSL_VERIFY_ERROR;
          break;

      }
      break;

    }
  }

_exit:
  if (x509_crl != NULL)
    X509_CRL_free(x509_crl);
  if (ikey != NULL)
    EVP_PKEY_free(ikey);
  if (Pkcs7 != NULL)
    PKCS7_free(Pkcs7);

  PurgeOpenSSLErrors(__FUNCTION__);

  LOG((EFI_D_ERROR, "%a.%d Status: %d\n", 
    __FUNCTION__, __LINE__, Status));

  lastStatus = Status;
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Compare CRLs */
/*! Check CRL's issuers and lastUpdate */
/*! \param[in] *x509_crl_1 CRL N1
    \param[in] *x509_crl_2 CRL N2 */
/*! \retval CRL1_NEWER CRL N1 is newer than CRL N2
    \retval CRL2_NEWER CRL N2 is newer than CRL N1
    \retval CRL_THE_SAME CRL's are the same
    \retval CRL_DIFF_ISSUERS Different issuers of CRLs
    \retval CRL_CMP_ERROR Comparison error - see OSSL lastError for details */
//------------------------------------------------------------------------------
STATIC
CRL_CMP_STATUS
CompareCRL (
  IN X509_CRL *x509_crl_1,
  IN X509_CRL *x509_crl_2,
  OSSL_STATUS *osslStatus
)
{
  CRL_CMP_STATUS Status = CRL_CMP_ERROR;
  int result = 0;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (x509_crl_1 == NULL || x509_crl_2 == NULL) {
    *osslStatus = OSSL_INVALID_PARAM;
    return CRL_CMP_ERROR;
  }

  LOG((EFI_D_ERROR, "crl1 issuer: %a\n",
    X509_NAME_oneline(x509_crl_1->crl->issuer,NULL,0)));
  LOG((EFI_D_ERROR, "crl2 issuer: %a\n",
    X509_NAME_oneline(x509_crl_2->crl->issuer,NULL,0)));

  if (X509_CRL_cmp(x509_crl_1, x509_crl_2) != 0) {
    *osslStatus = OSSL_VERIFY_SUCCESS;
    Status = CRL_DIFF_ISSUERS;
    goto _exit;
  }

  result = ASN1TimeCmp(X509_CRL_get_lastUpdate(x509_crl_1), X509_CRL_get_lastUpdate(x509_crl_2));
  if (result > 0) {
    Status = CRL1_NEWER;
    *osslStatus = OSSL_VERIFY_SUCCESS;
   } else if (result < 0) {
    Status = CRL2_NEWER;
    *osslStatus = OSSL_VERIFY_SUCCESS;
  } else {
    Status = CRL_THE_SAME;
    *osslStatus = OSSL_VERIFY_SUCCESS;
  }

_exit:
  PurgeOpenSSLErrors(__FUNCTION__);

  LOG((EFI_D_ERROR, "%a.%d Status: %d\n", __FUNCTION__, __LINE__, Status));
  LOG((EFI_D_ERROR, "%a.%d osslStatus: %d\n", __FUNCTION__, __LINE__, *osslStatus));

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Return last error has occured */
//------------------------------------------------------------------------------
OSSL_STATUS
GetOsslLastError (
  VOID
)
{
  return lastStatus;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set OSSL error */
//------------------------------------------------------------------------------
VOID
SetOsslLastError (
  OSSL_STATUS Status
)
{
  lastStatus = Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get public key from CA */
/*! Find user certificate's issuer in CA Chain and get public key from it */
//------------------------------------------------------------------------------
OSSL_STATUS
GetPKeyFromCAChainWithCert (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen,
  IN CHAR8 *userCertData,
  IN UINTN userCertLen,
  IN OUT X509 **x509
)
{
  PKCS7       *Pkcs7     = NULL;
  X509        *userX509  = NULL, *CAcert = NULL;
  X509_STORE  *CertStore = NULL;
  X509_STORE_CTX    *csc = NULL;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  lastStatus = OSSL_CANT_GET_PKEY_FROM_CERT;

  if (chainData == NULL || chainDataLen == 0 || userCertData == NULL ||  
    userCertLen == 0 || x509 == NULL) {
    lastStatus  = OSSL_INVALID_PARAM;
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return lastStatus;
  }

  // Lazy initializing of OpenSSL
  InitializeOpenSSL();

  userX509 = GetCertificateFromBinary(userCertData, userCertLen, &lastStatus);
  if (userX509 == NULL) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    PurgeOpenSSLErrors(__FUNCTION__);
    return lastStatus;
  }

  // Retrieve PKCS#7 Data (DER encoding)
  Pkcs7 = d2i_PKCS7 (NULL, &chainData, (int)chainDataLen);
  if (Pkcs7 == NULL) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    PurgeOpenSSLErrors(__FUNCTION__);
    lastStatus  = OSSL_UNKNOWN_PKCS7_FORMAT;
    return lastStatus;
  }

  // Check trusted chain of CAs
  if (Pkcs7->d.sign->cert == NULL) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    lastStatus = OSSL_CANT_GET_TRUSTED_CERTS;
    goto _exit;
  }

  CertStore = X509_STORE_new ();
  if (CertStore == NULL) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    lastStatus = OSSL_MEMORY_ERROR;
    goto _exit;
  }

  csc = X509_STORE_CTX_new();
  if (csc == NULL) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    lastStatus = OSSL_MEMORY_ERROR;
    goto _exit;
  }

  if(!X509_STORE_CTX_init(csc, CertStore, userX509, NULL)) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    lastStatus = OSSL_INIT_ERROR;
    goto _exit;
  }

  // Add the trusted chain of CAs to the context structure
  X509_STORE_CTX_trusted_stack(csc, Pkcs7->d.sign->cert);

  csc->get_issuer(&CAcert, csc, userX509);
  if (CAcert == NULL) {
    lastStatus = OSSL_ERROR_TO_LOAD_ISSUER_CERT_LOCALLY;
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    goto _exit;
  }

  *x509 = X509_dup(CAcert);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  lastStatus = OSSL_VERIFY_SUCCESS;

_exit:
  if (CertStore != NULL) {
    X509_STORE_free(CertStore);
  }
  if (Pkcs7 != NULL) {
    PKCS7_free(Pkcs7);
  }
  if (userX509 != NULL) {
    X509_free(userX509);
  }
  if (CAcert != NULL) {
    X509_free(CAcert);
  }
  if (csc != NULL) {
    X509_STORE_CTX_free(csc);
  }
  PurgeOpenSSLErrors(__FUNCTION__);
  LOG((EFI_D_ERROR, "%a.%d lastStatus: %d\n", 
    __FUNCTION__, __LINE__, lastStatus));

  return lastStatus;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Verify a certificate using certificate chain */
/*! \param[in] *userCertData A pointer to a binary data to verify
    \param[in] userCertLen A length of the cert data binary
    \param[in] *chainData A pointer to a trusted chain binary
    \param[in] chainDataLen A length of the trusted chain binary
    \param[in] crlData A pointer to CRL binary
    \param[in] crlDataLen A length of the CRL binary */
//------------------------------------------------------------------------------
OSSL_STATUS
VerifyCertificateWithCRLandCA (
  IN CHAR8 *userCertData,
  IN UINTN userCertLen,
  IN CHAR8 *chainData,
  IN UINTN chainDataLen,
  IN CHAR8 *crlData,
  IN UINTN crlDataLen
)
{
  PKCS7       *Pkcs7     = NULL;
  X509        *userX509  = NULL;
  X509_STORE  *CertStore = NULL;
  X509_CRL    *x509_crl  = NULL;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (chainData == NULL || chainDataLen == 0) {
    lastStatus  = OSSL_INVALID_PARAM;
    return lastStatus;
  }

  // Lazy initializing of OpenSSL
  InitializeOpenSSL();

  lastStatus = OSSL_INVALID_SIGNATURE;

  userX509 = GetCertificateFromBinary(userCertData, userCertLen, &lastStatus);
  if (userX509 == NULL) {
    PurgeOpenSSLErrors(__FUNCTION__);
    return lastStatus;
  }

  // Retrieve PKCS#7 Data (DER encoding)
  Pkcs7 = d2i_PKCS7 (NULL, &chainData, (int)chainDataLen);
  if (Pkcs7 == NULL) {
    PurgeOpenSSLErrors(__FUNCTION__);
    lastStatus  = OSSL_UNKNOWN_PKCS7_FORMAT;
    return lastStatus;
  }
  // Check PCKS7 type
  if (!PKCS7_type_is_signed (Pkcs7)) {
    lastStatus = OSSL_PKCS7_NOT_SIGNED;
    goto _exit;
  }
  // Check trusted chain of CAs
  if (Pkcs7->d.sign->cert == NULL) {
    lastStatus = OSSL_CANT_GET_TRUSTED_CERTS;
    goto _exit;
  }
  
  if (Pkcs7->d.sign->crl == NULL) {
    LOG((EFI_D_ERROR, "Make crl stack\n"));
    Pkcs7->d.sign->crl = sk_X509_CRL_new_null();
  }

  CertStore = X509_STORE_new ();
  if (CertStore == NULL) {
    lastStatus = OSSL_MEMORY_ERROR;
    goto _exit;
  }
  X509_STORE_set_ocsp_process_resp(CertStore, &ocsp_process_responder);

  // Get a stack of CRLs
  if (crlData != NULL && crlDataLen > 0) {
    x509_crl = GetCRLFromBinary(crlData, crlDataLen, &lastStatus);
    PKCS7_add_crl(Pkcs7, x509_crl);
  }

  CheckAndSaveStackToPkcs7CAChain(GetCRLLocalStack(), Pkcs7, NULL);

  // Verify user certificate
  lastStatus = Check(CertStore, Pkcs7->d.sign->cert, Pkcs7->d.sign->crl, userX509);

_exit:
  if (CertStore != NULL)
    X509_STORE_free(CertStore);
  if (Pkcs7 != NULL)
    PKCS7_free(Pkcs7);
  if (userX509 != NULL)
    X509_free(userX509);

  PurgeOpenSSLErrors(__FUNCTION__);

  LOG((EFI_D_ERROR, "%a.%d lastStatus: %d\n", 
    __FUNCTION__, __LINE__, lastStatus));

  return lastStatus;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Callback to print error messages */
//------------------------------------------------------------------------------
STATIC
int
MsgCallback (
  int ok,
  X509_STORE_CTX *ctx,
  OSSL_STATUS *Status
)
{
  int cert_error = X509_STORE_CTX_get_error(ctx);
  X509 *current_cert = X509_STORE_CTX_get_current_cert(ctx);

  if (!ok) {
    CHAR8 *subjectCert = NULL;

    if (current_cert) {
      subjectCert = X509_NAME_oneline(X509_get_subject_name(current_cert),NULL,0);

      LogOpensslMessage(EFI_D_ERROR, "cert: %a\n%a error %d at %d depth lookup:%a", subjectCert,
        X509_STORE_CTX_get0_parent_ctx(ctx) ? "[CRL path]" : "",
        cert_error,
        X509_STORE_CTX_get_error_depth(ctx),
        X509_verify_cert_error_string(cert_error));

      FreePool(subjectCert);
    } else
      LogOpensslMessage(EFI_D_ERROR, "%a error %d at %d depth lookup:%a",
        X509_STORE_CTX_get0_parent_ctx(ctx) ? "[CRL path]" : "",
        cert_error,
        X509_STORE_CTX_get_error_depth(ctx),
        X509_verify_cert_error_string(cert_error));
  }

  // Convert openssl error code to owr error code
  switch (cert_error) {
  case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
    *Status = OSSL_ERROR_TO_LOAD_ISSUER_CERT_LOCALLY;
    break;
  case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
    *Status = OSSL_ERROR_TO_LOAD_ISSUER_CERT;
    break;
  case X509_V_ERR_CERT_SIGNATURE_FAILURE:
    *Status = OSSL_INVALID_SIGNATURE;
    break;
  case X509_V_ERR_CRL_SIGNATURE_FAILURE:
    *Status = OSSL_INVALID_CRL_SIGNATURE;
    break;
  case X509_V_ERR_CERT_REVOKED:
    *Status = OSSL_CERT_REVOKED;
    break;
  case X509_V_ERR_CERT_NOT_YET_VALID:
    *Status = OSSL_CERT_NOT_YET_VALID;
    break;
  case X509_V_ERR_CERT_HAS_EXPIRED:
    *Status = OSSL_CERT_HAS_EXPIRED;
    break;
  case X509_V_ERR_CRL_NOT_YET_VALID:
    *Status = OSSL_CRL_NOT_YET_VALID;
    break;
  case X509_V_ERR_CRL_HAS_EXPIRED:
    *Status = OSSL_CRL_HAS_EXPIRED;
    break;
  case X509_V_ERR_UNABLE_TO_FIND_OCSP_URL:
  case X509_V_ERR_UNPARSABLE_OCSP_URL:
    *Status = OSSL_OCSP_URL_ERROR;
    break;
  case X509_V_ERR_OCSP_RESPONSE_VERIFICATION:
    *Status = OSSL_OCSP_RESPONSE_VERIFICATION;
    break;
  case X509_V_ERR_OCSP_RESPONDER_QUERY_FAILED:
    *Status = OSSL_OCSP_RESPONDER_QUERY_FAILED;
    break;
  case X509_V_ERR_CERT_UNKNOWN:
    *Status = OSSL_OCSP_CERT_UNKNOWN;
    break;
  case X509_V_ERR_UNABLE_TO_GET_CRL:
    *Status = OSSL_ERR_UNABLE_TO_GET_CRL;
    break;
  default:
    *Status = OSSL_VERIFY_ERROR;
    break;
  }

  return ok;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Verify X509 certificate */
/*! MsgCallback is used to process openssl error messages */
/*! \param[in] *ctx A pointer to the context structure
    \param[in] *cert A stack of trusted signer's certificates
    \param[in] *crls A stack of CRLs
    \param[in] *userX509 Certificate to verify */
/*! \return Code Of Verification Error */
//------------------------------------------------------------------------------
STATIC
OSSL_STATUS
Check (
  IN X509_STORE *ctx,
  IN STACK_OF(X509) *cert,
  STACK_OF(X509_CRL) *crls,
  IN X509       *userX509
)
{
  int retval, ocsp_validate = X509_OCSP_VALIDATE_DISABLED;
  X509 *ocspCA = NULL;
  CHAR8 *ocsp_url8 = NULL;
  CHAR16 *ocsp_url16 = NULL;
  X509_VERIFY_PARAM *vpm = NULL;
  X509_STORE_CTX    *csc = NULL;
  OSSL_STATUS Status = OSSL_INVALID_PARAM;
  UINT16 crlCheckMode;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  // Flush the cache of revokeChkConfig
  DeleteRevokeChkConfig();

  if (cert == NULL) {
    PurgeOpenSSLErrors(__FUNCTION__);
    return OSSL_INVALID_PARAM;
  }

  csc = X509_STORE_CTX_new();
  if (csc == NULL) {
    PurgeOpenSSLErrors(__FUNCTION__);
    return OSSL_MEMORY_ERROR;
  }

  // Set CRL check parameters if needed
  crlCheckMode = GetCrlCheckMode();
  if (CRL_CHECK == crlCheckMode || ALL_CRL_CHECK == crlCheckMode) {
    vpm = X509_VERIFY_PARAM_new();
    if (vpm == NULL) {
      Status = OSSL_MEMORY_ERROR;
      goto _exit;
    }
    if (CRL_CHECK == crlCheckMode)
      X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_CRL_CHECK);
    else
      X509_VERIFY_PARAM_set_flags(vpm, X509_V_FLAG_CRL_CHECK_ALL | X509_V_FLAG_CRL_CHECK);
    X509_STORE_set1_param(ctx, vpm);
  }

  if(!X509_STORE_CTX_init(csc, ctx, userX509, NULL)) {
    Status = OSSL_INIT_ERROR;
    goto _exit;
  }

  // Add CRL to the context structure
  if (crls != NULL) {
    LOG((EFI_D_ERROR, "Now csc crl stack contains %d CRLs\n", sk_X509_CRL_num(crls)));
    X509_STORE_CTX_set0_crls(csc, crls);
  }

  // Add the trusted chain of CAs to the context structure
  X509_STORE_CTX_trusted_stack(csc, cert);

  // Set OCSP check parameters
  if (GetOcspUsageFlag() == TRUE) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    ocsp_url16 = GetOcspUrl();
    ocsp_url8 = AllocateZeroPool(StrLen(ocsp_url16)*sizeof(CHAR8) + sizeof(CHAR8));
    UnicodeStrToAsciiStr(ocsp_url16, ocsp_url8);
    ocsp_validate = X509_OCSP_VALIDATE_ENABLED;
    csc->get_issuer(&ocspCA, csc, userX509);
    if (ocspCA == NULL) {
      Status = OSSL_ERROR_TO_LOAD_ISSUER_CERT_LOCALLY;
      goto _exit;
    }
    LOG((EFI_D_ERROR, "%a.%d ocsp_url8: %a\n", __FUNCTION__, __LINE__, ocsp_url8));
    X509_set_cert_ocsp_opt_with_ca(csc->ctx, ocspCA, ocsp_url8, ocsp_validate);
    csc->param->flags |= X509_V_FLAG_OCSP_CHECK;
    if (GetOCSPResponceVerifyUsageFlag() == USE) {
      csc->param->flags |= X509_V_FLAG_OCSP_RESPONSE_VERIFY;
    }
  }

  // Verify user certificate
  retval = X509_verify_cert(csc);

  // Print error messages to debug
  if (retval <= 0)
    MsgCallback(retval, csc, &Status);
  else
    Status = OSSL_VERIFY_SUCCESS;

_exit:
  if (vpm != NULL)
    X509_VERIFY_PARAM_free(vpm);
  if (csc != NULL)
    X509_STORE_CTX_free(csc);
  if (ocsp_url8 != NULL)
    FreePool(ocsp_url8);

  DeleteRevokeChkConfig();

  PurgeOpenSSLErrors(__FUNCTION__);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Add CRL to the local CRL stack */
/*! If the stack contains a CRL, which is newer than the CRL to save, skip adding */
/*! This stack is not a Cert Storage! This is a stack of X509_CRL structures. 
    Use CheckAndSaveStackToChainStorage() to add this stack to CA Chain and save 
    this chain to the storage */
/*! \param[in] *crlData A pointer to CRL binary
    \param[in] crlDataLen A length of the CRL binary */
//------------------------------------------------------------------------------
OSSL_STATUS
AddCRLtoLocalStack (
  IN CHAR8 *crlData,
  IN UINTN crlDataLen
)
{
  int count, crlCount = 0;
  X509_CRL *x509_crl  = NULL, *X509_crlToCmp = NULL;
  CRL_CMP_STATUS cmpStatus = CRL_CMP_ERROR;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  if (crlData == NULL || crlDataLen == 0) {
    lastStatus = OSSL_INVALID_PARAM;
    goto _exit;
  }

  // Lazy initializing of OpenSSL
  InitializeOpenSSL();

  if (localCRLStack.localCRLs == NULL) {
    localCRLStack.localCRLs = sk_X509_CRL_new_null();
    localCRLStack.stackIsFresh = FALSE;
  }
  if (localCRLStack.localCRLs == NULL) {
    lastStatus = OSSL_MEMORY_ERROR;
    goto _exit;
  }

  X509_crlToCmp = GetCRLFromBinary(crlData, crlDataLen, &lastStatus);
  if (X509_crlToCmp == NULL)
    goto _exit;

  // Perform a comparision of CRLs
  for(count = 0; count < sk_X509_CRL_num(localCRLStack.localCRLs); count++) {
    x509_crl = sk_X509_CRL_value (localCRLStack.localCRLs, count);
    cmpStatus = CompareCRL(x509_crl, X509_crlToCmp, &lastStatus);
    if (cmpStatus == CRL2_NEWER) {
      LOG((EFI_D_ERROR, "X509_crlToCmp is newer, push it in\n"));
      X509_CRL_free(x509_crl);
      sk_X509_CRL_set(localCRLStack.localCRLs, count, X509_crlToCmp);
      break;
    }
    crlCount++;
  }

  // If CRL is not in the stack or stack is empty, push it in
  if (crlCount == sk_X509_CRL_num(localCRLStack.localCRLs) || crlCount == 0) {
    LOG((EFI_D_ERROR, "CRL isn't in stack, push it in\n"));
    if (!sk_X509_CRL_push(localCRLStack.localCRLs, X509_crlToCmp)) {
      lastStatus = OSSL_ERROR_TO_SAVE_CRL_TO_LOCAL_STACK;
      goto _exit;
    }
  }
  lastStatus = OSSL_VERIFY_SUCCESS;
  localCRLStack.stackIsFresh = TRUE;

_exit:
  PurgeOpenSSLErrors(__FUNCTION__);
  LOG((EFI_D_ERROR, "%a.%d status: %d\n", __FUNCTION__, __LINE__, lastStatus));
  return lastStatus;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Flush Local Stack of CRLs */
//------------------------------------------------------------------------------
VOID
FlushCRLLocalStack (
  VOID
)
{
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  sk_X509_CRL_free(localCRLStack.localCRLs);
  localCRLStack.localCRLs = NULL;
  localCRLStack.stackIsFresh = FALSE;
  PurgeOpenSSLErrors(__FUNCTION__);
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a pointer to the Local Stack */
/*! Use this function to get access to the localCRLs. Don't use localCRLs
    directly! */
//------------------------------------------------------------------------------
STATIC
STACK_OF(X509_CRL)*
GetCRLLocalStack (
  VOID
)
{
  if (localCRLStack.localCRLs == NULL) {
    localCRLStack.localCRLs = sk_X509_CRL_new_null();
    localCRLStack.stackIsFresh = FALSE;
  }
  PurgeOpenSSLErrors(__FUNCTION__);

  return localCRLStack.localCRLs;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a status of the local CRL stack */
//------------------------------------------------------------------------------
BOOLEAN
IsCRLLocalStackFresh (
  VOID
)
{
  return localCRLStack.stackIsFresh;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Check CRLs (lastUpdate and Issuer) and add to CA Chain Storage */
/*! Save all CRLs from Local Stack to CA Chain Storage */
/*! \param[in] *chainData A binary data of the CA Chain Storage 
    \param[in] chainDataLen A length of a binary data of the CA Chain Storage */
/*! \return OSSL_NO_NEED_TO_SAVE_CRLS if CRLs haven't been saved because of no need */
//------------------------------------------------------------------------------
OSSL_STATUS
CheckAndSaveStackToChainStorage (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen
)
{
  BOOLEAN needToResave = FALSE;
  PKCS7 *Pkcs7 = NULL;

  OSSL_STATUS    Status    = OSSL_INVALID_PARAM;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  // Lazy initializing of OpenSSL
  InitializeOpenSSL();

  Pkcs7 = GetChainFromBinary(chainData, chainDataLen, &Status);
  if (Pkcs7 == NULL)
    goto _exit;

  Status = CheckAndSaveStackToPkcs7CAChain (GetCRLLocalStack(), Pkcs7, &needToResave);
  if (Status != OSSL_VERIFY_SUCCESS)
    goto _exit;

  if (TRUE == needToResave)
    Status = SavePkcs7CAChainToFlash(Pkcs7);
  else
    Status = OSSL_NO_NEED_TO_SAVE_CRLS;

_exit:
  if (Pkcs7 != NULL) PKCS7_free(Pkcs7);

  PurgeOpenSSLErrors(__FUNCTION__);

  lastStatus = Status;
  LOG((EFI_D_ERROR, "%a.%d status: %d\n", __FUNCTION__, __LINE__, Status));
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Check CRLs (lastUpdate and Issuer) and add to PKCS7 CA Chain */
/*! We use dublicate copies of CRLs, because stack's GET and SET functions
    work with pointers, not object's copies */
/*! \param[in] *crlStack Stack of CRLs to add
    \param[in] *Pkcs7 PKCS7 CA Chain 
    \param[out] *needToResave Need to refresh CA Chain binary in the flash */
/*! \return Code Of Error or OSSL_VERIFY_SUCCESS */
/*! \retval TRUE Pkcs7 contains new CRLs, FALSE Pkcs7 hasn't been change */
//------------------------------------------------------------------------------
STATIC
OSSL_STATUS
CheckAndSaveStackToPkcs7CAChain (
  IN STACK_OF(X509_CRL) *crlStack,
  IN OUT PKCS7 *Pkcs7,
  OUT OPTIONAL BOOLEAN *needToResave
)
{
  int i, j, numCRLs;
  STACK_OF(X509_CRL) *crls = NULL;
  X509_CRL *newCRL = NULL, *oldCRL = NULL, *crlForStack = NULL;
  BOOLEAN isNotInStack = TRUE;

  CRL_CMP_STATUS cmpStatus = CRL_CMP_ERROR;
  OSSL_STATUS    Status    = OSSL_VERIFY_SUCCESS;

  if (crlStack == NULL || Pkcs7 == NULL)
    return OSSL_INVALID_PARAM;

  if (Pkcs7->d.sign->crl == NULL) {
    Pkcs7->d.sign->crl = sk_X509_CRL_new_null();
    if (Pkcs7->d.sign->crl == NULL) {
      PurgeOpenSSLErrors(__FUNCTION__);
      return OSSL_MEMORY_ERROR;
    }
  }

  crls = Pkcs7->d.sign->crl;

  LOG((EFI_D_ERROR, "PKCS7 contains %d CRLs\n", sk_X509_CRL_num(crls)));

  for(i = 0; i < sk_X509_CRL_num(crlStack); i++) {
    newCRL = sk_X509_CRL_value (crlStack, i);
    isNotInStack = TRUE;
    numCRLs = sk_X509_CRL_num(crls);
    for(j = 0; j < numCRLs; j++) {
      oldCRL = sk_X509_CRL_value (crls, j);
      cmpStatus = CompareCRL(oldCRL, newCRL, &Status);
      if (cmpStatus == CRL2_NEWER) {
        LOG((EFI_D_ERROR, "Update CRL...\n"));
        X509_CRL_free(oldCRL);
        crlForStack = X509_CRL_dup(newCRL);
        sk_X509_CRL_set(crls, j, crlForStack);
        if (needToResave != NULL) *needToResave = TRUE;
        isNotInStack = FALSE;
        break;
      } else if (cmpStatus == CRL_THE_SAME || cmpStatus == CRL1_NEWER) {
        isNotInStack = FALSE;
        break;
      }
    }

    if (isNotInStack == TRUE) {
      LOG((EFI_D_ERROR, "CRL isn't in the stack or stack is empty, push it in\n"));
      crlForStack = X509_CRL_dup(newCRL);
      if (!sk_X509_CRL_push(crls, crlForStack)) {
        PurgeOpenSSLErrors(__FUNCTION__);
        return OSSL_ERROR_TO_SAVE_CRL_TO_CA_CHAIN;
      }
      if (needToResave != NULL) *needToResave = TRUE;
    }
  }

  PurgeOpenSSLErrors(__FUNCTION__);
  LOG((EFI_D_ERROR, "Now PKCS7 contains %d CRLs\n", sk_X509_CRL_num(Pkcs7->d.sign->crl)));

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Save Pkcs7 to the storage */
/*! This function doesn't use CertStorageLib directly. We use BIO_write to save
    BIO struct to the file -> StdLib fwrite() method saves it to the storage. */
/*! \param[in] *Pkcs7 PKCS7 CA Chain to save */
/*! \return Code Of Error or OSSL_VERIFY_SUCCESS */
//------------------------------------------------------------------------------
STATIC
OSSL_STATUS
SavePkcs7CAChainToFlash (
  IN OUT PKCS7 *Pkcs7
)
{
  int result;
  BIO *bioToSave = NULL;
  OSSL_STATUS Status = OSSL_VERIFY_SUCCESS;
  UINT8 *bioData;
  UINTN bioDataLen;
  EFI_STATUS EfiStatus;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  
  bioToSave = BIO_new(BIO_s_mem());
  if (bioToSave == NULL) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    Status = OSSL_ERROR_TO_SAVE_BIO;
    goto _exit;
  }
  result = i2d_PKCS7_bio(bioToSave, Pkcs7);
  if (!result) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    Status = OSSL_ERROR_TO_SAVE_BIO;
    goto _exit;
  }

  bioDataLen = BIO_get_mem_data(bioToSave, &bioData);
  LOG((EFI_D_ERROR, "%a.%d bioDataLen = %d\n", __FUNCTION__, __LINE__, bioDataLen));

  EfiStatus = CertStorageLibSetRawData (L"StorageFile", 
    CHAIN_STORAGE_VAR_NAME, &gChainStorageGuid, 
    CS_TYPE_GOST, STORAGE_RDWR_ATTR, 
    bioData, bioDataLen);
  if (EFI_ERROR(EfiStatus)) {
    LOG((EFI_D_ERROR, "%a.%d EfiStatus = %r\n", __FUNCTION__, __LINE__, EfiStatus));
    Status = OSSL_ERROR_TO_SAVE_CRL_TO_CA_CHAIN;
  }

_exit:
  if (bioToSave != NULL) BIO_free_all(bioToSave);

  PurgeOpenSSLErrors(__FUNCTION__);

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Copy CRL Stack */
/*! Deep copy of the stack. All CRLs from the stack will be copied */
/*! \param[in] *stackToCopy CRL Stack to copy */
/*! \return Deep copy of the Stack */
//------------------------------------------------------------------------------
STATIC
STACK_OF(X509_CRL)*
DeepCopyCrlStack (
  STACK_OF(X509_CRL) *stackToCopy
)
{
  int i;
  STACK_OF(X509_CRL) *crls  = NULL;
  X509_CRL *newCRL = NULL, *crlForStack = NULL;

  crls = sk_X509_CRL_new_null();
  if (crls == NULL)
    goto _error;

  for(i = 0; i < sk_X509_CRL_num(stackToCopy); i++) {
    newCRL = sk_X509_CRL_value (stackToCopy, i);
    crlForStack = X509_CRL_dup(newCRL);
    if (!sk_X509_CRL_push(crls, crlForStack))
      goto _error;
  }

  PurgeOpenSSLErrors(__FUNCTION__);

  return crls;

_error:
  if (crls != NULL)
    sk_X509_CRL_free(crls);

  PurgeOpenSSLErrors(__FUNCTION__);

  return NULL;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Copy CRL stack from Local CRL Stack */
/*! This method hides data type. You have to use sk_X509_CRL_free() when you dont
    need it anymore. */
//------------------------------------------------------------------------------
VOID*
CopyCRLStackFromLocalStack (
  VOID
)
{
  STACK_OF(X509_CRL) *crls  = NULL;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  // Lazy initializing of OpenSSL
  InitializeOpenSSL();

  crls = DeepCopyCrlStack(localCRLStack.localCRLs);
  if (crls == NULL)
    lastStatus = OSSL_MEMORY_ERROR;

  PurgeOpenSSLErrors(__FUNCTION__);

  LOG((EFI_D_ERROR, "tlsStack: %d CRLs\n", sk_X509_CRL_num(crls)));

  return (VOID *)crls;
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
/*! \brief Copy CRL stack from CA Chain */
/*! This method hides data type. You have to use sk_X509_CRL_free() when you dont
    need it anymore. */
/*! \param[in] *chainData CA Chain binary 
    \param[in] chainDataLen The lenght of the data */
/*! \return Deep copy of CRL Stack or NULL if error */
//------------------------------------------------------------------------------
VOID*
CopyCRLStackFromCAChain (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen
)
{
  PKCS7              *Pkcs7 = NULL;
  STACK_OF(X509_CRL) *crls  = NULL;

  OSSL_STATUS Status = OSSL_INVALID_PARAM;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (chainData == NULL || chainDataLen == 0) {
    lastStatus = OSSL_INVALID_PARAM;
    return NULL;
  }

  // Lazy initializing of OpenSSL
  InitializeOpenSSL();

  Pkcs7 = GetChainFromBinary(chainData, chainDataLen, &Status);
  if (Pkcs7 == NULL)
    goto _exit;

  Status = CheckAndSaveStackToPkcs7CAChain (GetCRLLocalStack(), Pkcs7, NULL);
  if (Status != OSSL_VERIFY_SUCCESS)
    goto _exit;

  crls = DeepCopyCrlStack(Pkcs7->d.sign->crl);
  if (crls == NULL)
    lastStatus = OSSL_MEMORY_ERROR;

  LOG((EFI_D_ERROR, "tlsStack: %d CRLs\n", sk_X509_CRL_num(crls)));

_exit:
  lastStatus = Status;
  if (Pkcs7 != NULL) PKCS7_free(Pkcs7);

  PurgeOpenSSLErrors(__FUNCTION__);

  return (VOID *)crls;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Copy X509 Stack */
/*! Deep copy of the stack. All certs from the stack will be copied */
/*! \param[in] *stackToCopy X509 Stack to copy */
/*! \return Deep copy of the Stack */
//------------------------------------------------------------------------------
STATIC
STACK_OF(X509)*
DeepCopyX509Stack (
  STACK_OF(X509) *stackToCopy
)
{
  int i;
  STACK_OF(X509) *stack  = NULL;
  X509 *newCert = NULL, *certForStack = NULL;

  stack = sk_X509_new_null();
  if (stack == NULL)
    goto _error;

  for(i = 0; i < sk_X509_num(stackToCopy); i++) {
    newCert = sk_X509_value (stackToCopy, i);
    certForStack = X509_dup(newCert);
    if (!sk_X509_push(stack, certForStack))
      goto _error;
  }

  PurgeOpenSSLErrors(__FUNCTION__);

  return stack;

_error:
  if (stack != NULL)
    sk_X509_free(stack);

  PurgeOpenSSLErrors(__FUNCTION__);

  return NULL;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get CRL stack from CA Chain */
/*! This method hides data type. You have to use sk_X509_free() when you dont
    need it anymore. */
/*! \param[in] *chainData CA Chain binary
    \param[in] chainDataLen The lenght of the data */
/*! \return Deep copy of X509 Stack or NULL if error */
//------------------------------------------------------------------------------
VOID*
CopyTrustedStackFromCAChain (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen
)
{
  PKCS7           *Pkcs7   = NULL;
  STACK_OF(X509)  *trusted = NULL;

  OSSL_STATUS Status = OSSL_INVALID_PARAM;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (chainData == NULL || chainDataLen == 0) {
    lastStatus = OSSL_INVALID_PARAM;
    return NULL;
  }

  // Lazy initializing of OpenSSL
  InitializeOpenSSL();

  Pkcs7 = GetChainFromBinary(chainData, chainDataLen, &Status);
  if (Pkcs7 == NULL)
    goto _exit;

  trusted = DeepCopyX509Stack(Pkcs7->d.sign->cert);
  if (trusted == NULL)
    lastStatus = OSSL_MEMORY_ERROR;

  LOG((EFI_D_ERROR, "tlsStack: %d certs\n", sk_X509_num(trusted)));

_exit:
  lastStatus = Status;
  if (Pkcs7 != NULL) PKCS7_free(Pkcs7);

  PurgeOpenSSLErrors(__FUNCTION__);

  return (VOID *)trusted;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Make TLS config */
/*! This config is used by OpenLDAP */
/*! \param[in] *chainData A pointer to the CA Chain binary, contains a CRL Stack
    \param[in] chainDataLen A lenght of the chain data */
/*! \return A pointer to the TLS config */
//------------------------------------------------------------------------------
tlsConfig_t
MakeTlsConfig (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen
)
{
  tlsConfig_t config = {0};

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  // Lazy initializing of OpenSSL
  InitializeOpenSSL();

  //------------------------------------------------------------------------
  // Create a CRL stack to check revocation status of TLS server certificate
  //------------------------------------------------------------------------
  if (GetCDPCasheUsageFlag() == USE)
    config.crlStack = CopyCRLStackFromCAChain(chainData, chainDataLen);
  else
    config.crlStack = CopyCRLStackFromLocalStack();
  //------------------------------------------------------------------------

  config.cnfFileData = GetOpensslConfigFromFV();
  config.trustedStack = CopyTrustedStackFromCAChain(chainData, chainDataLen);
  config.crlFlag = GetTLSCrlCheckMode();

  PurgeOpenSSLErrors(__FUNCTION__);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return config;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get CDP URLs from X509 certificate */
/*! \param[in] cert X509 certificate */
/*! \param[out] cdpListHead A head of CDP URLs list
    \param[out] cdpUrlCount A count of CDP URLs */
//------------------------------------------------------------------------------
OSSL_STATUS
GetCDPListFromX509 (
  IN X509 *cert,
  OUT LIST_ENTRY *cdpListHead,
  OUT UINTN *cdpUrlCount
)
{
  INT32 i, j;
  GENERAL_NAMES *gens = NULL;
  STACK_OF(DIST_POINT) *crldp = NULL;

  LOG((EFI_D_ERROR, "%a.%d cdpUrlCount: %d\n", __FUNCTION__, __LINE__, *cdpUrlCount));

  if (cert == NULL || cdpListHead == NULL || cdpUrlCount == NULL)
    return OSSL_INVALID_PARAM;

  crldp = X509_get_ext_d2i(cert, NID_crl_distribution_points, NULL, NULL);
  if (crldp == NULL) {
    LOG((EFI_D_ERROR, "%a.%d OSSL_ERR_UNABLE_TO_GET_CERT_CDP_EXT\n", __FUNCTION__, __LINE__));
    PurgeOpenSSLErrors(__FUNCTION__);
    return OSSL_ERR_UNABLE_TO_GET_CERT_CDP_EXT;
  }

  for (i = 0; i < sk_DIST_POINT_num(crldp); i++) {
    DIST_POINT *dp = sk_DIST_POINT_value(crldp, i);
    gens = dp->distpoint->name.fullname;
    if (dp->distpoint->type == 0) {
      GENERAL_NAME *gen;
      for(j = 0; j < sk_GENERAL_NAME_num(gens); j++) {
        ASN1_IA5STRING *crlUri;
        CHAR8 *uri;
        gen = sk_GENERAL_NAME_value(gens, j);
        if (gen->type == GEN_URI) {
          CDP_URL_ENTRY *cdpEntry;
          crlUri = gen->d.uniformResourceIdentifier;
          uri = ASN1_STRING_data(crlUri);
          LOG((EFI_D_ERROR, "%a.%d uri: %a\n", __FUNCTION__, __LINE__, uri));
          cdpEntry = AllocateZeroPool(sizeof(CDP_URL_ENTRY));
          if (cdpEntry == NULL) {
            // Just return what we have
            LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
            PurgeOpenSSLErrors(__FUNCTION__);
            return OSSL_VERIFY_SUCCESS;
          }
          cdpEntry->cdpUri = uri;
          InsertTailList(cdpListHead, &cdpEntry->ListEntry);
          (*cdpUrlCount)++;
        }
      }
    }
  }

  PurgeOpenSSLErrors(__FUNCTION__);
  return OSSL_VERIFY_SUCCESS;

}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get Get CDP extensions for CAChain in PKCS7 */
/*! \param[in] *chainData CAChain binary
    \param[in] chainDataLen Binary size
    \param[out] A pointer to the head of the list of cdp uri */
/*! \return Count of cdp uri */
//------------------------------------------------------------------------------
UINTN
GetCDPListFromCaChainBinary (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen,
  OUT LIST_ENTRY *cdpListHead
)
{
  X509  *cert  = NULL;
  PKCS7 *Pkcs7 = NULL;
  STACK_OF(X509) *certChain   = NULL;

  INT32 i;
  UINTN cdpUrlCount = 0, count = 0;
  OSSL_STATUS lastStatus = OSSL_UNKNOWN_PKCS7_FORMAT;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  // Retrieve PKCS#7 Data (DER encoding)
  Pkcs7 = d2i_PKCS7 (NULL, &chainData, (int)chainDataLen);
  if (Pkcs7 == NULL) {
    PurgeOpenSSLErrors(__FUNCTION__);
    lastStatus  = OSSL_UNKNOWN_PKCS7_FORMAT;
    return 0;
  }
  // Check chain of CAs
  if (Pkcs7->d.sign->cert == NULL) {
    lastStatus = OSSL_CANT_GET_TRUSTED_CERTS;
    goto _exit;
  }

  certChain = Pkcs7->d.sign->cert;

  for(i = 0; i < sk_X509_num(certChain); i++) {
    cert = sk_X509_value (certChain, i);
    if (cert != NULL) {
      lastStatus = GetCDPListFromX509(cert, cdpListHead, &count);
      if (count != 0)
        cdpUrlCount += count;
      count = 0;
    }
  }

_exit:
  if (Pkcs7 != NULL)
    PKCS7_free(Pkcs7);

  PurgeOpenSSLErrors(__FUNCTION__);

  LOG((EFI_D_ERROR, "%a.%d Num CDP uri: %d\n", __FUNCTION__, __LINE__, cdpUrlCount));

  return cdpUrlCount;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get CDP extension from certificate binary */
/*! \param[in] *certData Certificate binary
    \param[in] certDataLen Binary size
    \param[out] A pointer to the head of the list of cdp uri */
/*! \return Count of cdp uri */
//------------------------------------------------------------------------------
UINTN
GetCDPListFromCertBinary (
  IN CHAR8 *certData,
  IN UINTN certDataLen,
  OUT LIST_ENTRY *cdpListHead
)
{
  X509 *cert = NULL;
  UINTN cdpUrlCount = 0;
  OSSL_STATUS lastStatus = OSSL_UNKNOWN_CERT_FORMAT;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  cert = GetCertificateFromBinary(certData, certDataLen, &lastStatus);
  if (cert == NULL) {
    PurgeOpenSSLErrors(__FUNCTION__);
    lastStatus = OSSL_MEMORY_ERROR;
    return 0;
  }

  lastStatus = GetCDPListFromX509(cert, cdpListHead, &cdpUrlCount);

  LOG((EFI_D_ERROR, "%a.%d lastStatus: %d, cdpUrlCount: %d\n", __FUNCTION__, __LINE__,
    lastStatus, cdpUrlCount));
  
  if (cert != NULL)
    X509_free(cert);

  PurgeOpenSSLErrors(__FUNCTION__);
  return cdpUrlCount;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Calculate a digest for a data file */
//------------------------------------------------------------------------------
EFI_STATUS
CalcDataDigest (
  IN UINT8 *CertData,
  IN UINTN CertDataLen,
  IN UINT8 *FileData,
  IN UINTN FileDataLen,
  OUT UINT8 **SignBuf,
  OUT UINTN *SignLen
  )
{
  EVP_MD_CTX md_ctx;
  EVP_PKEY *Pkey = NULL;
  BIO *Cert = NULL;
  EFI_STATUS Status = EFI_ABORTED;
  X509 *x509 = NULL;
  int Err, SigType, MdNid, PkNid;
  unsigned int len;
  const char rnd_seed[] = "string to make the random number generator think it has entropy";

  CalcDataDigest_MdType = 0;

  if (CertData == NULL || CertDataLen == 0) {
    LogOpensslMessage ( EFI_D_ERROR, "Error: %a", "CA trusted chain is empty!");
    return EFI_INVALID_PARAMETER;
  }

  if (FileData == NULL || FileDataLen == 0) {
    return EFI_INVALID_PARAMETER;
  }

  // Lazy initializing of OpenSSL
  InitializeOpenSSL();

  RAND_seed(rnd_seed, sizeof rnd_seed);

  *SignBuf = NULL;
  *SignLen = 0;

  // check for format
  if (OSSL_SUCCESS_CONVERT_TO_ASN == CheckChainFormat(CertData, CertDataLen)) {
      if (OSSL_VERIFY_SUCCESS != GetPKeyFromCAChainWithCert(CertData, CertDataLen,
                                   FileData, FileDataLen, &x509)) {
        LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
        PurgeOpenSSLErrors(__FUNCTION__);
        return EFI_INVALID_PARAMETER;
      }
  } else {
    Cert = BIO_new_mem_buf(CertData, (int)CertDataLen);
    if (Cert == NULL) {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      Status = EFI_OUT_OF_RESOURCES;
      goto _exit;
    }

    x509 = d2i_X509_bio(Cert, NULL);     
    if (x509 == NULL) {
      LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
      x509 = PEM_read_mem_X509(CertData, CertDataLen, NULL, NULL, NULL);      
    }    
  }

  if (x509 == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    Status = EFI_ABORTED;
    goto _exit;
  }

  Pkey = X509_get_pubkey(x509);    
  if (Pkey == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));    
    Status = EFI_ABORTED;
    goto _exit;
  }
  
  SigType = OBJ_obj2nid(x509->sig_alg->algorithm);
  LOG((EFI_D_ERROR, "%a.%d SigType=0x%X\n", __FUNCTION__, __LINE__, SigType));
      
  if (!OBJ_find_sigid_algs(SigType, &MdNid, &PkNid)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));    
    Status = EFI_ABORTED;
    goto _exit;
  }
  LOG((EFI_D_ERROR, "%a.%d MdNid=0x%X PkNid=0x%X\n", 
    __FUNCTION__, __LINE__, MdNid, PkNid));
  CalcDataDigest_MdType = (UINTN)MdNid;

  *SignBuf = AllocateZeroPool(128);
  if (*SignBuf == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));    
    Status = EFI_ABORTED;
    goto _exit;
  }

  EVP_MD_CTX_init(&md_ctx);

  if (EVP_DigestInit(&md_ctx, EVP_get_digestbynid(MdNid)) != 1) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));    
    Status = EFI_ABORTED;
    goto _exit;
  }

  if (EVP_DigestUpdate(&md_ctx, FileData, FileDataLen) != 1) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));    
    Status = EFI_ABORTED;
    goto _exit;
  }

  len = EVP_PKEY_size(Pkey);
  Err = EVP_DigestFinal (&md_ctx, (unsigned char*)*SignBuf, &len);
  if (Err != 1) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    Status = EFI_CRC_ERROR;
  } else { 
    Status = EFI_SUCCESS;
    LOG((EFI_D_ERROR, "%a.%d Digest (%d)\n", __FUNCTION__, __LINE__, len));
    DumpBytes(*SignBuf, len);
    *SignLen = (UINTN)len;
  }
  
_exit:
  if (EFI_ERROR(Status) && *SignBuf != NULL) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    FreePool(*SignBuf);
    *SignBuf = NULL;
  }
  if (Pkey != NULL) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    EVP_PKEY_free(Pkey);
  }
  if (x509 != NULL) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    X509_free(x509);
  }
  if (Cert != NULL) {
    LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    BIO_free(Cert);
  }
  
  PurgeOpenSSLErrors(__FUNCTION__);
  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return Status;
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
/*! \brief Check data signature method */
//------------------------------------------------------------------------------
EFI_STATUS
CheckDataSignature (
  IN UINT8 *CertData,
  IN UINTN CertDataLen,
  IN UINT8 *Data,
  IN UINTN DataLen,
  IN UINT8 *SigData,
  IN UINTN SigDataLen
  )
{
  EVP_MD_CTX md_ctx;
  EVP_PKEY *Pkey = NULL;
  BIO *Cert;
  EFI_STATUS Status = EFI_SUCCESS;
  X509 *x509;
  int Err, SigType, MdNid, PkNid;

  if (CertData == NULL || SigData == NULL || CertDataLen == 0 || 
      SigDataLen == 0 || Data == NULL || DataLen == 0) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  Cert = BIO_new_mem_buf(CertData, (int)CertDataLen);
  if (Cert == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    Status = EFI_OUT_OF_RESOURCES;
    goto _exit;
  }

  x509 = d2i_X509_bio(Cert, NULL); 
  BIO_free(Cert);
  if (x509 == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    x509 = PEM_read_mem_X509(CertData, CertDataLen, NULL, NULL, NULL);
    if (x509 == NULL) {
      DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));  
      Status = EFI_ABORTED;
      goto _exit;
    }
  }

  Pkey = X509_get_pubkey(x509);    
  if (Pkey == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));    
    Status = EFI_ABORTED;
    goto _exit;
  }  
  SigType = OBJ_obj2nid(x509->sig_alg->algorithm);
  X509_free(x509);
  if (!OBJ_find_sigid_algs(SigType, &MdNid, &PkNid)) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));    
    Status = EFI_ABORTED;
    goto _exit;
  }
  DEBUG((EFI_D_ERROR, "%a.%d MdNid=0x%X PkNid=0x%X\n", 
    __FUNCTION__, __LINE__, MdNid, PkNid));    
  
  if (EVP_VerifyInit(&md_ctx, EVP_get_digestbynid(MdNid)) != 1) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));    
    Status = EFI_ABORTED;
    goto _exit;
  }
  if (EVP_VerifyUpdate(&md_ctx, Data, DataLen) != 1) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));    
    Status = EFI_ABORTED;
    goto _exit;
  }
  Err = EVP_VerifyFinal (&md_ctx, SigData, (unsigned int)SigDataLen, Pkey);
  if (Err != 1) {
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    Status = EFI_CRC_ERROR;
  }

_exit:
  if (Pkey) {
    EVP_PKEY_free(Pkey);
  }
  return Status;
}
//------------------------------------------------------------------------------



//------------------------------------------------------------------------------
/*! \brief Getter method for the calculated digest */
//------------------------------------------------------------------------------
UINTN
GetCalcDataDigest_MdType (
  VOID
  )
{
  return CalcDataDigest_MdType;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Check that Digest is a GOST */
//------------------------------------------------------------------------------
BOOLEAN
IsGostDigest (
  IN UINTN digestType
  )
{
  if (NID_id_GostR3411_94 == digestType)
    return TRUE;
  else
    return FALSE;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a subject name in a CHAR16 representation from the given certificate */
/*! \param[in] *certData A certificate in a bynary form
    \param[in] certDataLen A length of the binary certificate
    \param[out] **subjectName A subject name */
//------------------------------------------------------------------------------
EFI_STATUS
GetCertificateSubjectName(
  IN CHAR8 *certData,
  IN UINTN certDataLen,
  OUT CHAR16 **subjectName
)
{
  X509 *x509 = NULL;

  EFI_STATUS Status = EFI_ABORTED;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if ((certData == NULL) || (certDataLen == 0) ||
      (subjectName == NULL) || (*subjectName != NULL)) {
    lastStatus = OSSL_INVALID_PARAM;
    return EFI_INVALID_PARAMETER;
  }

  x509 = GetCertificateFromBinary(certData, certDataLen, &lastStatus);
  if (x509 == NULL) {
    PurgeOpenSSLErrors(__FUNCTION__);
    return EFI_INVALID_PARAMETER;
  }

  lastStatus = GetSubjectFromX509(x509, subjectName);
  if (OSSL_NO_ERROR == lastStatus)
    Status = EFI_SUCCESS;

  if (x509 != NULL)
    X509_free(x509);

  PurgeOpenSSLErrors(__FUNCTION__);
  LOG((EFI_D_ERROR, "%a.%d Status: %d\n", __FUNCTION__, __LINE__, Status));

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get an issuer name in a CHAR16 representation from the given certificate */
//------------------------------------------------------------------------------
EFI_STATUS
GetCertificateIssuerName(
  IN CHAR8 *certData,
  IN UINTN certDataLen,
  OUT CHAR16 **issuerName
)
{
  X509 *x509 = NULL;

  EFI_STATUS Status = EFI_ABORTED;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if ((certData == NULL) || (certDataLen == 0) ||
      (issuerName == NULL) || (*issuerName != NULL)) {
    lastStatus = OSSL_INVALID_PARAM;
    return EFI_INVALID_PARAMETER;
  }

  x509 = GetCertificateFromBinary(certData, certDataLen, &lastStatus);
  if (x509 == NULL) {
    PurgeOpenSSLErrors(__FUNCTION__);
    return EFI_INVALID_PARAMETER;
  }

  lastStatus = GetIssuerFromX509(x509, issuerName);
  if (OSSL_NO_ERROR == lastStatus)
    Status = EFI_SUCCESS;

  if (x509 != NULL)
    X509_free(x509);

  PurgeOpenSSLErrors(__FUNCTION__);
  LOG((EFI_D_ERROR, "%a.%d Status: %d\n", __FUNCTION__, __LINE__, Status));

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a notBefore date in a CHAR16 representation from the given certificate */
//------------------------------------------------------------------------------
EFI_STATUS
GetCertificateNotBeforeDate(
  IN CHAR8 *certData,
  IN UINTN certDataLen,
  OUT CHAR16 **notBeforeDate
)
{
  X509 *x509 = NULL;

  EFI_STATUS Status = EFI_ABORTED;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if ((certData == NULL) || (certDataLen == 0) ||
      (notBeforeDate == NULL) || (*notBeforeDate != NULL)) {
    lastStatus = OSSL_INVALID_PARAM;
    return EFI_INVALID_PARAMETER;
  }

  x509 = GetCertificateFromBinary(certData, certDataLen, &lastStatus);
  if (x509 == NULL) {
    PurgeOpenSSLErrors(__FUNCTION__);
    lastStatus = OSSL_INVALID_PARAM;
    return EFI_INVALID_PARAMETER;
  }

  Status = GetASN1Time(X509_get_notBefore(x509), notBeforeDate);
  if (Status == EFI_INVALID_PARAMETER) {
    lastStatus = OSSL_INVALID_PARAM;
    Status = EFI_INVALID_PARAMETER;
  }

  if (x509 != NULL)
    X509_free(x509);

  PurgeOpenSSLErrors(__FUNCTION__);
  LOG((EFI_D_ERROR, "%a.%d Status: %d\n", __FUNCTION__, __LINE__, Status));

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a notAfter date in a CHAR16 representation from the given certificate */
//------------------------------------------------------------------------------
EFI_STATUS
GetCertificateNotAfterDate(
  IN CHAR8 *certData,
  IN UINTN certDataLen,
  OUT CHAR16 **notAfterDate
)
{
  X509 *x509 = NULL;

  EFI_STATUS Status = EFI_ABORTED;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if ((certData == NULL) || (certDataLen == 0) ||
      (notAfterDate == NULL) || (*notAfterDate != NULL)) {
    lastStatus = OSSL_INVALID_PARAM;
    return EFI_INVALID_PARAMETER;
  }

  x509 = GetCertificateFromBinary(certData, certDataLen, &lastStatus);
  if (x509 == NULL) {
    PurgeOpenSSLErrors(__FUNCTION__);
    lastStatus = OSSL_INVALID_PARAM;
    return EFI_INVALID_PARAMETER;
  }

  Status = GetASN1Time(X509_get_notAfter(x509), notAfterDate);
  if (Status == EFI_INVALID_PARAMETER) {
    lastStatus = OSSL_INVALID_PARAM;
    Status = EFI_INVALID_PARAMETER;
  }

  if (x509 != NULL)
    X509_free(x509);

  PurgeOpenSSLErrors(__FUNCTION__);
  LOG((EFI_D_ERROR, "%a.%d Status: %d\n", __FUNCTION__, __LINE__, Status));

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a serial in a CHAR16 representation from the given certificate */
/*! \param[in] *certData
    \param[in] certDataLen
    \param[out] **serialStr16 */
//------------------------------------------------------------------------------
EFI_STATUS
GetCertificateSerialNumber(
  IN CHAR8 *certData,
  IN UINTN certDataLen,
  OUT CHAR16 **serialStr16
)
{
  X509 *x509 = NULL;

  EFI_STATUS Status = EFI_ABORTED;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if ((certData == NULL) || (certDataLen == 0) ||
      (serialStr16 == NULL) || (*serialStr16 != NULL)) {
    lastStatus = OSSL_INVALID_PARAM;
    return EFI_INVALID_PARAMETER;
  }

  x509 = GetCertificateFromBinary(certData, certDataLen, &lastStatus);
  if (x509 == NULL) {
    PurgeOpenSSLErrors(__FUNCTION__);
    lastStatus = OSSL_INVALID_PARAM;
    return EFI_INVALID_PARAMETER;
  }

  lastStatus = GetSerialFromX509(x509, serialStr16);
  if (lastStatus == OSSL_NO_ERROR)
    Status = EFI_SUCCESS;

  if (x509 != NULL)
    X509_free(x509);

  PurgeOpenSSLErrors(__FUNCTION__);
  LOG((EFI_D_ERROR, "%a.%d Status: %d\n", __FUNCTION__, __LINE__, Status));

  return Status;

}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a count of certificates in a p7b chain */
/*! \param[in] *chainData A pointer to p7b chain binary
    \param[in] chainDataLen A length of the binary */
//------------------------------------------------------------------------------
INT32
GetCertificateCountFromChain (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen
)
{
  PKCS7 *Pkcs7 = NULL;
  INT32 certCount = 0;
  STACK_OF(X509) *certChain = NULL;

  OSSL_STATUS Status = OSSL_INVALID_PARAM;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (chainData == NULL || chainDataLen == 0) {
    lastStatus = OSSL_INVALID_PARAM;
    return 0;
  }

  // Lazy initializing of OpenSSL
  InitializeOpenSSL();

  Pkcs7 = GetChainFromBinary(chainData, chainDataLen, &Status);
  if (Pkcs7 == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    PurgeOpenSSLErrors(__FUNCTION__);
    lastStatus = Status;
    return 0;
  }

  if (!PKCS7_type_is_signed (Pkcs7)) {
    Status = OSSL_PKCS7_NOT_SIGNED;
    goto _exit;
  }

  certChain = Pkcs7->d.sign->cert;
  if (certChain == NULL) {
    Status = OSSL_CANT_GET_TRUSTED_CERTS;
    goto _exit;
  }

  certCount = sk_X509_num(certChain);

  Status = OSSL_NO_ERROR;

_exit:

  LOG((EFI_D_ERROR, "%a.%d lastStatus: %d\n", __FUNCTION__, __LINE__, Status));

  if (Pkcs7 != NULL)
    PKCS7_free(Pkcs7);

  PurgeOpenSSLErrors(__FUNCTION__);
  lastStatus = Status;

  return certCount;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Free certificate info */
//------------------------------------------------------------------------------
VOID
FreeCertInfo(
  IN OSSL_CERT_INFO_T *certInfo
)
{
  if (certInfo == NULL)
    return;

  if (certInfo->certCN != NULL) {
    FreePool(certInfo->certCN);
    certInfo->certCN = NULL;
  }
  if (certInfo->certIssuer != NULL) {
    FreePool(certInfo->certIssuer);
    certInfo->certIssuer = NULL;
  }
  if (certInfo->notAfter != NULL) {
    FreePool(certInfo->notAfter);
    certInfo->notAfter = NULL;
  }
  if (certInfo->notBefore != NULL) {
    FreePool(certInfo->notBefore);
    certInfo->notBefore = NULL;
  }
  if (certInfo->serial != NULL) {
    FreePool(certInfo->serial);
    certInfo->serial = NULL;
  }

  FreePool(certInfo);

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a certificate info from the p7b chain binary */
/*! \param[in] *chainData
    \param[in] chainDataLen
    \param[in] certIndex
    \param[out] **certInfo*/
//------------------------------------------------------------------------------
EFI_STATUS
GetCertificateInfoFromChain (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen,
  IN INT32 certIndex,
  OUT OSSL_CERT_INFO_T **certInfo
)
{
  X509  *x509  = NULL;
  PKCS7 *Pkcs7 = NULL;

  STACK_OF(X509) *certChain = NULL;

  EFI_STATUS Status = EFI_ABORTED;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (chainData == NULL || chainDataLen == 0 ||
      certInfo == NULL || *certInfo != NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    lastStatus = OSSL_INVALID_PARAM;
    return EFI_INVALID_PARAMETER;
  }

  // Lazy initializing of OpenSSL
  InitializeOpenSSL();

  Pkcs7 = GetChainFromBinary(chainData, chainDataLen, &lastStatus);
  if (Pkcs7 == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    PurgeOpenSSLErrors(__FUNCTION__);
    return EFI_ABORTED;
  }

  if (!PKCS7_type_is_signed (Pkcs7)) {
    Status     = EFI_ABORTED;
    lastStatus = OSSL_PKCS7_NOT_SIGNED;
    goto _exit;
  }

  certChain = Pkcs7->d.sign->cert;
  if (certChain == NULL) {
    lastStatus = OSSL_CANT_GET_TRUSTED_CERTS;
    goto _exit;
  }

  Status = OSSL_INVALID_CRL_SIGNATURE;

  x509 = sk_X509_value (certChain, certIndex);
  if (x509 == NULL) {
    Status = EFI_ABORTED;
    lastStatus = OSSL_CANT_GET_TRUSTED_CERTS;
    goto _exit;
  }

  *certInfo = AllocateZeroPool(sizeof(OSSL_CERT_INFO_T));
  if (*certInfo == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    lastStatus = OSSL_MEMORY_ERROR;
    goto _exit;
  }

  lastStatus = GetSubjectFromX509(x509, &((*certInfo)->certCN));
  if (lastStatus != OSSL_NO_ERROR) {
    Status = EFI_ABORTED;
    goto _exit;
  }

  lastStatus = GetIssuerFromX509(x509, &((*certInfo)->certIssuer));
  if (lastStatus != OSSL_NO_ERROR) {
    Status = EFI_ABORTED;
    goto _exit;
  }

  Status = GetASN1Time(X509_get_notBefore(x509), &((*certInfo)->notBefore));
  if (EFI_ERROR(Status)) {
    lastStatus = OSSL_ERR_CANT_GET_NOT_BEFORE_DATE;
    goto _exit;
  }

  Status = GetASN1Time(X509_get_notAfter(x509), &((*certInfo)->notAfter));
  if (EFI_ERROR(Status)) {
    lastStatus = OSSL_ERR_CANT_GET_NOT_AFTER_DATE;
    goto _exit;
  }

  Status = GetSerialFromX509(x509, &((*certInfo)->serial));
  if (EFI_ERROR(Status)) {
    lastStatus = OSSL_ERR_CANT_GET_NOT_AFTER_DATE;
    goto _exit;
  }

_exit:

  if (Pkcs7 != NULL)
    PKCS7_free(Pkcs7);

  if (EFI_ERROR(Status)) {
    FreeCertInfo(*certInfo);
    *certInfo = NULL;    
  }

  PurgeOpenSSLErrors(__FUNCTION__);
  LOG((EFI_D_ERROR, "%a.%d Status: %d\n", __FUNCTION__, __LINE__, Status));

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a certificate info from a binary of certificate */
//------------------------------------------------------------------------------
EFI_STATUS
GetCertificateInfoFromCertBinary (
  IN CHAR8 *certData,
  IN UINTN certDataLen,
  OUT OSSL_CERT_INFO_T **certInfo
)
{
  X509 *x509 = NULL;

  EFI_STATUS Status = EFI_SUCCESS;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (certData == NULL || certDataLen == 0 ||
      certInfo == NULL || *certInfo != NULL) {
    LOG((EFI_D_ERROR, "%a.%d Error\n", __FUNCTION__, __LINE__));
    lastStatus = OSSL_INVALID_PARAM;
    return EFI_INVALID_PARAMETER;
  }

  *certInfo = AllocateZeroPool(sizeof(OSSL_CERT_INFO_T));
  if (*certInfo == NULL) {
    lastStatus = OSSL_MEMORY_ERROR;
    return EFI_OUT_OF_RESOURCES;
  }

  x509 = GetCertificateFromBinary(certData, certDataLen, &lastStatus);
  if (x509 == NULL) {
    PurgeOpenSSLErrors(__FUNCTION__);
    return EFI_INVALID_PARAMETER;
  }

  lastStatus = GetSubjectFromX509(x509, &((*certInfo)->certCN));
  if (OSSL_NO_ERROR != lastStatus) {
    Status = EFI_ABORTED;
    goto _exit;
  }

  lastStatus = GetIssuerFromX509(x509, &((*certInfo)->certIssuer));
  if (OSSL_NO_ERROR != lastStatus) {
    Status = EFI_ABORTED;
    goto _exit;
  }

  Status = GetASN1Time(X509_get_notBefore(x509), &((*certInfo)->notBefore));
  if (EFI_ERROR(Status)) {
    lastStatus = OSSL_ERR_CANT_GET_NOT_BEFORE_DATE;
    goto _exit;
  }

  Status = GetASN1Time(X509_get_notAfter(x509), &((*certInfo)->notAfter));
  if (EFI_ERROR(Status)) {
    lastStatus = OSSL_ERR_CANT_GET_NOT_AFTER_DATE;
    goto _exit;
  }

  lastStatus = GetSerialFromX509(x509, &((*certInfo)->serial));
  if (OSSL_NO_ERROR != lastStatus) {
    Status = EFI_ABORTED;;
    goto _exit;
  }

_exit:

  if (x509 != NULL)
    X509_free(x509);

  if (EFI_ERROR(Status)) {
    FreeCertInfo(*certInfo);
    *certInfo = NULL;    
  }

  PurgeOpenSSLErrors(__FUNCTION__);
  LOG((EFI_D_ERROR, "%a.%d Status: %d\n", __FUNCTION__, __LINE__, Status));

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
VOID
OsslInit (
  VOID
  )
{
  InitializeOpenSSL();
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Check CA chain for validity */
//------------------------------------------------------------------------------
OSSL_STATUS
VerifyCAChain (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen
  )
{
  INT32 error, count = 0;

  PKCS7       *Pkcs7     = NULL;

  time_t currentTime32U = 0;

  EFI_TIME   currentTime;
  EFI_STATUS Status;

  STACK_OF(X509) *trustedCerts = NULL;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (chainData == NULL || chainDataLen == 0) {
    lastStatus  = OSSL_INVALID_PARAM;
    return lastStatus;
  }

  // Lazy initializing of OpenSSL
  InitializeOpenSSL();

  lastStatus = OSSL_INVALID_SIGNATURE;

  // Retrieve PKCS#7 Data (DER encoding)
  Pkcs7 = d2i_PKCS7 (NULL, &chainData, (int)chainDataLen);
  if (Pkcs7 == NULL) {
    PurgeOpenSSLErrors(__FUNCTION__);
    lastStatus  = OSSL_UNKNOWN_PKCS7_FORMAT;
    return lastStatus;
  }
  // Check PCKS7 type
  if (!PKCS7_type_is_signed (Pkcs7)) {
    lastStatus = OSSL_PKCS7_NOT_SIGNED;
    goto _exit;
  }

  trustedCerts = Pkcs7->d.sign->cert;

  // Check trusted chain of CAs
  if (trustedCerts == NULL) {
    lastStatus = OSSL_CANT_GET_TRUSTED_CERTS;
    goto _exit;
  }

  Status = gRT->GetTime (&currentTime, NULL);
  if (EFI_ERROR(Status)) {
    PurgeOpenSSLErrors(__FUNCTION__);
    return OSSL_VERIFY_ERROR;
  }

  currentTime32U = Efi2Time(&currentTime);

  LOG((EFI_D_ERROR, "%a.%d currentTime: %d\n", __FUNCTION__, __LINE__, currentTime32U));

  for(count = 0; count < sk_X509_num(trustedCerts); count++) {

    X509 *x509_ca;
    x509_ca = sk_X509_value (trustedCerts, count);

    error = CheckCertTime(x509_ca, &currentTime32U);
    if (error != X509_V_OK) {
      CHAR8 *subjectCert = X509_NAME_oneline(X509_get_subject_name(x509_ca),NULL,0);
      LogOpensslMessage(EFI_D_ERROR, "cert: %a\n error :%a",subjectCert,X509_verify_cert_error_string(error));
      FreePool(subjectCert);

      switch(error) {
        case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
          lastStatus = OSSL_ERR_IN_CERT_NOT_BEFORE_FIELD;
          break;
        case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
          lastStatus = OSSL_ERR_IN_CERT_NOT_AFTER_FIELD;
          break;
        case X509_V_ERR_CERT_NOT_YET_VALID:
          lastStatus = OSSL_CERT_NOT_YET_VALID;
          break;
        case X509_V_ERR_CERT_HAS_EXPIRED:
          lastStatus = OSSL_CERT_HAS_EXPIRED;
          break;
        default:
          lastStatus = OSSL_VERIFY_ERROR;
          break;
      }
      goto _exit;
    }
    lastStatus = OSSL_VERIFY_SUCCESS;
  }

  if (Pkcs7->d.sign->crl != NULL) {
    for(count = 0; count < sk_X509_CRL_num(Pkcs7->d.sign->crl); count++) {

      X509_CRL *x509_crl = NULL;
      x509_crl = sk_X509_CRL_value(Pkcs7->d.sign->crl, count);

      error = CheckCRLTime(x509_crl, &currentTime32U);
      if (error != X509_V_OK) {
        CHAR8 *crlIssuer = X509_NAME_oneline(X509_CRL_get_issuer(x509_crl),NULL,0);
        LogOpensslMessage(EFI_D_ERROR, "crl: %a\n error :%a", crlIssuer, X509_verify_cert_error_string(error));
        FreePool(crlIssuer);

        switch(error) {
          case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
            lastStatus = OSSL_ERR_IN_CERT_NOT_BEFORE_FIELD;
            break;
          case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
            lastStatus = OSSL_ERR_IN_CERT_NOT_AFTER_FIELD;
            break;
          case X509_V_ERR_CERT_NOT_YET_VALID:
            lastStatus = OSSL_CERT_NOT_YET_VALID;
            break;
          case X509_V_ERR_CERT_HAS_EXPIRED:
            lastStatus = OSSL_CERT_HAS_EXPIRED;
            break;
          default:
            lastStatus = OSSL_VERIFY_ERROR;
            break;
        }
        goto _exit;
      }
      lastStatus = OSSL_VERIFY_SUCCESS;
    }
  }


_exit:
  if (Pkcs7 != NULL)
    PKCS7_free(Pkcs7);

  PurgeOpenSSLErrors(__FUNCTION__);
  LOG((EFI_D_ERROR, "%a.%d lastStatus: %d\n", 
    __FUNCTION__, __LINE__, lastStatus));

  return lastStatus;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief*/
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------


