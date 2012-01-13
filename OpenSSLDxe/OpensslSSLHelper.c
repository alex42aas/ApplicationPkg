/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/


#include "OpensslSSLHelper.h"

#if 1
#define LOG(MSG)
#else
//be very verbose
#define LOG(MSG) DEBUG(MSG)
#endif

LIST_ENTRY  gSSLHandlesListHead = INITIALIZE_LIST_HEAD_VARIABLE(gSSLHandlesListHead);

PKCS7 *gCaCertsPkcs7 = NULL;

/**
  Callback for loading PKCS7 to SSL context
**/
STACK_OF(X509)* 
SslP7bLookupCertsCallback(
  X509_STORE_CTX *ctx,
  X509_NAME *nm
  )
{
  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  LOG ((EFI_D_INFO, "%a.%d gCaCertsPkcs7 == 0x%X\n", __FUNCTION__, __LINE__, gCaCertsPkcs7));

  if (gCaCertsPkcs7 != NULL) {
    LOG ((EFI_D_INFO, "%a.%d return: gCaCertsPkcs7->d.sign->cert == 0x%X\n", __FUNCTION__, __LINE__, gCaCertsPkcs7->d.sign->cert));
    return gCaCertsPkcs7->d.sign->cert;
  } else {
    LOG ((EFI_D_ERROR, "%a.%d return: 0\n", __FUNCTION__, __LINE__));
    return 0;
  }
}

/**
  Check is SSL handle valid or not
  
  @param  SslHandle               SSL handle
  
  @retval TRUE                    Handle is valid
  @retval FALSE                   Handle is not valid
**/
BOOLEAN
EFIAPI
SslIsValidHandle(
  IN OPENSSL_HELPER_HANDLE *SslHandle
  )
{
  OPENSSL_HELPER_HANDLE *SslNode;
  SslNode = (OPENSSL_HELPER_HANDLE *)GetFirstNode(&gSSLHandlesListHead);
  while ( !IsNull(&gSSLHandlesListHead, &SslNode->Link) ) {
    if (SslNode == SslHandle) {
      return TRUE;
    }
    SslNode = (OPENSSL_HELPER_HANDLE *)GetNextNode(&gSSLHandlesListHead, &SslNode->Link);
  }
  return FALSE;
}

static
int
SslBioCreate(
  BIO *Bio
  )
{
  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  Bio->init = 1;
  Bio->num = 0;
  Bio->ptr = NULL;
  Bio->flags = 0;
  return 1;
}

static
int
SslBioDestroy(
  BIO *Bio
  )
{
  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  if (Bio == NULL) {
    return 0;
  }
  Bio->ptr = NULL;
  Bio->init = 0;
  Bio->flags = 0;
  return 1;
}

static 
int
SslBioRead(
  BIO *Bio,
  char *Buf,
  int Len
  )
{
  EFI_STATUS Status;
  UINTN Result = 0;
  OPENSSL_HELPER_HANDLE *SslHandle;
  
  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  
  SslHandle = (OPENSSL_HELPER_HANDLE *)Bio->ptr;
  if (!SslIsValidHandle(SslHandle)) {
    DEBUG ((EFI_D_ERROR, "%a.%d SslIsValidHandle(): SslHandle == 0x%X\n", __FUNCTION__, __LINE__, SslHandle));
    return 0;
  }
  if (SslHandle->BioRead == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d BioRead == 0x%X\n", __FUNCTION__, __LINE__, SslHandle->BioRead));
    return 0;
  }
  if (Buf == NULL || Len <= 0) {
    DEBUG ((EFI_D_ERROR, "%a.%d Buf = 0x%X, Len == %d\n", __FUNCTION__, __LINE__, Buf, Len));
    return 0;
  }
	
  BIO_clear_retry_flags(Bio);
  Status = SslHandle->BioRead(SslHandle->BioHandle, 
                              Buf, 
                              Len, 
                              &Result);
  if (Status == EFI_SUCCESS) {
    if (Result < (UINTN)Len) {
      BIO_set_retry_read(Bio);
    }
    if (Result == 0) {
      return -1;
    } else {      
      return (int)Result;
    }
  } else {
    DEBUG ((EFI_D_ERROR, "%a.%d BioRead(): Status == 0x%X\n", __FUNCTION__, __LINE__, Status));
    return -1;
  }
}

static
int
SslBioWrite(
  BIO *Bio,
  const char *Buf,
  int Len 
  )
{
  EFI_STATUS Status;
  UINTN Result = 0;
  OPENSSL_HELPER_HANDLE *SslHandle;
  
  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  
  SslHandle = (OPENSSL_HELPER_HANDLE *)Bio->ptr;
  if (!SslIsValidHandle(SslHandle)) {
    DEBUG ((EFI_D_ERROR, "%a.%d SslIsValidHandle(): SslHandle == 0x%X\n", __FUNCTION__, __LINE__, SslHandle));
    return 0;
  }
  if (SslHandle->BioWrite == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d BioWrite == 0x%X\n", __FUNCTION__, __LINE__, SslHandle->BioWrite));
    return 0;
  }
  if (Buf == NULL || Len <= 0) {
    DEBUG ((EFI_D_ERROR, "%a.%d Buf = 0x%X, Len == %d\n", __FUNCTION__, __LINE__, Buf, Len));
    return 0;
  }

  BIO_clear_retry_flags(Bio);
  Status = SslHandle->BioWrite(SslHandle->BioHandle, 
                               Buf, 
                               Len, 
                               &Result);
  if (Status == EFI_SUCCESS) {
    if (Result < (UINTN)Len) {
      BIO_set_retry_write(Bio);
    }
    if (Result == 0) {
      return -1;
    } else {
      return (int)Result;
    }
  } else {
    DEBUG ((EFI_D_ERROR, "%a.%d BioWrite(): Status == 0x%X\n", __FUNCTION__, __LINE__, Status));
    return -1;
  }
}

static
long
SslBioCtrl(
  BIO *Bio,
  int Cmd,
  long Num,
  void *Ptr
  )
{
  DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  if (Cmd == BIO_CTRL_FLUSH) {
    /* The OpenSSL library needs this */
    return 1;
  }
  return 0;
}

static
int
SslBioGets(
  BIO *Bio,
  char *Buf,
  int Len
  )
{
  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return -1;
}

static 
int
SslBioPuts(
  BIO *Bio,
  const char *Str
  )
{
  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
  return SslBioWrite(Bio, Str, (int)AsciiStrLen(Str));
}

static BIO_METHOD SslBioMethod = {
  ( 86/*BIO number - just some 8bit value*/ | BIO_TYPE_SOURCE_SINK ),
  "Ssl Helper BIO",
  SslBioWrite,
  SslBioRead,
  SslBioPuts,
  SslBioGets,
  SslBioCtrl,
  SslBioCreate,
  SslBioDestroy
};


/**
  Create SSL handle
  
  @param  SslHandle               A pointer to the location of newly created Ssl handle
  @param  SslSettings             A pointer to the structure with OpenSSL certificates and private keys
  
  @retval EFI_INVALID_PARAMETER   Function got invalid pointer in parameters
  @retval EFI_OUT_OF_RESOURCES    Cannot allocate memory for internal structures
  @retval EFI_LOAD_ERROR          OpenSSL initiliazing error
  @retval EFI_ABORTED             Error occured, handle not created
  @retval EFI_SUCCESS             Handle succesfully created
**/
EFI_STATUS
EFIAPI
ThisSslCreate(
  IN OPENSSL_PROTOCOL *This,
  OUT EFI_HANDLE *SslHandle,
  IN OPENSSL_SETTINGS *SslSettings
  )
{
  int i;
  int Result;
  OPENSSL_HELPER_HANDLE *InnerSslHandle;  
  unsigned long SslErr;
  const SSL_METHOD *ProtocolSMethod = NULL, *ProtocolCMethod = NULL;
  long NewOpt = 0;

  UINT8 RndSeedArray[256];

  unsigned char *CertBuf;
  X509 *Cert;
  EVP_PKEY *CertPubKey;
  int CertPubKeyType;
  unsigned char *PrivKeyBuf;
	EVP_PKEY *PrivKey;
  unsigned char *CaCertsBuf;
  X509_STORE *CtxX509Store;

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (SslHandle == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d SslHandle == 0x%X\n", __FUNCTION__, __LINE__, SslHandle));
    return EFI_INVALID_PARAMETER;
  }

  if (SslSettings == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d SslSettings == 0x%X\n", __FUNCTION__, __LINE__, SslSettings));
    return EFI_INVALID_PARAMETER;
  }

  if ((SslSettings->CertAsn1BufLen != 0 && SslSettings->CertAsn1Buf == NULL) ||
      (SslSettings->CertAsn1Buf != NULL && SslSettings->CertAsn1BufLen == 0)) {
    DEBUG ((EFI_D_ERROR, "%a.%d CertAsn1Buf == 0x%X, CertAsn1BufLen == %d\n", __FUNCTION__, __LINE__, 
      SslSettings->CertAsn1Buf, SslSettings->CertAsn1BufLen));
    return EFI_INVALID_PARAMETER;
  }
  if ((SslSettings->PrivKeyAsn1BufLen != 0 && SslSettings->PrivKeyAsn1Buf == NULL) ||
      (SslSettings->PrivKeyAsn1Buf != NULL && SslSettings->PrivKeyAsn1BufLen == 0)) {
    DEBUG ((EFI_D_ERROR, "%a.%d PrivKeyAsn1Buf == 0x%X, PrivKeyAsn1BufLen == %d\n", __FUNCTION__, __LINE__, 
      SslSettings->PrivKeyAsn1Buf, SslSettings->PrivKeyAsn1BufLen));
    return EFI_INVALID_PARAMETER;
  }
  if ((SslSettings->CaCertsP7bBufLen != 0 && SslSettings->CaCertsP7bBuf == NULL) ||
      (SslSettings->CaCertsP7bBuf != NULL && SslSettings->CaCertsP7bBufLen == 0)) {
    DEBUG ((EFI_D_ERROR, "%a.%d CaCertsP7bBuf == 0x%X, CaCertsP7bBufLen == %d\n", __FUNCTION__, __LINE__, 
      SslSettings->CaCertsP7bBuf, SslSettings->CaCertsP7bBufLen));
    return EFI_INVALID_PARAMETER;
  }
  if ((SslSettings->CertAsn1Buf != NULL && SslSettings->CertAsn1BufLen != 0) &&
      (SslSettings->PrivKeyAsn1Buf == NULL || SslSettings->PrivKeyAsn1BufLen == 0)) {
    DEBUG ((EFI_D_ERROR, "%a.%d PrivKeyAsn1Buf == 0x%X\n, PrivKeyAsn1BufLen == %d\n", __FUNCTION__, __LINE__, 
      SslSettings->PrivKeyAsn1Buf, SslSettings->PrivKeyAsn1BufLen));
    return EFI_INVALID_PARAMETER;
  }
  if ((SslSettings->PrivKeyAsn1Buf != NULL && SslSettings->PrivKeyAsn1BufLen != 0) &&
      (SslSettings->CertAsn1Buf == NULL || SslSettings->CertAsn1BufLen == 0)) {
    DEBUG ((EFI_D_ERROR, "%a.%d CertAsn1Buf == 0x%X, CertAsn1BufLen == %d\n", __FUNCTION__, __LINE__, 
      SslSettings->CertAsn1Buf, SslSettings->CertAsn1BufLen));
    return EFI_INVALID_PARAMETER;
  }
  if (SslSettings->Type == OPENSSL_SERVER &&
      (SslSettings->PrivKeyAsn1Buf == NULL || SslSettings->PrivKeyAsn1BufLen == 0 ||
        SslSettings->CertAsn1Buf == NULL || SslSettings->CertAsn1BufLen == 0)) {
    DEBUG ((EFI_D_ERROR, "%a.%d PrivKeyAsn1Buf == 0x%X\n, PrivKeyAsn1BufLen == %d\n", __FUNCTION__, __LINE__, 
      SslSettings->PrivKeyAsn1Buf, SslSettings->PrivKeyAsn1BufLen));
    DEBUG ((EFI_D_ERROR, "%a.%d CertAsn1Buf == 0x%X, CertAsn1BufLen == %d\n", __FUNCTION__, __LINE__, 
      SslSettings->CertAsn1Buf, SslSettings->CertAsn1BufLen));
    return EFI_INVALID_PARAMETER;
  }

  if (SslSettings->Type != OPENSSL_SERVER && SslSettings->Type != OPENSSL_CLIENT) {
    DEBUG ((EFI_D_ERROR, "%a.%d Type == %d\n", __FUNCTION__, __LINE__, SslSettings->Type));
    return EFI_INVALID_PARAMETER;
  }
  if (SslSettings->Version == OPENSSL_USE_SSL_2) {
    ProtocolSMethod = SSLv2_server_method();
    ProtocolCMethod = SSLv2_client_method();
  } else if (SslSettings->Version == OPENSSL_USE_SSL_3) {
    ProtocolSMethod = SSLv3_server_method();
    ProtocolCMethod = SSLv3_client_method();
  } else if (SslSettings->Version == OPENSSL_USE_SSL_2_3) {
    ProtocolSMethod = SSLv23_server_method();
    ProtocolCMethod = SSLv23_client_method();
    if (SslSettings->Type == OPENSSL_CLIENT) {
      NewOpt = SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2;
    }
  } else if (SslSettings->Version == OPENSSL_USE_TLS_1_0) {
    ProtocolSMethod = TLSv1_server_method();
    ProtocolCMethod = TLSv1_client_method();
  } else if (SslSettings->Version == OPENSSL_USE_TLS_1_1) {
    ProtocolSMethod = TLSv1_1_server_method();
    ProtocolCMethod = TLSv1_1_client_method();
  } else if (SslSettings->Version == OPENSSL_USE_TLS_1_2) {
    ProtocolSMethod = TLSv1_2_server_method();
    ProtocolCMethod = TLSv1_2_client_method();
  } else {
    DEBUG ((EFI_D_ERROR, "%a.%d Version == %d\n", __FUNCTION__, __LINE__, SslSettings->Version));
    return EFI_INVALID_PARAMETER;
  }
  if (SslSettings->BioRead == NULL || SslSettings->BioWrite == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d BioRead == 0x%X, BioWrite == 0x%X\n", __FUNCTION__, __LINE__, 
      SslSettings->BioRead, SslSettings->BioWrite));
    return EFI_INVALID_PARAMETER;
  }

  //initialize OpenSSL before handle creating
  This->Init();

  //create new handle
  //if success - add it to list
  *SslHandle = NULL;
  InnerSslHandle = NULL;
  
  //allocate memory and init handle
  InnerSslHandle = AllocatePool(sizeof(OPENSSL_HELPER_HANDLE));
  if (InnerSslHandle == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d AllocatePool(): InnerSslHandle == 0x%X\n", __FUNCTION__, __LINE__, InnerSslHandle));
    return EFI_OUT_OF_RESOURCES;
  }

  ZeroMem(InnerSslHandle, 
          sizeof(OPENSSL_HELPER_HANDLE));

  //now handle is without type
  InnerSslHandle->Type = SslSettings->Type;

  //common
  InnerSslHandle->Ctx = NULL;
  InnerSslHandle->Ssl = NULL;
  InnerSslHandle->CaCertsPkcs7 = NULL;
  InnerSslHandle->IsSslCalled = FALSE;
  //server
  //client

  InnerSslHandle->ConnectionState = OPENSSL_NOT_CONNECTED;

  //init OpenSSL random generator
  for (i = 0; i < sizeof(RndSeedArray); i++) {
    RndSeedArray[i] = (UINT8)(AsmReadTsc() & 0xFF);
  }
  RAND_seed(RndSeedArray, sizeof(RndSeedArray));

  //create OpenSSL context
  if (InnerSslHandle->Type == OPENSSL_SERVER) {
    InnerSslHandle->Ctx = SSL_CTX_new(ProtocolSMethod);
  } else if (InnerSslHandle->Type == OPENSSL_CLIENT) {
    InnerSslHandle->Ctx = SSL_CTX_new(ProtocolCMethod);
  } else {
    DEBUG ((EFI_D_ERROR, "%a.%d Type == %d\n", __FUNCTION__, __LINE__, InnerSslHandle->Type));
    FreePool(InnerSslHandle);
    return EFI_INVALID_PARAMETER;
  }
  if (NewOpt != 0) {
    DEBUG ((EFI_D_ERROR, "%a.%d NewOpt == 0x%x\n", __FUNCTION__, __LINE__, NewOpt));
    SSL_CTX_set_options(InnerSslHandle->Ctx, NewOpt);
  }
  if (InnerSslHandle->Ctx == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d SSL_CTX_new(): Ctx == 0x%X\n", __FUNCTION__, __LINE__, InnerSslHandle->Ctx));
    while((SslErr = ERR_get_error()) != 0) {
      DEBUG ((EFI_D_ERROR, "%a.%d SSL_CTX_new(): 0x%X, %a\n", __FUNCTION__, __LINE__, SslErr, ERR_error_string(SslErr, NULL)));
    }
    FreePool(InnerSslHandle);
    return EFI_OUT_OF_RESOURCES;
  }

  if (SslSettings->CertAsn1Buf != NULL && SslSettings->CertAsn1BufLen != 0 &&
      SslSettings->PrivKeyAsn1Buf != NULL && SslSettings->PrivKeyAsn1BufLen != 0) {

    DEBUG ((EFI_D_ERROR, "%a.%d SslSettings->CertAsn1Buf = 0x%X\n", __FUNCTION__, __LINE__, SslSettings->CertAsn1Buf));
    DEBUG ((EFI_D_ERROR, "%a.%d SslSettings->CertAsn1BufLen = %d\n", __FUNCTION__, __LINE__, SslSettings->CertAsn1BufLen));
    DEBUG ((EFI_D_ERROR, "%a.%d SslSettings->PrivKeyAsn1Buf = 0x%X\n", __FUNCTION__, __LINE__, SslSettings->PrivKeyAsn1Buf));
    DEBUG ((EFI_D_ERROR, "%a.%d SslSettings->PrivKeyAsn1BufLen = %d\n", __FUNCTION__, __LINE__, SslSettings->PrivKeyAsn1BufLen));

    //set certificate(public key)
    //parse certificate ASN1 buffer
    CertBuf = (unsigned char*)SslSettings->CertAsn1Buf;
    Cert = d2i_X509(NULL, 
                    (unsigned char **)&CertBuf,
                    (long)SslSettings->CertAsn1BufLen);
    if (Cert == NULL) {
      DEBUG ((EFI_D_ERROR, "%a.%d d2i_X509(): Cert == 0x%X\n", __FUNCTION__, __LINE__, Cert));
      while((SslErr = ERR_get_error()) != 0) {
        DEBUG ((EFI_D_ERROR, "%a.%d d2i_X509(): 0x%X, %a\n", __FUNCTION__, __LINE__, SslErr, ERR_error_string(SslErr, NULL)));
      }
      SSL_CTX_free(InnerSslHandle->Ctx);
      FreePool(InnerSslHandle);
      return EFI_LOAD_ERROR;
    }
    //load certificate to context
    Result = SSL_CTX_use_certificate(InnerSslHandle->Ctx, 
                                     Cert);
    if (Result != 1) {
      DEBUG ((EFI_D_ERROR, "%a.%d SSL_CTX_use_certificate(): Result == %d\n", __FUNCTION__, __LINE__, Result));
      while((SslErr = ERR_get_error()) != 0) {
        DEBUG ((EFI_D_ERROR, "%a.%d SSL_CTX_use_certificate(): 0x%X, %a\n", __FUNCTION__, __LINE__, SslErr, ERR_error_string(SslErr, NULL)));
      }
      X509_free(Cert);
      SSL_CTX_free(InnerSslHandle->Ctx);
      FreePool(InnerSslHandle);
      return EFI_LOAD_ERROR;
    }
    //get certificate public key
    CertPubKey = X509_get_pubkey(Cert);
    if (CertPubKey == NULL) {
      DEBUG ((EFI_D_ERROR, "%a.%d X509_get_pubkey(): CertPubKey == 0x%X\n", __FUNCTION__, __LINE__, CertPubKey));
      while((SslErr = ERR_get_error()) != 0) {
        DEBUG ((EFI_D_ERROR, "%a.%d X509_get_pubkey(): 0x%X, %a\n", __FUNCTION__, __LINE__, SslErr, ERR_error_string(SslErr, NULL)));
      }
      X509_free(Cert);
      SSL_CTX_free(InnerSslHandle->Ctx);
      FreePool(InnerSslHandle);
      return EFI_LOAD_ERROR;
    }
    //get public key algorithm type
    CertPubKeyType = CertPubKey->type;
    EVP_PKEY_free(CertPubKey);
    X509_free(Cert);

    //set private key
    //parse private key ASN1 buffer
    PrivKeyBuf = SslSettings->PrivKeyAsn1Buf;
    PrivKey = d2i_PrivateKey(CertPubKeyType,//use previous saved public key algorithm type
                             NULL,
                             &PrivKeyBuf,
                             (long)SslSettings->PrivKeyAsn1BufLen);
    if (PrivKey == NULL) {
      DEBUG ((EFI_D_ERROR, "%a.%d CertPubKey->type == %d\n", __FUNCTION__, __LINE__, CertPubKeyType));
      DEBUG ((EFI_D_ERROR, "%a.%d d2i_PrivateKey(): PrivKey == 0x%X\n", __FUNCTION__, __LINE__, PrivKey));
      while((SslErr = ERR_get_error()) != 0) {
        DEBUG ((EFI_D_ERROR, "%a.%d d2i_PrivateKey(): 0x%X, %a\n", __FUNCTION__, __LINE__, SslErr, ERR_error_string(SslErr, NULL)));
      }
      SSL_CTX_free(InnerSslHandle->Ctx);
      FreePool(InnerSslHandle);
      return EFI_LOAD_ERROR;
    }
    //load private key to context
    Result = SSL_CTX_use_PrivateKey(InnerSslHandle->Ctx,
                                    PrivKey);
    if (Result != 1) {
      DEBUG ((EFI_D_ERROR, "%a.%d SSL_CTX_use_PrivateKey(): Result == %d\n", __FUNCTION__, __LINE__, Result));
      while((SslErr = ERR_get_error()) != 0) {
        DEBUG ((EFI_D_ERROR, "%a.%d SSL_CTX_use_PrivateKey(): 0x%X, %a\n", __FUNCTION__, __LINE__, SslErr, ERR_error_string(SslErr, NULL)));
      }
      EVP_PKEY_free(PrivKey);
      SSL_CTX_free(InnerSslHandle->Ctx);
      FreePool(InnerSslHandle);
      return EFI_LOAD_ERROR;
    }
    EVP_PKEY_free(PrivKey);
  }

  if (SslSettings->CaCertsP7bBuf != NULL && SslSettings->CaCertsP7bBufLen != 0) {
    DEBUG ((EFI_D_ERROR, "%a.%d SslSettings->CaCertsP7bBuf = 0x%X\n", __FUNCTION__, __LINE__, SslSettings->CaCertsP7bBuf));
    DEBUG ((EFI_D_ERROR, "%a.%d SslSettings->CaCertsP7bBufLen = %d\n", __FUNCTION__, __LINE__, SslSettings->CaCertsP7bBufLen));
    SSL_CTX_set_verify(InnerSslHandle->Ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    //load CA chain
    //parse PKCS7 ASN1 buffer
    CaCertsBuf = SslSettings->CaCertsP7bBuf;
    InnerSslHandle->CaCertsPkcs7 = d2i_PKCS7(NULL,
                                             &CaCertsBuf,
                                             (long)SslSettings->CaCertsP7bBufLen);
    if (InnerSslHandle->CaCertsPkcs7 == NULL) {
      DEBUG ((EFI_D_ERROR, "%a.%d d2i_PKCS7(): SslHandle->CaCertsPkcs7 == 0x%X\n", __FUNCTION__, __LINE__, InnerSslHandle->CaCertsPkcs7));
      while((SslErr = ERR_get_error()) != 0) {
        DEBUG ((EFI_D_ERROR, "%a.%d d2i_PKCS7(): 0x%X, %a\n", __FUNCTION__, __LINE__, SslErr, ERR_error_string(SslErr, NULL)));
      }
      SSL_CTX_free(InnerSslHandle->Ctx);
      FreePool(InnerSslHandle);
      return EFI_LOAD_ERROR;
    }
    CtxX509Store = SSL_CTX_get_cert_store(InnerSslHandle->Ctx);
    if (CtxX509Store == NULL) {
      DEBUG ((EFI_D_ERROR, "%a.%d SSL_CTX_get_cert_store(): CtxX509Store == 0x%X\n", __FUNCTION__, __LINE__, CtxX509Store));
      while((SslErr = ERR_get_error()) != 0) {
        DEBUG ((EFI_D_ERROR, "%a.%d SSL_CTX_get_cert_store(): 0x%X, %a\n", __FUNCTION__, __LINE__, SslErr, ERR_error_string(SslErr, NULL)));
      }
      PKCS7_free(InnerSslHandle->CaCertsPkcs7);
      SSL_CTX_free(InnerSslHandle->Ctx);
      FreePool(InnerSslHandle);
      return EFI_LOAD_ERROR;
    }
    //set callback for loading PKCS7
    CtxX509Store->lookup_certs = SslP7bLookupCertsCallback;
    DEBUG ((EFI_D_INFO, "%a.%d CtxX509Store->lookup_certs == 0x%X\n", __FUNCTION__, __LINE__, CtxX509Store->lookup_certs));
  } else {
    DEBUG ((EFI_D_ERROR, "%a.%d SSL_VERIFY_NONE\n", __FUNCTION__, __LINE__));
    SSL_CTX_set_verify(InnerSslHandle->Ctx, SSL_VERIFY_NONE, NULL);
  }
/*
  PKCS7 loading code needs this OpenSSL patch to callback working:
--- a/CryptoPkg/Library/OpensslLib/openssl-1.0.1a/crypto/x509/x509_vfy.c
+++ b/CryptoPkg/Library/OpensslLib/openssl-1.0.1a/crypto/x509/x509_vfy.c
@@ -2116,9 +2116,10 @@ int X509_STORE_CTX_init(X509_STORE_CTX *ctx, X509_STORE *store, X509 *x509,
 	else
    ctx->cert_crl = cert_crl;
 
-	if (store && store->lookup_certs)
+	if (store && store->lookup_certs) {
    ctx->lookup_certs = store->lookup_certs;
- else
+	  X509_STORE_CTX_trusted_stack(ctx, ctx->lookup_certs(ctx, NULL));
+ } else
    ctx->lookup_certs = X509_STORE_get1_certs;
 
 	if (store && store->lookup_crls) 
*/
  
  //create SSL connection
  InnerSslHandle->Ssl = SSL_new(InnerSslHandle->Ctx);
  if (InnerSslHandle->Ssl == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d SSL_new(): Ssl == 0x%X\n", __FUNCTION__, __LINE__, InnerSslHandle->Ssl));
    while((SslErr = ERR_get_error()) != 0) {
      DEBUG ((EFI_D_ERROR, "%a.%d SSL_new(): 0x%X, %a\n", __FUNCTION__, __LINE__, SslErr, ERR_error_string(SslErr, NULL)));
    }
    PKCS7_free(InnerSslHandle->CaCertsPkcs7);
    SSL_CTX_free(InnerSslHandle->Ctx);
    FreePool(InnerSslHandle);
    return EFI_OUT_OF_RESOURCES;
  }

  //create new BIO
  InnerSslHandle->BioHandle = SslSettings->BioHandle;
  InnerSslHandle->BioRead = SslSettings->BioRead;
  InnerSslHandle->BioWrite = SslSettings->BioWrite;
  InnerSslHandle->SslBio = BIO_new(&SslBioMethod);
  if (InnerSslHandle->SslBio == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d BIO_new(): SslBio == 0x%X\n", __FUNCTION__, __LINE__, InnerSslHandle->SslBio));
    while((SslErr = ERR_get_error()) != 0) {
      DEBUG ((EFI_D_ERROR, "%a.%d BIO_new(): 0x%X, %a\n", __FUNCTION__, __LINE__, SslErr, ERR_error_string(SslErr, NULL)));
    }
    SSL_free(InnerSslHandle->Ssl);
    PKCS7_free(InnerSslHandle->CaCertsPkcs7);
    SSL_CTX_free(InnerSslHandle->Ctx);
    FreePool(InnerSslHandle);
    return EFI_OUT_OF_RESOURCES;
  }
  //set BIO on SSL connection
  InnerSslHandle->SslBio->ptr = (void *)InnerSslHandle;
  SSL_set_bio(InnerSslHandle->Ssl, InnerSslHandle->SslBio, InnerSslHandle->SslBio);

  //save handle
  InsertHeadList(&gSSLHandlesListHead, &InnerSslHandle->Link);
  *SslHandle = (EFI_HANDLE)InnerSslHandle;
  return EFI_SUCCESS;
}

/**
  Start Ssl server/client and try to accept incoming connection/connect to remote server
  
  @param  SslHandle               SSL handle
 
  @retval EFI_INVALID_PARAMETER   Function got invalid parameters
  @retval EFI_LOAD_ERROR          OpenSSL initiliazing error
  @retval EFI_DEVICE_ERROR        OpenSSL connecting error
  @retval EFI_ABORTED             Error occured
  @retval EFI_NOT_READY           Server/client started but yet no connection. Retry SslStart() call
  @retval EFI_SUCCESS             Server/client started and succesfully connected
**/
EFI_STATUS
EFIAPI
ThisSslStart(
  IN OPENSSL_PROTOCOL *This,
  IN EFI_HANDLE SslHandle
  )
{
  int Result, Result2;
  EFI_STATUS Status = EFI_ABORTED;
  OPENSSL_HELPER_HANDLE *InnerSslHandle;
  unsigned long SslErr;

  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
    
  InnerSslHandle = (OPENSSL_HELPER_HANDLE *)SslHandle;
  if (!SslIsValidHandle(InnerSslHandle)) {
    DEBUG ((EFI_D_ERROR, "%a.%d SslIsValidHandle(): SslHandle == 0x%X\n", __FUNCTION__, __LINE__, SslHandle));
    return EFI_INVALID_PARAMETER;
  }

  if (InnerSslHandle->Type != OPENSSL_SERVER && InnerSslHandle->Type != OPENSSL_CLIENT) {
    DEBUG ((EFI_D_ERROR, "%a.%d SslHandle->Type == %d\n", __FUNCTION__, __LINE__, InnerSslHandle->Type));
    return EFI_INVALID_PARAMETER;
  }

  //now handle already created
  //try to connect
  //EFI_NOT_READY signals that call to SslStart() must be retried
  do {
    switch (InnerSslHandle->ConnectionState) {

    case OPENSSL_NOT_CONNECTED:
      DEBUG ((EFI_D_INFO, "%a.%d SslHandle->ConnectionState == %d\n", __FUNCTION__, __LINE__, InnerSslHandle->ConnectionState));

      //jump to connecting state
      InnerSslHandle->ConnectionState = OPENSSL_CONNECTING_TLS;
      Status = EFI_NOT_READY;
      break;
      
    case OPENSSL_CONNECTING_TLS:
      LOG ((EFI_D_INFO, "%a.%d SslHandle->ConnectionState == %d\n", __FUNCTION__, __LINE__, InnerSslHandle->ConnectionState));
      //try to connect/accept
      gCaCertsPkcs7 = InnerSslHandle->CaCertsPkcs7;//set global PKCS7 for callback
      LOG ((EFI_D_INFO, "%a.%d gCaCertsPkcs7 == 0x%X\n", __FUNCTION__, __LINE__, gCaCertsPkcs7));
      if (InnerSslHandle->Type == OPENSSL_SERVER) {
        Result = SSL_accept(InnerSslHandle->Ssl);
      } else if (InnerSslHandle->Type == OPENSSL_CLIENT) {
        Result = SSL_connect(InnerSslHandle->Ssl);
      } else {
        DEBUG ((EFI_D_ERROR, "%a.%d SslHandle->Type == %d\n", __FUNCTION__, __LINE__, InnerSslHandle->Type));
        gCaCertsPkcs7 = NULL;
        return EFI_INVALID_PARAMETER;
      }
      InnerSslHandle->IsSslCalled = TRUE;//now SSL is initiliazed and SSL_shutdown may be called without error
      gCaCertsPkcs7 = NULL;
      LOG ((EFI_D_INFO, "%a.%d gCaCertsPkcs7 == 0x%X\n", __FUNCTION__, __LINE__, gCaCertsPkcs7));
      if (Result != 1) {
        //SSL cannot connect
        Result2 = Result;
        Result = SSL_get_error(InnerSslHandle->Ssl, Result2);
        if (Result == SSL_ERROR_WANT_READ || Result == SSL_ERROR_WANT_WRITE) {
          //call to SSL_connect()/SSL_accept() needs to be retried - stand on connecting state
          LOG ((EFI_D_INFO, "%a.%d %a: Result == %d\n", __FUNCTION__, __LINE__, 
            (InnerSslHandle->Type == OPENSSL_SERVER?"SSL_accept()":(InnerSslHandle->Type == OPENSSL_CLIENT?"SSL_connect()":"_unknown_")),
            Result2));
          LOG ((EFI_D_INFO, "%a.%d %a: SSL_get_error() == (SSL_ERROR_WANT_READ/WRITE)\n", __FUNCTION__, __LINE__,
            (InnerSslHandle->Type == OPENSSL_SERVER?"SSL_accept()":(InnerSslHandle->Type == OPENSSL_CLIENT?"SSL_connect()":"_unknown_"))));
          InnerSslHandle->ConnectionState = OPENSSL_CONNECTING_TLS;
          return EFI_NOT_READY;
        } else if (Result == SSL_ERROR_SYSCALL) {
          //BIO report IO error
          DEBUG ((EFI_D_ERROR, "%a.%d %a(): Result == %d\n", __FUNCTION__, __LINE__, 
            (InnerSslHandle->Type == OPENSSL_SERVER?"SSL_accept()":(InnerSslHandle->Type == OPENSSL_CLIENT?"SSL_connect()":"_unknown_")),
            Result2));
          DEBUG ((EFI_D_ERROR, "%a.%d %a(): SSL_get_error() == SSL_ERROR_SYSCALL\n", __FUNCTION__, __LINE__,
            (InnerSslHandle->Type == OPENSSL_SERVER?"SSL_accept()":(InnerSslHandle->Type == OPENSSL_CLIENT?"SSL_connect()":"_unknown_"))));
          while((SslErr = ERR_get_error()) != 0) {
            DEBUG ((EFI_D_ERROR, "%a.%d %a: 0x%X, %a\n", __FUNCTION__, __LINE__,
              (InnerSslHandle->Type == OPENSSL_SERVER?"SSL_accept()":(InnerSslHandle->Type == OPENSSL_CLIENT?"SSL_connect()":"_unknown_")),
              SslErr, ERR_error_string(SslErr, NULL)));
          }
          //IO not available, we can't read/send anything
          //handshake not completed - SSL_shutdown() at this point return 1 instantly
          //block calls to all protocol functions except This->Destroy()
          InnerSslHandle->ConnectionState = OPENSSL_BIO_ERROR;
          Status = EFI_DEVICE_ERROR;
          break;
        } else {
          //SSL_connect()/SSL_accept() fails - goto error state
          DEBUG ((EFI_D_ERROR, "%a.%d %a: Result == %d\n", __FUNCTION__, __LINE__, 
            (InnerSslHandle->Type == OPENSSL_SERVER?"SSL_accept()":(InnerSslHandle->Type == OPENSSL_CLIENT?"SSL_connect()":"_unknown_")),
            Result2));
          DEBUG ((EFI_D_ERROR, "%a.%d %a: SSL_get_error() == %d\n", __FUNCTION__, __LINE__,
            (InnerSslHandle->Type == OPENSSL_SERVER?"SSL_accept()":(InnerSslHandle->Type == OPENSSL_CLIENT?"SSL_connect()":"_unknown_")), 
            Result));
          while((SslErr = ERR_get_error()) != 0) {
            DEBUG ((EFI_D_ERROR, "%a.%d %a: 0x%X, %a\n", __FUNCTION__, __LINE__,
              (InnerSslHandle->Type == OPENSSL_SERVER?"SSL_accept()":(InnerSslHandle->Type == OPENSSL_CLIENT?"SSL_connect()":"_unknown_")),
              SslErr, ERR_error_string(SslErr, NULL)));
          }
          //unexpected error
          //handshake not completed - SSL_shutdown() at this point return 1 instantly
          //block calls to all protocol functions except This->Destroy()
          InnerSslHandle->ConnectionState = OPENSSL_CONNECTING_ERROR_TLS;
          Status = EFI_DEVICE_ERROR;
          break;
        }
      } else {
        //SSL connected - goto connected state
        DEBUG ((EFI_D_ERROR, "%a.%d %a: Result == %d\n", __FUNCTION__, __LINE__, 
          (InnerSslHandle->Type == OPENSSL_SERVER?"SSL_accept()":(InnerSslHandle->Type == OPENSSL_CLIENT?"SSL_connect()":"_unknown_")),
          Result));
        InnerSslHandle->ConnectionState = OPENSSL_CONNECTED_TLS;
        Status = EFI_NOT_READY;
        break;
      }

    case OPENSSL_CONNECTING_ERROR_TLS:
      //error occured
      DEBUG ((EFI_D_ERROR, "%a.%d SslHandle->ConnectionState == %d\n", __FUNCTION__, __LINE__, InnerSslHandle->ConnectionState));
      return Status;

    case OPENSSL_CONNECTED_TLS:
      //now SslRead/SslWrite is available
      DEBUG ((EFI_D_INFO, "%a.%d SslHandle->ConnectionState == %d\n", __FUNCTION__, __LINE__, InnerSslHandle->ConnectionState));
      DEBUG ((EFI_D_INFO, "%a.%d SSL_get_cipher_name() == %a\n", __FUNCTION__, __LINE__, (CHAR8 *)SSL_get_cipher_name(InnerSslHandle->Ssl)));
      return EFI_SUCCESS;

    case OPENSSL_ERROR:
    case OPENSSL_CLOSED_BY_PEER:
    case OPENSSL_BIO_ERROR:
    default:
      //error occured or unknown state
      DEBUG ((EFI_D_ERROR, "%a.%d SslHandle->ConnectionState == %d\n", __FUNCTION__, __LINE__, InnerSslHandle->ConnectionState));
      return Status;
    }
  } while (TRUE);
}

/**
  Return num of bytes buffered in OpenSSL internal buffers
  
  @param  SslHandle               SSL handle
  @param  NumOfPendingBytes       Num of bytes available to immediate reading
  
  @retval EFI_INVALID_PARAMETER   Function got invalid handle or pointer in parameters
  @retval EFI_SUCCESS             Some of data successfully readed
**/
EFI_STATUS
EFIAPI
ThisSslPending(
  IN OPENSSL_PROTOCOL *This,
  IN EFI_HANDLE SslHandle,
  OUT UINTN *NumOfPendingBytes
  )
{
  int Result;
  OPENSSL_HELPER_HANDLE *InnerSslHandle;

  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  
  if (NumOfPendingBytes == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d NumOfPendingBytes == 0x%X\n", __FUNCTION__, __LINE__, NumOfPendingBytes));
    return EFI_INVALID_PARAMETER;
  }

  InnerSslHandle = (OPENSSL_HELPER_HANDLE *)SslHandle;
  if (!SslIsValidHandle(InnerSslHandle)) {
    DEBUG ((EFI_D_ERROR, "%a.%d SslIsValidHandle(): SslHandle == 0x%X\n", __FUNCTION__, __LINE__, SslHandle));
    return EFI_INVALID_PARAMETER;
  }

  Result = SSL_pending(InnerSslHandle->Ssl);
  *NumOfPendingBytes = (UINTN)Result;
  return EFI_SUCCESS;
}

/**
  Try to read or send data
  
  @param  SslHandle               SSL handle
  @param  SslCmd                  Command: OPENSSL_CMD_READ or OPENSSL_CMD_WRITE
  @param  Buf                     A pointer to the buffer for exchange
  @param  BufSize                 Number of data try to exchange
  @param  ExchangedLen            Length of really exchanged data
  
  @retval EFI_INVALID_PARAMETER   Function got invalid handle, command or pointer in parameters
  @retval EFI_NOT_STARTED         Not connected
  @retval EFI_DEVICE_ERROR        OpenSSL data exchanging error
  @retval EFI_ABORTED             Error occured
  @retval EFI_SUCCESS             Some of data successfully exchanged
**/
EFI_STATUS
EFIAPI
SslExchangeData(
  IN EFI_HANDLE SslHandle,
  IN UINTN SslCmd,
  IN VOID *Buf,
  IN UINTN BufSize,
  OUT UINTN *ExchangedLen
  )
{
  int Result, Result2;
  OPENSSL_HELPER_HANDLE *InnerSslHandle;
  unsigned long SslErr;

  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (SslCmd != OPENSSL_CMD_READ && SslCmd != OPENSSL_CMD_WRITE) {
    DEBUG ((EFI_D_ERROR, "%a.%d SslCmd == %d\n", __FUNCTION__, __LINE__, SslCmd));
    return EFI_INVALID_PARAMETER;
  }

  if (Buf == NULL || BufSize == 0 || ExchangedLen == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d Buf == 0x%X, BufSize == %d, ExchangedLen == 0x%X\n", __FUNCTION__, __LINE__, Buf, BufSize, ExchangedLen));
    return EFI_INVALID_PARAMETER;
  }

  InnerSslHandle = (OPENSSL_HELPER_HANDLE *)SslHandle;
  if (!SslIsValidHandle(InnerSslHandle)) {
    DEBUG ((EFI_D_ERROR, "%a.%d SslIsValidHandle(): SslHandle == 0x%X\n", __FUNCTION__, __LINE__, SslHandle));
    return EFI_INVALID_PARAMETER;
  }

  if (InnerSslHandle->Type != OPENSSL_SERVER && InnerSslHandle->Type != OPENSSL_CLIENT) {
    //unknown handle type
    DEBUG ((EFI_D_ERROR, "%a.%d SslHandle->Type == %d\n", __FUNCTION__, __LINE__, InnerSslHandle->Type));
    return EFI_INVALID_PARAMETER;
  }

  if (InnerSslHandle->ConnectionState == OPENSSL_CONNECTED_TLS) {
    if (SslCmd == OPENSSL_CMD_READ) {
      //try to receive data
      Result = SSL_read(InnerSslHandle->Ssl,
                        Buf,
                        (int)BufSize);
    } else if (SslCmd == OPENSSL_CMD_WRITE) {
      //try to send data
      Result = SSL_write(InnerSslHandle->Ssl,
                         Buf,
                         (int)BufSize);
    } else {
      DEBUG ((EFI_D_ERROR, "%a.%d SslCmd == %d\n", __FUNCTION__, __LINE__, SslCmd));
      return EFI_INVALID_PARAMETER;
    }
    if (Result > 0) {
      //return number of readed/sended bytes
      *ExchangedLen = (UINTN)Result;
      return EFI_SUCCESS;
    } else {
      //nothing exchanged
      Result2 = Result;
      Result = SSL_get_error(InnerSslHandle->Ssl, Result2);
      if (Result == SSL_ERROR_WANT_READ || Result == SSL_ERROR_WANT_WRITE) {
        //call to SSL_read()/SSL_write() needs to be retried
        LOG ((EFI_D_INFO, "%a.%d %a(): Result == %d\n", __FUNCTION__, __LINE__, 
          ((SslCmd == OPENSSL_CMD_READ) ? "SSL_read" : ((SslCmd == OPENSSL_CMD_WRITE) ? "SSL_write" : "_unknown_")),
          Result2));
        LOG ((EFI_D_INFO, "%a.%d %a(): SSL_get_error() == (SSL_ERROR_WANT_READ/WRITE)\n", __FUNCTION__, __LINE__,
          ((SslCmd == OPENSSL_CMD_READ) ? "SSL_read" : ((SslCmd == OPENSSL_CMD_WRITE) ? "SSL_write" : "_unknown_"))));
        *ExchangedLen = 0;
        return EFI_SUCCESS;
      } else if (Result == SSL_ERROR_ZERO_RETURN) {
        //Peer call SSL_shutdown()
        DEBUG ((EFI_D_ERROR, "%a.%d %a(): Result == %d\n", __FUNCTION__, __LINE__, 
          ((SslCmd == OPENSSL_CMD_READ) ? "SSL_read" : ((SslCmd == OPENSSL_CMD_WRITE) ? "SSL_write" : "_unknown_")),
          Result2));
        DEBUG ((EFI_D_ERROR, "%a.%d %a(): SSL_get_error() == SSL_ERROR_ZERO_RETURN\n", __FUNCTION__, __LINE__,
          ((SslCmd == OPENSSL_CMD_READ) ? "SSL_read" : ((SslCmd == OPENSSL_CMD_WRITE) ? "SSL_write" : "_unknown_"))));
        while((SslErr = ERR_get_error()) != 0) {
          DEBUG ((EFI_D_ERROR, "%a.%d %a(): 0x%X, %a\n", __FUNCTION__, __LINE__,
            ((SslCmd == OPENSSL_CMD_READ) ? "SSL_read" : ((SslCmd == OPENSSL_CMD_WRITE) ? "SSL_write" : "_unknown_")),
            SslErr, ERR_error_string(SslErr, NULL)));
        }
        //SSL_RECEIVED_SHUTDOWN flag now must be set by SSL_read()
        Result = SSL_get_shutdown(InnerSslHandle->Ssl);
        if ((Result & SSL_RECEIVED_SHUTDOWN) == 0) {//excessive check
          //oddity - we must never get here
          DEBUG ((EFI_D_ERROR, "%a.%d %a(): SSL_get_shutdown() == %d\n", __FUNCTION__, __LINE__, 
            ((SslCmd == OPENSSL_CMD_READ) ? "SSL_read" : ((SslCmd == OPENSSL_CMD_WRITE) ? "SSL_write" : "_unknown_")),
            Result));
        }
        //block calls to all protocol functions except This->Destroy()
        InnerSslHandle->ConnectionState = OPENSSL_CLOSED_BY_PEER;
        *ExchangedLen = 0;
        return EFI_DEVICE_ERROR;
      } else if (Result == SSL_ERROR_SYSCALL) {
        //BIO report IO error
        DEBUG ((EFI_D_ERROR, "%a.%d %a(): Result == %d\n", __FUNCTION__, __LINE__, 
          ((SslCmd == OPENSSL_CMD_READ) ? "SSL_read" : ((SslCmd == OPENSSL_CMD_WRITE) ? "SSL_write" : "_unknown_")),
          Result2));
        DEBUG ((EFI_D_ERROR, "%a.%d %a(): SSL_get_error() == SSL_ERROR_SYSCALL\n", __FUNCTION__, __LINE__,
          ((SslCmd == OPENSSL_CMD_READ) ? "SSL_read" : ((SslCmd == OPENSSL_CMD_WRITE) ? "SSL_write" : "_unknown_"))));
        while((SslErr = ERR_get_error()) != 0) {
          DEBUG ((EFI_D_ERROR, "%a.%d %a(): 0x%X, %a\n", __FUNCTION__, __LINE__,
            ((SslCmd == OPENSSL_CMD_READ) ? "SSL_read" : ((SslCmd == OPENSSL_CMD_WRITE) ? "SSL_write" : "_unknown_")),
            SslErr, ERR_error_string(SslErr, NULL)));
        }
        //IO not available, we can't read/send anything - set session as 'closed' to disable any exchange attempts
        SSL_set_shutdown(InnerSslHandle->Ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);//SSL_shutdown() at this point return 1 instantly
        //block calls to all protocol functions except This->Destroy()
        InnerSslHandle->ConnectionState = OPENSSL_BIO_ERROR;
        *ExchangedLen = 0;
        return EFI_DEVICE_ERROR;
      } else {
        //SSL_read()/SSL_write() fails
        DEBUG ((EFI_D_ERROR, "%a.%d %a(): Result == %d\n", __FUNCTION__, __LINE__, 
          ((SslCmd == OPENSSL_CMD_READ) ? "SSL_read" : ((SslCmd == OPENSSL_CMD_WRITE) ? "SSL_write" : "_unknown_")),
          Result2));
        DEBUG ((EFI_D_ERROR, "%a.%d %a(): SSL_get_error() == %d\n", __FUNCTION__, __LINE__,
          ((SslCmd == OPENSSL_CMD_READ) ? "SSL_read" : ((SslCmd == OPENSSL_CMD_WRITE) ? "SSL_write" : "_unknown_")),
          Result));
        while((SslErr = ERR_get_error()) != 0) {
          DEBUG ((EFI_D_ERROR, "%a.%d %a(): 0x%X, %a\n", __FUNCTION__, __LINE__,
            ((SslCmd == OPENSSL_CMD_READ) ? "SSL_read" : ((SslCmd == OPENSSL_CMD_WRITE) ? "SSL_write" : "_unknown_")),
            SslErr, ERR_error_string(SslErr, NULL)));
        }
        //unexpected error - set session as 'closed' to disable any exchange attempts
        SSL_set_shutdown(InnerSslHandle->Ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);//SSL_shutdown() at this point return 1 instantly
        //block calls to all protocol functions except This->Destroy()
        InnerSslHandle->ConnectionState = OPENSSL_ERROR;
        *ExchangedLen = 0;
        return EFI_DEVICE_ERROR;
      }
    }
  } else {
    //no connection
    DEBUG ((EFI_D_ERROR, "%a.%d SslHandle->ConnectionState == %d\n", __FUNCTION__, __LINE__, InnerSslHandle->ConnectionState));
    *ExchangedLen = 0;
    return EFI_NOT_STARTED;
  }
}

/**
  Try to read data
  
  @param  SslHandle               SSL handle
  @param  Buf                     A pointer to the buffer for read in
  @param  BufSize                 Number of data try to read
  @param  ExchangedLen            Length of really readed data
  
  @retval EFI_INVALID_PARAMETER   Function got invalid handle, command or pointer in parameters
  @retval EFI_NOT_STARTED         Not connected
  @retval EFI_DEVICE_ERROR        OpenSSL data exchanging error
  @retval EFI_ABORTED             Error occured
  @retval EFI_SUCCESS             Some of data successfully readed
**/
EFI_STATUS
EFIAPI
ThisSslRead(
  IN OPENSSL_PROTOCOL *This,
  IN EFI_HANDLE SslHandle,
  IN VOID *Buf,
  IN UINTN BufSize,
  OUT UINTN *ReadedLen
  )
{
  return SslExchangeData(SslHandle,
                         OPENSSL_CMD_READ,
                         Buf,
                         BufSize,
                         ReadedLen);
}

/**
  Try to send data
  
  @param  SslHandle               SSL handle
  @param  Buf                     A pointer to the buffer for send out
  @param  BufSize                 Number of data try to send
  @param  ExchangedLen            Length of really sended data
  
  @retval EFI_INVALID_PARAMETER   Function got invalid handle, command or pointer in parameters
  @retval EFI_NOT_STARTED         Not connected
  @retval EFI_DEVICE_ERROR        OpenSSL data exchanging error
  @retval EFI_ABORTED             Error occured
  @retval EFI_SUCCESS             Some of data successfully sended
**/
EFI_STATUS
EFIAPI
ThisSslWrite(
  IN OPENSSL_PROTOCOL *This,
  IN EFI_HANDLE SslHandle,
  IN CONST VOID *Buf,
  IN UINTN BufSize,
  OUT UINTN *WritedLen
  )
{
  return SslExchangeData(SslHandle,
                         OPENSSL_CMD_WRITE,
                         (VOID*)Buf, //remove const qualifier
                         BufSize,
                         WritedLen);
}

/**
  Destroy SSL handle. If in connected state disconnect.
  
  @param  SslHandle               SSL handle
  @param  MakeFullShutdown        If TRUE - don't finish destroy until peer answer on 'close notify' or error occurs
                                  If FALSE - just send 'close notify', immediately free memory and exit
  
  @retval EFI_INVALID_PARAMETER   Function got invalid handle in parameters
  @retval EFI_NOT_READY           If MakeFullShutdown==TRUE:  peer answer on 'close notify' not yet received,
                                                              handle NOT destroyed, retry call to SslDestroy()
                                  If MakeFullShutdown==FALSE: peer answer on 'close notify' not yet received,
                                                              handle successfully destroyed
  @retval EFI_DEVICE_ERROR        OpenSSL data exchanging error while sendind/reading 'close notify',
                                  handle successfully destroyed
  @retval EFI_SUCCESS             Handle successfully destroyed
**/
EFI_STATUS
EFIAPI
ThisSslDestroy(
  IN OPENSSL_PROTOCOL *This,
  IN EFI_HANDLE SslHandle,
  IN BOOLEAN MakeFullShutdown
  )
{
  int Result, Result2;
  EFI_STATUS Status;
  OPENSSL_HELPER_HANDLE *InnerSslHandle;
  unsigned long SslErr;

  DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  InnerSslHandle = (OPENSSL_HELPER_HANDLE *)SslHandle;
  if (!SslIsValidHandle(InnerSslHandle)) {
    DEBUG ((EFI_D_ERROR, "%a.%d SslIsValidHandle(): SslHandle == 0x%X\n", __FUNCTION__, __LINE__, SslHandle));
    return EFI_INVALID_PARAMETER;
  }

  DEBUG ((EFI_D_ERROR, "%a.%d SslHandle->ConnectionState == %d\n", __FUNCTION__, __LINE__, InnerSslHandle->ConnectionState));
  DEBUG ((EFI_D_ERROR, "%a.%d SslHandle->Type == %d\n", __FUNCTION__, __LINE__, InnerSslHandle->Type));

  if (InnerSslHandle->IsSslCalled) {//it was calls to SSL_connect()/SSL_accept()
    if (!MakeFullShutdown) {
      DEBUG ((EFI_D_ERROR, "%a.%d MakeFullShutdown == %d\n", __FUNCTION__, __LINE__, MakeFullShutdown));
      SSL_set_shutdown(InnerSslHandle->Ssl, SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);//SSL_shutdown() at this point return 1 instantly
    }
    Result = SSL_shutdown(InnerSslHandle->Ssl);
    if (Result == 0) {
      //if Result == 0 SSL_get_error() may return 'fake' error codes
      Result2 = Result;
      Result = SSL_get_error(InnerSslHandle->Ssl, Result2);
      DEBUG ((EFI_D_ERROR, "%a.%d SSL_shutdown(): Result == %d\n", __FUNCTION__, __LINE__, Result2));
      if (Result == SSL_ERROR_WANT_READ || Result == SSL_ERROR_WANT_WRITE) {
        DEBUG ((EFI_D_ERROR, "%a.%d SSL_shutdown(): SSL_get_error() == (SSL_ERROR_WANT_READ/WRITE)\n", __FUNCTION__, __LINE__));
      } else if (Result == SSL_ERROR_SYSCALL) {
        DEBUG ((EFI_D_ERROR, "%a.%d SSL_shutdown(): SSL_get_error() == SSL_ERROR_SYSCALL [FAKE ERROR]\n", __FUNCTION__, __LINE__));
        while((SslErr = ERR_get_error()) != 0) {
          DEBUG ((EFI_D_ERROR, "%a.%d SSL_shutdown(): 0x%X, %a\n", __FUNCTION__, __LINE__, SslErr, ERR_error_string(SslErr, NULL)));
        }
      } else {
        DEBUG ((EFI_D_ERROR, "%a.%d SSL_shutdown(): SSL_get_error() == %d\n", __FUNCTION__, __LINE__, Result));
        while((SslErr = ERR_get_error()) != 0) {
          DEBUG ((EFI_D_ERROR, "%a.%d SSL_shutdown(): 0x%X, %a\n", __FUNCTION__, __LINE__, SslErr, ERR_error_string(SslErr, NULL)));
        }
      }
      if (MakeFullShutdown) {
        return EFI_NOT_READY;
      } else {
        Status = EFI_NOT_READY;
      }
    } else if (Result == -1) {
      Result2 = Result;
      Result = SSL_get_error(InnerSslHandle->Ssl, Result2);
      if (Result == SSL_ERROR_WANT_READ || Result == SSL_ERROR_WANT_WRITE) {
        //call to SSL_shutdown() needs to be retried
        DEBUG ((EFI_D_ERROR, "%a.%d SSL_shutdown(): Result == %d\n", __FUNCTION__, __LINE__, Result2));
        DEBUG ((EFI_D_ERROR, "%a.%d SSL_shutdown(): SSL_get_error() == (SSL_ERROR_WANT_READ/WRITE)\n", __FUNCTION__, __LINE__));
        if (MakeFullShutdown) {
          return EFI_NOT_READY;
        } else {
          Status = EFI_NOT_READY;
        }
      } else if (Result == SSL_ERROR_SYSCALL) {
        //BIO report IO error
        DEBUG ((EFI_D_ERROR, "%a.%d SSL_shutdown(): Result == %d\n", __FUNCTION__, __LINE__, Result2));
        DEBUG ((EFI_D_ERROR, "%a.%d SSL_shutdown(): SSL_get_error() == SSL_ERROR_SYSCALL\n", __FUNCTION__, __LINE__));
        while((SslErr = ERR_get_error()) != 0) {
          DEBUG ((EFI_D_ERROR, "%a.%d SSL_shutdown(): 0x%X, %a\n", __FUNCTION__, __LINE__, SslErr, ERR_error_string(SslErr, NULL)));
        }
        //IO not available, we can't read/send anything - finish destroying
        Status = EFI_DEVICE_ERROR;
      } else {
        //SSL_shutdown() fails
        DEBUG ((EFI_D_ERROR, "%a.%d SSL_shutdown(): Result == %d\n", __FUNCTION__, __LINE__, Result2));
        DEBUG ((EFI_D_ERROR, "%a.%d SSL_shutdown(): SSL_get_error() == %d\n", __FUNCTION__, __LINE__, Result));
        while((SslErr = ERR_get_error()) != 0) {
          DEBUG ((EFI_D_ERROR, "%a.%d SSL_shutdown(): 0x%X, %a\n", __FUNCTION__, __LINE__, SslErr, ERR_error_string(SslErr, NULL)));
        }
        //unexpected error - finish destroying
        Status = EFI_DEVICE_ERROR;
      }
    } else {
      DEBUG ((EFI_D_ERROR, "%a.%d SSL_shutdown(): Result == %d\n", __FUNCTION__, __LINE__, Result));
      Status = EFI_SUCCESS;
    }
  } else {
    DEBUG ((EFI_D_INFO, "%a.%d SslHandle->IsSslCalled == %d\n", __FUNCTION__, __LINE__, InnerSslHandle->IsSslCalled));
    Status = EFI_SUCCESS;
  }
  //BIO callbacks need handle to be valid
  RemoveEntryList(&InnerSslHandle->Link);
  //handle now not valid

  //free SSL objects
  //BIO will be freed in SSL_free()
  //DEBUG ((EFI_D_INFO, "%a.%d BIO_free(): SslHandle->SslBio == 0x%X\n", __FUNCTION__, __LINE__, InnerSslHandle->SslBio));
  //BIO_free(InnerSslHandle->SslBio);
  DEBUG ((EFI_D_INFO, "%a.%d SSL_free(): SslHandle->Ssl == 0x%X\n", __FUNCTION__, __LINE__, InnerSslHandle->Ssl));
  SSL_free(InnerSslHandle->Ssl);
  DEBUG ((EFI_D_INFO, "%a.%d PKCS7_free(): SslHandle->CaCertsPkcs7 == 0x%X\n", __FUNCTION__, __LINE__, InnerSslHandle->CaCertsPkcs7));
  PKCS7_free(InnerSslHandle->CaCertsPkcs7);
  DEBUG ((EFI_D_INFO, "%a.%d SSL_CTX_free(): SslHandle->Ctx == 0x%X\n", __FUNCTION__, __LINE__, InnerSslHandle->Ctx));
  SSL_CTX_free(InnerSslHandle->Ctx);
  //free handle memory
  DEBUG ((EFI_D_INFO, "%a.%d FreePool(): SslHandle == 0x%X\n", __FUNCTION__, __LINE__, SslHandle));
  FreePool(InnerSslHandle);
  
  return Status;
}

