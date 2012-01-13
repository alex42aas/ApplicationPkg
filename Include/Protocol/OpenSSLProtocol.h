/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef OPENSSL_PROTOCOL_H_
#define OPENSSL_PROTOCOL_H_

#include <TlsConfigStruct.h>
#include <OpensslErrors.h>

typedef struct {
  LIST_ENTRY  ListEntry;
  CHAR8       *cdpUri;
} CDP_URL_ENTRY;

#define OPENSSL_SERVER               101
#define OPENSSL_CLIENT               102

#define OPENSSL_USE_SSL_2            2
#define OPENSSL_USE_SSL_3            3
#define OPENSSL_USE_SSL_2_3          (2+3) // TLS1.1 & TLS1.2 will be disabled in client mode for compability
#define OPENSSL_USE_TLS_1_0          10
#define OPENSSL_USE_TLS_1_1          11
#define OPENSSL_USE_TLS_1_2          12

typedef struct {
  CHAR16 *certCN;     //!< Common name of a certificate
  CHAR16 *certIssuer; //!< Issuer name of a certificate
  CHAR16 *notBefore;  //!< Not before valid date
  CHAR16 *notAfter;   //!< Not after valid date
  CHAR16 *serial;
} OSSL_CERT_INFO_T;

/**
  Try to read data
  
  @param  Bio                     Optional BIO parameter
  @param  Buf                     A pointer to the buffer for read in
  @param  BufSize                 Number of data try to read
  @param  ExchangedLen            Length of really readed data
  
  @retval EFI_SUCCESS             Some of data successfully readed
  @retval [any other value]       Error occured
**/
typedef
EFI_STATUS
(EFIAPI *BIO_READ)(
  IN OPTIONAL VOID* Bio,
  IN VOID *Buf,
  IN UINTN BufSize,
  OUT UINTN *ReadedLen
  );

/**
  Try to write data
  
  @param  Bio                     Optional BIO parameter
  @param  Buf                     A pointer to the buffer for send out
  @param  BufSize                 Number of data try to send
  @param  ExchangedLen            Length of really sended data
  
  @retval EFI_SUCCESS             Some of data successfully readed
  @retval [any other value]       Error occured
**/
typedef
EFI_STATUS
(EFIAPI *BIO_WRITE)(
  IN OPTIONAL VOID* Bio,
  IN CONST VOID *Buf,
  IN UINTN BufSize,
  OUT UINTN *WritedLen
  );

typedef struct _OPENSSL_SETTINGS{
  UINTN Type;               //Type: OPENSSL_SERVER or OPENSSL_CLIENT
  UINTN Version;            //Version of SSL or TLS protocol to use

  //user defined BIO functions
  VOID*               BioHandle;  //optional parameter passed to BIO functions
  BIO_READ            BioRead;
  BIO_WRITE           BioWrite;

  //certificate
  VOID *CertAsn1Buf;        //Pointer to the buffer with certificate in ASN1/DER format
  UINTN CertAsn1BufLen;     //Length of the buffer with certificate
  //private key
  VOID *PrivKeyAsn1Buf;     //Pointer to the buffer with private key in ASN1/DER format
  UINTN PrivKeyAsn1BufLen;  //Length of the buffer with private key
  //pkcs7 with CA certificates
  VOID *CaCertsP7bBuf;      //Pointer to the buffer with verify certificates in PKCS7 ASN1/DER format
  UINTN CaCertsP7bBufLen;   //Length of the buffer with verify certificates
} OPENSSL_SETTINGS;

typedef struct _OPENSSL_PROTOCOL OPENSSL_PROTOCOL;

typedef
OSSL_STATUS
(EFIAPI *OPENSSL_VERIFY_CERTIFICATE_WITH_CRL_AND_CA) (
  IN CHAR8 *userCertData,
  IN UINTN userCertLen,
  IN CHAR8 *chainData,
  IN UINTN chainDataLen,
  IN CHAR8 *crlData,
  IN UINTN crlDataLen
  );

typedef
OSSL_STATUS
(EFIAPI *OPENSSL_VERIFY_SELFSIGNED_CERTIFICATE) (
  IN CHAR8 *certData,
  IN UINTN certDataLen
  );

typedef
OSSL_STATUS
(EFIAPI *OPENSSL_VERIFY_CA_CHAIN) (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen
  );

typedef
OSSL_STATUS
(EFIAPI *OPENSSL_CHECK_CRL_WITH_CA) (
  IN CHAR8 *crlData,
  IN UINTN crlDataLen,
  IN CHAR8 *chainData,
  IN UINTN chainDataLen
);

typedef
OSSL_STATUS
(EFIAPI *OPENSSL_CHECK_CERTIFICATE_FORMAT) (
  IN CHAR8 *userCertData,
  IN UINTN userCertLen
);

typedef
OSSL_STATUS
(EFIAPI *OPENSSL_CHECK_CHAIN_FORMAT) (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen
);

typedef
OSSL_STATUS
(EFIAPI *OPENSSL_ADD_CRL_TO_LOCAL_STACK) (
  IN CHAR8 *crlData,
  IN UINTN crlDataLen
);

typedef
VOID
(EFIAPI *OPENSSL_FLUSH_CRL_LOCAL_STACK) (
  VOID
);

typedef
OSSL_STATUS
(EFIAPI *OPENSSL_CHECK_AND_SAVE_STACK_TO_CHAIN) (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen
);

typedef
VOID *
(EFIAPI *OPENSSL_COPY_CRL_STACK_FROM_CA_CHAIN) (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen
);

typedef
VOID*
(EFIAPI *OPENSSL_COPY_CRL_STACK_FROM_LOCAL_STACK) (
  VOID
);

typedef
UINTN
(EFIAPI *OPENSSL_GET_CDP_LIST_FROM_CER_BINARY) (
  IN CHAR8 *certData,
  IN UINTN certDataLen,
  OUT LIST_ENTRY *cdpListHead
);

typedef
UINTN
(EFIAPI *OPENSSL_GET_CDP_LIST_FROM_CA_CHAIN_BINARY) (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen,
  OUT LIST_ENTRY *cdpListHead
);

typedef
OSSL_STATUS
(EFIAPI *OPENSSL_GET_LAST_ERROR) (
    VOID
);

typedef
VOID
(EFIAPI *OPENSSL_SET_LAST_ERROR) (
  OSSL_STATUS Status
);

typedef
EFI_STATUS
(EFIAPI *OPENSSL_CALC_DATA_DIGEST) (
  IN UINT8 *CertData,
  IN UINTN CertDataLen,
  IN UINT8 *FileData,
  IN UINTN FileDataLen,
  OUT UINT8 **SignBuf,
  OUT UINTN *SignLen
);

typedef
UINTN
(EFIAPI *OPENSSL_GET_CALC_DATA_DIGEST_TYPE) (
  VOID
);

typedef
tlsConfig_t
(EFIAPI *OPENSSL_MAKE_TLS_CONFIG) (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen
);

typedef
BOOLEAN
(EFIAPI *OPENSSL_IS_GOST_DIGEST) (
  IN UINTN digestType
);

typedef
EFI_STATUS
(EFIAPI *OPENSSL_GET_CERT_SUBJECT_NAME) (
  IN CHAR8 *certData,
  IN UINTN certDataLen,
  OUT CHAR16 **subjectName
);

typedef
EFI_STATUS
(EFIAPI *OPENSSL_GET_CERT_ISSUER_NAME)(
  IN CHAR8 *certData,
  IN UINTN certDataLen,
  OUT CHAR16 **issuerName
);

typedef
EFI_STATUS
(EFIAPI *OPENSSL_GET_CERT_NOT_AFTER_DATE) (
  IN CHAR8 *certData,
  IN UINTN certDataLen,
  OUT CHAR16 **notAfterDate
);

typedef
EFI_STATUS
(EFIAPI *OPENSSL_GET_CERT_NOT_BEFORE_DATE) (
  IN CHAR8 *certData,
  IN UINTN certDataLen,
  OUT CHAR16 **notBeforeDate
);

typedef
EFI_STATUS
(EFIAPI *OPENSSL_GET_CERT_SERIAL_NUMBER) (
  IN CHAR8 *certData,
  IN UINTN certDataLen,
  OUT CHAR16 **serialNumber
);

typedef
INT32
(EFIAPI *OPENSSL_GET_CERT_COUNT_FROM_CHAIN) (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen
);

typedef
EFI_STATUS
(EFIAPI *OPENSSL_GET_CERT_INFO_FROM_CHAIN) (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen,
  IN INT32 certIndex,
  OUT OSSL_CERT_INFO_T **certInfo
);

typedef
EFI_STATUS
(EFIAPI *OPENSSL_GET_CERT_INFO_FROM_CERT) (
  IN CHAR8 *certData,
  IN UINTN certDataLen,
  OUT OSSL_CERT_INFO_T **certInfo
);

typedef
VOID
(EFIAPI *OPENSSL_FREE_CERT_INFO) (
  IN OSSL_CERT_INFO_T *certInfo
);

typedef
EFI_STATUS
(EFIAPI *OPENSSL_CRYPTO_EVP_New_MD_CTX) (
  IN OPENSSL_PROTOCOL *This,
  IN OUT VOID **MdCtx
  );

typedef
EFI_STATUS
(EFIAPI *OPENSSL_CRYPTO_EVP_New_CIPHER_CTX) (
  IN OPENSSL_PROTOCOL *This,
  IN OUT VOID **Ctx
  );

typedef
EFI_STATUS
(EFIAPI *OPENSSL_CRYPTO_EVP_New_CIPHER) (
  IN OPENSSL_PROTOCOL *This,
  IN OUT VOID **Cipher
  );

typedef
VOID *
(EFIAPI *OPENSSL_CRYPTO_EVP_get_digestbyname) (
  IN OPENSSL_PROTOCOL *This,
  IN VOID *Name
  );

typedef
VOID *
(EFIAPI *OPENSSL_CRYPTO_EVP_get_digestbynid) (
  IN OPENSSL_PROTOCOL *This,
  IN UINTN Nid
  );



typedef
VOID
(EFIAPI *OPENSSL_CRYPTO_EVP_MD_CTX_init) (
  IN OPENSSL_PROTOCOL *This,
  IN VOID *Ctx
  );

typedef
EFI_STATUS
(EFIAPI *OPENSSL_CRYPTO_EVP_DigestInit) (
  IN OPENSSL_PROTOCOL *This,
  IN OUT VOID *Ctx,
  IN VOID *Type
  );

typedef
EFI_STATUS
(EFIAPI *OPENSSL_CRYPTO_EVP_DigestUpdate) (
  IN OPENSSL_PROTOCOL *This,
  IN VOID *Ctx,
  IN CONST VOID *Data,
  IN UINTN Cnt
  );

typedef
EFI_STATUS
(EFIAPI *OPENSSL_CRYPTO_EVP_DigestFinal) (
  IN OPENSSL_PROTOCOL *This,
  IN VOID *Ctx,
  IN VOID *Md,
  IN OUT VOID *Size
  );

typedef
EFI_STATUS
(EFIAPI *OPENSSL_CRYPTO_EVP_MD_CTX_cleanup) (
  IN OPENSSL_PROTOCOL *This,
  IN OUT VOID *Ctx
  );


typedef
VOID
(EFIAPI *OPENSSL_CRYPTO_EVP_CIPHER_CTX_init) (
  IN OPENSSL_PROTOCOL *This,
  IN OUT VOID *Ctx
  );

typedef
VOID *
(EFIAPI *OPENSSL_CRYPTO_EVP_des_ede3) (
  IN OPENSSL_PROTOCOL *This
  );

typedef
VOID *
(EFIAPI *OPENSSL_CRYPTO_EVP_des_ede_cbc) (
  IN OPENSSL_PROTOCOL *This
  );

typedef
EFI_STATUS
(EFIAPI *OPENSSL_CRYPTO_EVP_EncryptInit) (
  IN OPENSSL_PROTOCOL *This,
  IN OUT VOID *Ctx, 
  IN VOID *Cipher,
  IN VOID *Key, 
  IN VOID *IV
  );

typedef
EFI_STATUS
(EFIAPI *OPENSSL_CRYPTO_EVP_EncryptUpdate) (
  IN OPENSSL_PROTOCOL *This,
  IN OUT VOID *Ctx, 
  IN OUT VOID *Out, 
  IN OUT VOID *Outl,
  IN VOID *In, 
  IN INTN Inl
  );

typedef
EFI_STATUS
(EFIAPI *OPENSSL_CRYPTO_EVP_EncryptFinal_ex) (
  IN OPENSSL_PROTOCOL *This,
  IN OUT VOID *Ctx, 
  IN OUT VOID *Out, 
  IN OUT VOID *Outl
  );

typedef
EFI_STATUS
(EFIAPI *OPENSSL_CRYPTO_EVP_SHA1_New_SHA_CTX) (
  IN OPENSSL_PROTOCOL *This,
  IN OUT VOID **Ctx
  );

typedef
EFI_STATUS
(EFIAPI *OPENSSL_CRYPTO_EVP_SHA1_Init) (
  IN OPENSSL_PROTOCOL *This,
  IN OUT VOID *Ctx
  );

typedef
EFI_STATUS
(EFIAPI *OPENSSL_CRYPTO_EVP_SHA1_Update) (
  IN OPENSSL_PROTOCOL *This,
  IN OUT VOID *Ctx, 
  IN VOID *Data, 
  IN UINTN Len
  );

typedef
EFI_STATUS
(EFIAPI *OPENSSL_CRYPTO_EVP_SHA1_Final) (
  IN OPENSSL_PROTOCOL *This,
  IN OUT VOID *Md, 
  IN OUT VOID *Ctx
  );

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
typedef
EFI_STATUS
(EFIAPI *OPENSSL_SSL_Create)(
  IN OPENSSL_PROTOCOL *This,
  OUT EFI_HANDLE *SslHandle,
  IN OPENSSL_SETTINGS *SslSettings
  );

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
typedef
EFI_STATUS
(EFIAPI *OPENSSL_SSL_Start)(
  IN OPENSSL_PROTOCOL *This,
  IN EFI_HANDLE SslHandle
  );

/**
  Return num of bytes buffered in OpenSSL internal buffers
  
  @param  SslHandle               SSL handle
  @param  NumOfPendingBytes       Num of bytes available to immediate reading
  
  @retval EFI_INVALID_PARAMETER   Function got invalid handle or pointer in parameters
  @retval EFI_SUCCESS             Some of data successfully readed
**/
typedef
EFI_STATUS
(EFIAPI *OPENSSL_SSL_Pending)(
  IN OPENSSL_PROTOCOL *This,
  IN EFI_HANDLE SslHandle,
  OUT UINTN *NumOfPendingBytes
  );

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
typedef
EFI_STATUS
(EFIAPI *OPENSSL_SSL_Read)(
  IN OPENSSL_PROTOCOL *This,
  IN EFI_HANDLE SslHandle,
  IN VOID *Buf,
  IN UINTN BufSize,
  OUT UINTN *ReadedLen
  );

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
typedef
EFI_STATUS
(EFIAPI *OPENSSL_SSL_Write)(
  IN OPENSSL_PROTOCOL *This,
  IN EFI_HANDLE SslHandle,
  IN CONST VOID *Buf,
  IN UINTN BufSize,
  OUT UINTN *WritedLen
  );

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
typedef
EFI_STATUS
(EFIAPI *OPENSSL_SSL_Destroy) (
  IN OPENSSL_PROTOCOL *This,
  IN EFI_HANDLE SslHandle,
  IN BOOLEAN MakeFullShutdown
  );

typedef
VOID
(EFIAPI *OPENSSL_INIT) (
  VOID
  );

typedef
EFI_STATUS
(EFIAPI *OPENSSL_CHECK_DATA_SIGNATURE) (
  IN UINT8 *CertData,
  IN UINTN CertDataLen,
  IN UINT8 *Data,
  IN UINTN DataLen,
  IN UINT8 *SigData,
  IN UINTN SigDataLen
  );




/*! Struct of the ldap auth protocol */
struct _OPENSSL_PROTOCOL {
  VOID *DirectOperations;
  VOID *X509DirectOperations;
  VOID *SSLDirectOperations;
  VOID *CryptoDirectOperations;
  VOID *BioDirectOperations;
  VOID *StackDirectionOperations;

  OPENSSL_VERIFY_CERTIFICATE_WITH_CRL_AND_CA VerifyCertificateWithCRLandCA;
  OPENSSL_VERIFY_SELFSIGNED_CERTIFICATE      VerifySelfSignedCertificate;
  OPENSSL_VERIFY_CA_CHAIN                    VerifyCAChain;
  OPENSSL_CHECK_CRL_WITH_CA                  CheckCRLWithCA;
  OPENSSL_CHECK_CERTIFICATE_FORMAT           CheckCertificateFormat;
  OPENSSL_CHECK_CHAIN_FORMAT                 CheckChainFormat;
  OPENSSL_ADD_CRL_TO_LOCAL_STACK             AddCRLtoLocalStack;
  OPENSSL_FLUSH_CRL_LOCAL_STACK              FlushCRLLocalStack;
  OPENSSL_CHECK_AND_SAVE_STACK_TO_CHAIN      CheckAndSaveStackToChainStorage;
  OPENSSL_COPY_CRL_STACK_FROM_CA_CHAIN       CopyCRLStackFromCAChain;
  OPENSSL_COPY_CRL_STACK_FROM_LOCAL_STACK    CopyCRLStackFromLocalStack;
  OPENSSL_GET_CDP_LIST_FROM_CER_BINARY       GetCDPListFromCertBinary;
  OPENSSL_GET_CDP_LIST_FROM_CA_CHAIN_BINARY  GetCDPListFromCaChainBinary;
  OPENSSL_MAKE_TLS_CONFIG                    MakeTlsConfig;
  OPENSSL_CALC_DATA_DIGEST                   CalcDataDigest;
  OPENSSL_GET_CALC_DATA_DIGEST_TYPE          GetCalcDataDigest_MdType;
  OPENSSL_IS_GOST_DIGEST                     IsGostDigest;
  
  OPENSSL_GET_CERT_SUBJECT_NAME              GetCertificateSubjectName;
  OPENSSL_GET_CERT_ISSUER_NAME               GetCertificateIssuerName;
  OPENSSL_GET_CERT_NOT_AFTER_DATE            GetCertificateNotAfterDate;
  OPENSSL_GET_CERT_NOT_BEFORE_DATE           GetCertificateNotBeforeDate;
  OPENSSL_GET_CERT_SERIAL_NUMBER             GetCertificateSerialNumber;
  OPENSSL_GET_CERT_COUNT_FROM_CHAIN          GetCertificateCountFromChain;

  OPENSSL_GET_CERT_INFO_FROM_CHAIN           GetCertificateInfoFromChain;
  OPENSSL_GET_CERT_INFO_FROM_CERT            GetCertificateInfoFromCertBinary;
  OPENSSL_FREE_CERT_INFO                     FreeCertInfo;

  OPENSSL_GET_LAST_ERROR                     GetOsslLastError;
  OPENSSL_SET_LAST_ERROR                     SetOsslLastError;

  OPENSSL_CRYPTO_EVP_New_MD_CTX              EVP_New_MD_CTX;
  OPENSSL_CRYPTO_EVP_New_CIPHER_CTX          EVP_New_CIPHER_CTX;
  OPENSSL_CRYPTO_EVP_New_CIPHER              EVP_New_CIPHER;
  OPENSSL_CRYPTO_EVP_get_digestbyname        EVP_get_digestbyname;
  OPENSSL_CRYPTO_EVP_get_digestbynid         EVP_get_digestbynid;
  OPENSSL_CRYPTO_EVP_MD_CTX_init             EVP_MD_CTX_init;
  OPENSSL_CRYPTO_EVP_DigestInit              EVP_DigestInit;
  OPENSSL_CRYPTO_EVP_DigestUpdate            EVP_DigestUpdate;
  OPENSSL_CRYPTO_EVP_DigestFinal             EVP_DigestFinal;
  OPENSSL_CRYPTO_EVP_MD_CTX_cleanup          EVP_MD_CTX_cleanup;
  OPENSSL_CRYPTO_EVP_CIPHER_CTX_init         EVP_CIPHER_CTX_init;
  OPENSSL_CRYPTO_EVP_des_ede3                EVP_des_ede3;
  OPENSSL_CRYPTO_EVP_des_ede_cbc             EVP_des_ede_cbc;
  OPENSSL_CRYPTO_EVP_EncryptInit             EVP_EncryptInit;
  OPENSSL_CRYPTO_EVP_EncryptUpdate           EVP_EncryptUpdate;
  OPENSSL_CRYPTO_EVP_EncryptFinal_ex         EVP_EncryptFinal_ex;
  OPENSSL_CRYPTO_EVP_SHA1_New_SHA_CTX        EVP_SHA1_New_SHA_CTX;
  OPENSSL_CRYPTO_EVP_SHA1_Init               EVP_SHA1_Init;
  OPENSSL_CRYPTO_EVP_SHA1_Update             EVP_SHA1_Update;
  OPENSSL_CRYPTO_EVP_SHA1_Final              EVP_SHA1_Final;

  OPENSSL_SSL_Create                         SslCreate;
  OPENSSL_SSL_Start                          SslStart;
  OPENSSL_SSL_Pending                        SslPending;
  OPENSSL_SSL_Read                           SslRead;
  OPENSSL_SSL_Write                          SslWrite;
  OPENSSL_SSL_Destroy                        SslDestroy;

  OPENSSL_CHECK_DATA_SIGNATURE               CheckDataSignature;

  OPENSSL_INIT                               Init;    
};

extern EFI_GUID gOpenSSLProtocolGuid;

#endif //  OPENSSL_PROTOCOL_H_
