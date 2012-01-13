/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/FsUtils.h>
#include <Library/CommonUtils.h>

#include <InternalErrDesc.h>

#include <Protocol/OpensslDirectOp.h>
#include <Protocol/OpensslProtocol.h>

#include <Protocol/LoadedImage.h>

#include "OpensslFunctions.h"
#include "OpenSSLDxeInternal.h"
#include "OpensslSSLHelper.h"

static OPENSSL_INTERNAL_DATA gOpenSSLInternalData;

#if 0
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

//------------------------------------------------------------------------------
/*! \brief Init FsUtils for StdLib is used by OpenSSLDxe */
//------------------------------------------------------------------------------
static VOID
InitFsUtilsForStdLib(
  IN EFI_HANDLE ImageHandle
  )
{
  EFI_LOADED_IMAGE_PROTOCOL *ImageInfo;
  EFI_DEVICE_PATH_PROTOCOL *pDp;
  CHAR16 *PathString;

  if (AllocFsDescTable(10) == -1) {
    MsgInternalError(INT_ERR_ALLOC_FS_DESC_TABLE_ERROR);
  }

  gBS->HandleProtocol (ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **) &ImageInfo);

  pDp = DevicePathFromHandle(ImageInfo->DeviceHandle);
  PathString = DevPathToString(pDp, FALSE, TRUE);
  LOG(( EFI_D_ERROR, "-*-> %S\n", PathString ));
  AddFsDescTableItem(L"fv", PathString, FALSE);
  
  return;
}
//------------------------------------------------------------------------------

EFI_STATUS
OPENSSL_EVP_New_MD_CTX_func (
  IN OPENSSL_PROTOCOL *This,
  IN OUT VOID **MdCtx
  )
{
  if (This == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *MdCtx = AllocateZeroPool (sizeof (EVP_MD_CTX));
  if (*MdCtx == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  return EFI_SUCCESS;
}

VOID *
OPENSSL_EVP_get_digestbyname_func (
  IN OPENSSL_PROTOCOL *This,
  IN VOID *Name
  )
{
  if (This == NULL) {
    return NULL;
  }
  return (VOID*)EVP_get_digestbyname (
                  (const char*)Name
                  );
}

VOID *
OPENSSL_EVP_get_digestbynid_func (
  IN OPENSSL_PROTOCOL *This,
  IN UINTN Nid
  )
{
  if (This == NULL) {
    return NULL;
  }
  return (VOID*)EVP_get_digestbynid (
                  (int)Nid
                  );
}


VOID
OPENSSL_EVP_MD_CTX_init_func (
  IN OPENSSL_PROTOCOL *This,
  IN VOID *Ctx
  )
{
  if (This == NULL || Ctx == NULL) {
    return;
  }
  EVP_MD_CTX_init ((EVP_MD_CTX*)Ctx);
}

EFI_STATUS
OPENSSL_EVP_DigestInit_func (
  IN OPENSSL_PROTOCOL *This,
  IN OUT VOID *Ctx,
  IN VOID *Type
  )
{
  int rv;

  if (This == NULL || Ctx == NULL || Type == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  rv = EVP_DigestInit (
          (EVP_MD_CTX*)Ctx, 
          (const EVP_MD*)Type
          );
  return rv == 1 ? EFI_SUCCESS : EFI_ABORTED;
}


EFI_STATUS
OPENSSL_EVP_DigestUpdate_func (
  IN OPENSSL_PROTOCOL *This,
  IN VOID *Ctx,
  IN CONST VOID *Data,
  IN UINTN Cnt
  )
{
  int rv;

  if (This == NULL || Ctx == NULL || Data == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  rv = EVP_DigestUpdate (
          (EVP_MD_CTX*)Ctx, 
          Data, 
          (size_t)Cnt
          );
  return rv == 1 ? EFI_SUCCESS : EFI_ABORTED;
}


EFI_STATUS
OPENSSL_EVP_DigestFinal_func (
  IN OPENSSL_PROTOCOL *This,
  IN VOID *Ctx,
  IN VOID *Md,
  IN OUT VOID *Size
  )
{
  int rv;
  
  if (This == NULL || Ctx == NULL || Md == NULL || 
      Size == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  rv = EVP_DigestFinal (
        (EVP_MD_CTX*)Ctx, 
        (unsigned char*)Md, 
        (unsigned int*)Size
        );

  return rv == 1 ? EFI_SUCCESS : EFI_ABORTED;
}

EFI_STATUS
OPENSSL_EVP_MD_CTX_cleanup_func (
  IN OPENSSL_PROTOCOL *This,
  IN OUT VOID *Ctx
  )
{
  int rv;
  
  if (This == NULL || Ctx == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  rv = EVP_MD_CTX_cleanup (
          (EVP_MD_CTX*)Ctx
          );
  
  return rv == 1 ? EFI_SUCCESS : EFI_ABORTED;
}


VOID
OPENSSL_EVP_CIPHER_CTX_init_func (
  IN OPENSSL_PROTOCOL *This,
  IN OUT VOID *Ctx
  )
{
  if (This == NULL || Ctx == NULL) {
    return;
  }
  EVP_CIPHER_CTX_init ((EVP_CIPHER_CTX*)Ctx);
}

VOID *
OPENSSL_EVP_des_ede3_func (
  IN OPENSSL_PROTOCOL *This
  )
{
  if (This == NULL) {
    return NULL;
  }
  return (VOID*)EVP_des_ede3 ();
}

VOID *
OPENSSL_EVP_des_ede_cbc_func (
  IN OPENSSL_PROTOCOL *This
  )
{
  if (This == NULL) {
    return NULL;
  }
  return (VOID*)EVP_des_ede_cbc ();
}


EFI_STATUS
OPENSSL_EVP_New_CIPHER_CTX_func (
  IN OPENSSL_PROTOCOL *This,
  IN OUT VOID **Ctx
  )
{
  if (This == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *Ctx = AllocateZeroPool (sizeof (EVP_CIPHER_CTX));
  if (*Ctx == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  return EFI_SUCCESS;
}

EFI_STATUS
OPENSSL_EVP_New_CIPHER_func (
  IN OPENSSL_PROTOCOL *This,
  IN OUT VOID **Cipher
  )
{
  if (This == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  *Cipher = AllocateZeroPool (sizeof (EVP_CIPHER));
  if (*Cipher == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  return EFI_SUCCESS;
}

EFI_STATUS
OPENSSL_EVP_EncryptInit_func (
  IN OPENSSL_PROTOCOL *This,
  IN OUT VOID *Ctx, 
  IN VOID *Cipher,
  IN VOID *Key, 
  IN VOID *IV
  )
{
  int rv;

  if (This == NULL || Ctx == NULL || Cipher == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  rv = EVP_EncryptInit (
        (EVP_CIPHER_CTX*)Ctx,
        (const EVP_CIPHER*)Cipher,
        (const unsigned char*)Key,
        (const unsigned char *)IV
        );

  return rv == 1 ? EFI_SUCCESS : EFI_ABORTED;
}

EFI_STATUS
OPENSSL_EVP_EncryptUpdate_func (
  IN OPENSSL_PROTOCOL *This,
  IN OUT VOID *Ctx, 
  IN OUT VOID *Out, 
  IN OUT VOID *Outl,
  IN VOID *In, 
  IN INTN Inl
  )
{
  int rv;

  if (This == NULL || Ctx == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  rv = EVP_EncryptUpdate (
          (EVP_CIPHER_CTX*)Ctx, 
          (unsigned char*)Out, 
          (int*)Outl,
          (const unsigned char*)In, 
          (int)Inl
          );

  return rv == 1 ? EFI_SUCCESS : EFI_ABORTED;
}


EFI_STATUS
OPENSSL_EVP_EncryptFinal_ex_func (
  IN OPENSSL_PROTOCOL *This,
  IN OUT VOID *Ctx, 
  IN OUT VOID *Out, 
  IN OUT VOID *Outl
  )
{
  int rv;

  if (This == NULL || Ctx == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  rv = EVP_EncryptFinal_ex (
          (EVP_CIPHER_CTX*)Ctx, 
          (unsigned char*)Out, 
          (int*)Outl
          );

  return rv == 1 ? EFI_SUCCESS : EFI_ABORTED;
}


EFI_STATUS
OPENSSL_EVP_SHA1_New_SHA_CTX_func (
  IN OPENSSL_PROTOCOL *This,
  IN OUT VOID **Ctx
  )
{
  if (This == NULL || Ctx == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  *Ctx = AllocateZeroPool(sizeof (SHA_CTX));
  if (*Ctx == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }
  return EFI_SUCCESS;
}


EFI_STATUS
OPENSSL_EVP_SHA1_Init_func (
  IN OPENSSL_PROTOCOL *This,
  IN OUT VOID *Ctx
  )
{
  int rv;
  
  if (This == NULL || Ctx == NULL) {
    return EFI_INVALID_PARAMETER;
  }
  
  rv = SHA1_Init ((SHA_CTX*)Ctx);

  return rv == 1 ? EFI_SUCCESS : EFI_ABORTED;
}

EFI_STATUS
OPENSSL_EVP_SHA1_Update_func (
  IN OPENSSL_PROTOCOL *This,
  IN OUT VOID *Ctx, 
  IN VOID *Data, 
  IN UINTN Len
  )
{
  int rv;
  
  if (This == NULL || Ctx == NULL || Data == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  rv = SHA1_Update (
          (SHA_CTX*)Ctx, 
          (const void*)Data, 
          (size_t) Len
          );
  
  return rv == 1 ? EFI_SUCCESS : EFI_ABORTED;
}

EFI_STATUS
OPENSSL_EVP_SHA1_Final_func (
  IN OPENSSL_PROTOCOL *This,
  IN OUT VOID *Md, 
  IN OUT VOID *Ctx
  )
{
  int rv;
  
  if (This == NULL || Ctx == NULL || Md == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  rv = SHA1_Final (
          (unsigned char*)Md, 
          (SHA_CTX*)Ctx
          );

  return rv == 1 ? EFI_SUCCESS : EFI_ABORTED;
}


//------------------------------------------------------------------------------
/*! \brief Entry point of the OpenSSL DXE driver */
//------------------------------------------------------------------------------
EFI_STATUS
EFIAPI
OpensslDxeInit (
  IN EFI_HANDLE ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  EFI_STATUS Status = EFI_SUCCESS;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  InitFsUtilsForStdLib(ImageHandle);

  ZeroMem(&gOpenSSLInternalData, sizeof(gOpenSSLInternalData));

  gOpenSSLInternalData.OpenSSLPtotocol.DirectOperations         = InitDirectOp();
  gOpenSSLInternalData.OpenSSLPtotocol.SSLDirectOperations      = InitSSLDirectOp();
  gOpenSSLInternalData.OpenSSLPtotocol.X509DirectOperations     = InitX509DirectOp();
  gOpenSSLInternalData.OpenSSLPtotocol.CryptoDirectOperations   = InitCryptoDirectOp();
  gOpenSSLInternalData.OpenSSLPtotocol.BioDirectOperations      = InitBioDirectOp();
  gOpenSSLInternalData.OpenSSLPtotocol.StackDirectionOperations = InitStackDirectOp();

  gOpenSSLInternalData.OpenSSLPtotocol.VerifyCertificateWithCRLandCA   = VerifyCertificateWithCRLandCA;
  gOpenSSLInternalData.OpenSSLPtotocol.VerifySelfSignedCertificate     = VerifySelfSignedCertificate;
  gOpenSSLInternalData.OpenSSLPtotocol.VerifyCAChain                   = VerifyCAChain;
  gOpenSSLInternalData.OpenSSLPtotocol.CheckCRLWithCA                  = CheckCRLWithCA;
  gOpenSSLInternalData.OpenSSLPtotocol.CheckCertificateFormat          = CheckCertificateFormat;
  gOpenSSLInternalData.OpenSSLPtotocol.CheckChainFormat                = CheckChainFormat;
  gOpenSSLInternalData.OpenSSLPtotocol.AddCRLtoLocalStack              = AddCRLtoLocalStack;
  gOpenSSLInternalData.OpenSSLPtotocol.FlushCRLLocalStack              = FlushCRLLocalStack;
  gOpenSSLInternalData.OpenSSLPtotocol.CheckAndSaveStackToChainStorage = CheckAndSaveStackToChainStorage;
  gOpenSSLInternalData.OpenSSLPtotocol.CopyCRLStackFromCAChain         = CopyCRLStackFromCAChain;
  gOpenSSLInternalData.OpenSSLPtotocol.CopyCRLStackFromLocalStack      = CopyCRLStackFromLocalStack;
  gOpenSSLInternalData.OpenSSLPtotocol.GetCDPListFromCertBinary        = GetCDPListFromCertBinary;
  gOpenSSLInternalData.OpenSSLPtotocol.GetCDPListFromCaChainBinary     = GetCDPListFromCaChainBinary;
  gOpenSSLInternalData.OpenSSLPtotocol.MakeTlsConfig                   = MakeTlsConfig;
  gOpenSSLInternalData.OpenSSLPtotocol.GetOsslLastError                = GetOsslLastError;
  gOpenSSLInternalData.OpenSSLPtotocol.SetOsslLastError                = SetOsslLastError;
  gOpenSSLInternalData.OpenSSLPtotocol.CalcDataDigest                  = CalcDataDigest;
  gOpenSSLInternalData.OpenSSLPtotocol.GetCalcDataDigest_MdType        = GetCalcDataDigest_MdType;
  gOpenSSLInternalData.OpenSSLPtotocol.IsGostDigest                    = IsGostDigest;

  gOpenSSLInternalData.OpenSSLPtotocol.GetCertificateSubjectName       = GetCertificateSubjectName;
  gOpenSSLInternalData.OpenSSLPtotocol.GetCertificateIssuerName        = GetCertificateIssuerName;
  gOpenSSLInternalData.OpenSSLPtotocol.GetCertificateNotAfterDate      = GetCertificateNotAfterDate;
  gOpenSSLInternalData.OpenSSLPtotocol.GetCertificateNotBeforeDate     = GetCertificateNotBeforeDate;
  gOpenSSLInternalData.OpenSSLPtotocol.GetCertificateSerialNumber      = GetCertificateSerialNumber;
  gOpenSSLInternalData.OpenSSLPtotocol.GetCertificateCountFromChain    = GetCertificateCountFromChain;
  gOpenSSLInternalData.OpenSSLPtotocol.GetCertificateInfoFromChain     = GetCertificateInfoFromChain;
  gOpenSSLInternalData.OpenSSLPtotocol.GetCertificateInfoFromCertBinary = GetCertificateInfoFromCertBinary;
  gOpenSSLInternalData.OpenSSLPtotocol.FreeCertInfo                    = FreeCertInfo;
  
  gOpenSSLInternalData.OpenSSLPtotocol.EVP_New_MD_CTX       = OPENSSL_EVP_New_MD_CTX_func;
  gOpenSSLInternalData.OpenSSLPtotocol.EVP_New_CIPHER_CTX   = OPENSSL_EVP_New_CIPHER_CTX_func;
  gOpenSSLInternalData.OpenSSLPtotocol.EVP_New_CIPHER       = OPENSSL_EVP_New_CIPHER_func;
  gOpenSSLInternalData.OpenSSLPtotocol.EVP_MD_CTX_init      = OPENSSL_EVP_MD_CTX_init_func;
  gOpenSSLInternalData.OpenSSLPtotocol.EVP_get_digestbyname = OPENSSL_EVP_get_digestbyname_func;
  gOpenSSLInternalData.OpenSSLPtotocol.EVP_get_digestbynid  = 
                                                         OPENSSL_EVP_get_digestbynid_func;
  gOpenSSLInternalData.OpenSSLPtotocol.EVP_DigestInit       = OPENSSL_EVP_DigestInit_func;
  gOpenSSLInternalData.OpenSSLPtotocol.EVP_DigestUpdate     = OPENSSL_EVP_DigestUpdate_func;
  gOpenSSLInternalData.OpenSSLPtotocol.EVP_DigestFinal      = OPENSSL_EVP_DigestFinal_func;
  gOpenSSLInternalData.OpenSSLPtotocol.EVP_MD_CTX_cleanup   = OPENSSL_EVP_MD_CTX_cleanup_func;
  gOpenSSLInternalData.OpenSSLPtotocol.EVP_CIPHER_CTX_init  = OPENSSL_EVP_CIPHER_CTX_init_func;
  gOpenSSLInternalData.OpenSSLPtotocol.EVP_des_ede3         = OPENSSL_EVP_des_ede3_func;
  gOpenSSLInternalData.OpenSSLPtotocol.EVP_des_ede_cbc      = OPENSSL_EVP_des_ede_cbc_func;
  gOpenSSLInternalData.OpenSSLPtotocol.EVP_EncryptInit      = OPENSSL_EVP_EncryptInit_func;
  gOpenSSLInternalData.OpenSSLPtotocol.EVP_EncryptUpdate    = OPENSSL_EVP_EncryptUpdate_func;
  gOpenSSLInternalData.OpenSSLPtotocol.EVP_EncryptFinal_ex  = OPENSSL_EVP_EncryptFinal_ex_func;

  gOpenSSLInternalData.OpenSSLPtotocol.EVP_SHA1_New_SHA_CTX = OPENSSL_EVP_SHA1_New_SHA_CTX_func;
  gOpenSSLInternalData.OpenSSLPtotocol.EVP_SHA1_Init        = OPENSSL_EVP_SHA1_Init_func; 
  gOpenSSLInternalData.OpenSSLPtotocol.EVP_SHA1_Update      = OPENSSL_EVP_SHA1_Update_func;
  gOpenSSLInternalData.OpenSSLPtotocol.EVP_SHA1_Final       = OPENSSL_EVP_SHA1_Final_func;

  gOpenSSLInternalData.OpenSSLPtotocol.SslCreate            = ThisSslCreate;
  gOpenSSLInternalData.OpenSSLPtotocol.SslStart             = ThisSslStart;
  gOpenSSLInternalData.OpenSSLPtotocol.SslPending           = ThisSslPending;
  gOpenSSLInternalData.OpenSSLPtotocol.SslRead              = ThisSslRead;
  gOpenSSLInternalData.OpenSSLPtotocol.SslWrite             = ThisSslWrite;
  gOpenSSLInternalData.OpenSSLPtotocol.SslDestroy           = ThisSslDestroy;

  gOpenSSLInternalData.OpenSSLPtotocol.CheckDataSignature   = CheckDataSignature;

  gOpenSSLInternalData.OpenSSLPtotocol.Init                 = OsslInit;

  Status = gBS->InstallProtocolInterface(
                  &gOpenSSLInternalData.DriverHandle,
                  &gOpenSSLProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  &gOpenSSLInternalData.OpenSSLPtotocol
                );

  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));

  return Status;
}
//------------------------------------------------------------------------------


