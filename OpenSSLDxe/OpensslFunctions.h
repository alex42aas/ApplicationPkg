/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef OPENSSL_FUNCTIONS_H_
#define OPENSSL_FUNCTIONS_H_

#include <TlsConfigStruct.h>
#include <OpensslErrors.h>

OSSL_STATUS
GetOsslLastError (
  VOID
);

VOID
SetOsslLastError (
  OSSL_STATUS Status
);

OSSL_STATUS
VerifySelfSignedCertificate (
  IN CHAR8 *certData,
  IN UINTN certDataLen
  );

OSSL_STATUS
VerifyCertificateWithCRLandCA (
  IN CHAR8 *certData,
  IN UINTN certDataLen,
  IN CHAR8 *caData,
  IN UINTN caDataLen,
  IN CHAR8 *crlData,
  IN UINTN crlDataLen
  );

OSSL_STATUS
CheckCRLWithCA (
  IN CHAR8 *crlData,
  IN UINTN crlDataLen,
  IN CHAR8 *chainData,
  IN UINTN chainDataLen
);

OSSL_STATUS
CheckCertificateFormat (
  IN CHAR8 *userCertData,
  IN UINTN userCertLen
);

OSSL_STATUS
CheckChainFormat (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen
);

OSSL_STATUS
AddCRLtoLocalStack (
  IN CHAR8 *crlData,
  IN UINTN crlDataLen
);

VOID
FlushCRLLocalStack (
  VOID
);

OSSL_STATUS
CheckAndSaveStackToChainStorage (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen
);

VOID *
CopyCRLStackFromCAChain (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen
);

VOID*
CopyCRLStackFromLocalStack (
  VOID
);


UINTN
GetCDPListFromCertBinary (
  IN CHAR8 *certData,
  IN UINTN certDataLen,
  OUT LIST_ENTRY *cdpListHead
);

UINTN
GetCDPListFromCaChainBinary (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen,
  OUT LIST_ENTRY *cdpListHead
);


tlsConfig_t
MakeTlsConfig (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen
);

EFI_STATUS
CalcDataDigest (
  IN UINT8 *CertData,
  IN UINTN CertDataLen,
  IN UINT8 *FileData,
  IN UINTN FileDataLen,
  OUT UINT8 **SignBuf,
  OUT UINTN *SignLen
  );

UINTN
GetCalcDataDigest_MdType (
  VOID
  );

BOOLEAN
IsGostDigest (
  IN UINTN digestType
  );

EFI_STATUS
GetCertificateSubjectName(
  IN CHAR8 *certData,
  IN UINTN certDataLen,
  OUT CHAR16 **subjectName
);

EFI_STATUS
GetCertificateIssuerName(
  IN CHAR8 *certData,
  IN UINTN certDataLen,
  OUT CHAR16 **issuerName
);

EFI_STATUS
GetCertificateNotAfterDate(
  IN CHAR8 *certData,
  IN UINTN certDataLen,
  OUT CHAR16 **notAfterDate
);

EFI_STATUS
GetCertificateNotBeforeDate(
  IN CHAR8 *certData,
  IN UINTN certDataLen,
  OUT CHAR16 **notBeforeDate
);

EFI_STATUS
GetCertificateSerialNumber(
  IN CHAR8 *certData,
  IN UINTN certDataLen,
  OUT CHAR16 **serial
);

INT32
GetCertificateCountFromChain (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen
);

EFI_STATUS
GetCertificateInfoFromChain (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen,
  IN INT32 certIndex,
  OUT OSSL_CERT_INFO_T **certInfo
);

EFI_STATUS
GetCertificateInfoFromCertBinary (
  IN CHAR8 *certData,
  IN UINTN certDataLen,
  OUT OSSL_CERT_INFO_T **certInfo
);

VOID
FreeCertInfo(
  IN OSSL_CERT_INFO_T *certInfo
);

VOID
OsslInit (
  VOID
  );

OSSL_STATUS
VerifyCAChain (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen
);

EFI_STATUS
CheckDataSignature (
  IN UINT8 *CertData,
  IN UINTN CertDataLen,
  IN UINT8 *Data,
  IN UINTN DataLen,
  IN UINT8 *SigData,
  IN UINTN SigDataLen
  );

#endif // OPENSSL_FUNCTIONS_H_

