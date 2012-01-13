/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef OPENSSL_FUNCTIONS_INTERNAL_H_
#define OPENSSL_FUNCTIONS_INTERNAL_H_

INT32
i2char8_ASN1_INTEGER(
  CHAR8 *str,
  INT32 strSize,
  ASN1_INTEGER *a
);

INT32
ASN1TimeCmp (
  ASN1_TIME *firstTime,
  ASN1_TIME *secondTime
);

EFI_STATUS
GetASN1GeneralizedTime(
  IN ASN1_TIME *tm,
  OUT CHAR16 **dateStr
);

EFI_STATUS
GetASN1UtcTime(
  IN ASN1_TIME *tm,
  OUT CHAR16 **dateStr
);

EFI_STATUS
GetASN1Time(
  IN ASN1_TIME *tm,
  OUT CHAR16 **dateStr
);

OSSL_STATUS
GetIssuerFromX509(
  IN X509 *x509,
  OUT CHAR16 **issuerName
);

OSSL_STATUS
GetSubjectFromX509(
  IN X509 *x509,
  OUT CHAR16 **subjectName
);

OSSL_STATUS
GetSerialFromX509(
  IN X509 *x509,
  OUT CHAR16 **serialStr16
);

PKCS7*
GetChainFromBinary (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen,
  OUT OSSL_STATUS *Status
);

X509*
GetCertificateFromBinary (
  IN CHAR8 *certData,
  IN UINTN certDataLen,
  OUT OSSL_STATUS *Status
);

X509_CRL*
GetCRLFromBinary (
  IN CHAR8 *crlData,
  IN UINTN crlDataLen,
  OUT OSSL_STATUS *Status
);

INT32
CheckCertTime (
  IN X509 *certToCheck,
  IN time_t *ptime
);

INT32
CheckCRLTime (
  IN X509_CRL *crlToCheck,
  IN time_t *ptime
);

VOID
LogOpensslMessage (
  IN UINTN logLevel,
  IN const CHAR8 *format,
  ...
);

EFI_STATUS
InitializeOpenSSL (
  VOID
);

#endif // OPENSSL_FUNCTIONS_INTERNAL_H_
