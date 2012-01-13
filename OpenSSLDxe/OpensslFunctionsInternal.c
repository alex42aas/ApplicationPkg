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

#include <Library/PrintLib.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/CommonUtils.h>
#include <Library/Lib/OpensslCnfFv.h>
#include <Library/Lib/OpensslFunctions.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>

#include <Protocol/BiosLogProtocol.h>

#include "OpensslFunctionsInternal.h"

#if 1
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

STATIC CONST CHAR16 *mon[12]=
    {
      L"Jan",L"Feb",L"Mar",L"Apr",L"May",L"Jun",
      L"Jul",L"Aug",L"Sep",L"Oct",L"Nov",L"Dec"
    };

STATIC BOOLEAN openssslConfigured = FALSE;

STATIC BIOS_LOG_PROTOCOL *pBiosLogProtocol;

//------------------------------------------------------------------------------
/*! \brief Does a string have binary data */
//------------------------------------------------------------------------------
STATIC
BOOLEAN
IsMixedStr (
  IN CHAR8 *strToCheck
)
{
  CHAR8 *str;

  str = AsciiStrStr(strToCheck, "\\x");
  if (str != NULL)
    return TRUE;
  else
    return FALSE;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Convert a string with hex data to ascii */
//------------------------------------------------------------------------------
STATIC
VOID
NormalizeStr (
  IN CHAR8 *strToNorm
)
{
  CHAR8 *tmpStr, *startStr, *startTmpStr;
  INTN tmpStrLen = 0;

  UINTN ch;

  startStr = strToNorm;

  tmpStrLen = AsciiStrLen(strToNorm);

  tmpStr = AllocateZeroPool(tmpStrLen*sizeof(CHAR8) + sizeof(CHAR8));
  if (tmpStr == NULL)
    return;

  startTmpStr = tmpStr;

  while(tmpStrLen > 0) {
    if (*strToNorm != '\\') {
      *tmpStr++ = *strToNorm++;
      tmpStrLen--;
    } else {
      strToNorm += 2;
      HStrToVal(strToNorm, 2, &ch);
      *tmpStr = (CHAR8)ch;
      tmpStr++;
      strToNorm += 2;
      tmpStrLen -= 4;
    }
  }
  LOG((EFI_D_ERROR, "%a.%d str: %a\n", __FUNCTION__, __LINE__, startTmpStr));

  AsciiStrCpy(startStr, startTmpStr);

  FreePool(startTmpStr);

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a time as a string from ASN1_TIME */
/*! You have to free returned value at the end */
//------------------------------------------------------------------------------
STATIC
char*
GetBufOfTime (
  ASN1_TIME *time
)
{
  char *str;
  char *p, *start;
  int i;

  p = AllocateZeroPool(sizeof(char)*24);
  if (p == NULL)
    return NULL;

  start = p;

  i = time->length;
  str = (char *)time->data;
  if (time->type == V_ASN1_UTCTIME) {
    if ((i < 11) || (i > 17)) return NULL;
    memcpy(p,str,10);
    p+=10;
    str+=10;
  } else {
    if (i < 13) return NULL;
    memcpy(p,str,12);
    p+=12;
    str+=12;
  }

  if ((*str == 'Z') || (*str == '-') || (*str == '+')) {
    *(p++)='0'; *(p++)='0';
  } else {
    *(p++)= *(str++);
    *(p++)= *(str++);
    /* Skip any fractional seconds... */
    if (*str == '.') {
      str++;
      while ((*str >= '0') && (*str <= '9')) str++;
    }
  }
  *(p++)='Z';
  *(p++)='\0';

  LOG((EFI_D_ERROR, "%a.%d time: %a\n", __FUNCTION__, __LINE__, start));
  return start;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Convert ASN1 integer value to CHAR8 string */
/*! \param[out] *str A buffer for CHAR8 string
    \param[in] *a ASN1_INTEGER data */
//------------------------------------------------------------------------------
INT32
i2char8_ASN1_INTEGER(
  CHAR8 *str,
  INT32 strSize,
  ASN1_INTEGER *a
)
{
  INT32 i, n = 0;
  STATIC CONST CHAR8 *h = "0123456789ABCDEF";

  if (a == NULL) return 0;

  for (i=0; i<a->length; i++) {
    if ((i != 0) && (i%35 == 0)) {
      continue;
    }

    if (i >= strSize)
      break;

  	str[n]   = h[((unsigned char)a->data[i]>>4)&0x0f];
  	str[n+1] = h[((unsigned char)a->data[i]   )&0x0f];

  	n += 2;
  }

  return n;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Compare two ASN1_TIMEs */
//------------------------------------------------------------------------------
INT32
ASN1TimeCmp (
  ASN1_TIME *firstTime,
  ASN1_TIME *secondTime
)
{
  char *buff1 = NULL, *buff2 = NULL;
  int i, j, result;

  buff1 = GetBufOfTime(firstTime);
  buff2 = GetBufOfTime(secondTime);

  LOG((EFI_D_ERROR, "%a.%d: %a, %a\n", __FUNCTION__, __LINE__, buff1, buff2));

  if (firstTime->type == V_ASN1_UTCTIME) {
    i = (buff1[0]-'0')*10 + (buff1[1]-'0');
    if (i < 50) i += 100; /* cf. RFC 2459 */
    j = (buff2[0]-'0')*10+(buff2[1]-'0');
    if (j < 50) j += 100;

    if (i < j) {
      result = -1;
      goto _exit;
    }
    if (i > j) {
      result = 1;
      goto _exit;
    }
  }

  i = strcmp(&buff1[0], &buff2[0]);

  if (i == 0) /* wait a second then return younger :-) */
    result = 0;
  else
    result = i;

_exit:
  if (buff1 != NULL)
    FreePool(buff1);
  if (buff2 != NULL)
    FreePool(buff2);

  return result;
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
/*! \brief Get an ASN1 Generalized date in CHAR16 representation */
/*! \param[in] *tm ASN1 time
    \param[out ] **dateStr A pointer to the string with a date */
//------------------------------------------------------------------------------
EFI_STATUS
GetASN1GeneralizedTime(
  IN ASN1_TIME *tm,
  OUT CHAR16 **dateStr
)
{
  CHAR8 *data;

  UINTN gmt = 0;
  UINTN i;
  INT32 y = 0, M = 0, d = 0, h = 0, m = 0, s = 0;
  CHAR8 *f = NULL;
  INT32 f_len = 0;

  CONST UINTN strLen = 255;

  i = tm->length;
  data = (CHAR8 *)tm->data;

  if (i < 12) return EFI_INVALID_PARAMETER;

  if (data[i-1] == 'Z') gmt = 1;

  for (i = 0; i < 12; i++)
    if ((data[i] > '9') || (data[i] < '0'))
      return EFI_INVALID_PARAMETER;

  y = (data[0]-'0')*1000+(data[1]-'0')*100 + (data[2]-'0')*10+(data[3]-'0');
  M = (data[4]-'0')*10+(data[5]-'0');

  if ((M > 12) || (M < 1)) return EFI_INVALID_PARAMETER;

  d = (data[6]-'0')*10+(data[7]-'0');
  h = (data[8]-'0')*10+(data[9]-'0');
  m =  (data[10]-'0')*10+(data[11]-'0');
  if (tm->length >= 14 &&
      (data[12] >= '0') && (data[12] <= '9') &&
      (data[13] >= '0') && (data[13] <= '9')) {
    s =  (data[12]-'0')*10+(data[13]-'0');
    /* Check for fractions of seconds. */
    if (tm->length >= 15 && data[14] == '.') {
      int l = tm->length;
      f = &data[14]; /* The decimal point. */
      f_len = 1;
      while (14 + f_len < l && f[f_len] >= '0' && f[f_len] <= '9')
        ++f_len;
      }
  }

  UnicodeSPrint(*dateStr, strLen * sizeof(CHAR16),
                L"%s %2d %02d:%02d:%02d%.*s %d%s",
                mon[M-1],d,h,m,s,f_len,f,y,(gmt) ? L" GMT":L"");

  LOG((EFI_D_ERROR, "%a.%d dateStr: %d\n", __FUNCTION__, __LINE__, *dateStr));

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get UTC time in a CHAR16 representation form */
//------------------------------------------------------------------------------
EFI_STATUS
GetASN1UtcTime(
  IN ASN1_TIME *tm,
  OUT CHAR16 **dateStr
)
{
  CHAR8 *data;
  UINTN gmt = 0;
  UINTN i;
  INT32 y = 0, M = 0, d = 0, h = 0, m = 0, s = 0;

  CONST UINTN strLen = 255;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  i = tm->length;
  data = (CHAR8 *)tm->data;

  if (i < 10) return EFI_INVALID_PARAMETER;

  if (data[i-1] == 'Z')
    gmt = 1;

  for (i = 0; i < 10; i++)
    if ((data[i] > '9') || (data[i] < '0'))
      return EFI_INVALID_PARAMETER;

  y = (data[0]-'0')*10+(data[1]-'0');

  if (y < 50)
    y += 100;

  M = (data[2]-'0')*10+(data[3]-'0');

  if ((M > 12) || (M < 1))
    return EFI_INVALID_PARAMETER;

  d = (data[4]-'0')*10+(data[5]-'0');
  h = (data[6]-'0')*10+(data[7]-'0');
  m = (data[8]-'0')*10+(data[9]-'0');

  if (tm->length >=12 &&
      (data[10] >= '0') && (data[10] <= '9') &&
      (data[11] >= '0') && (data[11] <= '9'))
    s = (data[10]-'0')*10+(data[11]-'0');

  *dateStr = AllocateZeroPool(strLen * sizeof(CHAR16));
  if (*dateStr == NULL)
    return EFI_OUT_OF_RESOURCES;

  UnicodeSPrint(*dateStr, strLen * sizeof(CHAR16),
                L"%s %2d %02d:%02d:%02d %d%s",
                mon[M-1],d,h,m,s,y+1900,(gmt) ? L" GMT":L"");

  LOG((EFI_D_ERROR, "%a.%d dateStr: %d\n", __FUNCTION__, __LINE__, *dateStr));

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get ASN1 time in CHAR16 representation */
//------------------------------------------------------------------------------
EFI_STATUS
GetASN1Time(
  IN ASN1_TIME *tm,
  OUT CHAR16 **dateStr
)
{
	if(tm->type == V_ASN1_UTCTIME)
    return GetASN1UtcTime(tm, dateStr);
	if(tm->type == V_ASN1_GENERALIZEDTIME)
	  return GetASN1GeneralizedTime(tm, dateStr);

	return EFI_ABORTED;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get an issuer name from a X509 certificate */
//------------------------------------------------------------------------------
OSSL_STATUS
GetIssuerFromX509(
  IN X509 *x509,
  OUT CHAR16 **issuerName
)
{
  OSSL_STATUS Status;
  CHAR8 *charName = NULL;
  UINTN  charNameLen = 0;

  charName = X509_NAME_oneline(X509_get_issuer_name(x509),NULL,0);
  if (charName == NULL)
    return OSSL_ERR_CANT_GET_SUBJECT_NAME;

  LOG((EFI_D_ERROR, "%a.%d charName: %a\n", __FUNCTION__, __LINE__, charName));

  charNameLen = AsciiStrLen(charName);

  *issuerName = AllocateZeroPool(charNameLen*sizeof(CHAR16) + sizeof(CHAR16));
  if (*issuerName == NULL) {
    Status     = OSSL_MEMORY_ERROR;
    goto _exit;
  }

  if (IsMixedStr(charName) == TRUE)
    NormalizeStr(charName);

  ConvertUtf8StrToUnicodeStr(*issuerName, charName, charNameLen);

  Status = OSSL_NO_ERROR;

_exit:

  if (charName != NULL)
    FreePool(charName);

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get subject name from a X509 certificate */
//------------------------------------------------------------------------------
OSSL_STATUS
GetSubjectFromX509(
  IN X509 *x509,
  OUT CHAR16 **subjectName
)
{
  CHAR8 *charName = NULL;
  UINTN  charNameLen = 0;

  OSSL_STATUS Status;

  charName = X509_NAME_oneline(X509_get_subject_name(x509),NULL,0);
  if (charName == NULL)
    return OSSL_ERR_CANT_GET_SUBJECT_NAME;

  LOG((EFI_D_ERROR, "%a.%d charName: %a\n", __FUNCTION__, __LINE__, charName));

  charNameLen = AsciiStrLen(charName);

  *subjectName = AllocateZeroPool(charNameLen*sizeof(CHAR16) + sizeof(CHAR16));
  if (*subjectName == NULL)
    Status = OSSL_MEMORY_ERROR;
  else {
    if (IsMixedStr(charName) == TRUE)
      NormalizeStr(charName);
    ConvertUtf8StrToUnicodeStr(*subjectName, charName, charNameLen);

    Status = OSSL_NO_ERROR;
  }

  if (charName != NULL)
    FreePool(charName);

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get serial number from a X509 certificate */
//------------------------------------------------------------------------------
OSSL_STATUS
GetSerialFromX509(
  IN X509 *x509,
  OUT CHAR16 **serialStr16
)
{
  CHAR8 serialStr8[255];

  ZeroMem(&serialStr8[0], sizeof(serialStr8));

  if (i2char8_ASN1_INTEGER(serialStr8, sizeof(serialStr8), X509_get_serialNumber(x509)) == 0)
    return OSSL_ERR_CANT_GET_SERIAL;

  LOG((EFI_D_ERROR, "%a.%d serialNum: %a\n", __FUNCTION__, __LINE__, serialStr8));

  *serialStr16 = AllocateZeroPool(AsciiStrLen(serialStr8)*sizeof(CHAR16) + sizeof(CHAR16));
  if (*serialStr16 == NULL)
    return OSSL_MEMORY_ERROR;

  AsciiStrToUnicodeStr(serialStr8, *serialStr16);

  LOG((EFI_D_ERROR, "%a.%d serialNum: %s\n", __FUNCTION__, __LINE__, *serialStr16));

  return OSSL_NO_ERROR;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get PKCS7 struct of a trusted chain from binary data */
/*! Only DER format is supported */
/*! \param[in] *chainData A chain binary
    \param[in] chainDataLen A length of the binary
    \param[out] *Status A status of operations */
//------------------------------------------------------------------------------
PKCS7*
GetChainFromBinary (
  IN CHAR8 *chainData,
  IN UINTN chainDataLen,
  OUT OSSL_STATUS *Status
  )
{
  PKCS7 *Pkcs7 = NULL;

  // Retrieve PKCS#7 Data (DER encoding)
  Pkcs7 = d2i_PKCS7 (NULL, &chainData, (int)chainDataLen);
  if (Pkcs7 == NULL) {
    *Status  = OSSL_UNKNOWN_PKCS7_FORMAT;
    return NULL;
  } else {
    *Status = OSSL_SUCCESS_CONVERT_TO_ASN;
    return Pkcs7;
  }
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get X509 struct of a certificate from binary data */
/*! Only DER format is supported. I have to free X509 structure at the end.*/
/*! \param[in] *certData Certificate's binary data
    \param[in] certDataLen Certificate's binary data length
    \param[out] Status Error code */
/*! \retval OSSL_INVALID_PARAM NULL data has been passedto the function
    \retval OSSL_MEMORY_ERROR Allocate memmory error
    \retval OSSL_UNKNOWN_CERT_FORMAT Unknown format
    \retval OSSL_SUCCESS_CONVERT_TO_ASN Success */
/*! \return A pointer to the X509 structure of the certificate */
//------------------------------------------------------------------------------
X509*
GetCertificateFromBinary (
  IN CHAR8 *certData,
  IN UINTN certDataLen,
  OUT OSSL_STATUS *Status
  )
{
  BIO *Cert;
  X509 *x509 = NULL;

  // Lazy initializing of OpenSSL
  InitializeOpenSSL();

  if (certData == NULL || certDataLen == 0) {
    *Status = OSSL_INVALID_PARAM;
    return NULL;
  }

  Cert = BIO_new_mem_buf(certData, (int)certDataLen);
  if (Cert == NULL) {
    *Status = OSSL_MEMORY_ERROR;
    return NULL;
  }

  x509 = d2i_X509_bio(Cert, NULL);
  BIO_free(Cert);
  if (x509 == NULL) {
    *Status = OSSL_UNKNOWN_CERT_FORMAT;
    return NULL;
  } else {
    *Status = OSSL_SUCCESS_CONVERT_TO_ASN;
    return x509;
  }
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get X509 struct of a CRL from binary data */
/*! Only DER format is supported. I have to free X509 structure at the end.*/
/*! \param[in] *crlData CRL's binary data
    \param[in] crlDataLen CRL's binary data length
    \param[out] Status Error code */
/*! \retval OSSL_INVALID_PARAM NULL data has been passedto the function
    \retval OSSL_MEMORY_ERROR Allocate memmory error
    \retval OSSL_UNKNOWN_CRL_FORMAT Unknown format
    \retval OSSL_SUCCESS_CONVERT_TO_ASN Success */
/*! \return A pointer to the X509 structure of the CRL */
//------------------------------------------------------------------------------
X509_CRL*
GetCRLFromBinary (
  IN CHAR8 *crlData,
  IN UINTN crlDataLen,
  OUT OSSL_STATUS *Status
  )
{
  BIO *Crl;
  X509_CRL *x509_crl = NULL;

  if (crlData == NULL || crlDataLen == 0) {
    *Status = OSSL_INVALID_PARAM;
    return NULL;
  }

  Crl = BIO_new_mem_buf(crlData, (int)crlDataLen);
  if (Crl == NULL) {
    *Status = OSSL_MEMORY_ERROR;
    return NULL;
  }

  x509_crl = d2i_X509_CRL_bio(Crl,NULL);
  BIO_free(Crl);
  if (x509_crl == NULL) {
    *Status = OSSL_UNKNOWN_CRL_FORMAT;
    return NULL;
  } else {
    *Status = OSSL_SUCCESS_CONVERT_TO_ASN;
    return x509_crl;
  }
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Check certificate time */
/* \param[in] *certToCheck Certificate to check
   \param[in] *ptime A time to compare with */
//------------------------------------------------------------------------------
INT32
CheckCertTime (
  IN X509 *certToCheck,
  IN time_t *ptime
)
{
  INT32 i;

  i = X509_cmp_time(X509_get_notBefore(certToCheck), ptime);
  if (i == 0)
    return X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD;
  if (i > 0)
    return X509_V_ERR_CERT_NOT_YET_VALID;

  i = X509_cmp_time(X509_get_notAfter(certToCheck), ptime);
  if (i == 0)
    return X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD;
  if (i < 0)
    return X509_V_ERR_CERT_HAS_EXPIRED;

  return X509_V_OK;  
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Check crl time */
/* \param[in] *crlToCheck CRL to check
   \param[in] *ptime A time to compare with */
//------------------------------------------------------------------------------
INT32
CheckCRLTime (
  IN X509_CRL *crlToCheck,
  IN time_t *ptime
)
{
  INT32 i;

  i = X509_cmp_time(X509_CRL_get_lastUpdate(crlToCheck), ptime);
  if (i == 0)
    return X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD;
  if (i > 0)
    return X509_V_ERR_CRL_NOT_YET_VALID;

  if (X509_CRL_get_nextUpdate(crlToCheck)) {
    i = X509_cmp_time(X509_CRL_get_nextUpdate(crlToCheck), ptime);
    if (i == 0)
      return X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD;
    if (i < 0)
      return X509_V_ERR_CRL_HAS_EXPIRED;
  }

  return X509_V_OK;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Put a message to BIOS LOG subsystem */
//------------------------------------------------------------------------------
VOID
LogOpensslMessage (
  IN UINTN logLevel,
  IN const CHAR8 *format,
  ...
)

{
  VA_LIST args;
  CHAR8   buffer[MAX_DEBUG_MESSAGE_LENGTH];

  EFI_STATUS status = EFI_ABORTED;

  VA_START (args, format);

  AsciiVSPrint (buffer, sizeof (buffer), format, args);

  VA_END(args);

  status = gBS->LocateProtocol (&gBiosLogProtocolGuid, NULL, (VOID **) &pBiosLogProtocol);
  if (EFI_ERROR(status))
    return;

  pBiosLogProtocol->PutError("Openssl", buffer);

  return;
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
/*! \brief Initialize OpenSSL */
/*! We don't do it in the library's constructor, because we don't want do it
    automatically. Library is initializing only once. */
//------------------------------------------------------------------------------
EFI_STATUS
InitializeOpenSSL (
  VOID
  )
{
  char *cp = NULL;
  BIO  *bp = NULL;

  if (openssslConfigured == FALSE) {
    cp = GetOpensslConfigFromFV();
    if (cp != NULL) {
      bp = BIO_new_mem_buf(cp,(int)(strlen(cp) + 1));
      OPENSSL_config_mem(NULL, bp);
      BIO_free(bp);
    }
    SSL_library_init();
    /* FIXME: mod_ssl does this */
    X509V3_add_standard_extensions();

    openssslConfigured = TRUE;
  }

  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

