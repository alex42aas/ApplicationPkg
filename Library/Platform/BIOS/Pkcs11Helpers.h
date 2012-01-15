/** @file
  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php
  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/

#ifndef __PKCS11__HELPERS__H

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/UefiLib.h>
#include <Library/PrintLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>

#include <Library/CommonUtils.h>
#include <Library/Lib/ComparisonDataHelper.h>
#include <Library/Lib/OpensslFunctions.h>
#include <Library/Pkcs11Lib.h>
#include <Library/Messages.h>
#include <Library/ExtHdrUtils.h>
#include <InternalErrDesc.h>
#include <Library/Lib/CertificatesControl.h>
#include <Library/Lib/Users.h>



#define ARRAY_ITEMS(Array_) (sizeof (Array_) / sizeof (*Array_))


CK_RV 
GetSubjectUid (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR  pUid
  );

CK_RV 
GetSubjectEmail (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR  pEmail
  );

CK_RV 
GetSubjectTitle (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR pTitle
  );

CK_RV 
GetSubjectCommonName (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE  hCert,
  IN OUT CK_ATTRIBUTE_PTR  pCN
  );

CK_RV 
GetCertificateDigest (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE hCert,
  IN CK_OBJECT_HANDLE hCACert,
  IN OUT CK_BYTE_PTR pDigest,
  IN CK_ULONG_PTR pulDigestLen
  );

EFI_STATUS
GetCertificateData (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE hCert,
  IN OUT UINT8 **Cdata,
  IN OUT UINTN *CdataLen
  );

CK_RV 
Verify (
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE  hCert    /* Certificate to verify */
  );

CK_RV 
GetCertificateDigest2 (
  IN CK_SESSION_HANDLE hSession,
  IN CK_OBJECT_HANDLE hCert,
  IN CK_OBJECT_HANDLE hCACert,
  IN OUT CK_BYTE_PTR pDigest,
  IN CK_ULONG_PTR pulDigestLen
  );


EFI_STATUS
CheckForCertExpire (
  CK_SESSION_HANDLE hSession,
  CK_OBJECT_HANDLE hCert
  );

VOID
Pkcs11_DestroySession (
  VOID
  );  

EFI_STATUS
Pkcs11_CreateSessionAndLogin (
  VOID
  );

EFI_STATUS
Pkcs11_CreateClientCertObjFromData (
  IN UINT8 *CertData,
  IN UINTN CertDataLen,
  IN OUT CK_OBJECT_HANDLE *hCert
  );

EFI_STATUS
Pkcs11_ComparisonDataByCertData (
  IN VOID *pCertData,
  IN UINTN CertDataLen,
  IN OUT UINT8 **Data,
  IN OUT UINTN *DataLen
  );

UINTN
GetCalcDataDigest_MdType(
  VOID
  );

CK_SESSION_HANDLE
Pkcs11_GetCurrentSessionHandler (
  VOID
  );

VOID
Pkcs11_FindObjectsFinish (
  IN CK_SESSION_HANDLE    hSession
  );


#endif /* #ifndef __PKCS11__HELPERS__H */

