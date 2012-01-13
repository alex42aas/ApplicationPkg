/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __PKCS_11_LIB__
#define __PKCS_11_LIB__

#include <Base.h>

#include "cryptoki.h"

/* The purpose of the following three definitions is to indicate the particular
   type of the string CommonName/E-Mail fields of a certificate are encoded with
   (see functions C_AuxGetSubjectCommonName and C_AuxGetSubjectEmail; the type
   is passed in the 'type' field of the CK_ATTRIBUTE structure)
*/
#define CKA_CHAR_STRING 0
#define CKA_UTF8_STRING 1
#define CKA_BMP_STRING  2

#define ASN1_PKCS15_APP_PATH_DEFAULT_VALUE { 0x3F, 0x00, 0x50, 0x00 }
#define ASN1_PKCS15_TI_NAME_DEFAULT_VALUE  { 0x50, 0x32 }

#define PKCS15_MF_PATH_DEFAULT_VALUE  { 0x3F, 0x00 }
#define PKCS15_DIR_PATH_DEFAULT_VALUE { 0x3F, 0x00, 0x2F, 0x00 }
#define PKCS15_APP_PATH_DEFAULT_VALUE { 0x3F, 0x00, 0x50, 0x00 }
#define PKCS15_ODF_NAME_DEFAULT_VALUE { 0x50, 0x31 }

#define PKCS15_RAPI_DEFAULT_VALUE { \
  0xA0, 0x00, 0x00, 0x00, 0x63, 'P', 'K', 'C', 'S', '-', '1', '5' \
}

#define PKCS15_MODEL_NAME_DEFAULT_VALUE { 'P', 'K', 'C', 'S', '#', '1', '5' }

extern CK_RV AllocMem (CK_VOID_PTR *P, CK_ULONG L);
extern CK_RV FreeMem (CK_VOID_PTR P);

/* Auxiliary functions for getting particular certificate fields */

extern CK_RV C_AuxGetIssuerCommonName (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE hCert,
               CK_ATTRIBUTE *CN
               );
extern CK_RV C_AuxGetIssuerEmail (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE hCert,
               CK_ATTRIBUTE *Email
               );
extern CK_RV C_AuxGetIssuerOrganizationName (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ATTRIBUTE_PTR  pOrganizationName
               );
extern CK_RV C_AuxGetIssuerOrganizationUnitName (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ATTRIBUTE_PTR  pOrganizationUnitName
               );
extern CK_RV C_AuxGetIssuerLocalityName (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ATTRIBUTE_PTR  pLocalityName
               );
extern CK_RV C_AuxGetIssuerStateOrProvinceName (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ATTRIBUTE_PTR  StateOrProvinceName
               );               
extern CK_RV C_AuxGetSubjectCommonName (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE hCert,
               CK_ATTRIBUTE *CN
               );
extern CK_RV C_AuxGetSubjectUid (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ATTRIBUTE_PTR  pUid
               );
extern CK_RV C_AuxGetSubjectTitle (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ATTRIBUTE_PTR  pTitle
               );
extern CK_RV C_AuxGetBasicConstraints (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ATTRIBUTE_PTR  pBasicConstr
               );
extern CK_RV C_AuxGetSubjectEmail (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE hCert,
               CK_ATTRIBUTE *Email
               );
extern CK_RV C_AuxGetSubjectOrganizationName (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ATTRIBUTE_PTR  pOrganizationName
               );
extern CK_RV C_AuxGetSubjectOrganizationUnitName (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ATTRIBUTE_PTR  pOrganizationUnitName
               );
extern CK_RV C_AuxGetSubjectLocalityName (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ATTRIBUTE_PTR  pLocalityName
               );
extern CK_RV C_AuxGetSubjectStateOrProvinceName (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE  hCert,
               CK_ATTRIBUTE_PTR  StateOrProvinceName
               );
extern CK_RV C_AuxGetSignatureAlgorithm (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE hCert,
               CK_MECHANISM_TYPE *M
               );
extern CK_RV C_AuxGetSignatureAlgorithmParamSet (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE hCert,
               CK_ATTRIBUTE *PS
               );

extern CK_RV C_AuxGetCertContent (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE hCert,
               CK_ATTRIBUTE *SV
               );

extern CK_RV C_AuxGetSignatureValue (
               CK_SESSION_HANDLE hSession,
               CK_OBJECT_HANDLE hCert,
               CK_ATTRIBUTE *SV
               );

/* Something needed for debugging stuff */

#include <Library/DebugLib.h>

#include <SomeCompilerFixes.h>
/* Debugging helper function */
static inline void emit (CHAR16 const *s) { DEBUG ((EFI_D_ERROR, "%s\n", s)); }

CK_RV
Pkcs11_GetSlotSession (
  CK_SLOT_ID            slotID,
  CK_SESSION_HANDLE_PTR phSession
  );


/* This is a testing part for debug purposes */

#define INCLUDE_TESTING

#ifdef INCLUDE_TESTING

struct _ASN1_TYPE_VAL;

CK_RV ShowASN1Tree(struct _ASN1_TYPE_VAL const *V);
CK_RV ShowASN1TreeByHandle(CK_SESSION_HANDLE hSession, CK_SESSION_HANDLE hObject);

extern int test_all(void);

#endif /* INCLUDE_TESTING */

#endif /* __PKCS_11_LIB__ */
