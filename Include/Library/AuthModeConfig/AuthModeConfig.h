/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef AUTH_MODE_CONFIG_H_
#define AUTH_MODE_CONFIG_H_

#include <Uefi/UefiBaseType.h>
#include <Protocol/GlobalConfigType.h>

#define AUTH_MODE_CONFIG_VAR_NAME L"AuthModeConfig" //!< Name of gRT variable for the auth mode config

/** \name Modes of the auth */
#define DEFAULT_AUTH_MODE   0  //!< Default mode - with an using a pin code for a token
#define GUEST_AUTH_MODE     1  //!< Guest mode - without using a pin code for a token. Only a public data is acceptable.

#define DONT_USE_SETTING 0  //!< Don't use
#define USE_SETTING      1  //!< Use ldap

/** \name Local usage status */
//#define DONT_USE_LOCAL_GUEST 0  //!< Don't use local to auth a guest user
//#define USE_LOCAL_GUEST      1  //!< Use local to auth a guest user

/** \name Type of a comparison */
#define CN_CMP       0x01    //!< Subject CN field for a local guest, CN for a ldap guest
#define OU_CMP       0x02    //!< Subject OU field for a local guest, OU for a ldap guest
#define SUBJECT_CMP  0x04    //!< Subject field for a local guest, Subject for a ldap guest (but for a ldap user usualy not specified)

CONFIG_ERROR_T
SetAuthConfigFromINIFile (
  CHAR8 *filePath
  );

CONFIG_ERROR_T
SetAuthConfigFromData (
  UINT8 *configData,
  UINTN dataLen
  );

EFI_STATUS
SaveAuthModeConfig (
  VOID
  );

EFI_STATUS
ReadAuthModeConfig (
  VOID
  );

VOID
DeleteAuthModeConfig (
  VOID
  );

UINT8
GetAuthMode (
  VOID
  );

UINT8
GetTypeOfComparison (
  VOID
  );

const CHAR16*
GetCmpDataByType (
  IN UINT8 cmpType
  );

const CHAR16*
GetComparisonDataAsStr (
  VOID
  );

EFI_STATUS
SetAuthMode (
  UINT8 newAuthMode
  );

EFI_STATUS
SetLdapUsageStatus (
  IN UINT8 ldapUsageStatus
  );

EFI_STATUS
SetLocalUsageStatus (
  IN UINT8 localUsageStatus
  );

EFI_STATUS
SetUserPCLinkCheckStatus (
  IN UINT8 flag
  );

EFI_STATUS
SetTypeOfComparison (
  UINT8 type
  );

EFI_STATUS
ClearTypeOfComparison (
  UINT8 type
  );

BOOLEAN
IsTypeOfComparison ( 
  IN UINT8 type
  );

EFI_STATUS
SetCmpDataByType (
  IN UINT8 cmpType,
  IN const CHAR16 *newData
  );

BOOLEAN
IsUseLdapGuestLogin (
  VOID
  );

BOOLEAN
IsUseLocalGuestLogin (
  VOID
  );

BOOLEAN
IsUserPCLinkCheck (
  VOID
  );

EFI_STATUS
CleanCmpData (
  UINT8 mask
  );

VOID
ResetAuthModeConfig (
  VOID
  );


#endif // AUTH_MODE_CONFIG_H_
