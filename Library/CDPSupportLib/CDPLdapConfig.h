/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef CDP_LDAP_CONFIG_H_
#define CDP_LDAP_CONFIG_H_

#include <Protocol/GlobalConfigType.h>
#include <TlsConfigStruct.h>

#define MAX_PORT_NUM_SIZE     5  //!< Length of string, contains a port value

#define STRING_ADDR_LEN      15  //!< Length of a string of ip address

#define VAR_VERSION           1 //!< A version of a CDP LDAP config variable

#define MIN_PORT           1024  //!< Min number of a port, allow to use
#define MAX_PORT          65535  //!< Max number of a port, allow to use

#define CDP_LDAP_CONFIG_VAR_NAME L"CDPLdapConfig" //!< Name of gRT variable for the CDP ldap config

/** CDP Ldap client config */
typedef struct T_CDP_LDAP_CONFIG {
  CHAR16 version;                       //!< version of the variable
  CHAR16 address[STRING_ADDR_LEN + 1];  //!< Ldap server IP address
  CHAR16 port;                          //!< Ldap server port
  UINTN  suffixLen;                     //!< Length in bytes of a suffix
  CHAR16 *pSuffix[1];                   //!< Suffix (e.x. dc=company,dc=ru)
  UINTN  rootdnLen;                     //!< Length in bytes of a rootdn
  CHAR16 *pRootdn[1];                   //!< Rootdn (e.x. admin)
  UINTN  rootpwLen;                     //!< Length in bytes of a rootpw
  CHAR16 *pRootpw[1];                   //!< Rootpw
  UINTN  nameLen;                       //!< Length of a ldap server name
  CHAR16 *pName[1];                     //!< Ldap server name (e.x. ldap.company.ru)
} CDP_LDAP_CONFIG;

EFI_STATUS
ReadCDPLdapConfig(
  VOID
);

EFI_STATUS
SaveCDPLdapConfig(
  VOID
);

VOID
DeleteCDPLdapConfig(
  VOID
);

const CHAR16*
GetCDPLdapServerAddr(
  VOID
);

UINTN
GetSizeOfCDPLdapServerAddr(
  VOID
);

CHAR16
GetCDPLdapServerPort(
  VOID
);

const CHAR16*
GetCDPLdapRootdn(
  VOID
);

UINTN
GetSizeOfCDPLdapRootdn( 
  VOID
);

const CHAR16*
GetCDPLdapRootpw( 
  VOID
);

UINTN
GetSizeOfCDPLdapRootpw( 
  VOID
);

const CHAR16*
GetCDPLdapServerName(
  VOID
);

UINTN
GetSizeOfCDPLdapServerName(
  VOID
);

EFI_STATUS
SetCDPLdapPort(
  IN UINTN portNum
);

EFI_STATUS
SetCDPLdapRootdn(
  IN CHAR16 *rootdn
);

EFI_STATUS
SetCDPLdapRootpw(
  IN CHAR16 *rootpw
);

EFI_STATUS
SetCDPLdapServerName(
  IN CHAR16 *name
);

EFI_STATUS
SetCDPLdapServerAddr(
 IN CHAR16 *ipAddr
);

CONFIG_ERROR_T
SetCDPLdapConfigFromINIFile(
  CHAR8 *filePath
);

VOID
ResetCDPLdapConfig (
  VOID
  );


#endif // CDP_LDAP_CONFIG_H_
