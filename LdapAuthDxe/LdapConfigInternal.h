/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef LDAP_CLIENT_CONFIG_INTERNAL_H_
#define LDAP_CLIENT_CONFIG_INTERNAL_H_

#include <Protocol/LdapConfigOp.h>
#include <Protocol/GlobalConfigType.h>

#define VAR_VERSION  1 //!< A version of a ldap variable

#define LDAP_CLIENT_CONFIG_VAR_NAME L"LdapClientConfig" //!< Name of gRT variable for the ldap client config

#define LDAP_USAGE_MASK 0x01  //!< A mask to get a first bit of an usage flag variable
#define TLS_USAGE_MASK  0x02  //!< A mask to get a second bit of an usage flag variable

#define USE_TLS         0x02  //!< Second bit - use tls to connect to a ldap server

#pragma pack(push, 1)
/** Ldap client config */
typedef struct T_LDAP_CLIENT_CONFIG {
  CHAR16 version;                       //!< version of the variable
  CHAR16 usageFlag;                     //!< Flag of a usage of a ldap auth
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
  UINTN  pcBaseLen;                     //!< Length of a PC search base
  CHAR16 *pcBase[1];                    //!< PC search base
} LDAP_CLIENT_CONFIG;
#pragma pack(pop)

LDAP_CLIENT_CONFIG*
ReadLdapClientConfig( 
  VOID 
  );
  
EFI_STATUS 
WriteLdapClientConfig(
  const LDAP_CLIENT_CONFIG *ldapConfig
);

VOID DeleteLdapConfig( VOID );

      CHAR16  GetLdapServerPort( VOID );
const CHAR16* GetLdapServerAddr( VOID );
const CHAR16* GetLdapServerName( VOID );
const CHAR16* GetLdapSuffix( VOID );
const CHAR16* GetLdapRootdn( VOID );
const CHAR16* GetLdapRootpw( VOID );
const CHAR16* GetLdapPCBase( VOID );
      CHAR16  GetLdapAuthUsageStatus ( VOID );

BOOLEAN IsUseTLS( VOID );

UINTN GetSizeOfLdapServerAddr( VOID );
UINTN GetSizeOfLdapServerName( VOID );
UINTN GetSizeOfLdapSuffix( VOID );
UINTN GetSizeOfLdapRootdn( VOID );
UINTN GetSizeOfLdapRootpw( VOID );
UINTN GetSizeOfPCBase( VOID );

BOOLEAN    IsValidPort( UINTN portNum );

EFI_STATUS SetLdapServerAddr( CHAR16 *ipAddr );
EFI_STATUS SetLdapPort( UINTN portNum );
EFI_STATUS SetLdapServerName( CHAR16 *name );
EFI_STATUS SetLdapSuffix( CHAR16 *rootdn );
EFI_STATUS SetLdapRootdn( CHAR16 *suffix );
EFI_STATUS SetLdapRootpw( CHAR16 *rootpw );
EFI_STATUS SetLdapPCBase( CHAR16 *pcBase );

EFI_STATUS SetLdapAuthUsageStatus ( CHAR16 usageSetting );
void       SetTLSUsage ( BOOLEAN isUseTLS );

EFI_STATUS SaveLdapConfig( VOID );
EFI_STATUS ReadLdapConfig( VOID );

CONFIG_ERROR_T SetConfigFromINIFile( CHAR8 *filePath);
CONFIG_ERROR_T SetConfigFromData( UINT8 *configData, UINTN dataLen);

EFI_STATUS RegisterSelfInGlobalConfig( VOID );
#endif //LDAP_CLIENT_CONFIG_INTERNAL_H_