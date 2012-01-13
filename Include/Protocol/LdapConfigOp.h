/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef LDAP_CLIENT_CONFIG_OP_H_
#define LDAP_CLIENT_CONFIG_OP_H_

#include <Uefi/UefiBaseType.h>
#include <TlsConfigStruct.h>
#include <Protocol/GlobalConfigType.h>

#define STRING_ADDR_LEN           15  //!< Length of a string of ip address
#define MAX_PORT_NUM_SIZE          5  //!< Length of string, contains a port value

#define MIN_PORT                1024  //!< Min number of a port, allow to use
#define MAX_PORT               65535  //!< Max number of a port, allow to use

#define NOT_USE_LDAP_AUTH          0  //!< Don't use a ldap auth when login
#define USE_LDAP_AUTH              1  //!< Use a ldap auth when login

typedef
CHAR16
(EFIAPI *GET_LDAP_SERVER_PORT) (
  VOID
  );

typedef
const CHAR16*
(EFIAPI *GET_LDAP_SERVER_ADDR) (
  VOID
  );

typedef
const CHAR16*
(EFIAPI *GET_LDAP_SERVER_NAME) (
  VOID
  );

typedef
const CHAR16*
(EFIAPI *GET_LDAP_SUFFIX) (
  VOID
  );
  
typedef
const CHAR16*
(EFIAPI *GET_LDAP_ROOTDN) (
  VOID
  );
  
typedef
const CHAR16*
(EFIAPI *GET_LDAP_ROOTPW) (
  VOID
  );

typedef
const CHAR16*
(EFIAPI *GET_LDAP_PCBASE) (
  VOID
  );
  
typedef
UINTN
(EFIAPI *GET_SIZE_OF_LDAP_SERVER_ADDR) (
  VOID
  );
  
typedef
UINTN
(EFIAPI *GET_SIZE_OF_LDAP_SERVER_NAME) (
  VOID
  );
  
typedef
UINTN
(EFIAPI *GET_SIZE_OF_LDAP_SUFFIX) (
  VOID
  );
  
typedef
UINTN
(EFIAPI *GET_SIZE_OF_LDAP_ROOTDN) (
  VOID
  );
  
typedef
UINTN
(EFIAPI *GET_SIZE_OF_LDAP_ROOTPW) (
  VOID
  );

typedef
UINTN
(EFIAPI *GET_SIZE_OF_LDAP_PCBASE) (
  VOID
  );
  
typedef
EFI_STATUS
(EFIAPI *SET_LDAP_SERVER_ADDR) (
  CHAR16 *ipAddr
  );
  
typedef
EFI_STATUS
(EFIAPI *SET_LDAP_SERVER_NAME) (
  CHAR16 *servName
  );
  
typedef
EFI_STATUS
(EFIAPI *SET_LDAP_PORT) (
  UINTN portNum
  );
  
typedef
EFI_STATUS
(EFIAPI *SET_LDAP_SUFFIX) (
  CHAR16 *searchBase
  );
  
typedef
EFI_STATUS
(EFIAPI *SET_LDAP_ROOTDN) (
  CHAR16 *rootDN
  );
  
typedef
EFI_STATUS
(EFIAPI *SET_LDAP_ROOTPW) (
  CHAR16 *rootPW
  );

typedef
EFI_STATUS
(EFIAPI *SET_LDAP_PCBASE) (
  CHAR16 *pcBase
  );

typedef
EFI_STATUS
(EFIAPI *SAVE_LDAP_CONFIG) (
  VOID
  );
  
typedef
EFI_STATUS
(EFIAPI *READ_LDAP_CONFIG) (
  VOID
  );
  
typedef
VOID
(EFIAPI *DELETE_LDAP_CONFIG) (
  VOID
  );
  
typedef
CHAR16
(EFIAPI *GET_LDAP_AUTH_USAGE_STATUS) (
  VOID
  );
  
typedef
EFI_STATUS
(EFIAPI *SET_LDAP_AUTH_USAGE_STATUS) (
  CHAR16 usageSetting
  );
  
typedef
void
(EFIAPI *SET_TLS_USAGE) (
  BOOLEAN isUseTLS
  );
  
typedef
BOOLEAN
(EFIAPI *IS_USE_TLS) (
  VOID
  );
  
typedef
EFI_STATUS
(EFIAPI *SET_OPENSSL_CNF) (
  tlsConfig_t config
  );

typedef
CONFIG_ERROR_T
(EFIAPI *SET_CNF) (
  CHAR8 *filePath
  );

typedef
CONFIG_ERROR_T
(EFIAPI *SET_CNF_DAT) (
  UINT8 *configData,
  UINTN dataLen
  );

/*! Operations to control ldap client parameters */
struct _LDAP_CONFIG_OP {
/*! Operations to get ldap config parameters */
  GET_LDAP_SERVER_PORT GetLdapServerPort;                   //!< Get a ldap port value.
  GET_LDAP_SERVER_ADDR GetLdapServerAddr;                   //!< Read ldap server address.
  GET_LDAP_SERVER_NAME GetLdapServerName;                   //!< Get ldap server name.
  GET_LDAP_SUFFIX      GetLdapSuffix;                       //!< Get suffix (base).
  GET_LDAP_ROOTDN      GetLdapRootdn;                       //!< Get rootdn.
  GET_LDAP_ROOTPW      GetLdapRootpw;                       //!< Get rootpw.
  GET_LDAP_PCBASE      GetLdapPCBase;                       //!< Get pcBase

  GET_SIZE_OF_LDAP_SERVER_ADDR GetSizeOfLdapServerAddr;     //!< Get a length of a string, contains the ldap server IP address.
  GET_SIZE_OF_LDAP_SERVER_NAME GetSizeOfLdapServerName;     //!< Get a length in bytes of a string, contains ldap server name.
  GET_SIZE_OF_LDAP_SUFFIX      GetSizeOfLdapSuffix;         //!< Get a length in bytes of a string, contains suffix.
  GET_SIZE_OF_LDAP_ROOTDN      GetSizeOfLdapRootdn;         //!< Get a length in bytes of a string, contains ldap rootdn.
  GET_SIZE_OF_LDAP_ROOTPW      GetSizeOfLdapRootpw;         //!< Get a length in bytes of a string, contains ldap rootpw.
  GET_SIZE_OF_LDAP_PCBASE      GetSizeOfLdapPCBase;

/*! Operations to set ldap config parameters */
  SET_LDAP_SERVER_ADDR SetLdapServerAddr;                   //!< Set a new ldap server IP address.
  SET_LDAP_SERVER_NAME SetLdapServerName;                   //!< Set a new value of the ldap server name.
  SET_LDAP_PORT        SetLdapPort;                         //!< Set a ldap port.
  SET_LDAP_SUFFIX      SetLdapSuffix;                       //!< Set a new value of the suffix.
  SET_LDAP_ROOTDN      SetLdapRootdn;                       //!< Set a new value of the rootdn.
  SET_LDAP_ROOTPW      SetLdapRootpw;                       //!< Set a new value of the rootpw.
  SET_LDAP_PCBASE      SetLdapPCBase;
  
  READ_LDAP_CONFIG     ReadLdapConfig;                      //!< Read Ldap config to init internal private data.
  SAVE_LDAP_CONFIG     SaveLdapConfig;                      //!< Save Ldap client config to the gRT.
  
  DELETE_LDAP_CONFIG   DeleteLdapConfig;                    //!< Erase buffers of a ldap server config data.
  
  GET_LDAP_AUTH_USAGE_STATUS GetLdapAuthUsageStatus;
  SET_LDAP_AUTH_USAGE_STATUS SetLdapAuthUsageStatus;
  
/*! Opeations to set TLS settings */
  IS_USE_TLS      IsUseTLS;                                 //!< Check use TLS to connect to a ldap server or not
  SET_TLS_USAGE   SetTLSUsage;                              //!< Set a TLS usage setting
  
  SET_OPENSSL_CNF  SetOpensslConfig;                        //!< Set a config of OpenSSL to use to setup TLS connection

  SET_CNF     SetConfigFromINI;                             //!< Set a Ldap config from INI file
  SET_CNF_DAT SetConfigFromData;                            //!< Set a Ldap config from data
  
  };
  
typedef struct _LDAP_CONFIG_OP LDAP_CONFIG_OP;
  
VOID
InitLdapConfigOp (
  LDAP_CONFIG_OP *This
  );

#endif // LDAP_CLIENT_CONFIG_OP_H_
