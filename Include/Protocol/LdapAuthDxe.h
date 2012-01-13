/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef LDAP_AUTH_DXE
#define LDAP_AUTH_DXE

#include "Protocol/LdapConfigOp.h"
#include <Library/UserManagerLib.h>

typedef struct {
  CHAR8 *userDN;                      //!< User DN in LDAP
  CHAR8 *userName;                    //!< User name. Attribute is not spceified there.
  CHAR8 *certData;                    //!< User certificate binary
  UINTN certDataLen;                  //!< A length of the binary
  USER_AUTH_PERMISSION permission;    //!< user permission
} LDAP_AUTH_TOKEN_USER_INFO;

typedef struct {
  UINTN userCount;
  LDAP_AUTH_TOKEN_USER_INFO *ldapAuthUserList;
} LDAP_USER_AUTH_DB;

/** \name Error codes of the ldap auth protocol */
#define LDAP_AUTH_PASS             0  //!< Auth is successful
#define CANT_CONNECT_TO_LDAP       1  //!< Can't connect to the ldap server
#define CANT_PROC_LDAP_OPT         2  //!< Bad ldap client options
#define CANT_INIT_LDAP_SESSION     3  //!< Can't init ldap session (internal error)
#define CANT_MAKE_REQUEST          4  //!< Can't make a search request
#define LDAP_OUT_OF_MEMORY         5  //!< Out of recources
#define LDAP_AUTH_FAIL             6  //!< Fail to auth the user
#define LDAP_SEARCH_ERROR          7  //!< Can't find user given name
#define LDAP_SEARCH_SUCCESS        8  //!< User has been found
#define LDAP_INTERNAL_ERROR        9  //!< Internal error of ldap client tool. See debug output for more details
#define LDAP_ROOT_ERR_CREDENTIALS 10  //!< Invalid rootdn or rootpw. rootdn auth fail.
#define LDAP_SERVER_DENY          11  //!< Ldap server unwilling to perform action
#define LDAP_TOO_MANY_ENTRIES     12  //!< We have to get one entry (user). But we received more.
#define LDAP_TLS_CACERTFILE_EMPTY 13  //!< Can't find TLS_CACERTFILE
#define LDAP_TLS_CACERTFILE_FAIL  14  //!< Error to save TLS_CACERTFILE to OpenLdap storage
#define LDAP_ERROR_TO_START_TLS   15  //!< Error to start TLS while making connection setup
#define LDAP_ERROR_TO_GET_PERMIT  16  //!< Error to get user permissions
#define LDAP_CANT_GET_SYSTEM_GUID 17  //!< Can't get system GUID
#define LDAP_INVALID_PARAMETER    18  //!< Invalid parameter has been passed to LDAP subsystem

typedef struct _LDAP_AUTH_PROTOCOL LDAP_AUTH_PROTOCOL;

typedef struct {
  UINTN dataLen;
  CHAR8 *data;
} UserCertificateData_t;

typedef
CHAR8*
(EFIAPI *LDAP_AUTH_GET_USER_DN) (
  IN  CHAR16* userName, 
  OUT UINTN* status
  );

typedef
UINTN
(EFIAPI *LDAP_AUTH_CHK_DN_PWD) (
  IN  CHAR8* userDN,
  IN  CHAR8* password
  );

typedef
CHAR8*
(EFIAPI *LDAP_AUTH_SEARCH_USER_CER)(
  IN  CHAR8*  matchedCertificateValue,
  OUT CHAR8** accountName,
  OUT UINTN*  numberOfCertificates,
  OUT UINTN*  retval
  );
  
typedef
VOID
(EFIAPI *LDAP_AUTH_GET_USER_CER) (
  IN  UINTN numberOfCertificate,
  OUT UserCertificateData_t* caData
  );
  
typedef
VOID
(EFIAPI *FREE_ALL_USER_CER) (
  VOID
  );
  
typedef
USER_AUTH_PERMISSION
(EFIAPI *LDAP_AUTH_CHK_USER_PERM) (
  IN CHAR8 *userDN,
  OUT UINTN *retval
  );

typedef
LDAP_USER_AUTH_DB*
(EFIAPI *LDAP_AUTH_GET_USER_DB) (
  OUT UINTN *retval
  );

typedef
VOID
(EFIAPI *FREE_AUTH_USER_DB) (
  IN LDAP_USER_AUTH_DB *userDB
  );

typedef
VOID
(EFIAPI *CLEAN_LDAP_CONNECTION) (
  VOID
  );

/*! Struct of the ldap auth protocol */
struct _LDAP_AUTH_PROTOCOL {
  LDAP_CONFIG_OP               LdapConfigOp;                         //!< Operations to configure ldap client options
  LDAP_AUTH_GET_USER_DN        GetUserDnFromLdapServer;              //!< Find a user and get a matched DN
  LDAP_AUTH_CHK_DN_PWD         CheckDnPwdOnLdapServer;               //!< Auth a user, using userDn and password
  
  LDAP_AUTH_SEARCH_USER_CER    SearchUserCertificateFromLdapServer;  //!< Search an user certificate from the server
  LDAP_AUTH_GET_USER_CER       GetUserCertificateByNum;              //!< Get the certificate we have found
  FREE_ALL_USER_CER            FreeReceivedUserCertificates;         //!< Free all received userCertificate
  
  LDAP_AUTH_CHK_USER_PERM      CheckUserLoginPermission;             //!< Check user permission for this PC using LDAP
  
  LDAP_AUTH_GET_USER_DB        GetTokenUserDBFromLdapServer;         //!< Get User BD for our workstation
  FREE_AUTH_USER_DB            FreeTokenUserDB;                      //!< Free received token user DB

  CLEAN_LDAP_CONNECTION        CleanLdapConnection;                  //!< Drop saved LDAP connection and free resources
};

extern EFI_GUID gLdapAuthDxeProtocolGuid;

#endif // LDAP_AUTH_DXE