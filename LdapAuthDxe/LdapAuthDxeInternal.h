/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef LDAP_AUTH_LIB_INTERNAL_H_
#define LDAP_AUTH_LIB_INTERNAL_H_

#include <Protocol/LdapAuthDxe.h>

#define FILTER_FORMAT           "(%a=%a)"
#define FILTER_AND_FORMAT       "(&%a(%a=%a))"
#define ALL_CLASS_FORMAT        "(objectClass=*)"

#define OBJ_CLASS_ATTR          "objectClass"
#define MEMBER_ATTR             "member"
#define MEMBER_OF_ATTR          "memberOf"
#define USER_CERT_ATTR          "userCertificate"
#define SAM_ACCOUNT_ATTR        "sAMAccountName"

#define GRP_CLASS               "group"

#define LDAP_CONN_NONE      0
#define LDAP_CONN_SEARCH    1

extern CHAR8   **g_ldap_argv;
extern UINTN   g_ldap_argc;
extern LDAP    *g_ldap_ld;
extern UINTN   g_ldap_conn_type;

#define LDAP_AUTH_NUM_ARGS  13              //!< Number of arguments in the auth request

/** Internal data of the ldap auth protocol */
typedef struct _LDAP_AUTH_INTERNAL_DATA {
  EFI_HANDLE            DriverHandle;       //!< Handle of the ldap auth DXE driver
  LDAP_AUTH_PROTOCOL    LdapAuhtPtotocol;   //!< Ldap auth protocol
} LDAP_AUTH_INTERNAL_DATA;

extern LDAP_AUTH_INTERNAL_DATA gLdapAuthInternalData;

typedef struct _LDAP_FILTER_PAIR {
  CHAR8*    Attribute;
  CHAR8*    Value;
} LDAP_FILTER_PAIR;

UINTN
GetAttributeListForEntry (
  IN OPTIONAL CHAR8 *customBaseDn,
  IN BOOLEAN searchOnlyBase,
  IN OPTIONAL LDAP_FILTER_PAIR *filterList,
  IN OUT ldapAttributePair *attrList
);

USER_AUTH_PERMISSION
GetPermWithUserDNandPCguid (
  IN CHAR8    *userDN,
  IN EFI_GUID *pcGuid,
  OUT UINTN   *retval
);

LDAP_USER_AUTH_DB*
GetTokenUserDBWithPCguid (
  IN EFI_GUID *pcGuid,
  OUT UINTN   *retval
);

CHAR8 **
MakeLdapSearchRequestN (
  UINTN *count
);

VOID
FlushRequest (
  UINTN argc,
  CHAR8** argv
);

UINTN
ProcessingLDAPError (
  int ldapErrorCode
);

VOID
FreeTokenUserDBInternal (
  IN LDAP_USER_AUTH_DB *userDB
);

VOID
FreeTokenUserDB (
  IN LDAP_USER_AUTH_DB *userDB
);

VOID
LogLdapAuthMessage ( 
  IN UINTN logLevel,
  IN const CHAR8 *format,
  ...
);

#endif // LDAP_AUTH_LIB_INTERNAL_H_
