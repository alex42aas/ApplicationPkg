/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef LDAP_PROTOCOL_H_
#define LDAP_PROTOCOL_H_

#include <TlsConfigStruct.h>
#include <LdapCommon.h>
#include <netdb.h>

typedef struct _LDAP_PROTOCOL LDAP_PROTOCOL;

typedef
int
(EFIAPI *LDAP_TOOL_ARGS) (
  int argc,
  char **argv
);

typedef
void
(EFIAPI *LDAP_TOOL_UNBIND) (
  LDAP *ld
);

typedef
LDAP* 
(EFIAPI *LDAP_TOOL_CONN_SETUP) (
  int dont,
  void (*private_setup)( LDAP * ),
  int *retval
);

typedef
int
(EFIAPI *LDAP_TOOL_BIND) ( 
  LDAP *ld
);

typedef
void
(EFIAPI *LDAP_TOOL_DESTROY) (
  void
);

typedef
int
(EFIAPI *LDAP_ATTR_SEARCH) (
  LDAP *ld,
  ldapAttributePair *attrs,
  char *filterParam
);

typedef
int
(EFIAPI *LDAP_ATTR_SEARCH_CUSTOM) (
  LDAP *ld,
  ldapAttributePair *attrs,
  char *filterParam, 
  char *custom_base, 
  int custom_scope
);

typedef
int
(EFIAPI *LDAP_ATTR_MULTISEARCH) (
  LDAP *ld,
  ldapAttributePair *attrs,
  char *filterParam
);

typedef
int
(EFIAPI *LDAP_SET_TLS_CONFIG) (
  tlsConfig_t config
);

typedef
int
(EFIAPI *LDAP_CHK_SERV_ADDR) (
	int af,
	const char *src,
	void *dst
);

typedef
struct hostent *
(EFIAPI *LDAP_GET_HOST_BY_ADDR) (
  const char *addr,
  socklen_t len,
  int type
);

typedef
int
(EFIAPI *LDAP_COPY_ATTR_VALUE_LIST) (
  attributeValue_t *attributeListDst,
  attributeValue_t *attributeListSrc,
  int numAttrsToCopy
);

typedef
void
(EFIAPI *LDAP_FLUSH_ATTR_VALUE_LIST) (
  ldapAttributeList_t* attrList
);

typedef
void
(EFIAPI *LDAP_PRINT_DEBUG_ATTR_VALUE_LIST) (
  IN char *attrName,
  IN ldapAttributeList_t* attrList
);

typedef
BOOLEAN
(EFIAPI *LDAP_IS_ATTR_VALUE_IN_LIST) (
  IN ldapAttributeList_t* attrList,
  IN char *attrValue,
  IN size_t attrValueSize
);


/*! Struct of the ldap auth protocol */
struct _LDAP_PROTOCOL {
  LDAP_TOOL_BIND                 LdapBind;
  LDAP_TOOL_UNBIND               LdapUnbind;
  LDAP_TOOL_CONN_SETUP           LdapConnSetup;
  LDAP_TOOL_ARGS                 LdapArgs;
  LDAP_TOOL_DESTROY              LdapDestroy;

  LDAP_ATTR_SEARCH               LdapSearch;
  LDAP_ATTR_SEARCH_CUSTOM        LdapSearchCustom;
  LDAP_ATTR_MULTISEARCH          LdapMultiSearch;
  LDAP_SET_TLS_CONFIG            LdapSetTlsConfig;

  LDAP_CHK_SERV_ADDR             LdapChkServerAddr;
  LDAP_GET_HOST_BY_ADDR          LdapGetHostByAddr;

  LDAP_COPY_ATTR_VALUE_LIST          LdapCopyAttributeValueList;
  LDAP_FLUSH_ATTR_VALUE_LIST         LdapFlushAttributeList;
  LDAP_PRINT_DEBUG_ATTR_VALUE_LIST   LdapPrintDebugAttributeValueList;
  LDAP_IS_ATTR_VALUE_IN_LIST         LdapIsAttributeValueInList;
};

extern EFI_GUID gLdapProtocolGuid;

#endif // LDAP_PROTOCOL_H_
