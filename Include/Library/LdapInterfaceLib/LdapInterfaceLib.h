/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef LDAP_INTERFACE_LIB_H_
#define LDAP_INTERFACE_LIB_H_

#include <LdapCommon.h>
#include <TlsConfigStruct.h>
#include <ldap.h>

#include <arpa/inet.h>
#include <netdb.h>

int
ldap_tool_args (
  int argc,
  char **argv
);

LDAP* 
ldap_tool_conn_setup (
  int dont,
  void (*private_setup)( LDAP * ),
  int *retval
);

int
ldap_tool_bind ( 
  LDAP *ld
);

void
ldap_tool_unbind (
  LDAP *ld
);

void
ldap_tool_destroy (
  void
);

int
ldap_attr_multisearch (
  LDAP *ld,
  ldapAttributePair *attrs,
  char *filterParam
);

int
ldap_attr_dosearch (
  LDAP *ld,
  ldapAttributePair *attrs,
  char *filterParam
);

int
ldap_attr_dosearch_custom (
  LDAP *ld,
  ldapAttributePair *attrs,
  char *filterParam, 
  char *custom_base, 
  int custom_scope
);

int
ldap_set_tls_config (
  tlsConfig_t config
);

int
ldap_chk_addr (
	int af,
	const char *src,
	void *dst
);

struct hostent *
ldap_gethostbyaddr (
  const char *addr,
  socklen_t len,
  int type
);

int
CopyAttributeValueList (
  attributeValue_t *attributeListDst,
  attributeValue_t *attributeListSrc,
  int numAttrsToCopy
);

void
FlushAttributeList (
  ldapAttributeList_t* attrList
);

void
PrintDebugAttributeValueList (
  IN char *attrName,
  IN ldapAttributeList_t* attrList
);

BOOLEAN
IsAttributeValueInList (
  IN ldapAttributeList_t* attrList,
  IN char *attrValue,
  IN size_t attrValueSize
);

#endif // LDAP_INTERFACE_LIB_H_