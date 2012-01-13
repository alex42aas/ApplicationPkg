/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Uefi/UefiBaseType.h>
#include <Uefi/UefiSpec.h>

#include <Library/BaseLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/DebugLib.h>
#include <Library/LdapInterfaceLib/LdapInterfaceLib.h>

#include <Protocol/LdapProtocol.h>

#if 0
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

static LDAP_PROTOCOL *pLdapProtocol;

//------------------------------------------------------------------------------
/*! \brief Wrapper for LdapArgs() method */
//------------------------------------------------------------------------------
int
ldap_tool_args (
  int argc,
  char **argv
)
{
  int retval;

  EFI_STATUS  Status = EFI_ABORTED;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (pLdapProtocol == NULL) {
    Status = gBS->LocateProtocol (
                    &gLdapProtocolGuid,
                    NULL,
                    (VOID **) &pLdapProtocol
                    );
    if (Status != EFI_SUCCESS) {
      LOG((EFI_D_ERROR, "%a.%d Status=%d\n", __FUNCTION__, __LINE__, Status));
      return LDAP_OPERATIONS_ERROR;
    }
  }

  retval = pLdapProtocol->LdapArgs(argc, argv);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Wrapper for LdapConnSetup() method */
//------------------------------------------------------------------------------
LDAP* 
ldap_tool_conn_setup (
  int dont,
  void (*private_setup)( LDAP * ),
  int *retval
)
{
  LDAP* ld = NULL;

  EFI_STATUS  Status = EFI_ABORTED;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (pLdapProtocol == NULL) {
    Status = gBS->LocateProtocol (
                    &gLdapProtocolGuid,
                    NULL,
                    (VOID **) &pLdapProtocol
                    );
    if (Status != EFI_SUCCESS) {
      LOG((EFI_D_ERROR, "%a.%d Status=%d\n", __FUNCTION__, __LINE__, Status));
      return NULL;
    }
  }

  ld = pLdapProtocol->LdapConnSetup(dont, private_setup, retval);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return ld;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Wrapper for LdapBind() method */
//------------------------------------------------------------------------------
int
ldap_tool_bind ( 
  LDAP *ld
)
{
  int retval;

  EFI_STATUS  Status = EFI_ABORTED;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (pLdapProtocol == NULL) {
    Status = gBS->LocateProtocol (
                    &gLdapProtocolGuid,
                    NULL,
                    (VOID **) &pLdapProtocol
                    );
    if (Status != EFI_SUCCESS) {
      LOG((EFI_D_ERROR, "%a.%d Status=%d\n", __FUNCTION__, __LINE__, Status));
      return LDAP_LOCAL_ERROR;
    }
  }

  retval = pLdapProtocol->LdapBind(ld);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Wrapper for LdapUnbind() method */
//------------------------------------------------------------------------------
void
ldap_tool_unbind (
  LDAP *ld
)
{
  EFI_STATUS  Status = EFI_ABORTED;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (pLdapProtocol == NULL) {
    Status = gBS->LocateProtocol (
                    &gLdapProtocolGuid,
                    NULL,
                    (VOID **) &pLdapProtocol
                    );
    if (Status != EFI_SUCCESS) {
      LOG((EFI_D_ERROR, "%a.%d Status=%d\n", __FUNCTION__, __LINE__, Status));
      return;
    }
  }

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  pLdapProtocol->LdapUnbind(ld);

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Wrapper for LdapDestroy() method */
//------------------------------------------------------------------------------
void
ldap_tool_destroy (
  void
)
{
  EFI_STATUS  Status = EFI_ABORTED;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (pLdapProtocol == NULL) {
    Status = gBS->LocateProtocol (
                    &gLdapProtocolGuid,
                    NULL,
                    (VOID **) &pLdapProtocol
                    );
    if (Status != EFI_SUCCESS) {
      LOG((EFI_D_ERROR, "%a.%d Status=%d\n", __FUNCTION__, __LINE__, Status));
      return;
    }
  }

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  pLdapProtocol->LdapDestroy();

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Wrapper for LdapSearch() method */
//------------------------------------------------------------------------------
int
ldap_attr_dosearch (
  LDAP *ld,
  ldapAttributePair *attrs,
  char *filterParam
)
{
  int retval;
  UINTN Index;

  EFI_STATUS  Status = EFI_ABORTED;

  LOG((EFI_D_ERROR, "%a.%d attrs: ", __FUNCTION__, __LINE__));
  for (Index = 0; attrs->attrs[Index] != NULL; Index++) {
    LOG((EFI_D_ERROR, "%a(0x%p) ", attrs->attrs[Index], attrs->pAttrList[Index]));
  }
  LOG((EFI_D_ERROR, "\n"));
  LOG((EFI_D_ERROR, "%a.%d filterParam = \"%a\"\n", __FUNCTION__, __LINE__, filterParam));

  if (pLdapProtocol == NULL) {
    Status = gBS->LocateProtocol (
                    &gLdapProtocolGuid,
                    NULL,
                    (VOID **) &pLdapProtocol
                    );
    if (Status != EFI_SUCCESS) {
      LOG((EFI_D_ERROR, "%a.%d Status=%d\n", __FUNCTION__, __LINE__, Status));
      return LDAP_LOCAL_ERROR;
    }
  }

  retval = pLdapProtocol->LdapSearch(ld, attrs, filterParam);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Wrapper for LdapSearchCustom() method */
//------------------------------------------------------------------------------
int
ldap_attr_dosearch_custom (
  LDAP *ld,
  ldapAttributePair *attrs,
  char *filterParam, 
  char *custom_base, 
  int custom_scope
)
{
  int retval;
  UINTN Index;

  EFI_STATUS  Status = EFI_ABORTED;

  LOG((EFI_D_ERROR, "%a.%d attrs: ", __FUNCTION__, __LINE__));
  for (Index = 0; attrs->attrs[Index] != NULL; Index++) {
    LOG((EFI_D_ERROR, "%a(0x%p) ", attrs->attrs[Index], attrs->pAttrList[Index]));
  }
  LOG((EFI_D_ERROR, "\n"));
  LOG((EFI_D_ERROR, "%a.%d filterParam = \"%a\"\n", __FUNCTION__, __LINE__, filterParam));
  LOG((EFI_D_ERROR, "%a.%d custom_base = \"%a\" custom_scope = %d\n", __FUNCTION__, __LINE__, custom_base, custom_scope));

  if (pLdapProtocol == NULL) {
    Status = gBS->LocateProtocol (
                    &gLdapProtocolGuid,
                    NULL,
                    (VOID **) &pLdapProtocol
                    );
    if (Status != EFI_SUCCESS) {
      LOG((EFI_D_ERROR, "%a.%d Status=%d\n", __FUNCTION__, __LINE__, Status));
      return LDAP_LOCAL_ERROR;
    }
  }

  retval = pLdapProtocol->LdapSearchCustom(ld, attrs, filterParam, custom_base, custom_scope);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Wrapper for LdapMultiSearch() method */
//------------------------------------------------------------------------------
int
ldap_attr_multisearch (
  LDAP *ld,
  ldapAttributePair *attrs,
  char *filterParam
)
{
  int retval;
  UINTN Index;

  EFI_STATUS  Status = EFI_ABORTED;

  LOG((EFI_D_ERROR, "%a.%d attrs: ", __FUNCTION__, __LINE__));
  for (Index = 0; attrs->attrs[Index] != NULL; Index++) {
    LOG((EFI_D_ERROR, "%a(0x%p) ", attrs->attrs[Index], attrs->pAttrList[Index]));
  }
  LOG((EFI_D_ERROR, "\n"));
  LOG((EFI_D_ERROR, "%a.%d filterParam = \"%a\"\n", __FUNCTION__, __LINE__, filterParam));

  if (pLdapProtocol == NULL) {
    Status = gBS->LocateProtocol (
                    &gLdapProtocolGuid,
                    NULL,
                    (VOID **) &pLdapProtocol
                    );
    if (Status != EFI_SUCCESS) {
      LOG((EFI_D_ERROR, "%a.%d Status=%d\n", __FUNCTION__, __LINE__, Status));
      return LDAP_LOCAL_ERROR;
    }
  }

  retval = pLdapProtocol->LdapMultiSearch(ld, attrs, filterParam);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Wrapper for LdapSetTlsConfig() method */
//------------------------------------------------------------------------------
int
ldap_set_tls_config (
  tlsConfig_t config
)
{
  int retval;

  EFI_STATUS  Status = EFI_ABORTED;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (pLdapProtocol == NULL) {
    Status = gBS->LocateProtocol (
                    &gLdapProtocolGuid,
                    NULL,
                    (VOID **) &pLdapProtocol
                    );
    if (Status != EFI_SUCCESS) {
      LOG((EFI_D_ERROR, "%a.%d Status=%d\n", __FUNCTION__, __LINE__, Status));
      return -1;
    }
  }

  retval = pLdapProtocol->LdapSetTlsConfig(config);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Wrapper for LdapChkServerAddr() method */
//------------------------------------------------------------------------------
int
ldap_chk_addr(
	int af,
	const char *src,
	void *dst
)
{
  int retval;

  EFI_STATUS  Status = EFI_ABORTED;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (pLdapProtocol == NULL) {
    Status = gBS->LocateProtocol (
                    &gLdapProtocolGuid,
                    NULL,
                    (VOID **) &pLdapProtocol
                    );
    if (Status != EFI_SUCCESS) {
      LOG((EFI_D_ERROR, "%a.%d Status=%d\n", __FUNCTION__, __LINE__, Status));
      return -1;
    }
  }

  retval = pLdapProtocol->LdapChkServerAddr(af, src,dst);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Wrapper for LdapGetHostByAddr() method */
//------------------------------------------------------------------------------
struct hostent *
ldap_gethostbyaddr (
  const char *addr,
  socklen_t len,
  int type
)
{
  struct hostent *host;

  EFI_STATUS  Status = EFI_ABORTED;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (pLdapProtocol == NULL) {
    Status = gBS->LocateProtocol (
                    &gLdapProtocolGuid,
                    NULL,
                    (VOID **) &pLdapProtocol
                    );
    if (Status != EFI_SUCCESS) {
      LOG((EFI_D_ERROR, "%a.%d Status=%d\n", __FUNCTION__, __LINE__, Status));
      return NULL;
    }
  }

  host = pLdapProtocol->LdapGetHostByAddr(addr, len, type);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return host;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Wrapper for LdapCopyAttributeValueList() method */
//------------------------------------------------------------------------------
int
CopyAttributeValueList (
  attributeValue_t *attributeListDst,
  attributeValue_t *attributeListSrc,
  int numAttrsToCopy
)
{
  int retval;

  EFI_STATUS  Status = EFI_ABORTED;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (pLdapProtocol == NULL) {
    Status = gBS->LocateProtocol (
                    &gLdapProtocolGuid,
                    NULL,
                    (VOID **) &pLdapProtocol
                    );
    if (Status != EFI_SUCCESS) {
      LOG((EFI_D_ERROR, "%a.%d Status=%d\n", __FUNCTION__, __LINE__, Status));
      return 0;
    }
  }

  retval = pLdapProtocol->LdapCopyAttributeValueList(attributeListDst, attributeListSrc, numAttrsToCopy);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;  
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Wrapper for LdapFlushAttributeList() method */
//------------------------------------------------------------------------------
void
FlushAttributeList (
  ldapAttributeList_t* attrList
)
{
  EFI_STATUS  Status = EFI_ABORTED;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (pLdapProtocol == NULL) {
    Status = gBS->LocateProtocol (
                    &gLdapProtocolGuid,
                    NULL,
                    (VOID **) &pLdapProtocol
                    );
    if (Status != EFI_SUCCESS) {
      LOG((EFI_D_ERROR, "%a.%d Status=%d\n", __FUNCTION__, __LINE__, Status));
      return;
    }
  }

  pLdapProtocol->LdapFlushAttributeList(attrList);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Wrapper for LdapPrintDebugAttributeValueList() method */
//------------------------------------------------------------------------------
void
PrintDebugAttributeValueList (
  IN char *attrName,
  IN ldapAttributeList_t* attrList
)
{
  EFI_STATUS  Status = EFI_ABORTED;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (pLdapProtocol == NULL) {
    Status = gBS->LocateProtocol (
                    &gLdapProtocolGuid,
                    NULL,
                    (VOID **) &pLdapProtocol
                    );
    if (Status != EFI_SUCCESS) {
      LOG((EFI_D_ERROR, "%a.%d Status=%d\n", __FUNCTION__, __LINE__, Status));
      return;
    }
  }

  pLdapProtocol->LdapPrintDebugAttributeValueList(attrName, attrList);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Wrapper for LdapIsAttributeValueInList() method */
//------------------------------------------------------------------------------
BOOLEAN
IsAttributeValueInList (
  IN ldapAttributeList_t* attrList,
  IN char *attrValue,
  IN size_t attrValueSize
)
{
  BOOLEAN retval;

  EFI_STATUS  Status = EFI_ABORTED;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (pLdapProtocol == NULL) {
    Status = gBS->LocateProtocol (
                    &gLdapProtocolGuid,
                    NULL,
                    (VOID **) &pLdapProtocol
                    );
    if (Status != EFI_SUCCESS) {
      LOG((EFI_D_ERROR, "%a.%d Status=%d\n", __FUNCTION__, __LINE__, Status));
      return FALSE;
    }
  }

  retval = pLdapProtocol->LdapIsAttributeValueInList(attrList, attrValue, attrValueSize);

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return retval;
}
//------------------------------------------------------------------------------

