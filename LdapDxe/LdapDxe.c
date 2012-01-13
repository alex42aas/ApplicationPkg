/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/DebugLib.h>
#include <Library/FsUtils.h>

#include <Protocol/LoadedImage.h>
#include <Protocol/LdapProtocol.h>

#include <arpa/inet.h>

#include <InternalErrDesc.h>

#include "LdapDxeInternal.h"

#if 0
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

STATIC LDAP_DXE_INTERNAL_DATA gLdapDxeInternalData;

//------------------------------------------------------------------------------
/*! \brief Pass arguments to setup LDAP library */
//------------------------------------------------------------------------------
int
LDAP_LdapArgs (
  int argc,
  char **argv
)
{
  int retval;

  retval = ldap_tool_args(argc, argv);

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Create LDAP structure and setup TLS connection */
//------------------------------------------------------------------------------
LDAP* 
LDAP_LdapConnSetup (
  int dont,
  void (*private_setup)( LDAP * ),
  int *retval
)
{
  LDAP* ld = NULL;

  ld = ldap_tool_conn_setup(dont, private_setup, retval);

  return ld;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief LDAP Bind on LDAP server */
//------------------------------------------------------------------------------
int
LDAP_LdapBind ( 
  LDAP *ld
)
{
  int retval;

  retval = ldap_tool_bind(ld);

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief LDAP Unbind on LDAP server */
//------------------------------------------------------------------------------
void
LDAP_LdapUnbind (
  LDAP *ld
)
{
  ldap_tool_unbind(ld);

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Ultimate finish LDAP connection */
//------------------------------------------------------------------------------
void
LDAP_LdapDestroy (
  void
)
{
  ldap_tool_destroy();

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int
LDAP_LdapSearch (
  LDAP *ld,
  ldapAttributePair *attrs,
  char *filterParam
)
{
  int retval;

  retval = ldap_attr_dosearch(ld, attrs, filterParam);

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
int
LDAP_LdapSearchCustom (
  LDAP *ld,
  ldapAttributePair *attrs,
  char *filterParam, 
  char *custom_base, 
  int custom_scope
)
{
  int retval;

  retval = ldap_attr_dosearch_custom(ld, attrs, filterParam, custom_base, custom_scope);

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Search multiple attributes on LDAP server */
//------------------------------------------------------------------------------
int
LDAP_LdapMultiSearch (
  LDAP *ld,
  ldapAttributePair *attrs,
  char *filterParam
)
{
  int retval;

  retval = ldap_attr_multisearch(ld, attrs, filterParam);

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set TLS config to the internal LDAP settings */
//------------------------------------------------------------------------------
int
LDAP_LdapSetTlsConfig (
  tlsConfig_t config
)
{
  int retval;

  retval = ldap_set_tls_config(config);

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Check IP address */
//------------------------------------------------------------------------------
int
LDAP_LdapChkServerAddr(
	int af,
	const char *src,
	void *dst
)
{
  int retval;

  retval = inet_pton(af, src, dst);

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! */
//------------------------------------------------------------------------------
struct hostent *
LdapGetHostByAddr (
  const char *addr,
  socklen_t len,
  int type
)
{
  struct hostent *host;

  host = gethostbyaddr(addr, len, type);

  return host;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
int
LdapCopyAttributeValueList (
  attributeValue_t *attributeListDst,
  attributeValue_t *attributeListSrc,
  int numAttrsToCopy
)
{
  int retval;

  retval = CopyAttributeValueList(attributeListDst, attributeListSrc, numAttrsToCopy);

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
void
LdapFlushAttributeList (
  ldapAttributeList_t* attrList
)
{
  FlushAttributeList(attrList);

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
void
LdapPrintDebugAttributeValueList (
  IN char *attrName,
  IN ldapAttributeList_t* attrList
)
{
  PrintDebugAttributeValueList(attrName, attrList);

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
BOOLEAN
LdapIsAttributeValueInList (
  IN ldapAttributeList_t* attrList,
  IN char *attrValue,
  IN size_t attrValueSize
)
{
  BOOLEAN retval;

  retval = IsAttributeValueInList(attrList, attrValue, attrValueSize);

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Init FsUtils for StdLib is used by LdapAuthDxe */
//------------------------------------------------------------------------------
STATIC VOID
InitFsUtilsForStdLib(
  IN EFI_HANDLE ImageHandle
  )
{
  EFI_LOADED_IMAGE_PROTOCOL *ImageInfo;
  EFI_DEVICE_PATH_PROTOCOL *pDp;
  CHAR16 *PathString;

  if (AllocFsDescTable(10) == -1) {
    MsgInternalError(INT_ERR_ALLOC_FS_DESC_TABLE_ERROR);
  }

  gBS->HandleProtocol (ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **) &ImageInfo);

  pDp = DevicePathFromHandle(ImageInfo->DeviceHandle);
  PathString = DevPathToString(pDp, FALSE, TRUE);
  LOG(( EFI_D_ERROR, "-*-> %S\n", PathString ));
  AddFsDescTableItem(L"fv", PathString, FALSE);
  
  return;
}
//------------------------------------------------------------------------------


//------------------------------------------------------------------------------
/*! \brief Entry point of the LDAP DXE driver */
//------------------------------------------------------------------------------
EFI_STATUS
EFIAPI
LdapDxeInit (
  IN EFI_HANDLE ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  EFI_STATUS Status = EFI_SUCCESS;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  InitFsUtilsForStdLib(ImageHandle);

  ZeroMem(&gLdapDxeInternalData, sizeof(gLdapDxeInternalData));

  gLdapDxeInternalData.LdapPtotocol.LdapArgs           = LDAP_LdapArgs;
  gLdapDxeInternalData.LdapPtotocol.LdapConnSetup      = LDAP_LdapConnSetup;
  gLdapDxeInternalData.LdapPtotocol.LdapBind           = LDAP_LdapBind;
  gLdapDxeInternalData.LdapPtotocol.LdapUnbind         = LDAP_LdapUnbind;
  gLdapDxeInternalData.LdapPtotocol.LdapDestroy        = LDAP_LdapDestroy;

  gLdapDxeInternalData.LdapPtotocol.LdapSearch         = LDAP_LdapSearch;
  gLdapDxeInternalData.LdapPtotocol.LdapSearchCustom   = LDAP_LdapSearchCustom;
  gLdapDxeInternalData.LdapPtotocol.LdapMultiSearch    = LDAP_LdapMultiSearch;
  gLdapDxeInternalData.LdapPtotocol.LdapSetTlsConfig   = LDAP_LdapSetTlsConfig;

  gLdapDxeInternalData.LdapPtotocol.LdapChkServerAddr  = LDAP_LdapChkServerAddr;
  gLdapDxeInternalData.LdapPtotocol.LdapGetHostByAddr  = LdapGetHostByAddr;
  
  gLdapDxeInternalData.LdapPtotocol.LdapCopyAttributeValueList         = LdapCopyAttributeValueList;
  gLdapDxeInternalData.LdapPtotocol.LdapFlushAttributeList             = LdapFlushAttributeList;
  gLdapDxeInternalData.LdapPtotocol.LdapPrintDebugAttributeValueList   = LdapPrintDebugAttributeValueList;
  gLdapDxeInternalData.LdapPtotocol.LdapIsAttributeValueInList         = LdapIsAttributeValueInList;
  
  Status = gBS->InstallProtocolInterface(
                  &gLdapDxeInternalData.DriverHandle,
                  &gLdapProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  &gLdapDxeInternalData.LdapPtotocol
                );

  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));

  return Status;
}
//------------------------------------------------------------------------------

