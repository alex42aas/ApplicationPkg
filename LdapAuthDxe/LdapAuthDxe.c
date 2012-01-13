/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/FsUtils.h>
#include <Library/CommonUtils.h>

#include <InternalErrDesc.h>
#include <Library/AuthModeConfig/AuthModeConfig.h>
#include <Library/NetSetupLib/NetSetupLib.h>
#include <Library/LdapInterfaceLib/LdapInterfaceLib.h>

#include <Protocol/LdapAuthDxe.h>
#include <Protocol/LdapConfigOp.h>
#include <Protocol/LoadedImage.h>

#include "LdapAuthDxeInternal.h"
#include "LdapConfigInternal.h"

#if 0
#define LOG(MSG)
#else
#define LOG(MSG)  DEBUG(MSG)
#endif

CHAR8   **g_ldap_argv     = NULL;
UINTN   g_ldap_argc       = 1;
LDAP    *g_ldap_ld        = NULL;
UINTN   g_ldap_conn_type  = LDAP_CONN_NONE;

LDAP_AUTH_INTERNAL_DATA gLdapAuthInternalData;

static CHAR8 hostOpt[] = "-h";
static CHAR8 portOpt[] = "-p";
static CHAR8 authOpt[] = "-x";
static CHAR8 baseOpt[] = "-b";
static CHAR8 dnOpt[]   = "-D";
static CHAR8 pwOpt[]   = "-w";
static CHAR8 tlsOpt[]  = "-ZZ";

static ldapAttributeList_t certList = {0, NULL};

enum{ADDR, NAME, HOSTS, NO_HOST_PARAM};

static CHAR8 addrC8[STRING_ADDR_LEN + 1], resultAddr[STRING_ADDR_LEN + 1];

//------------------------------------------------------------------------------
/*! \brief Check an using ldapserver address or name */
/*! \retval ADDR Use ldap server adress as a -H param 
    \retval NAME Use ldap server name as a -H param
    \retval HOSTS Use ldap server name as a -H param
    \retval NO_HOST_PARAM  No -H param */
//------------------------------------------------------------------------------
static
UINT8
CheckLdapServerAddr( LDAP_CONFIG_OP* LdapConfig )
{
  if (LdapConfig->GetLdapServerAddr() != NULL &&
      LdapConfig->GetSizeOfLdapServerName() > 0 &&
      LdapConfig->GetLdapServerName() != NULL)
    return HOSTS;

  if (LdapConfig->GetLdapServerAddr() != NULL)
    return ADDR;

  if (LdapConfig->GetSizeOfLdapServerName() > 0 &&
      LdapConfig->GetLdapServerName() != NULL)
    return NAME;
  else
    return NO_HOST_PARAM;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Convert LDAP internal errors to LDAP auth errors */
/*! \param[in] ldapErrorCode Error code from openLdap library */
/*! \return LDAP auth error */
//------------------------------------------------------------------------------
UINTN
ProcessingLDAPError(
  int ldapErrorCode
  )
{
  UINTN retval = CANT_CONNECT_TO_LDAP;

  LOG((EFI_D_ERROR, "%a.%d: LDAP status: %d\n", 
    __FUNCTION__, __LINE__, ldapErrorCode));

  switch(ldapErrorCode) {
  case LDAP_NO_SUCH_OBJECT:
    retval = LDAP_SEARCH_ERROR;
    break;
  case LDAP_LOCAL_ERROR:
    retval = LDAP_INTERNAL_ERROR;
    break;
  case LDAP_INVALID_CREDENTIALS:
    retval = LDAP_ROOT_ERR_CREDENTIALS;
    break;
  case LDAP_UNWILLING_TO_PERFORM:
    retval = LDAP_SERVER_DENY;
    break;
  case LDAP_INVALID_DN_SYNTAX:
    retval = CANT_PROC_LDAP_OPT;
    break;
  case LDAP_MORE_RESULTS_TO_RETURN:
    retval = LDAP_TOO_MANY_ENTRIES;
    break;
  default:
    retval = CANT_CONNECT_TO_LDAP;
    break;
  }

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \btief Make a request to authenticate on the ldap server */
/*! It is the same function with MakeLdapSearchRequestN(), but we don't 
    read binddn and bindpw from the ldap config setting */
/*! \param[in] *userDn Pointer to binddn of the user we need to authenticate 
    \param[in] *password Pointer to a password 
    \param[out] *count Count of args of the request */
/*! \return Vector of arguments for a ldap tool */
//------------------------------------------------------------------------------
static CHAR8**
MakeAuthRequestN(const CHAR8* userDn, CHAR8* password, UINTN *count)
{
  CHAR8 *hostData   = NULL;
  CHAR8 *portData   = NULL;
  CHAR8 *baseData   = NULL;
  CHAR8 *dnData     = NULL;
  CHAR8 *pwData     = NULL;

  CHAR8 *pHostOpt   = NULL;
  CHAR8 *pPortOpt   = NULL;
  CHAR8 *pAuthOpt   = NULL;
  CHAR8 *pBaseOpt   = NULL;
  CHAR8 *pDnOpt     = NULL;
  CHAR8 *pPwOpt     = NULL;
  CHAR8 *pStTLSOpt  = NULL;

  CHAR8 **request   = NULL;

  UINTN Index;

  UINTN           argc = 1;
  LDAP_CONFIG_OP* LdapConfig = &gLdapAuthInternalData.LdapAuhtPtotocol.LdapConfigOp;

  if (LdapConfig->ReadLdapConfig() != EFI_SUCCESS) {
      LOG((EFI_D_ERROR, "%a.%d: Error: Can't read ldap config!\n", 
          __FUNCTION__, __LINE__));
      return NULL;
  }

  request = AllocateZeroPool(LDAP_AUTH_NUM_ARGS*sizeof(CHAR8*));
  if (NULL == request) {
    LOG((EFI_D_ERROR, "%a.%d: Can't allocate %d bytes for request!\n", 
        __FUNCTION__, __LINE__, LDAP_AUTH_NUM_ARGS*sizeof(CHAR8*)));
    return NULL;
  }

  UnicodeStrToAsciiStr(LdapConfig->GetLdapServerAddr(), addrC8);

  //------------------------------------------------------------
  // Make -h (host) argument
  //------------------------------------------------------------
  switch (CheckLdapServerAddr(LdapConfig)) {
  case ADDR:
    if (1 == ldap_chk_addr(AF_INET, addrC8, resultAddr)) {
      // copy ip address as a host
      pHostOpt = AllocateZeroPool(sizeof(hostOpt));
      if (NULL == pHostOpt)
        goto ERROR_EXIT;

      AsciiStrCpy(pHostOpt, hostOpt);
      request[argc++] = pHostOpt;

      hostData = AllocateZeroPool(STRING_ADDR_LEN + 1);
      if (NULL == hostData)
        goto ERROR_EXIT;

      AsciiStrCpy(hostData, addrC8);
      request[argc++] = hostData;
    }
    break;
  case NAME:
  case HOSTS:
      // copy server name as a host
      pHostOpt = AllocateZeroPool(sizeof(hostOpt));
      if (NULL == pHostOpt)
        goto ERROR_EXIT;

      AsciiStrCpy(pHostOpt, hostOpt);
      request[argc++] = pHostOpt;

      hostData = AllocateZeroPool((LdapConfig->GetSizeOfLdapServerName())/2);
      if (NULL == hostData)
        goto ERROR_EXIT;

      UnicodeStrToAsciiStr(LdapConfig->GetLdapServerName(), hostData);
      request[argc++] = hostData;
    break;
  }

  //------------------------------------------------------------
  // Make -p (port) argument
  //------------------------------------------------------------
  pPortOpt = AllocateZeroPool(sizeof(portOpt));
  if (NULL == pPortOpt)
    goto ERROR_EXIT;

  AsciiStrCpy(pPortOpt, portOpt);
  request[argc++] = pPortOpt;

  portData = AllocateZeroPool(MAX_PORT_NUM_SIZE);
  if (NULL == portData) {
    goto ERROR_EXIT;
  }
  AsciiValueToString(portData, 0, LdapConfig->GetLdapServerPort(), MAX_PORT_NUM_SIZE);
  request[argc++] = portData;

  //------------------------------------------------------------
  // Make -x (auth) argument
  //------------------------------------------------------------
  pAuthOpt = AllocateZeroPool(sizeof(authOpt));
  if (NULL == pAuthOpt)
    goto ERROR_EXIT;
  
  AsciiStrCpy(pAuthOpt, authOpt);
  request[argc++] = pAuthOpt;

  //------------------------------------------------------------
  // Make -ZZ (StartTLS with a reading the status) argument
  //------------------------------------------------------------
  if (LdapConfig->IsUseTLS() == TRUE) {
    pStTLSOpt = AllocateZeroPool(sizeof(tlsOpt));
    if (NULL == pStTLSOpt)
      goto ERROR_EXIT;
        
    AsciiStrCpy(pStTLSOpt, tlsOpt);
    request[argc++] = pStTLSOpt;
  }

  //------------------------------------------------------------
  // Make -b (base) argument
  //------------------------------------------------------------
  if (LdapConfig->GetSizeOfLdapSuffix() && LdapConfig->GetLdapSuffix() != NULL) {
    pBaseOpt = AllocateZeroPool(sizeof(baseOpt));
    if (NULL == pBaseOpt)
      goto ERROR_EXIT;

    AsciiStrCpy(pBaseOpt, baseOpt);
    request[argc++] = pBaseOpt;

    baseData = AllocateZeroPool((LdapConfig->GetSizeOfLdapSuffix())/2);
    if (NULL == baseData) {
      goto ERROR_EXIT;
    }
    UnicodeStrToAsciiStr(LdapConfig->GetLdapSuffix(), baseData);
    request[argc++] = baseData;
  }

  //------------------------------------------------------------
  // Make -D (dn) argument
  //------------------------------------------------------------
  if (userDn != NULL) {
    pDnOpt = AllocateZeroPool(sizeof(dnOpt));
    if (NULL == pDnOpt)
      goto ERROR_EXIT;

    AsciiStrCpy(pDnOpt, dnOpt);
    request[argc++] = pDnOpt;

    dnData = AllocateZeroPool(AsciiStrSize(userDn));
    if (NULL == dnData) {
      goto ERROR_EXIT;
    }
    AsciiStrCpy(dnData, userDn);
    request[argc++] = dnData;
  }

  //------------------------------------------------------------
  // Make -w (pw) argument
  //------------------------------------------------------------
  if (password != NULL) {
    pPwOpt = AllocateZeroPool(sizeof(pwOpt));
    if (NULL == pPwOpt)
      goto ERROR_EXIT;

    AsciiStrCpy(pPwOpt, pwOpt);
    request[argc++] = pPwOpt;

    pwData = AllocateZeroPool(AsciiStrSize(password));
    if (NULL == pwData) {
      goto ERROR_EXIT;
    }
    AsciiStrCpy(pwData, password);
    request[argc++] = pwData;
  }

  LOG((EFI_D_ERROR, "%a.%d: Success! argc: %d request: %p\n", 
    __FUNCTION__, __LINE__, argc, request));

  *count = argc;

  LOG((EFI_D_ERROR, "%a.%d ", __FUNCTION__, __LINE__));
  for (Index = 0; Index < argc; Index++) {
    LOG((EFI_D_ERROR, "%a ", request[Index]));
  }
  LOG((EFI_D_ERROR, "\n"));

  return request;

ERROR_EXIT:
  FlushRequest( argc, request );

  LOG((EFI_D_ERROR, "%a.%d: ERROR_EXIT! argc: %d\n", 
    __FUNCTION__, __LINE__, argc));

  return NULL;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Make a  search request for the ldap server */
/*! Make a request to search uid of a user in the ldap server. */
/*! \param[out] *count Number of args int the result vector */
/*! \return Vector of arguments for a ldap tool */
//------------------------------------------------------------------------------
CHAR8 **
MakeLdapSearchRequestN( 
  UINTN *count
  )
{
  CHAR8 *hostData   = NULL;
  CHAR8 *portData   = NULL;
  CHAR8 *baseData   = NULL;
  CHAR8 *dnData     = NULL;
  CHAR8 *pwData     = NULL;

  CHAR8 *pHostOpt   = NULL;
  CHAR8 *pPortOpt   = NULL;
  CHAR8 *pAuthOpt   = NULL;
  CHAR8 *pBaseOpt   = NULL;
  CHAR8 *pDnOpt     = NULL;
  CHAR8 *pPwOpt     = NULL;
  CHAR8 *pStTLSOpt  = NULL;

  CHAR8 **request   = NULL;

  UINTN Index;

  UINTN           argc = 1;
  LDAP_CONFIG_OP* LdapConfig = &gLdapAuthInternalData.LdapAuhtPtotocol.LdapConfigOp;

  if (LdapConfig->ReadLdapConfig() != EFI_SUCCESS) {
    LOG((EFI_D_ERROR, "%a.%d: Error: Can't read ldap config!\n", 
      __FUNCTION__, __LINE__));
    return NULL;
  }

  request = AllocateZeroPool(LDAP_AUTH_NUM_ARGS*sizeof(CHAR8*));
  if (NULL == request) {
    LOG((EFI_D_ERROR, "%a.%d: Can't allocate %d bytes for request!\n", 
      __FUNCTION__, __LINE__, LDAP_AUTH_NUM_ARGS*sizeof(CHAR8*)));
    return NULL;
  }

  UnicodeStrToAsciiStr(LdapConfig->GetLdapServerAddr(), addrC8);

  //------------------------------------------------------------
  // Make -h (host) argument
  //------------------------------------------------------------
  switch (CheckLdapServerAddr(LdapConfig)) {
  case ADDR:
    if (1 == ldap_chk_addr(AF_INET, addrC8, resultAddr)) {
      // copy ip address as a host
      pHostOpt = AllocateZeroPool(sizeof(hostOpt));
      if (NULL == pHostOpt)
        goto ERROR_EXIT;

      AsciiStrCpy(pHostOpt, hostOpt);
      request[argc++] = pHostOpt;

      hostData = AllocateZeroPool(STRING_ADDR_LEN + 1);
      if (NULL == hostData)
        goto ERROR_EXIT;

      AsciiStrCpy(hostData, addrC8);
      request[argc++] = hostData;
    }
    break;
  case NAME:
  case HOSTS:
    // copy server name as a host
    pHostOpt = AllocateZeroPool(sizeof(hostOpt));
    if (NULL == pHostOpt)
      goto ERROR_EXIT;

    AsciiStrCpy(pHostOpt, hostOpt);
    request[argc++] = pHostOpt;

    hostData = AllocateZeroPool((LdapConfig->GetSizeOfLdapServerName())/2);
    if (NULL == hostData)
      goto ERROR_EXIT;

    UnicodeStrToAsciiStr(LdapConfig->GetLdapServerName(), hostData);
    request[argc++] = hostData;
    break;
  }

  //------------------------------------------------------------
  // Make -p (port) argument
  //------------------------------------------------------------
  pPortOpt = AllocateZeroPool(sizeof(portOpt));
  if (NULL == pPortOpt)
    goto ERROR_EXIT;
    
  AsciiStrCpy(pPortOpt, portOpt);
  request[argc++] = pPortOpt;

  portData = AllocateZeroPool(MAX_PORT_NUM_SIZE);
  if (NULL == portData) {
    goto ERROR_EXIT;
  }
  AsciiValueToString(portData, 0, LdapConfig->GetLdapServerPort(), MAX_PORT_NUM_SIZE);
  request[argc++] = portData;

  //------------------------------------------------------------
  // Make -x (auth) argument
  //------------------------------------------------------------
  pAuthOpt = AllocateZeroPool(sizeof(authOpt));
  if (NULL == pAuthOpt)
    goto ERROR_EXIT;

  AsciiStrCpy(pAuthOpt, authOpt);
  request[argc++] = pAuthOpt;

  //------------------------------------------------------------
  // Make -ZZ (StartTLS with a reading the status) argument
  //------------------------------------------------------------
  if (LdapConfig->IsUseTLS() == TRUE) {
    pStTLSOpt = AllocateZeroPool(sizeof(tlsOpt));
    if (NULL == pStTLSOpt)
      goto ERROR_EXIT;

    AsciiStrCpy(pStTLSOpt, tlsOpt);
    request[argc++] = pStTLSOpt;
  }
  
  //------------------------------------------------------------
  // Make -b (base) argument
  //------------------------------------------------------------
  if (LdapConfig->GetSizeOfLdapSuffix() && LdapConfig->GetLdapSuffix() != NULL) {
    pBaseOpt = AllocateZeroPool(sizeof(baseOpt));
    if (NULL == pBaseOpt)
      goto ERROR_EXIT;

    AsciiStrCpy(pBaseOpt, baseOpt);
    request[argc++] = pBaseOpt;

    baseData = AllocateZeroPool((LdapConfig->GetSizeOfLdapSuffix())/2);
    if (NULL == baseData) {
      goto ERROR_EXIT;
    }
    UnicodeStrToAsciiStr(LdapConfig->GetLdapSuffix(), baseData);
    request[argc++] = baseData;
  }

  //------------------------------------------------------------
  // Make -D (dn) argument
  //------------------------------------------------------------
  if (LdapConfig->GetSizeOfLdapRootdn() > 0 && LdapConfig->GetLdapRootdn() != NULL) {
    pDnOpt = AllocateZeroPool(sizeof(dnOpt));
    if (NULL == pDnOpt)
      goto ERROR_EXIT;

    AsciiStrCpy(pDnOpt, dnOpt);
    request[argc++] = pDnOpt;

    dnData = AllocateZeroPool((LdapConfig->GetSizeOfLdapRootdn())/2);
    if (NULL == dnData) {
      goto ERROR_EXIT;
    }
    UnicodeStrToAsciiStr(LdapConfig->GetLdapRootdn(), dnData);
    request[argc++] = dnData;
  }

  //------------------------------------------------------------
  // Make -w (pw) argument
  //------------------------------------------------------------
  if (LdapConfig->GetSizeOfLdapRootpw() > 0 && LdapConfig->GetLdapRootpw() != NULL) {
    pPwOpt = AllocateZeroPool(sizeof(pwOpt));
    if (NULL == pPwOpt)
      goto ERROR_EXIT;

    AsciiStrCpy(pPwOpt, pwOpt);
    request[argc++] = pPwOpt;

    pwData = AllocateZeroPool((LdapConfig->GetSizeOfLdapRootpw())/2);
    if (NULL == pwData) {
      goto ERROR_EXIT;
    }
    UnicodeStrToAsciiStr(LdapConfig->GetLdapRootpw(), pwData);
    request[argc++] = pwData;
  }

  LOG((EFI_D_ERROR, "%a.%d: Success! argc: %d request: %p\n", 
    __FUNCTION__, __LINE__, argc, request));

  *count = argc;

  LOG((EFI_D_ERROR, "%a.%d ", __FUNCTION__, __LINE__));
  for (Index = 0; Index < argc; Index++) {
    LOG((EFI_D_ERROR, "%a ", request[Index]));
  }
  LOG((EFI_D_ERROR, "\n"));

  return request;

ERROR_EXIT:
  FlushRequest( argc, request );

  LOG((EFI_D_ERROR, "%a.%d: ERROR_EXIT! argc: %d\n", 
    __FUNCTION__, __LINE__, argc));

  return NULL;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Flush a request (a vector of arguments) */
/*! \param[in] argc Number of arguments in the vector
    \param[in] **argv Pointer to the vector */
//------------------------------------------------------------------------------
VOID
FlushRequest( UINTN argc, CHAR8** argv)
{
  UINTN count; 

  if ((argc <= 1) || (NULL == argv))
    return;

  for(count = 1; count < argc; count++) {
    if (argv[count] != NULL) {
      FreePool(argv[count]);
      argv[count] = NULL;
    }
  }

  FreePool(argv);
  argv = NULL;

  return;
}
//------------------------------------------------------------------------------

CHAR8*
MakeFilterString (
  LDAP_FILTER_PAIR *filterList
  )
{
  CHAR8* FilterElem;
  CHAR8* FilterNextElem;
  UINTN FilterElemSize;

  if (filterList == NULL) {
    return (CHAR8*)AllocateCopyPool (AsciiStrSize(ALL_CLASS_FORMAT), ALL_CLASS_FORMAT);
  }

  if (filterList->Attribute == NULL || filterList->Value == NULL) {
    LOG((EFI_D_ERROR, "%a.%d Attribute = 0x%p Value = 0x%p\n", __FUNCTION__, __LINE__, filterList->Attribute, filterList->Value));
    return NULL;
  }

  if ((filterList + 1)->Attribute != NULL && (filterList + 1)->Value != NULL) {
    FilterNextElem = MakeFilterString (filterList + 1);
    if (FilterNextElem == NULL) {
      LOG((EFI_D_ERROR, "%a.%d FilterNextElem = 0x%p\n", __FUNCTION__, __LINE__, FilterNextElem));
      return NULL;
    }
  } else {
    FilterNextElem = NULL;
  }

  if (FilterNextElem == NULL) {
    FilterElemSize = AsciiStrSize(FILTER_FORMAT) + AsciiStrLen(filterList->Attribute) + AsciiStrLen(filterList->Value);
  } else {
    FilterElemSize = AsciiStrLen(FILTER_AND_FORMAT) + AsciiStrLen(FilterNextElem) + AsciiStrLen(filterList->Attribute) + AsciiStrLen(filterList->Value);
  }
  FilterElem = AllocatePool (FilterElemSize);
  if (FilterElem == NULL) {
    if (FilterNextElem != NULL) {
      FreePool (FilterNextElem);
    }
    LOG((EFI_D_ERROR, "%a.%d FilterElem = 0x%p\n", __FUNCTION__, __LINE__, FilterElem));
    return NULL;
  }
  if (FilterNextElem == NULL) {
    AsciiSPrint (FilterElem, FilterElemSize, FILTER_FORMAT, filterList->Attribute, filterList->Value);
  } else {
    AsciiSPrint (FilterElem, FilterElemSize, FILTER_AND_FORMAT, FilterNextElem, filterList->Attribute, filterList->Value);
  }

  return FilterElem;
}

//------------------------------------------------------------------------------
/*! \brief Get a list of attributes for a LDAP entry */
/*! Get a list of <attrList> LDAP attributes for the LDAP entry, which has <nameOpt>
    attribute with <nameValue> value. */
/*! \param[in] *customBaseDn If set - use this DN as BaseDN, if NULL - use default from config
    \param[in] *searchOnlyBase TRUE - search only base entry, FALSE - search all subentries
    \param[in] *filterList Array of filter conditions, terminated with {NULL, NULL} element
    \param[in] **attrList A list of attributes to request
    \param[in] attrObjs A list of attribute objects
    \param[out] **entryDN distinguished name of found entry */
//------------------------------------------------------------------------------
UINTN
GetAttributeListForEntry (
  IN OPTIONAL CHAR8 *customBaseDn,
  IN BOOLEAN searchOnlyBase,
  IN OPTIONAL LDAP_FILTER_PAIR *filterList,
  IN OUT ldapAttributePair *attrList
  )
{
  UINT32 status       = LDAP_SUCCESS;
  LDAP    *ld         = NULL;
  CHAR8   **argv      = NULL;
  CHAR8   *searchData = NULL;
  UINTN   argc = 1, retval = CANT_INIT_LDAP_SESSION;
  UINTN Index, Index2;

  LOG((EFI_D_ERROR, "%a.%d customBaseDn: \"%a\" searchOnlyBase: %d\n", __FUNCTION__, __LINE__, customBaseDn, searchOnlyBase));
  LOG((EFI_D_ERROR, "%a.%d filterList: 0x%p\n", __FUNCTION__, __LINE__, filterList));
  for (Index = 0; (filterList != NULL) && (filterList[Index].Attribute != NULL) && (filterList[Index].Value != NULL); Index++) {
    LOG((EFI_D_ERROR, "%a=%a\n", filterList[Index].Attribute, filterList[Index].Value));
  }
  LOG((EFI_D_ERROR, "%a.%d attrList: ", __FUNCTION__, __LINE__));
  for (Index = 0; attrList->attrs[Index] != NULL; Index++) {
    LOG((EFI_D_ERROR, "%a(0x%p) ", attrList->attrs[Index], attrList->pAttrList[Index]));
  }
  LOG((EFI_D_ERROR, "\n"));

  if (g_ldap_conn_type != LDAP_CONN_SEARCH) {
    LOG((EFI_D_ERROR, "%a.%d: Make new connection\n", __FUNCTION__, __LINE__));
    if (g_ldap_conn_type != LDAP_CONN_NONE) {
      LOG((EFI_D_ERROR, "%a.%d: Drop previous connection\n", __FUNCTION__, __LINE__));
      if (g_ldap_ld != NULL) {
        ldap_tool_unbind(g_ldap_ld);
      }

      ldap_tool_destroy();

      FlushRequest(g_ldap_argc, g_ldap_argv);
      g_ldap_argv = NULL;
      g_ldap_argc = 1;
      g_ldap_ld = NULL;
      g_ldap_conn_type = LDAP_CONN_NONE;
    }
    //------------------------------------------------------------
    // Make A list of arguments for ldap tools
    //------------------------------------------------------------
    argv = MakeLdapSearchRequestN(&argc);
    if (NULL == argv) {
      LOG((EFI_D_ERROR, "%a.%d: Can't make ldap request!\n", 
        __FUNCTION__, __LINE__));
      return CANT_MAKE_REQUEST;
    }

    //------------------------------------------------------------
    // Pass a list of arguments to ldap tools
    //------------------------------------------------------------
    status = ldap_tool_args((int)argc, argv);
    if (status != LDAP_SUCCESS) {
      LOG((EFI_D_ERROR, "%a.%d: Bad ldap server options!\n", 
        __FUNCTION__, __LINE__));
      FlushRequest( argc, argv);
      return CANT_PROC_LDAP_OPT;
    }

    //------------------------------------------------------------
    // Make a struct of ldap connection
    //------------------------------------------------------------
    ld = ldap_tool_conn_setup( 0, NULL, &status);
    if (ld == NULL) {
      if (status == LDAP_CON_ERROR_TO_START_TLS) {
        retval = LDAP_ERROR_TO_START_TLS;
      } else if (status == LDAP_CON_ERROR_SERVER_DOWN) {
        retval = CANT_CONNECT_TO_LDAP;
      } else {
        retval = CANT_INIT_LDAP_SESSION;
      }
      goto EXIT;
    }

    status = ldap_tool_bind( ld );
  } else {
    LOG((EFI_D_ERROR, "%a.%d: Reuse previous connection\n", __FUNCTION__, __LINE__));
    argc = g_ldap_argc;
    argv = g_ldap_argv;
    ld = g_ldap_ld;
  }
  LOG((EFI_D_ERROR, "%a.%d status = %d\n", __FUNCTION__, __LINE__, status));
  if (LDAP_SUCCESS == status) {
    // Make a filter string
    searchData = MakeFilterString (filterList);
    LOG((EFI_D_ERROR, "%a.%d searchData = %a\n", __FUNCTION__, __LINE__, searchData));
    if (NULL == searchData) {
      LOG((EFI_D_ERROR, "%a.%d: Error!\n", 
        __FUNCTION__, __LINE__));
      retval = LDAP_OUT_OF_MEMORY;
      goto EXIT;
    }

    if (customBaseDn != NULL) {
      status = ldap_attr_dosearch_custom( ld, attrList, searchData, customBaseDn, (searchOnlyBase ? LDAP_SCOPE_BASE : LDAP_SCOPE_SUB) );
    } else {
      status = ldap_attr_dosearch( ld, attrList, searchData );
    }
    if (status != LDAP_SUCCESS) {
      goto ERROR_EXIT;
    }

    // Debug print all received attributes
    if (attrList->entryDn != NULL && *(attrList->entryDn) != NULL) {
      LOG((EFI_D_ERROR, "%a.%d attrList->entryDn = \"%a\"\n", __FUNCTION__, __LINE__, *(attrList->entryDn)));
    }
    for (Index = 0; attrList->attrs[Index] != NULL; Index++) {
      if (attrList->pAttrList[Index] != NULL) {
        LOG((EFI_D_ERROR, "%a.%d attrList[%d] = \"%a\": %d\n", __FUNCTION__, __LINE__, Index, attrList->attrs[Index], attrList->pAttrList[Index]->numberOfItems));
        for (Index2 = 0; Index2 < attrList->pAttrList[Index]->numberOfItems; Index2++) {
          LOG((EFI_D_ERROR, "\"%.*a\"\n", attrList->pAttrList[Index]->attributeValueList[Index2].dataLen, 
            attrList->pAttrList[Index]->attributeValueList[Index2].data));
        }
        if (attrList->pAttrList[Index]->numberOfItems > 0) {
          if (CheckPcdDebugPropertyMask() == TRUE) {
            PrintDebugAttributeValueList(attrList->attrs[Index], attrList->pAttrList[Index]);
          }
        }
      } else {
        LOG((EFI_D_ERROR, "%a.%d attrList[%d] = \"%a\": 0x%p\n", __FUNCTION__, __LINE__, Index, attrList->attrs[Index], attrList->pAttrList[Index]));
      }
    }

    retval = LDAP_SEARCH_SUCCESS;
  } else {
ERROR_EXIT:
    retval = ProcessingLDAPError(status);
  }
EXIT:
  LOG((EFI_D_ERROR, "%a.%d status = %d\n", __FUNCTION__, __LINE__, status));
  if (status != LDAP_SUCCESS) {
    LOG((EFI_D_ERROR, "%a.%d: Drop current connection\n", __FUNCTION__, __LINE__));
    if (ld != NULL) {
      ldap_tool_unbind(ld);
    }

    ldap_tool_destroy();

    FlushRequest(argc, argv);

    g_ldap_argc = 1;
    g_ldap_argv = NULL;
    g_ldap_ld = NULL;
    g_ldap_conn_type = LDAP_CONN_NONE;
  } else {
    LOG((EFI_D_ERROR, "%a.%d: Keep current connection\n", __FUNCTION__, __LINE__));
    g_ldap_argc = argc;
    g_ldap_argv = argv;
    g_ldap_ld = ld;
    g_ldap_conn_type = LDAP_CONN_SEARCH;
  }

  if (searchData != NULL) {
    FreePool(searchData);
  }

  LOG((EFI_D_ERROR, "%a.%d retval: %d\n", 
    __FUNCTION__, __LINE__, retval));

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Authenticate an user on the server */
/*! Authenticate as an user on ldap server. This function is a path of the
    authorization process */
/*! \param[in] *userDn User dn for an auth on the server 
    \param[in] *password User password */
/*! \return Status of the authentication */
/*! \retval LDAP_AUTH_PASS User has passed authentication
    \retval CANT_MAKE_REQUEST Can't make a search request 
    \retval CANT_PROC_LDAP_OPT Bad ldap client options
    \retval CANT_INIT_LDAP_SESSION Can't init ldap session (internal error) 
    \retval LDAP_AUTH_FAIL Fail to auth the user 
    \retval LDAP_INTERNAL_ERROR Internal error of the ldap client tool. See debug output for more details */
//------------------------------------------------------------------------------
UINTN
CheckDnPwdOnLdapServer(CHAR8* userDn, CHAR8* password)
{
  LDAP    *ld      = NULL;
  CHAR8   **argv   = NULL;
  UINTN    argc    = 1;

  UINT32   status = LDAP_OPERATIONS_ERROR, retval = LDAP_AUTH_FAIL, conSetupStatus = LDAP_CON_SETUP_ERROR;

  if (g_ldap_conn_type != LDAP_CONN_NONE) {
    LOG((EFI_D_ERROR, "%a.%d: Drop previous connection\n", __FUNCTION__, __LINE__));
    if (g_ldap_ld != NULL) 
      ldap_tool_unbind(g_ldap_ld);

    ldap_tool_destroy();

    FlushRequest(g_ldap_argc, g_ldap_argv);
    g_ldap_argv = NULL;
    g_ldap_argc = 1;
    g_ldap_ld = NULL;
    g_ldap_conn_type = LDAP_CONN_NONE;
  }

  argv = MakeAuthRequestN(userDn, password, &argc);
  if (NULL == argv) {
    LOG((EFI_D_ERROR, "%a.%d: Can't make ldap auth request!\n", 
      __FUNCTION__, __LINE__));
    return CANT_MAKE_REQUEST;
  }

  status = ldap_tool_args((int)argc, argv);
  if (status != LDAP_SUCCESS) {
    LOG((EFI_D_ERROR, "%a.%d: Bad ldap server options!\n", 
      __FUNCTION__, __LINE__));
    FlushRequest( argc, argv);
    return CANT_PROC_LDAP_OPT;
  }

  ld = ldap_tool_conn_setup( 0, NULL, &conSetupStatus );
  if (ld == NULL) {
    LOG((EFI_D_ERROR, "Can't init ldap session!\n"));
    if (conSetupStatus == LDAP_CON_ERROR_TO_START_TLS)
      retval = LDAP_ERROR_TO_START_TLS;
    else if (conSetupStatus == LDAP_CON_ERROR_SERVER_DOWN)
      retval = CANT_CONNECT_TO_LDAP;
    else
      retval = CANT_INIT_LDAP_SESSION;
    goto EXIT;
  }

  status = ldap_tool_bind( ld );
  if ( LDAP_SUCCESS == status) {
    LOG((EFI_D_ERROR, "%a.%d: Ok! Auth success!!\n", 
      __FUNCTION__, __LINE__));
    retval = LDAP_AUTH_PASS;
  } else if ( LDAP_INVALID_CREDENTIALS == status) {
    LOG((EFI_D_ERROR, "%a.%d: Fail to auth the user!\n", 
      __FUNCTION__, __LINE__));
    retval = LDAP_AUTH_FAIL;
  } else {
    LOG((EFI_D_ERROR, "%a.%d: Ldap internal error!\n", 
      __FUNCTION__, __LINE__));
    retval = LDAP_INTERNAL_ERROR;
  }

EXIT:
  if (ld != NULL) 
    ldap_tool_unbind(ld);

  ldap_tool_destroy();

  FlushRequest( argc, argv);

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Find a user and get a matched DN */
/*! \param[in]  *userName Pointer to user name
    \param[out] Status of the operation */
/*! \return Pointer to a found DN for a user */
/*! \retval CANT_MAKE_REQUEST Can't make a search request 
    \retval CANT_PROC_LDAP_OPT Bad ldap client options
    \retval CANT_INIT_LDAP_SESSION Can't init ldap session (internal error) 
    \retval LDAP_INTERNAL_ERROR Internal error of the ldap client tool. See debug output for more details */
//------------------------------------------------------------------------------
CHAR8*
GetUserDnFromLdapServer(
  IN  CHAR16* userName, 
  OUT UINTN*  status
  )
{
  CHAR8 *userName8;
  CHAR8 *userDn        = NULL;

  LDAP_FILTER_PAIR FilterOne[2] = {{SAM_ACCOUNT_ATTR, NULL}, {NULL, NULL}};
  CHAR8 *attrs[] = { OBJ_CLASS_ATTR, NULL };
  ldapAttributeList_t *attrsList[] = {NULL, NULL};
  ldapAttributePair attrPair = {NULL, NULL, NULL};

  LOG((EFI_D_ERROR, "%a.%d userName = %s\n", __FUNCTION__, __LINE__, userName));

  *status = CANT_CONNECT_TO_LDAP;

  userName8 = AllocateZeroPool(StrSize(userName));
  if (NULL == userName8) {
    LOG((EFI_D_ERROR, "%a.%d: Error!\n", 
      __FUNCTION__, __LINE__));
    *status = LDAP_OUT_OF_MEMORY;
    return NULL;
  }
  UnicodeStrToAsciiStr(userName, userName8);

  attrPair.entryDn = &userDn;
  attrPair.attrs = attrs;
  attrPair.pAttrList = attrsList;
  FilterOne[0].Value = userName8;
  *status = GetAttributeListForEntry(NULL, FALSE, FilterOne, &attrPair);

  FreePool (userName8);

  if (LDAP_SEARCH_SUCCESS == *status) {
    LOG((EFI_D_ERROR, "%a.%d userDn = %a\n", __FUNCTION__, __LINE__, userDn));
    return userDn;
  }

  LOG((EFI_D_ERROR, "%a.%d: *status = %d\n", __FUNCTION__, __LINE__, *status));
  return NULL;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get an user certificate from ldap server */
/*! \param[in] matchedCertificateValue A value to find a CA on a server: certificate_serial_number$certificate_issuer_DN
    \param[out] number of certificates has been found
    \param[out] retval Status of the operation */
/*! \return dn of a user with the matched certificate */
/*! \retval CANT_MAKE_REQUEST Can't make a search request 
    \retval CANT_PROC_LDAP_OPT Bad ldap client options
    \retval CANT_INIT_LDAP_SESSION Can't init ldap session (internal error) 
    \retval LDAP_INTERNAL_ERROR Internal error of the ldap client tool. See debug output for more details
    \retval LDAP_ROOT_ERR_CREDENTIALS Invalid bind DN or bind PW
    \retval CANT_CONNECT_TO_LDAP Can't connect to ldap server
    \retval LDAP_SEARCH_ERROR No entries
    \retval LDAP_SEARCH_SUCCESS Ldap server returned a success */
//------------------------------------------------------------------------------
CHAR8*
EFIAPI
SearchUserCertificateFromLdapServer(
  IN  CHAR8*  matchedCertificateValue,
  OUT CHAR8** accountName,
  OUT UINTN*  numberOfCertificates,
  OUT UINTN*  retval
  )
{
  CHAR8 *userDn    = NULL;

  LDAP_FILTER_PAIR FilterOne[2] = {{USER_CERT_ATTR, NULL}, {NULL, NULL}};
  CHAR8 *userAttrs[]   = { USER_CERT_ATTR, SAM_ACCOUNT_ATTR, NULL };
  ldapAttributeList_t *attrsList[] = {NULL, NULL, NULL};
  ldapAttributePair attrPair = {NULL, NULL, NULL};

  ldapAttributeList_t userList = {0, NULL};

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  if (matchedCertificateValue == NULL) {
    LOG((EFI_D_ERROR, "%a.%d: matchedCertificateValue is NULL!\n", 
      __FUNCTION__, __LINE__));
    *retval = CANT_MAKE_REQUEST;
    return NULL;
  }

  attrsList[0] = &certList;
  attrsList[1] = &userList;
  attrPair.entryDn = &userDn;
  attrPair.attrs = userAttrs;
  attrPair.pAttrList = attrsList;
  FilterOne[0].Value = matchedCertificateValue;
  *retval = GetAttributeListForEntry(NULL, FALSE, FilterOne, &attrPair);

  if (LDAP_SEARCH_SUCCESS != *retval) {
    LOG((EFI_D_ERROR, "%a.%d: *retval = %d\n", __FUNCTION__, __LINE__, *retval));
    return NULL;
  }

  *numberOfCertificates = certList.numberOfItems;
  LOG((EFI_D_ERROR, "%a.%d *numberOfCertificates = %d\n", __FUNCTION__, __LINE__, *numberOfCertificates));

  if (userList.numberOfItems > 1) {
    LOG((EFI_D_ERROR, "%a.%d: Too many entries: %d!\n", 
      __FUNCTION__, __LINE__, userList.numberOfItems));
    *retval = LDAP_TOO_MANY_ENTRIES;
    goto EXIT;
  }

  if (userList.numberOfItems == 1) {
    *accountName = AllocateZeroPool (userList.attributeValueList[0].dataLen + sizeof(CHAR8));
    if (NULL == *accountName) {
      LOG((EFI_D_ERROR, "%a.%d: Error!\n", 
        __FUNCTION__, __LINE__));
      *retval = LDAP_OUT_OF_MEMORY;
      goto EXIT;
    }
    AsciiStrnCpy (*accountName, userList.attributeValueList[0].data, userList.attributeValueList[0].dataLen);
    LOG((EFI_D_ERROR, "%a.%d *accountName = %a\n", __FUNCTION__, __LINE__, *accountName));
  } else {
    LOG((EFI_D_ERROR, "%a.%d: No entries: %d!\n", 
      __FUNCTION__, __LINE__, userList.numberOfItems));
    *retval = LDAP_SEARCH_ERROR;
    goto EXIT;
  }

EXIT:
  FlushAttributeList(&userList);

  if (LDAP_SEARCH_SUCCESS == *retval) {
    return userDn;
  }

  return NULL;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get an userCertificate we have found */
/*! You have to init caData before call this function! e.g: caData = {0, NULL} */
/*! You have to delete received caData, when you dont need it any more. Use FreeReceivedUserCertificates() */
/*! \param[in] numberOfCertificate A number of a requested userCertificate (0..N-1), N - is a count of certificates
    \param[out] caData data of a userCertificate */
//------------------------------------------------------------------------------
VOID
GetUserCertificateByNum (
  IN  UINTN numberOfCertificate,
  OUT UserCertificateData_t* caData
  )
{
  if ((certList.numberOfItems > 0) && (numberOfCertificate < certList.numberOfItems)) {
    if (certList.attributeValueList != NULL) {
      if (certList.attributeValueList[numberOfCertificate].data != NULL) {
        caData->dataLen = certList.attributeValueList[numberOfCertificate].dataLen;
        caData->data    = certList.attributeValueList[numberOfCertificate].data;
        return;
      }
    }
  }

  caData->data = NULL;

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Free data of a received userCertificates */
//------------------------------------------------------------------------------
VOID
FreeReceivedUserCertificates (
  VOID
  )
{
  FlushAttributeList(&certList);
  ZeroMem(&certList, sizeof(certList));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get an user permission to login */
/*! Host is a system GUID */
/*! \param[in] *userDN DN of the user
    \param[out] *retval A status of operaton */
//------------------------------------------------------------------------------
USER_AUTH_PERMISSION
CheckUserLoginPermission (
  IN CHAR8 *userDN,
  OUT UINTN *retval
  )
{
  EFI_STATUS     Status = EFI_ABORTED;
  EFI_GUID       hostGuid;

  USER_AUTH_PERMISSION  permission = NOT_ALLOW_TO_LOGIN;

  Status = GetSystemGuidFromVolume(&hostGuid);
  if (EFI_ERROR(Status)) {
    *retval = LDAP_CANT_GET_SYSTEM_GUID;
    return permission;
  }

  *retval = LDAP_ERROR_TO_GET_PERMIT;

   permission = GetPermWithUserDNandPCguid(userDN, &hostGuid, retval);

  return permission;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get an auth users list from LDAP server */
/*! \param[out] *retval A status of operaton */
//------------------------------------------------------------------------------
LDAP_USER_AUTH_DB*
GetTokenUserDBFromLdapServer (
  OUT UINTN *retval
)
{
  EFI_STATUS     Status = EFI_ABORTED;
  EFI_GUID       hostGuid;

  LDAP_USER_AUTH_DB *ldapAuthUserList = NULL;

  Status = GetSystemGuidFromVolume(&hostGuid);
  if (EFI_ERROR(Status)) {
    *retval = LDAP_CANT_GET_SYSTEM_GUID;
    return NULL;
  }

  *retval = LDAP_SEARCH_ERROR;

  ldapAuthUserList = GetTokenUserDBWithPCguid(&hostGuid, retval);

  return ldapAuthUserList;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Free received token user DB */
/*! param[in] *userDB A DB to free */
//------------------------------------------------------------------------------
VOID
FreeTokenUserDBInternal (
  IN LDAP_USER_AUTH_DB *userDB
)
{
  UINTN userCount = 0;
  LDAP_AUTH_TOKEN_USER_INFO *beginOfList = NULL;

  LOG((EFI_D_ERROR, "%a.%d:\n", __FUNCTION__, __LINE__));

  if (userDB == NULL) {
    LOG((EFI_D_ERROR, "%a.%d: No need to free\n", __FUNCTION__, __LINE__));
    return;
  }

  if (userDB->userCount > 0 && userDB->ldapAuthUserList != NULL) {
    beginOfList = userDB->ldapAuthUserList;
    for (userCount = 0; userCount < userDB->userCount; userCount++) {
      if (beginOfList == NULL)
        break;

      if (beginOfList->userDN != NULL)
        FreePool(beginOfList->userDN);
      if (beginOfList->userName != NULL)
        FreePool(beginOfList->userName);
      if (beginOfList->certData != NULL)
        FreePool(beginOfList->certData); 

      beginOfList++;
    }
  }

  if (userDB->ldapAuthUserList != NULL)
    FreePool(userDB->ldapAuthUserList);

  LOG((EFI_D_ERROR, "%a.%d:\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Free received token user DB */
/*! param[in] *userDB A DB to free */
//------------------------------------------------------------------------------
VOID
FreeTokenUserDB (
  IN LDAP_USER_AUTH_DB *userDB
)
{
  LOG((EFI_D_ERROR, "%a.%d:\n", __FUNCTION__, __LINE__));

  if (userDB == NULL) {
    LOG((EFI_D_ERROR, "%a.%d: No need to free\n", __FUNCTION__, __LINE__));
    return;
  }

  FreeTokenUserDBInternal (userDB);
  FreePool (userDB);

  LOG((EFI_D_ERROR, "%a.%d:\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Drop saved LDAP connection and free resources */
//------------------------------------------------------------------------------
VOID
EFIAPI
CleanLdapConnection(VOID)
{
  LOG((EFI_D_ERROR, "%a.%d:\n", __FUNCTION__, __LINE__));

  if (g_ldap_conn_type != LDAP_CONN_NONE) {
    LOG((EFI_D_ERROR, "%a.%d: Drop saved connection\n", __FUNCTION__, __LINE__));
    if (g_ldap_ld != NULL) 
      ldap_tool_unbind(g_ldap_ld);

    ldap_tool_destroy();

    FlushRequest(g_ldap_argc, g_ldap_argv);
    g_ldap_argv = NULL;
    g_ldap_argc = 1;
    g_ldap_ld = NULL;
    g_ldap_conn_type = LDAP_CONN_NONE;
  }

  LOG((EFI_D_ERROR, "%a.%d:\n", __FUNCTION__, __LINE__));
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Init FsUtils for StdLib is used by LdapAuthDxe */
//------------------------------------------------------------------------------
static VOID
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
/*! \brief Entry point of the ldap auth DXE driver */
//------------------------------------------------------------------------------
EFI_STATUS
EFIAPI
LdapAuthDxeInit (
  IN EFI_HANDLE ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  EFI_STATUS Status = EFI_SUCCESS;

  LOG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  InitFsUtilsForStdLib(ImageHandle);

  ZeroMem(&gLdapAuthInternalData, sizeof(gLdapAuthInternalData));

  InitLdapConfigOp(&(gLdapAuthInternalData.LdapAuhtPtotocol.LdapConfigOp));

  gLdapAuthInternalData.LdapAuhtPtotocol.GetUserDnFromLdapServer              = GetUserDnFromLdapServer;
  gLdapAuthInternalData.LdapAuhtPtotocol.CheckDnPwdOnLdapServer               = CheckDnPwdOnLdapServer;

  gLdapAuthInternalData.LdapAuhtPtotocol.SearchUserCertificateFromLdapServer  = SearchUserCertificateFromLdapServer;
  gLdapAuthInternalData.LdapAuhtPtotocol.GetUserCertificateByNum              = GetUserCertificateByNum;
  gLdapAuthInternalData.LdapAuhtPtotocol.FreeReceivedUserCertificates         = FreeReceivedUserCertificates;

  gLdapAuthInternalData.LdapAuhtPtotocol.CheckUserLoginPermission             = CheckUserLoginPermission;

  gLdapAuthInternalData.LdapAuhtPtotocol.GetTokenUserDBFromLdapServer         = GetTokenUserDBFromLdapServer;
  gLdapAuthInternalData.LdapAuhtPtotocol.FreeTokenUserDB                      = FreeTokenUserDB;

  gLdapAuthInternalData.LdapAuhtPtotocol.CleanLdapConnection                  = CleanLdapConnection;

  if (RegisterSelfInGlobalConfig() != EFI_SUCCESS) {
    LOG((EFI_D_ERROR, "Error to register LdapConfig in GlobalConfig\n"));
    return EFI_ABORTED;
  }

  Status = gBS->InstallProtocolInterface(
                  &gLdapAuthInternalData.DriverHandle,
                  &gLdapAuthDxeProtocolGuid,
                  EFI_NATIVE_INTERFACE,
                  &gLdapAuthInternalData.LdapAuhtPtotocol
                );

  LOG((EFI_D_ERROR, "%a.%d Status=0x%X\n", __FUNCTION__, __LINE__, Status));

  return Status;
}
//------------------------------------------------------------------------------

