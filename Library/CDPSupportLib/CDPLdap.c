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

#include <LdapCommon.h>

#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include <Library/Lib/OpensslFunctions.h>
#include <Library/Lib/CertificatesControl.h>

#include "CDPInternal.h"
#include "CDPLdapConfig.h"

static CHAR8 hostOpt[] = "-h";
static CHAR8 portOpt[] = "-p";
static CHAR8 authOpt[] = "-x";
static CHAR8 dnOpt[]   = "-D";
static CHAR8 pwOpt[]   = "-w";
static CHAR8 baseOpt[] = "-b";
static CHAR8 objOpt[]  = "objectClass=cRLDistributionPoint";
static CHAR8 tlsOpt[]  = "-ZZ";

static ldapAttributeList_t crlList = {0, NULL};

//------------------------------------------------------------------------------
/*! \brief Convert LDAP internal errors to LDAP CDP errors */
/*! \param[in] ldapErrorCode Error code from openLdap library */
/*! \return LDAP CDP error */
//------------------------------------------------------------------------------
static
CDP_STATUS
ProcessingLDAPError(
  int ldapErrorCode
  )
{
  CDP_STATUS retval = CDP_CANT_CONNECT_TO_LDAP;
    
  DEBUG((EFI_D_ERROR, "%a.%d: LDAP status: %d\n", 
    __FUNCTION__, __LINE__, ldapErrorCode));
    
  switch(ldapErrorCode) {
  case LDAP_NO_SUCH_OBJECT:
    retval = CDP_LDAP_SEARCH_ERROR;
    break;
  case LDAP_LOCAL_ERROR:
    retval = CDP_LDAP_INTERNAL_ERROR;
    break;
  case LDAP_INVALID_CREDENTIALS:
    retval = CDP_LDAP_ROOT_ERR_CREDENTIALS;
    break;
  case LDAP_UNWILLING_TO_PERFORM:
    retval = CDP_LDAP_SERVER_DENY;
    break;
  case LDAP_INVALID_DN_SYNTAX:
    retval = CDP_LDAP_CANT_PROC_OPT;
    break;
  case LDAP_MORE_RESULTS_TO_RETURN:
    retval = CDP_LDAP_TOO_MANY_ENTRIES;
    break;
  default:
    retval = CDP_CANT_CONNECT_TO_LDAP;
    break;
  }

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Flush a request (a vector of arguments) */
/*! \param[in] argc Number of arguments in the vector
    \param[in] **argv Pointer to the vector */
//------------------------------------------------------------------------------
static VOID
FlushRequest( UINTN argc, CHAR8** argv)
{
  UINTN count; 

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

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

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Make a search request for the ldap server */
/*! Make a request to search certificateRevocationList in the ldap server. */
/*! We use LdapAuthProtocol to read LdapConfig: binddn and bindpw */
/*! \return Vector of arguments for a ldap tool */
//------------------------------------------------------------------------------
static
CHAR8**
MakeLdapSearchRequest (
  IN BOOLEAN useSSL,
  IN CHAR8 *host,
  IN CHAR8 *port,
  IN CHAR8 *dn,
  OUT UINTN *count
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
  CHAR8 *pStTLSOpt  = NULL;
  CHAR8 *pDnOpt     = NULL;
  CHAR8 *pPwOpt     = NULL;

  CHAR8 **request   = NULL;

  UINTN argc = 1;

  if (host == NULL || port == NULL || dn == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return NULL;
  }

  if (EFI_ERROR(ReadCDPLdapConfig())) {
    DEBUG((EFI_D_ERROR, "%a.%d: Error \n", __FUNCTION__, __LINE__));
    return NULL;
  }

  request = AllocateZeroPool(LDAP_CDP_NUM_ARGS*sizeof(CHAR8*));
  if (NULL == request) {
    DEBUG((EFI_D_ERROR, "%a.%d: Can't allocate %d bytes for request!\n", 
      __FUNCTION__, __LINE__, LDAP_CDP_NUM_ARGS*sizeof(CHAR8*)));
    return NULL;
  }

  //------------------------------------------------------------
  // Make -h (host) argument
  //------------------------------------------------------------
  pHostOpt = AllocateZeroPool(sizeof(hostOpt));
  if (NULL == pHostOpt)
      goto _error_exit;

  AsciiStrCpy(pHostOpt, hostOpt);
  request[argc++] = pHostOpt;

  hostData = AllocateZeroPool(AsciiStrSize(host));
  if (NULL == hostData)
      goto _error_exit;

  AsciiStrCpy(hostData, host);
  request[argc++] = hostData;

  //------------------------------------------------------------
  // Make -p (port) argument
  //------------------------------------------------------------
  pPortOpt = AllocateZeroPool(sizeof(portOpt));
  if (NULL == pPortOpt)
      goto _error_exit;
      
  AsciiStrCpy(pPortOpt, portOpt);
  request[argc++] = pPortOpt;
  
  portData = AllocateZeroPool(AsciiStrSize(port));
  if (NULL == portData) {
      goto _error_exit;
  }
  AsciiStrCpy(portData, port);
  request[argc++] = portData;

  //------------------------------------------------------------
  // Make -x (auth) argument
  //------------------------------------------------------------
  pAuthOpt = AllocateZeroPool(sizeof(authOpt));
  if (NULL == pAuthOpt)
      goto _error_exit;
  
  AsciiStrCpy(pAuthOpt, authOpt);
  request[argc++] = pAuthOpt;

  //------------------------------------------------------------
  // Make -ZZ (StartTLS with a reading the status) argument
  //------------------------------------------------------------
  if (useSSL == TRUE) {
      pStTLSOpt = AllocateZeroPool(sizeof(tlsOpt));
      if (NULL == pStTLSOpt)
          goto _error_exit;
          
      AsciiStrCpy(pStTLSOpt, tlsOpt);
      request[argc++] = pStTLSOpt;
  }

  //------------------------------------------------------------
  // Make -b (base) argument
  //------------------------------------------------------------
  pBaseOpt = AllocateZeroPool(sizeof(baseOpt));
  if (NULL == pBaseOpt)
      goto _error_exit;

  AsciiStrCpy(pBaseOpt, baseOpt);
  request[argc++] = pBaseOpt;
  
  baseData = AllocateZeroPool(AsciiStrSize(dn));
  if (NULL == baseData) {
      goto _error_exit;
  }

  AsciiStrCpy(baseData, dn);
  request[argc++] = baseData;

  //------------------------------------------------------------
  // Make -D (dn) argument
  //------------------------------------------------------------
  if (GetSizeOfCDPLdapRootdn() > 0 &&
        GetCDPLdapRootdn() != NULL) {
    pDnOpt = AllocateZeroPool(sizeof(dnOpt));
    if (NULL == pDnOpt)
      goto _error_exit;

    AsciiStrCpy(pDnOpt, dnOpt);
    request[argc++] = pDnOpt;
    
    dnData = AllocateZeroPool((GetSizeOfCDPLdapRootdn())/2);
    if (NULL == dnData) {
      goto _error_exit;
    }
    UnicodeStrToAsciiStr(GetCDPLdapRootdn(), dnData);
    request[argc++] = dnData;
  }
  
  //------------------------------------------------------------
  // Make -w (pw) argument
  //------------------------------------------------------------
  if (GetSizeOfCDPLdapRootpw() > 0 &&
        GetCDPLdapRootpw() != NULL) {
    pPwOpt = AllocateZeroPool(sizeof(pwOpt));
    if (NULL == pPwOpt)
      goto _error_exit;

    AsciiStrCpy(pPwOpt, pwOpt);
    request[argc++] = pPwOpt;
    
    pwData = AllocateZeroPool((GetSizeOfCDPLdapRootpw())/2);
    if (NULL == pwData) {
      goto _error_exit;
    }
    UnicodeStrToAsciiStr(GetCDPLdapRootpw(), pwData);
    request[argc++] = pwData;
  }

  DEBUG((EFI_D_ERROR, "%a.%d: Success! argc: %d request: %p\n", 
    __FUNCTION__, __LINE__, argc, request));

  *count = argc;
  
  return request;

_error_exit:
  FlushRequest( argc, request );
  
  DEBUG((EFI_D_ERROR, "%a.%d: _error_exit! argc: %d\n", 
    __FUNCTION__, __LINE__, argc));
  
  return NULL;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Read ldap server ip or name frol LdapConfig */
/*! You have to free memory, when you don't need the host string */
/*! \return A host */
//------------------------------------------------------------------------------
static
CHAR8*
GetLdapServerFromConfig (
  VOID
)
{
  CHAR8* host = NULL;

  if (StrLen(GetCDPLdapServerAddr()) > 0) {
    // Use LDAP server address
    host = AllocateZeroPool(StrLen(GetCDPLdapServerAddr()));
    if (host == NULL)
      return NULL;
    UnicodeStrToAsciiStr(GetCDPLdapServerAddr(), host);

  } else if (GetSizeOfCDPLdapServerName() > 0 &&
             GetCDPLdapServerName() != NULL) {
    // Use LDAP server name
    if (StrLen(GetCDPLdapServerName()) > 0) {
      host = AllocateZeroPool(StrLen(GetCDPLdapServerName()));
      if (host == NULL)
        return NULL;
      UnicodeStrToAsciiStr(GetCDPLdapServerName(), host);
    }

  }

  DEBUG((EFI_D_ERROR, "%a.%d host: %a \n", __FUNCTION__, __LINE__, host));

  return host;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get a list of CRLs from LDAP server */
/*! Find crlDistributionPoint entries on LDAP server, get CRLs from them */
/*! \param[in] useSSL
    \param[in] host A name or an adress of LDAP server
    \param[in] port Port of LDAP server
    \param[in] dn A search base where we search CDP entries
    \param[out] numCRLs A number of received CRLs
    \param[out] Status Error code */
/*! \return A list of CRLs, NULL if error or no CRLs */
/*! \retval CDP_INVALID_PARAMETER IN parameters shouldn't be NULL
    \retval CDP_CANT_MAKE_REQUEST Cant make LDAP request (local error) */
//------------------------------------------------------------------------------
CDP_STATUS
SearchListOfCRLFromLDAP (
  IN BOOLEAN useSSL,
  IN CHAR8 *host,
  IN CHAR8 *port,
  IN CHAR8 *dn,
  OUT UINTN *numCRLs
)
{
  LDAP   *ld         = NULL;
  CHAR8  *searchData = NULL;
  CHAR8  **argv      = NULL;
  CHAR8  *hostReserv = NULL;
  CHAR8  *hostToUse  = NULL;
  UINTN  argc        = 1;
  UINT32 status      = LDAP_SUCCESS;
  CDP_STATUS Status;

  CHAR8 *attrs[] = {"certificateRevocationList", 0};
  ldapAttributeList_t *attrsList[] = {&crlList, NULL};
  ldapAttributePair attrPair = {NULL, NULL, NULL};

  DEBUG((EFI_D_ERROR, "%a.%d:\n", __FUNCTION__, __LINE__));

  attrPair.attrs = attrs;
  attrPair.pAttrList = attrsList;

  if (useSSL == TRUE) {
    tlsConfig_t config = MakeTlsConfig(ChainGetData()->Data, ChainGetData()->DataLen);
    if (ldap_set_tls_config(config) != 0)
       DEBUG((EFI_D_ERROR, "%a.%d: Can't set OpenSSL.cnf. Will be used default settings\n",
         __FUNCTION__, __LINE__));
  }

  if (AsciiStrLen(host) == 0) {
    hostReserv = GetLdapServerFromConfig();
    if (hostReserv == NULL)
      return CDP_CANT_GET_SERVER_ADDRESS;
    else
      hostToUse = hostReserv;
  } else
    hostToUse = host; 

  argv = MakeLdapSearchRequest(useSSL, hostToUse, port, dn, &argc);
  if (NULL == argv) {
    DEBUG((EFI_D_ERROR, "%a.%d: Can't make ldap request!\n", 
      __FUNCTION__, __LINE__));
    Status = CDP_LDAP_CANT_MAKE_REQUEST;
    goto _exit;
  }

  status = ldap_tool_args((int)argc, argv);
  if (status != LDAP_SUCCESS) {
    DEBUG((EFI_D_ERROR, "%a.%d: Bad ldap server options!\n", 
      __FUNCTION__, __LINE__));
    FlushRequest( argc, argv);
    Status = CDP_LDAP_CANT_PROC_OPT;
    goto _exit;
  }

  ld = ldap_tool_conn_setup( 0, NULL, &status );
  if (ld == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d: Can't init ldap session!\n", 
      __FUNCTION__, __LINE__));
    Status = CDP_LDAP_CANT_INIT_SESSION;
    goto _exit;
  }

  status = ldap_tool_bind( ld );

  if (LDAP_SUCCESS == status) {
    searchData = AllocateZeroPool(sizeof(objOpt));
    if (NULL == searchData) {
      Status = CDP_OUT_OF_MEMORY;
      goto _exit;
    }

    AsciiStrCpy(searchData, objOpt);

    status = ldap_attr_multisearch(ld, &attrPair, searchData);
    if (status != LDAP_SUCCESS)
      goto _error_exit;

    *numCRLs = crlList.numberOfItems;

    DEBUG((EFI_D_ERROR, "%a.%d: num CRLs: %d\n", 
      __FUNCTION__, __LINE__, *numCRLs));

    if (crlList.numberOfItems > 0)
      Status = CDP_LDAP_SEARCH_SUCCESS;
    else
      Status = CDP_LDAP_SEARCH_ERROR;

  }
   else {
_error_exit:
  Status = ProcessingLDAPError(status);
  }
_exit:
  if (ld != NULL) 
    ldap_tool_unbind(ld);

  ldap_tool_destroy();

  FlushRequest(argc, argv);

  if (searchData != NULL)
    FreePool(searchData);
  if (hostReserv != NULL)
    FreePool(hostReserv);

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get CRL we have found */
/*! \param[in] numberOfCRL A number of a requested CRL (0..N-1), N - is a count of CRLs
    \param[out] crlData data of a CRL
    \param[out] lenOfData A length of data */
//------------------------------------------------------------------------------
VOID
GetCRLByNum (
  IN  UINTN numberOfCRL,
  OUT UINT8 **crlData,
  OUT UINTN *lenOfData
  )
{
  if ((crlList.numberOfItems > 0) && (numberOfCRL < crlList.numberOfItems)) {
    if (crlList.attributeValueList != NULL) {
      if (crlList.attributeValueList[numberOfCRL].data != NULL) {
        *lenOfData  = crlList.attributeValueList[numberOfCRL].dataLen;
        *crlData    = crlList.attributeValueList[numberOfCRL].data;
        return;
      }
    }
  }

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Free data of a received CRLs */
//------------------------------------------------------------------------------
VOID
FreeReceivedCRLs (
  VOID
  )
{
  FlushAttributeList(&crlList);
  
  return;
}
//------------------------------------------------------------------------------
