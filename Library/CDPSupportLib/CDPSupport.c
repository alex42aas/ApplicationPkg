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
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/CDPSupportLib/CDPSupport.h>

#include <string.h>
#include <stdlib.h>

#include <Protocol/IniParserDxe.h>
#include <Protocol/GlobalConfigDxe.h>
#include <Protocol/GlobalConfigType.h>

#include "CDPInternal.h"

static CDP_STATUS lastStatus = CDP_INVALID_PARAMETER;

extern CHAR8 cdpLdapSectionName[];

extern
CONFIG_ERROR_T
SetCDPLdapConfigFromDictionary (
  IN dictionary *dict
);

extern
CONFIG_ERROR_T
DumpCDPLdapConfigToDictionary (
  IN dictionary *dict
);

//------------------------------------------------------------------------------
/*! \brief Parse url */
/*! URL can contain %20. This is a SPACE character. We have to replace it */
//------------------------------------------------------------------------------
static
UINT8
ParseUrl (
  IN CHAR8 *url,
  OUT CHAR8 **pHost,
  OUT CHAR8 **pPort,
  OUT CHAR8 **pPath
  )
{
  CHAR8 *end = NULL, *p = NULL, *m = NULL, *chunk = NULL, *host = NULL, *port = NULL;
  UINTN i, j, len;

  DEBUG((EFI_D_ERROR, "%a.%d url: %a\n", __FUNCTION__, __LINE__, url));

  i = 0;
  j = 0;

  // Check for at least one %20 (space)
  chunk = strchr(url, '%');
  if (chunk != NULL) {
    len = strlen(url);
    m = AllocateZeroPool(len + sizeof(CHAR8));
    while(i < len) {
      if (url[i] == 0x25) {
        m[j] = 0x20; // add space
        i += 3;
        j++;
        if (i >= len) {
          break;
        }
      } else {
        m[j] = url[i];
        i++;
        j++;
      }
    }
  }
  DEBUG((EFI_D_ERROR, "%a.%d m: %a\n", __FUNCTION__, __LINE__, m));

  if (m != NULL)
    p = strchr(m, ':');
  else
    p = strchr(url, ':');

  if (p == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return 0;
  }

  p++;

  // Check for double slash
  if ((p[0] != '/') || (p[1] != '/')) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return 0;
  }

  p += 2;
  host = p;

  // Check for trailing part of path (dn)
  p = strchr(p, '/');
  if (p == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return 0;
  } else {
    p++;
    end = strchr(p, '?');
    if (end == NULL) {
      *pPath = strdup(p);
    } else {
      *end = '\0';
      *pPath = strdup(p);
    }
    *(--p) = '\0';
  }

  // Look for optional ':' for port number
  p = strchr(host, ':');
  if (p != NULL) {
    port = p + 1;
    *pPort = strdup(port);
    if (*pPort == NULL) {
      DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
      goto _error;
    }
  }

  *pHost = strdup(host);
  if (*pHost == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    goto _error;
  }

  if (m != NULL)
    free(m);

  return 1;
  
_error:
  if (m != NULL)
    free(m);

  if (*pPath != NULL) {
    free(*pPath);
    *pPath = NULL;
  }
  if (*pPort != NULL) {
    free(*pPort);
    *pPort = NULL;
  }
  if (*pHost != NULL) {
    free(*pHost);
    *pHost = NULL;
  }
  return 0;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Parse CDP URL */
//------------------------------------------------------------------------------
static
UINT8
ParseUrlCDP (
  IN CHAR8 *cdpURL,
  IN UINT8 *protocol,
  IN BOOLEAN *useSSL,
  OUT CHAR8 **pHost,
  OUT CHAR8 **pPort,
  OUT CHAR8 **pDn,
  OUT CHAR8 **pPath
)
{
  CHAR8 *buf = NULL, *p = NULL;
  UINT8 retval = 0;

  *pHost = NULL;
  *pPort = NULL;
  *pDn   = NULL;
  *pPath = NULL;

  buf = strdup(cdpURL);
  if (buf == NULL) {
    DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return 0;
  }

  p = strstr(buf, "ldaps");
  if (p != NULL) {
    retval = ParseUrl(p, pHost, pPort, pDn);
    if (retval > 0) {
      *protocol = CDP_LDAP;
      *useSSL = TRUE;
      if (*pPort == NULL)
        *pPort = strdup("389");
      goto _exit;
    }
  }
  p = strstr(buf, "ldap");
  if (p != NULL) {
    retval = ParseUrl(p, pHost, pPort, pDn);
    if (retval > 0) {
      *protocol = CDP_LDAP;
      *useSSL = FALSE;
      if (*pPort == NULL)
        *pPort = strdup("389");
      goto _exit;
    }
  }
  p = strstr(buf, "https");
  if (p != NULL) {
    retval = ParseUrl(p, pHost, pPort, pPath);
    if (retval > 0) {
      *protocol = CDP_HTTP;
      *useSSL = TRUE;
      if (*pPort == NULL)
        *pPort = strdup("80");
      goto _exit;
    }
  }
  p = strstr(buf, "http");
  if (p != NULL) {
    retval = ParseUrl(p, pHost, pPort, pPath);
    if (retval > 0) {
      *protocol = CDP_HTTP;
      *useSSL = FALSE;
      if (*pPort == NULL)
        *pPort = strdup("80");
      goto _exit;
    }
  }

  *protocol = CDP_OTHER;

_exit:
  free(buf);
  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get CRL using url */
/*! Hide details. Use specific functions for LDAP and HTTP */
/*! \param[in] *cdpURL A pointer to the URL 
    \param[out] *numCRLs Number of CRLs have been received from LDAP server 
    \return Status Status of operation */
//------------------------------------------------------------------------------
CDP_STATUS
SearchCrlWithCDP (
  IN CHAR8 *cdpURL,
  OUT UINTN *numCRLs
)
{
  UINT8 protocol;
  CDP_STATUS Status;
  BOOLEAN useSSL = FALSE;
  CHAR8 *host = NULL, *dn = NULL, *path = NULL, *port = NULL;

  DEBUG((EFI_D_ERROR, "%a.%d: %a\n", __FUNCTION__, __LINE__, cdpURL));

  if (cdpURL == NULL || numCRLs == NULL)
    return CDP_INVALID_PARAMETER;

  if (ParseUrlCDP(cdpURL, &protocol, &useSSL, &host, &port, &dn, &path) <= 0) {
    DEBUG((EFI_D_ERROR, "%a.%d: CDP_CANT_PARSE_URL\n", __FUNCTION__, __LINE__));
    return CDP_CANT_PARSE_URL;
  }

  DEBUG((EFI_D_ERROR, "%a.%d: %host: %a\n dn: %a\n port: %a\n path: %a\n protocol: %d\n",
    __FUNCTION__, __LINE__, host, dn, port, path, protocol));

  switch (protocol) {
    case CDP_LDAP:
      Status = SearchListOfCRLFromLDAP(useSSL, host, port, dn, numCRLs);
      if (Status == CDP_LDAP_SEARCH_SUCCESS) Status = CDP_SEARCH_SUCCESS;
      break;
    case CDP_HTTP:
    default:
      Status = CDP_UNSUPPORTED_PROTOCOL;
      break;
  }

  if (host != NULL)
    FreePool(host);
  if (dn != NULL)
    FreePool(dn);
  if (path != NULL)
    FreePool(path);
  if (port != NULL)
    FreePool(port);

  DEBUG((EFI_D_ERROR, "%a.%d: Status: %d\n", __FUNCTION__, __LINE__, Status));

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Return last error has occured */
//------------------------------------------------------------------------------
CDP_STATUS
GetCDPLastError (
  VOID
)
{
  return lastStatus;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set CDP last error code */
//------------------------------------------------------------------------------
VOID
SetCDPLastError (
  CDP_STATUS status
)
{
  lastStatus = status;
  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief CDPSupportLib Constructor */
//------------------------------------------------------------------------------
EFI_STATUS
EFIAPI
CDPSupportLibConstructor (
  VOID
)
{
  EFI_STATUS status;
  GLOBAL_CONFIG_PROTOCOL *pGlobalConfigProtocol = NULL;

  DEBUG((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));

  status = gBS->LocateProtocol (
           &gGlobalConfigProtocolGuid,
           NULL,
           (VOID **) &pGlobalConfigProtocol
           );
  if (EFI_ERROR(status)) {
    DEBUG((EFI_D_ERROR, "%a.%d: Error: status = 0x%x\n", __FUNCTION__, __LINE__, status));
    return status;
  }

  status = pGlobalConfigProtocol->AddConfig(cdpLdapSectionName,
                                    SetCDPLdapConfigFromDictionary, DumpCDPLdapConfigToDictionary);

  DEBUG((EFI_D_ERROR, "%a.%d:  status: 0x%x\n", __FUNCTION__, __LINE__, status));

  return status;
}
//------------------------------------------------------------------------------

