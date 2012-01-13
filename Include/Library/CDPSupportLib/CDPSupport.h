/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef CDP_SUPPORT_H_
#define CDP_SUPPORT_H_

#define CDP_LDAP  0
#define CDP_HTTP  1
#define CDP_OTHER 2

typedef enum {
              CDP_REFRESH_SUCCESSFUL,         // 0
              CDP_NO_NEED_TO_REFRESH,         // 1
              CDP_ERROR_TO_SAVE_NEW_CRL,      // 2
              CDP_URL_IS_EMPTY,               // 3
              CDP_CANT_PARSE_URL,             // 4
              CDP_UNSUPPORTED_PROTOCOL,       // 5
              CDP_OUT_OF_MEMORY,              // 6
              CDP_INVALID_PARAMETER,          // 7
              CDP_CANT_GET_CA_CHAIN,          // 8
              CDP_LDAP_CANT_MAKE_REQUEST,     // 9
              CDP_LDAP_CANT_PROC_OPT,         // 10
              CDP_LDAP_CANT_INIT_SESSION,     // 11
              CDP_LDAP_SEARCH_SUCCESS,        // 12
              CDP_LDAP_SEARCH_ERROR,          // 13
              CDP_LDAP_INTERNAL_ERROR,        // 14
              CDP_LDAP_ROOT_ERR_CREDENTIALS,  // 15
              CDP_LDAP_SERVER_DENY,           // 16
              CDP_LDAP_TOO_MANY_ENTRIES,      // 17
              CDP_CANT_CONNECT_TO_LDAP,       // 18
              CDP_SEARCH_SUCCESS,             // 19
              CDP_CANT_GET_CDP_FROM_CERT,     // 20
              CDP_CANT_GET_SERVER_ADDRESS     // 21
             }
  CDP_STATUS;

CDP_STATUS
GetCDPLastError (
  VOID
);

CDP_STATUS
SearchCrlWithCDP (
  IN CHAR8 *cdpURL, 
  OUT UINTN *numCRLs
);

CDP_STATUS
RefreshLocalCRL (
  UINT8 *certData,
  UINTN certDataLen
);

#endif // CDP_SUPPORT_H_