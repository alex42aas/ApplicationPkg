/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef LDAP_DXE_INTERNAL_H_
#define LDAP_DXE_INTERNAL_H_

#include <Protocol/LdapProtocol.h>

/** Internal data of the LDAP protocol */
typedef struct _LDAP_DXE_INTERNAL_DATA {
  EFI_HANDLE         DriverHandle;       //!< Handle of the LDAP DXE driver
  LDAP_PROTOCOL      LdapPtotocol;       //!< LDAP DXE protocol
} LDAP_DXE_INTERNAL_DATA;

#endif // LDAP_DXE_INTERNAL_H_