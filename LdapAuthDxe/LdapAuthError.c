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

#include <Library/PrintLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include <Protocol/BiosLogProtocol.h>

#include "LdapConfigInternal.h"

STATIC BIOS_LOG_PROTOCOL *pBiosLogProtocol;

//------------------------------------------------------------------------------
/*! \brief Put a message to BIOS LOG message */
//------------------------------------------------------------------------------
VOID
LogLdapAuthMessage (
  IN UINTN logLevel,
  IN const CHAR8 *format,
  ...
)
{
  VA_LIST args;
  CHAR8   buffer[MAX_DEBUG_MESSAGE_LENGTH];

  EFI_STATUS status = EFI_ABORTED;

  VA_START (args, format);

  AsciiVSPrint (buffer, sizeof (buffer), format, args);

  VA_END(args);

  status = gBS->LocateProtocol (&gBiosLogProtocolGuid, NULL, (VOID **) &pBiosLogProtocol);
  if (EFI_ERROR(status))
    return;

  pBiosLogProtocol->PutError("LdapAuth", buffer);

  return;
}
//------------------------------------------------------------------------------

