/** @file
  String support

Copyright (c) 2004 - 2009, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "Bds.h"
#include "Language.h"
#include "FrontPage.h"

EFI_HII_HANDLE gStringPackHandle;

EFI_GUID mBdsStringPackGuid = {
  0x7bac95d3, 0xddf, 0x42f3, {0x9e, 0x24, 0x7c, 0x64, 0x49, 0x40, 0x37, 0x9a}
};

/**
  Initialize HII global accessor for string support.

**/
VOID
InitializeStringSupport (
  VOID
  )
{
#if 0
  gStringPackHandle = HiiAddPackages (
                         &mBdsStringPackGuid,
                         mBdsImageHandle,
                         BdsDxeStrings,
                         NULL
                         );
  ASSERT (gStringPackHandle != NULL);
#endif
}

/**
  Get string by string id from HII Interface


  @param Id              String ID.

  @retval  CHAR16 *  String from ID.
  @retval  NULL      If error occurs.

**/
CHAR16 *
GetStringById (
  IN  CHAR16 *Str
  )
{
  UINTN Len;
  CHAR16 *OutStr;

  Len = StrLen(Str);
  OutStr = AllocateZeroPool((Len  + 1) * 2);
  if (OutStr) {
    StrCpy(OutStr, Str);
  }
  return OutStr;
}
