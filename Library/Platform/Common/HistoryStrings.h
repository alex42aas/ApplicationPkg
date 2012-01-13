/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __HISTORY__STRINGS__H
#define __HISTORY__STRINGS__H

#include <Base.h>
#include <Library/HiiLib.h>


EFI_STRING_ID
GetHistoryStringByIdx (
  IN UINTN Idx
  );


#endif // #ifndef __HISTORY__STRINGS__H
