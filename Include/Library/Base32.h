/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/


#ifndef _BASE32LIB_H
#define _BASE32LIB_H

#include <Uefi/UefiBaseType.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>

#define BASE32_TBL_SIZE       32
#define BASE32_FILL_SYMBOL    BASE32_TBL_SIZE
#define BASE32_BAD_SYMBOL     0xFF

INTN
Base32Encode(
  IN CONST UINT8 *Buf,
  IN UINTN BufLen,
  OUT CHAR8 *StrEnc,
  IN UINTN StrEncMaxLen,
  OUT UINTN *StrEncLen
  );

BOOLEAN
Base32TestChar(
  IN CHAR8 Letter
  );

INTN
Base32Decode(
  IN CONST CHAR8 *Str,
  OUT UINT8 *BufDec,
  IN UINTN BufDecMaxLen,
  OUT UINTN *BufDecLen
  );

#endif /*_BASE32LIB_H*/
