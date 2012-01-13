/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/


#ifndef _BASE64LIB_H
#define _BASE64LIB_H

#include <Uefi/UefiBaseType.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>

#define BASE64_TBL_SIZE       64
#define BASE64_FILL_SYMBOL    BASE64_TBL_SIZE
#define BASE64_BAD_SYMBOL     0xFF

extern CONST CHAR8 Base64TblDefault[];
extern CONST CHAR8 Base64TblCustom[];

INTN
Base64EncodeCustom(
  IN CONST CHAR8 *Base64Tbl,
  IN CONST UINT8 *Buf,
  IN UINTN BufLen,
  OUT CHAR8 *StrEnc,
  IN UINTN StrEncMaxLen,
  OUT UINTN *StrEncLen
  );

INTN
Base64Encode(
  IN CONST UINT8 *Buf,
  IN UINTN BufLen,
  OUT CHAR8 *StrEnc,
  IN UINTN StrEncMaxLen,
  OUT UINTN *StrEncLen
  );

BOOLEAN
Base64TestChar(
  IN CONST CHAR8 *Base64Tbl,
  IN CHAR8 Letter
  );

INTN
Base64DecodeCustom(
  IN CONST CHAR8 *Base64Tbl,
  IN CONST CHAR8 *Str,
  OUT UINT8 *BufDec,
  IN UINTN BufDecMaxLen,
  OUT UINTN *BufDecLen
  );

INTN
Base64Decode(
  IN CONST CHAR8 *Str,
  OUT UINT8 *BufDec,
  IN UINTN BufDecMaxLen,
  OUT UINTN *BufDecLen
  );

#endif /*_BASE64LIB_H*/
