/** @file
  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php
  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
**/

#include <Library/Lib/ComparisonDataHelper.h>


EFI_STATUS
GetComparisonDataType(
  IN CHAR8 *Str,
  IN UINT8 *Type
  )
{
  CHAR8 *OptionsNames[] = {
    "CN", "SUBJECT", "MAIL", "DIGEST", "UID", "UNKNOWN"
  };
  UINT8 i;
  
  for (i = 0; i < MAX_COMPARISON_NUM; i++) {
    if (AsciiStrCmp(OptionsNames[i], Str) == 0) {
      *Type = i;
      return EFI_SUCCESS;
    }
  }
  return EFI_NOT_FOUND;
}

EFI_STATUS
GetComparisonDataType16(
  IN CHAR16 *Str,
  IN UINT8 *Type
  )
{
  CHAR16 *OptionsNames[] = {
    L"CN", L"SUBJECT", L"MAIL", L"DIGEST", L"UID", L"UNKNOWN"
  };
  UINT8 i;
  
  for (i = 0; i < MAX_COMPARISON_NUM; i++) {
    if (StrCmp(OptionsNames[i], Str) == 0) {
      *Type = i;
      return EFI_SUCCESS;
    }
  }
  return EFI_NOT_FOUND;
}


CHAR8 *
GetComparisonDataName(
  IN UINT8 Type
  )
{
  CHAR8 *OptionsNames[] = {
    "CN", "SUBJECT", "MAIL", "DIGEST", "UID", "UNKNOWN"
  };
  
  if (Type >= MAX_COMPARISON_NUM) {
    return OptionsNames[MAX_COMPARISON_NUM];
  }
  return OptionsNames[Type];
}

CHAR16 *
GetComparisonDataName16(
  IN UINT8 Type
  )
{
  CHAR16 *OptionsNames[] = {
    L"CN", L"SUBJECT", L"MAIL", L"DIGEST", L"UID", L"UNKNOWN"
  };
  
  if (Type >= MAX_COMPARISON_NUM) {
    return OptionsNames[MAX_COMPARISON_NUM];
  }
  return OptionsNames[Type];
}

