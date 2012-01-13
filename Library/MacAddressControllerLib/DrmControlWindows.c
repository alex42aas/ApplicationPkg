/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "DrmControlWindows.h"


VOID
ShowBiosActivationWindow (
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language,
  IN EFI_GUID *Guid
  )
{
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut;
  CHAR16 GuidStr[40];
  CHAR16 *WindowTitleStr, *TextStr, *GuidTitleStr;

  ConOut = gST->ConOut;
  ConOut->ClearScreen(ConOut);

  WindowTitleStr = HiiGetString(HiiHandle, STRING_TOKEN(STR_DRM_TITLE), Language);
  TextStr = HiiGetString(HiiHandle, STRING_TOKEN(STR_DRM_ACTIVATION_HLP), Language);
  GuidTitleStr = HiiGetString(HiiHandle, STRING_TOKEN(STR_DRM_GUID_TITLE), Language);
  UnicodeSPrint(GuidStr, sizeof(GuidStr) - 1, L"  %g  ", Guid);

  CreatePopUp(EFI_LIGHTGRAY | EFI_BACKGROUND_BLUE, NULL, L"", WindowTitleStr, L"", 
      TextStr, L"", GuidTitleStr, GuidStr, L"", NULL);

  FreePool(WindowTitleStr);
  FreePool(TextStr);
  FreePool(GuidTitleStr);
}


VOID
ShowDrmKeyRequestWindow (
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language,
  IN EFI_GUID *Guid
  )
{
  CHAR16 GuidStr[40];
  CHAR16 *HiiTitle, *HiiGuidTitle, *HiiPrompt;
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut;
  UINTN PosX, PosY, Columns, Rows, Ncols, Nlines;
  EFI_SIMPLE_TEXT_OUTPUT_MODE ConsoleMode;

  UnicodeSPrint(GuidStr, sizeof(GuidStr) - 1, L"  %g  ", Guid);

  HiiTitle = HiiGetString(HiiHandle, STRING_TOKEN(STR_DRM_TITLE), Language);
  HiiGuidTitle = HiiGetString(HiiHandle, STRING_TOKEN(STR_DRM_GUID_TITLE), Language);
  HiiPrompt = HiiGetString(HiiHandle, STRING_TOKEN(STR_DRM_PROMPT), Language); 
  
  ConOut = gST->ConOut;
  ConOut->ClearScreen(ConOut);
  
  CreatePopUp(EFI_LIGHTGRAY | EFI_BACKGROUND_BLUE, NULL, L"", 
      HiiTitle, L"", HiiGuidTitle, GuidStr, L"", HiiPrompt, L"", L"", NULL);

  CopyMem(&ConsoleMode, ConOut->Mode, sizeof(ConsoleMode));
  ConOut->QueryMode (ConOut, ConsoleMode.Mode, &Columns, &Rows);
  Nlines = 8 + 2;   // currently 8 lines in popup
  Ncols = MAX (StrLen(HiiTitle), StrLen(HiiGuidTitle));
  Ncols = MAX (Ncols, StrLen(GuidStr));
  Ncols = MAX (Ncols, StrLen(HiiPrompt));
  Ncols = MIN (Ncols, Columns - 2);

  // Calc starting row and starting column for the popup
  PosY = (Rows - (Nlines + 3)) / 2;
  PosX = (Columns - (Ncols + 2)) / 2;
  
  PosY += 7 + 2; // over 8 lines (4 + 1-border)
  PosX += 2;     // one column + one bolder

  PrepareInputLine(PosX, PosY, Ncols - 2);
  
  FreePool(HiiTitle);
  FreePool(HiiGuidTitle);
  FreePool(HiiPrompt);
}


VOID
ShowDrmKeyConfirmSuccessWindow (
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  )
{
  CHAR16 *HiiGoodKey;
  
  HiiGoodKey = HiiGetString(HiiHandle, STRING_TOKEN(STR_DRM_GOOD_KEY), Language);
  
  ShowSuccessPopup(HiiHandle, HiiGoodKey);
  
  FreePool(HiiGoodKey);
}


VOID
ShowDrmKeyConfirmUnsuccessWindow (
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  )
{
  CHAR16 *HiiBadKey;
  
  HiiBadKey = HiiGetString(HiiHandle, STRING_TOKEN(STR_DRM_BAD_KEY), Language);
  
  ShowErrorPopup(HiiHandle, HiiBadKey);
  
  FreePool(HiiBadKey);
}
