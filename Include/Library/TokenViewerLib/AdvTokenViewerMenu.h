/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef ADV_TOKEN_VIEWER_MENU_H_
#define ADV_TOKEN_VIEWER_MENU_H_

#include <Protocol/AdvMenuHandlerProto.h>

#define ADV_TOKEN_VIEWER_FORM_GUID \
  { \
    0xd8f6f414, 0xa120, 0x4bf2, {0x8d, 0x46, 0x88, 0x66, 0x16, 0xd9, 0x50, 0x96}\
  }

EFI_STATUS
ProcessTokenViewerFormElement(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
);

#endif // ADV_TOKEN_VIEWER_MENU_H_
