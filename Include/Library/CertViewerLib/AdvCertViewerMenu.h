/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef ADV_CERT_VIEWER_MENU_H_
#define ADV_CERT_VIEWER_MENU_H_

#include <Protocol/AdvMenuHandlerProto.h>

#define ADV_CERT_VIEWER_FORM_GUID \
  { \
    0x986602c9, 0xf4e5, 0x4f27, {0xbe, 0x32, 0x26, 0xe9, 0xd1, 0x41, 0xaa, 0x54}\
  }

EFI_STATUS
ProcessCertViewerFormElement(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
);

#endif // ADV_CERT_VIEWER_MENU_H_
