/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef ADV_DIAGNOSTICS_CONFIG_MENU_H_
#define ADV_DIAGNOSTICS_CONFIG_MENU_H_

#include <Protocol/AdvMenuHandlerProto.h>

#define ADV_DIAGNOSTICS_CONFIG_MENU_GUID \
  { \
    0x1f291689, 0x3cfa, 0x4afd, {0x8c, 0x4d, 0xf7, 0x21, 0x4d, 0xdd, 0xe6, 0x5d} \
  }

#define ADV_DIAGNOSTICS_CONFIG_MENU_ID 0xA008

#define USE_DIAGNOSTICS_LOG        0xA001
#define USE_COM_PORT               0xA002
#define SAVE_DIAGNOSTICS_SETTINGS  0xA003
#define USE_NET_LOG                0xA004
#define USE_RAM_LOG                0xA005

VOID
DeleteDiagnosticsConfigFormData (
  VOID
);

EFI_STATUS
ProcessDiagnosticsConfigFormElement(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
);

EFI_STATUS
FillDiagnosticsConfigFormElement(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
);

#endif // ADV_DIAGNOSTICS_CONFIG_MENU_H_ 
