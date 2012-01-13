/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef ADV_REMOTE_CFG_TLS_CONFIG_MENU_H_
#define ADV_REMOTE_CFG_TLS_CONFIG_MENU_H_

#include <Protocol/AdvMenuHandlerProto.h>

// 9e216ce8-42dd-4279-b41b-65c77e84d803
#define ADV_REMOTE_CFG_TLS_CONFIG_MENU_FORM_GUID \
  { \
    0x9e216ce8, 0x42dd, 0x4279, {0xb4, 0x1b, 0x65, 0xc7, 0x7e, 0x84, 0xd8, 0x3}\
  }

#define ADV_REMOTE_CFG_TLS_CONFIG_MENU_FORM_ID  0xA007

/*! QuestionsId for a Remote Config TLS Menu. Check xml config file. */
#define RCT_ENABLED               0xA001
#define RCT_TLS_VERSION           0xA002
#define RCT_SERVER_IP_ADDR        0xA003
#define RCT_SERVER_PORT           0xA004
#define RCT_INFINITE_CTIMEOUT     0xA005
#define RCT_CTIMEOUT              0xA006
#define RCT_INFINITE_ETIMEOUT     0xA007
#define RCT_ETIMEOUT              0xA008
#define RCT_INFINITE_ATTEMPTS     0xA009
#define RCT_ATTEMPTS              0xA00A
#define RCT_LABEL1                0xA00B
#define RCT_SAVE_CONFIG           0xA00C
#define RCT_LABEL2                0xA00D
#define RCT_APPLY_CONFIG          0xA00E
#define RCT_SHOW_STATE            0xA00F

EFI_STATUS
InitRemoteCfgTlsFormData( 
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This
  );
  
VOID
DeleteRemoteCfgTlsFormData( 
  VOID
  );

EFI_STATUS
ProcessRemoteCfgTlsFormAction(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  );

EFI_STATUS
FillRemoteCfgTlsFormElement(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  );

#endif // ADV_REMOTE_CFG_TLS_CONFIG_MENU_H_
