/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef ADV_NETWORK_MENU
#define ADV_NETWORK_MENU

#include <Protocol/AdvMenuHandlerProto.h>

#define ADV_NETWORK_MENU_FORM_GUID \
  { \
    0xc5827ceb, 0x84ca, 0x45b6, {0xb4, 0x36, 0x1b, 0x4e, 0x7a, 0x5b, 0x10, 0x88}\
  }
  
/*! QuestionsId for a Advanced Network Menu. Check xml config file. */
#define ENTER_DNS_SERVER_1 0xA001  //!< Primary DNS address field
#define ENTER_DNS_SERVER_2 0xA002  //!< Secondary DNS address field
#define SAVE_CONFIG        0xA003  //!< Save config button

EFI_STATUS
FillAdvNetworkFormElement(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
);

EFI_STATUS
ProcessAdvNetworkFormElement(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
);

EFI_STATUS
ReadResolvConf( 
  IN EFI_QUESTION_ID QuestionId
);

VOID
FlushDnsAddr(
  IN EFI_QUESTION_ID QuestionId
);

#endif // ADV_NETWORK_MENU