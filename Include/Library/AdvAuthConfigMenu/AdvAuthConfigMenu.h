/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef ADV_AUTH_CONFIG_MENU_H_
#define ADV_AUTH_CONFIG_MENU_H_

#include <Protocol/AdvMenuHandlerProto.h>

// USAGE_USER_PC_LINK is switched off. Add these strings to the xml config to switch it on
//   <ENTRY Id="0xA00C" Name="Проверять права пользователя:" Mnitem="checkbox">
//     <GUID>b7e385bc-775e-4a66-bf91-5421b36e6b1d</GUID>
//   </ENTRY>

#define ADV_AUTH_MENU_FORM_GUID \
  { \
    0x82c2425b, 0x8b12, 0x43ad, {0xa1, 0x27, 0x70, 0xa6, 0xd5, 0xe3, 0x73, 0x52}\
  }

#define ADV_AUTH_MENU_FORM_ID 0xA003
  
/** \name QuestionsId for the Auth Mode Config Menu. Check xml config file. */
#define SELECT_AUTH_MODE    0xA001  //!< A list to select an auth mode
#define USAGE_LOCAL_GUEST   0xA002  //!< A checkbox to turn on/off a local guest
#define CN_COMPARISON       0xA004  //!< A checkbox to use CN as a comparison data
#define CN_DATA             0xA005  //!< A textbox to input CN
#define OU_COMPARISON       0xA006  //!< A checkbox to use OU as a comparison data
#define OU_DATA             0xA007  //!< A textbox to input OU
#define SUBJECT_COMPARISON  0xA008  //!< A checkbox to use SUBJECT as a comparison data
#define SUBJECT_DATA        0xA009  //!< A textbox to input SUBJECT
#define USAGE_LDAP_GUEST    0xA00A  //!< A checkbox to turn up/down a ldap guest
#define SAVE_AUTH_CONFIG    0xA00B  //!< A button to save the config
#define USAGE_USER_PC_LINK  0xA00C  //!< A button to turn on/off an User-PC link checking

EFI_STATUS
FillAuthConfigFormElement(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
);

EFI_STATUS
ProcessAuthConfigFormElement(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
);

VOID
DeleteAuthModeFormData( 
  VOID
  );

#endif // ADV_AUTH_CONFIG_MENU_H_
