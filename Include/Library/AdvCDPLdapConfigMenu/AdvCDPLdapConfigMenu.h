/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef ADV_CDP_LDAP_CONFIG_MENU_H_
#define ADV_CDP_LDAP_CONFIG_MENU_H_

#include <Protocol/AdvMenuHandlerProto.h>

// 5cd2e126-4329-4006-8c8d-4284380aa969
#define ADV_CDP_LDAP_CONFIG_MENU_FORM_GUID \
  { \
    0x5cd2e126, 0x4329, 0x4006, {0x8c, 0x8d, 0x42, 0x84, 0x38, 0x0a, 0xa9, 0x69}\
  }

#define ADV_CDP_LDAP_CONFIG_MENU_FORM_ID  0xA006

/*! QuestionsId for a CDP Ldap Config Menu. Check xml config file. */
#define ENTER_CDP_LDAP_SERVER_IP_ADDR 0xA001
#define ENTER_CDP_LDAP_SERVER_PORT    0xA002
#define ENTER_CDP_LDAP_SERVER_NAME    0xA003
#define ENTER_CDP_LDAP_ROOTDN         0xA004
#define ENTER_CDP_LDAP_ROOTPW         0xA005
#define SAVE_CDP_LDAP_CONFIG          0xA006

EFI_STATUS
InitCDPLdapConfigFormData( 
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This
);


VOID
DeleteCDPLdapConfigFormData( 
  VOID
);

EFI_STATUS
ProcessCDPLdapConfigFormAction(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
);

EFI_STATUS
FillCDPLdapConfigFormElement(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
);

#endif // ADV_CDP_LDAP_CONFIG_MENU_H_
