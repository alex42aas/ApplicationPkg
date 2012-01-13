/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef ADV_REVOKE_CHECK_CONFIG_MENU_H_
#define ADV_REVOKE_CHECK_CONFIG_MENU_H_

#include <Protocol/AdvMenuHandlerProto.h>

#define ADV_REVOKE_CHECK_CONFIG_MENU_GUID \
  { \
    0x009dc97d, 0x01df, 0x4793, {0xa0, 0xc1, 0x69, 0x91, 0x3a, 0xe1, 0xd7, 0xbe}\
  }

#define ADV_REVOKE_CHECK_CONFIG_MENU_ID 0xA004

/*! \name QuestionsId for a Adv Ocsp Config Menu. Check xml config file. */
#define USE_OCSP_CONFIG             0xA001
#define OCSP_URL_INPUT              0xA002
#define USE_LOCAL_CDP_CONFIG        0xA003
#define SAVE_REVOKE_CHECK_CONFIG    0xA004
#define LOCAL_CDP_URL_INPUT         0xA005
#define USE_CRL_CHECK               0xA006
#define USE_CDP_CASHE               0xA007
#define USE_OCSP_RSP_VERITY         0xA008
#define USE_TLS_CRL_CHECK           0xA009
#define USE_CDP_FROM_CERT           0xA00A

VOID
DeleteRevokeChkConfigFormData (
  VOID
);

EFI_STATUS
ProcessRevokeChkConfigFormElement(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
);

EFI_STATUS
FillRevokeChkConfigFormElement(
  IN CONST ADV_MENU_HANDLER_PROTOCOL *This,
  IN EFI_QUESTION_ID QuestionId,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
);

#endif //ADV_OCSP_CONFIG_MENU_H_
