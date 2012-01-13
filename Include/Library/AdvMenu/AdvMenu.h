/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef _NETWORK_SETUP_MENU_H_
#define _NETWORK_SETUP_MENU_H_

#define ADV_MENU_FORM_PIN_ID        0xA005
#define ADV_MENU_FORM_MEM_TEST_ID   0xA00A
#define ADV_MENU_FORM_INT_TEST_ID   0xA00B

EFI_STATUS RegisterAdvMenu(EFI_STRING_ID *idList);

#endif // _NETWORK_SETUP_MENU_H_