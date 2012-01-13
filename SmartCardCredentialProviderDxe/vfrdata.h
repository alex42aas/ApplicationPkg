/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef SC_IFR_DATA_H
#define SC_IFR_DATA_H

#pragma pack(1)
typedef struct {
    UINT16 Password[21];
} USBKEY_CONFIG;
#pragma pack()

#define USBKEY_MANAGER_FORM_ID 0x1044

#endif
