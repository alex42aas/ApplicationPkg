/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __ETOKEN__VFR__DATA__H
#define __ETOKEN__VFR__DATA__H

#include <Base.h>

#define ETOKEN_VFR_GUID { 0x543cd5fe, 0x1276, 0x443d, \
  { 0x41, 0x42, 0x34, 0xc2, 0x32, 0xef, 0xa1, 0xe4 } }
#define ETOKEN_SETUP_VAR_GUID  { 0x543cd4ff, 0x1276, 0x443d, 0x41, 0x42, 0x34, 0xc2, 0x32, 0xfe, 0x62, 0x52 }

#define START_LABEL_ID           0x1001
#define END_LABEL_ID             0x1002

#define ETOKEN_VAR_NAME          L"ETokenSetup"

enum {
  SC_MODE_PRO,
  SC_MODE_GOST
};

typedef struct {
  UINT8         eTokenMode;
} ETOKEN_VARSTORE_DATA;


#endif /* #ifndef __ETOKEN__VFR__DATA__H */
