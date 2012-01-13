/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef TLS_CONFIG_STRUCT_H_
#define TLS_CONFIG_STRUCT_H_

typedef struct {
  CHAR8 *cnfFileData;
  VOID *crlStack;
  VOID *trustedStack;
  CHAR16 crlFlag;
} tlsConfig_t;

#endif // TLS_CONFIG_STRUCT_H_
