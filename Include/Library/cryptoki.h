/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __CRYPTOKI_H__
#define __CRYPTOKI_H__

#pragma pack(push, 1)

#define CK_CALL_SPEC EFIAPI

#define CK_PTR *

#define CK_DEFINE_FUNCTION(returnType, name) \
  returnType CK_CALL_SPEC name

#define CK_DECLARE_FUNCTION(returnType, name) \
  returnType CK_CALL_SPEC name

#define CK_DECLARE_FUNCTION_POINTER(returnType, name) \
  returnType (CK_CALL_SPEC CK_PTR name)

#define CK_CALLBACK_FUNCTION(returnType, name) \
  CK_DECLARE_FUNCTION_POINTER(returnType, name)

#ifndef NULL_PTR
#define NULL_PTR NULL
#endif

#include "pkcs11.h"

#pragma pack(pop)

#endif /* __CRYPTOKI_H__ */
