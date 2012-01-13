/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __PKCS11_H__
#define __PKCS11_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "pkcs11t.h"
#include "pkcs11t-2.3.h"

#define __PASTE(x, y) X##y

#define CK_NEED_ARG_LIST 1
#define CK_PKCS11_FUNCTION_INFO(name) \
  extern CK_DECLARE_FUNCTION(CK_RV, name)

#include "pkcs11f.h"

#undef CK_PKCS11_FUNCTION_INFO

#define CK_PKCS11_FUNCTION_INFO(name) \
  typedef CK_DECLARE_FUNCTION_POINTER(CK_RV, __PASTE(CK_, name))

#include "pkcs11f.h"

#undef CK_NEED_ARG_LIST
#undef CK_PKCS11_FUNCTION_INFO

#define CK_PKCS11_FUNCTION_INFO(name) \
  __PASTE(CK_, name) name;

struct CK_FUNCTION_LIST {
  CK_VERSION version;

#include "pkcs11f.h"

};

#undef CK_PKCS11_FUNCTION_INFO

#ifdef __cplusplus
}
#endif

#endif /* __PKCS11_H__ */
