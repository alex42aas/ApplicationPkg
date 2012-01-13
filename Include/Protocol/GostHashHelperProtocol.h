/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __GOST__HASH__HELPER__PROTOCOL__H
#define __GOST__HASH__HELPER__PROTOCOL__H


#include <Library/BaseLib.h>


typedef struct _GOST_HASH_HELPER_PROTOCOL GOST_HASH_HELPER_PROTOCOL;

typedef enum {
  GOSTR3411_94_TEST_PARAMSET,
  GOSTR3411_94_CRYPTOPRO_PARAMSET,
  GOSTR3411_94_ERROR_PARAMSET
} GOST_PARAM_SET;


typedef
EFI_STATUS
(EFIAPI *GOST_HASH_INIT) (
  IN GOST_HASH_HELPER_PROTOCOL *This,
  IN OUT EFI_HANDLE *Handle,
  IN GOST_PARAM_SET ParamSet
  );


typedef
EFI_STATUS
(EFIAPI *GOST_HASH_UPDATE) (
  IN GOST_HASH_HELPER_PROTOCOL *This,
  IN EFI_HANDLE Handle,
  IN UINT8 *Data,
  IN UINTN DataLen
  );

typedef
EFI_STATUS
(EFIAPI *GOST_HASH_FINAL) (
  IN GOST_HASH_HELPER_PROTOCOL *This,
  IN EFI_HANDLE Handle,
  IN OUT UINT8 *Hash
  );


struct _GOST_HASH_HELPER_PROTOCOL {
  GOST_HASH_INIT    Init;
  GOST_HASH_UPDATE  Update;
  GOST_HASH_FINAL   Final;
};

extern EFI_GUID gGostHashHelperProtocolGuid;

#endif /* #ifndef __GOST__HASH__HELPER__PROTOCOL__H */
