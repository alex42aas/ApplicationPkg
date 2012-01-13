/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __ACTIVATION_KEY_PROVIDER__PROTOCOL__H
#define __ACTIVATION_KEY_PROVIDER__PROTOCOL__H

#include <Library/BaseLib.h>

typedef struct _ACTIVATION_KEY_PROVIDER_PROTOCOL ACTIVATION_KEY_PROVIDER_PROTOCOL;

typedef
EFI_STATUS
(EFIAPI *ACTIVATION_KEY_PROVIDER_INIT) (
  IN ACTIVATION_KEY_PROVIDER_PROTOCOL *This,
  IN OPTIONAL VOID *Params,
  IN OPTIONAL UINTN ParamsLen
  );


typedef
EFI_STATUS
(EFIAPI *ACTIVATION_KEY_PROVIDER_RESET) (
  IN ACTIVATION_KEY_PROVIDER_PROTOCOL *This,
  IN OPTIONAL VOID *Params,
  IN OPTIONAL UINTN ParamsLen
  );

typedef
EFI_STATUS
(EFIAPI *ACTIVATION_KEY_PROVIDER_GET_KEY) (
  IN ACTIVATION_KEY_PROVIDER_PROTOCOL *This,
  IN EFI_GUID *Guid,
  OUT VOID **KeyBuf,
  OUT UINTN *KeyBufLen,
  IN OPTIONAL VOID *Params,
  IN OPTIONAL UINTN ParamsLen
  );


struct _ACTIVATION_KEY_PROVIDER_PROTOCOL {
  ACTIVATION_KEY_PROVIDER_INIT      Init;
  ACTIVATION_KEY_PROVIDER_RESET     Reset;
  ACTIVATION_KEY_PROVIDER_GET_KEY   GetKey;
};

extern EFI_GUID gActivationKeyProviderProtocolGuid;

#endif /* #ifndef __ACTIVATION_KEY_PROVIDER__PROTOCOL__H */
