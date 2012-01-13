/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __SETUP__VAR__PROTO__H
#define __SETUP__VAR__PROTO__H


#include <Library/BaseLib.h>


#define SETUP_VAR_PROTOCOL_GUID \
  { \
    0x977eb8a3,0x304f,0x4352,{0xbb,0x70,0x3b,0x59,0x3a,0x4d,0x9,0xe1} \
  }

typedef struct _SETUP_VAR_PROTOCOL SETUP_VAR_PROTOCOL;

typedef
EFI_STATUS
(EFIAPI *SETUP_VAR_GET_PCI_DA_DEVICES)(
  IN CONST SETUP_VAR_PROTOCOL  *This,
  IN OUT   UINT8 **Data,
  IN OUT   UINTN *RecordsNum
  );


typedef
EFI_STATUS
(EFIAPI *SETUP_VAR_SET_PCI_DA_DEVICES)(
  IN CONST SETUP_VAR_PROTOCOL  *This,
  IN       UINTN ModeIndex,
  IN       UINT8 *Data,
  IN       UINTN RecordsNum
  );


typedef
EFI_STATUS
(EFIAPI *SETUP_VAR_SET_DEFAULT_PCI_DA_DEVICES)(
  IN CONST SETUP_VAR_PROTOCOL  *This
  );



struct _SETUP_VAR_PROTOCOL {
  SETUP_VAR_SET_DEFAULT_PCI_DA_DEVICES SetDefaultPciDaDevices;
  SETUP_VAR_GET_PCI_DA_DEVICES         GetPciDaDevices;
  SETUP_VAR_SET_PCI_DA_DEVICES         SetPciDaDevices;
};


extern EFI_GUID gSetupVarProtocolGuid;


#endif /* #ifndef __SETUP__VAR__PROTO__H */

