/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef NET_SETUP_INTERNAL_H_
#define NET_SETUP_INTERNAL_H_

#define IP4_STR_MAX_SIZE    16

typedef struct {
  BOOLEAN enable;
  BOOLEAN useDHCP;
  CHAR16 *localAddr;
  CHAR16 *netMask;
  CHAR16 *gateway;
  CHAR16 *primaryDns;
  CHAR16 *secondaryDns;
  CHAR16 *dnsDomainName;
} NIC_CONFIG_T;

EFI_STATUS
SetNicConfigByIndex (
  IN UINTN nicIndex,
  IN NIC_CONFIG_T config
);

EFI_STATUS
EFIAPI
IfconfigGetAllNicCount (
  IN OUT UINTN      *NicCount
  );

EFI_STATUS
EFIAPI
IfconfigGetNicInfoByIndex (
  IN UINTN            nicIndex,
  IN OUT NIC_CONFIG_T **Config
  );

VOID
EFIAPI
IfConfigFree (
  IN NIC_CONFIG_T *Config
  );

#endif // NET_SETUP_INTERNAL_H_