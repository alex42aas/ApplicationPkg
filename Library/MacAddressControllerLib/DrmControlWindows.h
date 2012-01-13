/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __DRM__CONTROL__WINDOWS__H
#define __DRM__CONTROL__WINDOWS__H

#include <Library/CommonUtils.h>
#include <PchAccess.h>
#include <PchRegsLan.h>




#define   INT_GBE_MMIO_BASE		PCI_LIB_ADDRESS (DEFAULT_PCI_BUS_NUMBER_PCH, PCI_DEVICE_NUMBER_PCH_LAN, PCI_FUNCTION_NUMBER_PCH_LAN, 0)


#define   I210_VID_REG_VALUE            0x8086
#define   I210_DID_REG_VALUE            0x1533
#define   I210_VID_DID_VALUE            ((I210_VID_REG_VALUE << 16) | I210_DID_REG_VALUE)
#define   I210_MAC_REG_HIGH_OFFSET      0x148   // Serial Number Register 
#define   I210_MAC_REG_LOW_OFFSET       0x144   // (see Intel Ethernet Controller I210 Datasheet, Rev. 2.8, September 2015)

#define   I350_VID_REG_VALUE            0x8086
#define   I350_DID_REG_VALUE            0x1521
#define   I350_VID_DID_VALUE            ((I350_VID_REG_VALUE << 16) | I350_DID_REG_VALUE)
#define   I350_MBAR_OFFSET		0x10    // in PCI-config: Memory Base Address
#define   I350_DEV_STATUS_OFFSET	0x08    // in MMIO: Device Status Register - STATUS (0x0008; RO)
#define   I350_EERD_OFFSET		0x14    // in MMIO: EEPROM Read Register - EERD (0x0014; RW)
#define   I350_LAN_BASE_OFFSET		0x00	// in EEPROM: Ethernet Address (LAN Base Address + Offsets 0x00-0x02)

#define   I350_MAC_REG_HIGH_OFFSET      0x148   // Serial Number Register 
#define   I350_MAC_REG_LOW_OFFSET       0x144   // (see Intel Ethernet Controller I210 Datasheet, Rev. 2.8, September 2015)

#define   RTL8111_VID_REG_VALUE         0x10EC
#define   RTL8111_DID_REG_VALUE         0x8168
#define   RTL8111_VID_DID_VALUE         ((RTL8111_VID_REG_VALUE << 16) | RTL8111_DID_REG_VALUE)
#define   RTL8111_MBARC_REG_OFFSET      0x18    // MBARC (see driver source code r8169.c)
#define   RTL8111_MAC_REG_HIGH_OFFSET   0x4     // MAC4 Register
#define   RTL8111_MAC_REG_LOW_OFFSET    0x0     // MAC0 Register

#define   INT_GBE_VID_REG_VALUE         0x8086
#define   INT_GBE_DID_REG_VALUE         0x153B
#define   INT_GBE_DID_REG_VALUE2        0x153A
#define   INT_GBE_VID_DID_VALUE         ((INT_GBE_VID_REG_VALUE << 16) | INT_GBE_DID_REG_VALUE)
#define   INT_GBE_VID_DID_VALUE2        ((INT_GBE_VID_REG_VALUE << 16) | INT_GBE_DID_REG_VALUE2)
#define   INT_GBE_MBARA_REG_OFFSET      0x10    // MBARA (see Intel 8 Series/C220 Series Chipset Family PCH, 328904-003, May 2014)
#define   INT_GBE_MAC_REG_HIGH_OFFSET   0x5404  // Gigabit Ethernet Capabilities and Status Register 5404
#define   INT_GBE_MAC_REG_LOW_OFFSET    0x5400  // Gigabit Ethernet Capabilities and Status Register 5400

#define   INT_GBE_DID_REG_VALUE3		0x10D4		// Skylake
#define   INT_GBE_VID_DID_VALUE3        ((INT_GBE_VID_REG_VALUE << 16) | INT_GBE_DID_REG_VALUE3)

#define   NETWORK_CTRL_CLASS_CODE       0x02
#define   ETH_CTRL_SUBCLASS_CODE        0x00
#define   NETWORK_ETH_CTRL_CODE         ((NETWORK_CTRL_CLASS_CODE << 24) | (ETH_CTRL_SUBCLASS_CODE << 16))



VOID
ShowBiosActivationWindow (
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language,
  IN EFI_GUID *Guid
  );


VOID
ShowDrmKeyRequestWindow (
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language,
  IN EFI_GUID *SysGuid
  );


VOID
ShowDrmKeyConfirmSuccessWindow (
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  );


VOID
ShowDrmKeyConfirmUnsuccessWindow (
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  );
  
#endif    // #ifndef __DRM__CONTROL__WINDOWS__H
