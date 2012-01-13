/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __PCI__DEVS_DESC__LIB__H
#define __PCI__DEVS_DESC__LIB__H

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/UefiLib.h>
#include <Protocol/AcpiSystemDescriptionTable.h>
#include <Protocol/PciRootBridgeIo.h>
#include <IndustryStandard/Pci.h>
#include <IndustryStandard/Acpi.h>
#include <Protocol/Runtime.h>

#pragma pack(1)
typedef struct {
  CHAR16 *BaseClass; // Pointer to the PCI base class string
  CHAR16 *SubClass;  // Pointer to the PCI sub class string
  CHAR16 *PIFClass;  // Pointer to the PCI programming interface string
} PCI_CLASS_STRINGS;

typedef struct PCI_CLASS_ENTRY_TAG {
  UINT8 Code;             // Class, subclass or I/F code
  CHAR16 *DescText;        // Description string
  struct PCI_CLASS_ENTRY_TAG *LowerLevelClass; // Subclass or I/F if any
} PCI_CLASS_ENTRY;

typedef struct {
  UINT16  VendorId;
  UINT16  DeviceId;

  UINT16  Command;
  UINT16  Status;

  UINT8   RevisionId;
  UINT8   ClassCode[3];

  UINT8   CacheLineSize;
  UINT8   PrimaryLatencyTimer;
  UINT8   HeaderType;
  UINT8   Bist;
} PCI_COMMON_HEADER;


//
// PCI configuration space header for devices(after the common part)
//
typedef struct {
  UINT32  Bar[6];           // Base Address Registers
  UINT32  CardBusCISPtr;    // CardBus CIS Pointer
  UINT16  SubVendorId;      // Subsystem Vendor ID
  UINT16  SubSystemId;      // Subsystem ID
  UINT32  ROMBar;           // Expansion ROM Base Address
  UINT8   CapabilitiesPtr;  // Capabilities Pointer
  UINT8   Reserved[3];

  UINT32  Reserved1;

  UINT8   InterruptLine;    // Interrupt Line
  UINT8   InterruptPin;     // Interrupt Pin
  UINT8   MinGnt;           // Min_Gnt
  UINT8   MaxLat;           // Max_Lat
} PCI_DEVICE_HEADER;

//
// PCI configuration space header for pci-to-pci bridges(after the common part)
//
typedef struct {
  UINT32  Bar[2];                 // Base Address Registers
  UINT8   PrimaryBus;             // Primary Bus Number
  UINT8   SecondaryBus;           // Secondary Bus Number
  UINT8   SubordinateBus;         // Subordinate Bus Number
  UINT8   SecondaryLatencyTimer;  // Secondary Latency Timer
  UINT8   IoBase;                 // I/O Base
  UINT8   IoLimit;                // I/O Limit
  UINT16  SecondaryStatus;        // Secondary Status
  UINT16  MemoryBase;             // Memory Base
  UINT16  MemoryLimit;            // Memory Limit
  UINT16  PrefetchableMemBase;    // Pre-fetchable Memory Base
  UINT16  PrefetchableMemLimit;   // Pre-fetchable Memory Limit
  UINT32  PrefetchableBaseUpper;  // Pre-fetchable Base Upper 32 bits
  UINT32  PrefetchableLimitUpper; // Pre-fetchable Limit Upper 32 bits
  UINT16  IoBaseUpper;            // I/O Base Upper 16 bits
  UINT16  IoLimitUpper;           // I/O Limit Upper 16 bits
  UINT8   CapabilitiesPtr;        // Capabilities Pointer
  UINT8   Reserved[3];

  UINT32  ROMBar;                 // Expansion ROM Base Address
  UINT8   InterruptLine;          // Interrupt Line
  UINT8   InterruptPin;           // Interrupt Pin
  UINT16  BridgeControl;          // Bridge Control
} PCI_BRIDGE_HEADER;

//
// PCI configuration space header for cardbus bridges(after the common part)
//
typedef struct {
  UINT32  CardBusSocketReg; // Cardus Socket/ExCA Base
  // Address Register
  //
  UINT8   CapabilitiesPtr;      // 14h in pci-cardbus bridge.
  UINT8   Reserved;
  UINT16  SecondaryStatus;      // Secondary Status
  UINT8   PciBusNumber;         // PCI Bus Number
  UINT8   CardBusBusNumber;     // CardBus Bus Number
  UINT8   SubordinateBusNumber; // Subordinate Bus Number
  UINT8   CardBusLatencyTimer;  // CardBus Latency Timer
  UINT32  MemoryBase0;          // Memory Base Register 0
  UINT32  MemoryLimit0;         // Memory Limit Register 0
  UINT32  MemoryBase1;
  UINT32  MemoryLimit1;
  UINT32  IoBase0;
  UINT32  IoLimit0;             // I/O Base Register 0
  UINT32  IoBase1;              // I/O Limit Register 0
  UINT32  IoLimit1;

  UINT8   InterruptLine;        // Interrupt Line
  UINT8   InterruptPin;         // Interrupt Pin
  UINT16  BridgeControl;        // Bridge Control
} PCI_CARDBUS_HEADER;

//
// Data region after PCI configuration header(for cardbus bridge)
//
typedef struct {
  UINT16  SubVendorId;  // Subsystem Vendor ID
  UINT16  SubSystemId;  // Subsystem ID
  UINT32  LegacyBase;   // Optional 16-Bit PC Card Legacy
  // Mode Base Address
  //
  UINT32  Data[46];
} PCI_CARDBUS_DATA;

typedef union {
  PCI_DEVICE_HEADER   Device;
  PCI_BRIDGE_HEADER   Bridge;
  PCI_CARDBUS_HEADER  CardBus;
} NON_COMMON_UNION;

typedef struct {
  PCI_COMMON_HEADER Common;
  NON_COMMON_UNION NonCommon;
  UINT32  Data[48];
} PCI_CONFIG_SPACE;

#pragma pack()

PCI_CLASS_ENTRY *
GetClassStringListDefs(
  VOID
  );

#endif /* #indef __PCI__DEVS_DESC__LIB__H */
