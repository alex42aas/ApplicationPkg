/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

/*
*/

#ifndef MULTIBOOT_PROTOCOL_H
#define MULTIBOOT_PROTOCOL_H

#include <Protocol/RemoteCfgPktProtocol.h>
#include <Protocol/SimpleFileSystem.h>

#define MULTIBOOT_VERSION_STR   "02.00.01.16"

#define MULTIBOOT_PROTOCOL_GUID \
{ 0x53FE300C, 0x3226, 0x42BE, \
{ 0x98, 0x87, 0x69, 0x5F, 0xCF, 0x4c, 0x4B, 0xEF } };

extern EFI_GUID gMultibootProtocolGuid;

typedef struct _MULTIBOOT_PROTOCOL MULTIBOOT_PROTOCOL;

typedef EFI_STATUS
(EFIAPI * MULTIBOOT_SET_MODULE ) (
    IN     MULTIBOOT_PROTOCOL* This,
    IN     UINTN Index,
    IN     EFI_FILE Root,
    IN     UINT16* FilePath,
    IN     CHAR8* Args
    );

typedef EFI_STATUS
(EFIAPI * MULTIBOOT_GET_MODULE ) (
    IN     MULTIBOOT_PROTOCOL* This,
    IN     UINTN Index,
    IN     EFI_FILE Root,
    IN     UINT16* FilePath,
    IN OUT CHAR8* ArgsBuffer,
    IN     UINTN ArgsBufferSize
    );

typedef EFI_STATUS
(EFIAPI * MULTIBOOT_REMOVE_MODULE ) (
    IN     MULTIBOOT_PROTOCOL* This,
    IN     UINTN Index
    );

typedef EFI_STATUS
(EFIAPI * MULTIBOOT_START ) (
    IN     MULTIBOOT_PROTOCOL* This
    );

typedef EFI_STATUS
(EFIAPI * MULTIBOOT_PROCESSING_REMOTE_CTRL_PKT ) (
    IN     MULTIBOOT_PROTOCOL* This,
    IN     UINT8 *RxBuf,
    IN     UINTN RxBufLen,
    IN     REMOTE_CFG_PKT_PROTOCOL *RCPkt,
    IN     EFI_HANDLE RCPktHandle
    );

typedef EFI_HANDLE
(EFIAPI * MULTIBOOT_GET_CURRENT_HII_HANDLE ) (
    VOID
    );

typedef EFI_HANDLE
(EFIAPI * MULTIBOOT_GET_DRIVER_HANDLE ) (
    VOID
    );

typedef CHAR16 *
(EFIAPI * MULTIBOOT_GET_VERSION_STR) (
    VOID
    );

typedef UINT8 *
(EFIAPI * MULTIBOOT_GET_XML_CONFIG_DATA) (
    IN OUT UINTN *DataSize
    );




struct _MULTIBOOT_PROTOCOL {
  MULTIBOOT_SET_MODULE SetModule;
  MULTIBOOT_GET_MODULE GetModule;
  MULTIBOOT_REMOVE_MODULE RemoveModule;
  MULTIBOOT_START Start;
  MULTIBOOT_PROCESSING_REMOTE_CTRL_PKT ProcessingRemoteCtrlPkt;
  MULTIBOOT_GET_CURRENT_HII_HANDLE GetCurrentHiiHandle;
  MULTIBOOT_GET_DRIVER_HANDLE GetDriverHandle;
  MULTIBOOT_GET_VERSION_STR GetVersionStr;
  MULTIBOOT_GET_XML_CONFIG_DATA GetXmlConfigData;
};

#endif

