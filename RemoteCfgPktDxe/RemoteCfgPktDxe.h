/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __REMOTE__CFG__PROTOCOL__DXE__H
#define __REMOTE__CFG__PROTOCOL__DXE__H


#include <Protocol/RemoteCfgPktProtocol.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/CircBufLib.h>
#include <Library/PrintLib.h>
#include <Library/MD5.h>
#include <Library/UefiLib.h>


#define RCFG_PKT_START_BYTE         ':'
#define RCFG_PKT_END_CR             0x0D
#define RCFG_PKT_END_LF             0x0A
#define RCFG_MIN_PKT_LEN            20
#define RCFG_MIN_PKT_CRC8_LEN       20
#define RCFG_MIN_PKT_MD5_LEN        52
#define RCFG_MAX_PKT_SIZE           (64 * 1024 * 1024)

#define POLINOM                     0x8C

typedef struct _REMOTE_CFG_PKT_DATA {
  UINT8 State;
  BOOLEAN bProtocolStarted;
  CIRC_BUF_DESC8 RxPktBuf;
  CIRC_BUF_DESC8 TxPktBuf;
  CIRC_BUF_DESC8 RxFragmPktBuf;
  UINT8 LastPktCrcType;
  BOOLEAN bRxFragmPkt;
  UINT8 RxFragmPktNum;
  UINT8 RxFragmPktFunc;
  UINT8 LastPktNum;
  UINT32 RxFragmTotalLen;
} REMOTE_CFG_PKT_DATA;


typedef struct _REMOTE_CFG_PKT_PRIVATE_DATA {
  EFI_HANDLE DriverHandle;  
  REMOTE_CFG_PKT_PROTOCOL HandlerProtocol;
} REMOTE_CFG_PKT_PRIVATE_DATA;


#endif /* #ifndef __REMOTE__CFG__PROTOCOL__DXE__H */
