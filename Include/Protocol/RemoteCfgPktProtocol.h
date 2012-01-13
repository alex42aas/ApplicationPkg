/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __REMOTE__CFG__PKT__PROTOCOL__H
#define __REMOTE__CFG__PKT__PROTOCOL__H


#include <Library/BaseLib.h>

#define RCFG_PKT_ADDR_OFFS          0x00
#define RCFG_PKT_NUM_OFFS           0x01
#define RCFG_PKT_OPCODE_OFFS        0x02
#define RCFG_PKT_STATUS_OFFS        0x03
#define RCFG_PKT_LEN_OFFS           0x04
#define RCFG_PKT_DATA_OFFS          0x08
#define RCFG_OPCODE_ANS_FLAG        0x80
#define RCFG_FRAG_PKT_FLAG          0x80


enum {
  FUNC_RESERVED,                          // 0
  FUNC_AUTH_LOGIN_PASS,                   // 1
  FUNC_AUTH_COMP_DATA,                    // 2
  FUNC_AUTH_AMT,                          // 3
  FUNC_CFG_ALL_SUBSYSTEMS,                // 4
  FUNC_CREATE_USERS_FROM_CSV,             // 5
  FUNC_HISTORY_UNLOAD,                    // 6
  FUNC_LOAD_CA,                           // 7
  FUNC_LOAD_CRL,                          // 8
  FUNC_LOAD_FILE_BIOS_UPDATE,             // 9
  FUNC_LOAD_BIOS_UPDATE_FROM_REMOTE_FDD,  // 10
  FUNC_DO_BIOS_UPDATE,                    // 11
  FUNC_GET_AUTH_STATUS,                   // 12
  FUNC_LOAD_TLS_CERT,                     // 13
  FUNC_LOAD_TLS_PRIV_KEY,                 // 14
  FUNC_CLEAN_UNLOADED_HISTORY,            // 15
  FUNC_HISTORY_CTRL,                      // 16
  FUNC_BOOT_MNGR_IMPORT_XML,              // 17
  FUNC_END_REMOTE_CFG,                    // 18
  FUNC_GET_USERS_CSV,                     // 19
  FUNC_GOTO_MII,                          // 20
  FUNC_GET_BIOS_INFO,                     // 21
  FUNC_BIOS_ACTIVATION,                   // 22
  FUNC_RST_BIOS_ACTIVATION,               // 23
  FUNC_HISTORY_CTRL_EXT,                  // 24
  FUNC_HISTORY_GET_CSV,                   // 25
  FUNC_HISTORY_SET_UNLOADED_FLAG,         // 26
  FUNC_SETUP_ECP,                         // 27
  FUNC_GET_XML_CONFIG,                    // 28
  FUNC_UNKNOWN          
};

enum {
  SC_SUCCESS,                             // 0
  SC_CRC_ERR,                             // 1
  SC_WRONG_DATA_LEN,                      // 2
  SC_UNKNOWN_FUNC,                        // 3
  SC_FUNC_ERR,                            // 4
  SC_ALLREADY_STARTED,                    // 5
  SC_WRONG_PKT_LEN,                       // 6
  SC_RX_INTERNAL_ERR,                     // 7
  SC_OPCODE_UNSUPPORTED,                  // 8
  SC_PROTOCOL_NOT_INIT,                   // 9
  SC_WRONG_PKT_NUM,                       // 10
  SC_WRONG_BIOS_UPDATA_FILE,              // 11
  SC_BIOS_UPDATE_NOT_LOADED,              // 12
  SC_XML_PARSER_ERR,                      // 13
  SC_AUTH_ALLREADY_COMPLETE_ERR,          // 14
  SC_PERMISSION_DENIED,                   // 15
  SC_NEED_HISTORY_OUTSWAP,                // 16
  SC_NOT_AUTH_ERR,                        // 17
  SC_CERT_CACHE_ERROR,                    // 18
  SC_CHECK_ECP_OPCODE_MISMATCH,           // 19
  SC_CHECK_ECP_USER_CERT_NOT_FOUND,       // 20
  SC_CHECK_ECP_WRONG_ECP,                 // 21
  SC_CANT_LOCATE_MDZ_PROTO,               // 22
  SC_CANT_GET_XML_CFG                     // 23
};

enum {
  CRC_TYPE_CRC8,
  CRC_TYPE_MD5,
  CRC_TYPE_LAST_RECEIVED,
  CRC_TYPE_UNKNOWN
};

enum {
  END_MODE_START_OS,
  END_MODE_ENTER_ADM_MENU,
  END_MODE_WAIT_FOR_CMD
};

enum {ST_START, ST_PKT, ST_END, ST_ERR};

typedef struct _REMOTE_CFG_PKT_PROTOCOL REMOTE_CFG_PKT_PROTOCOL;


typedef 
EFI_STATUS
(EFIAPI *REMOTE_CFG_PKT_OPEN) (
  IN REMOTE_CFG_PKT_PROTOCOL *This,
  IN OUT EFI_HANDLE *Handle
  );

typedef 
UINT8
(EFIAPI *REMOTE_CFG_PKT_GET_STATE) (
  IN REMOTE_CFG_PKT_PROTOCOL *This,
  IN EFI_HANDLE Handle
  );

typedef 
VOID
(EFIAPI *REMOTE_CFG_PKT_RESET_STATE) (
  IN REMOTE_CFG_PKT_PROTOCOL *This,
  IN EFI_HANDLE Handle
  );


typedef 
BOOLEAN
(EFIAPI *REMOTE_CFG_PKT_PROTOCOL_STARTED) (
  IN REMOTE_CFG_PKT_PROTOCOL *This,
  IN EFI_HANDLE Handle
  );

typedef 
EFI_STATUS
(EFIAPI *REMOTE_CFG_PKT_PROCESSING_RX_PACKETS) (
  IN REMOTE_CFG_PKT_PROTOCOL *This,
  IN EFI_HANDLE Handle,
  IN UINT8 *InData,
  IN UINTN InDataLen,
  IN OUT BOOLEAN *bNewPktRx,
  IN OUT UINT8 **NewPkt,
  IN OUT UINTN *NewPktLen
  );

typedef 
EFI_STATUS
(EFIAPI *REMOTE_CFG_PKT_SEND_ANS) (
  IN REMOTE_CFG_PKT_PROTOCOL *This,
  IN EFI_HANDLE Handle,
  IN UINT8 Addr,
  IN UINT8 Func,
  IN UINT8 Sc,
  IN UINTN DataLen,
  IN UINT8 *Data,
  IN UINT8 CrcType
  );


typedef 
EFI_STATUS
(EFIAPI *REMOTE_CFG_PKT_CLOSE) (
  IN REMOTE_CFG_PKT_PROTOCOL *This,
  IN EFI_HANDLE Handle
  );

typedef 
EFI_STATUS
(EFIAPI *REMOTE_CFG_PKT_TX) (
  IN REMOTE_CFG_PKT_PROTOCOL *This,
  IN EFI_HANDLE Handle,
  IN UINT8 *TxBuf,
  IN OUT UINTN *TxLen
  );


struct _REMOTE_CFG_PKT_PROTOCOL {
  REMOTE_CFG_PKT_OPEN ProtocolOpen;
  REMOTE_CFG_PKT_GET_STATE GetState;
  REMOTE_CFG_PKT_RESET_STATE ResetState;
  REMOTE_CFG_PKT_PROTOCOL_STARTED  ProtocolStarted;
  REMOTE_CFG_PKT_PROCESSING_RX_PACKETS ProcessingRxPackets;
  REMOTE_CFG_PKT_SEND_ANS SendAns;
  REMOTE_CFG_PKT_TX Tx;
  REMOTE_CFG_PKT_CLOSE ProtocolClose;
};

extern EFI_GUID gRemoteCfgPktProtocolGuid;

#endif /* #ifndef __REMOTE__CFG__PKT__PROTOCOL__H */
