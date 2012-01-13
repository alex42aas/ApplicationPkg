/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __CCID__H
#define __CCID__H

//#include <SomeCompilerFixes.h>


#ifdef _MSC_VER
#pragma warning (disable: 4201)
#endif


#define CCID_DEV_SIGNATURE            SIGNATURE_32 ('c', 'c', 'i', 'd')

// dwFeatures
#define AUTOMATIC_ICC_CLOCK_FRQ_CHG   0x10
#define AUTOMATIC_ICC_BAUD_RATE_CHG   0x20
#define TPDU_EXCHANGE_LEVEL           0x10000
#define APDU_EXCHANGE_LEVEL           0x20000
#define APDU_EXT_EXCHANGE_LEVEL       0x40000
#define AUTO_CONFIG_ATR_PARSE         0x2
#define AUTO_ACTIVATE                 0x4
#define AUTO_VOLTAGE                  0x8
#define AUTO_PARAM_NEG                0x40
#define AUTO_PPS                      0x80

#define SUPPORT_T0                    0x1
#define SUPPORT_T1                    0x2
#define SUPPORT_ESCAPE                0x80

#define SUPPORT_VOLTAGE_50V           0x1
#define SUPPORT_VOLTAGE_33V           0x2
#define SUPPORT_VOLTAGE_18V           0x4


#define FLAG_NO_PTS                   0x001
#define FLAG_NO_SETPARAM              0x002
#define FLAG_AUTO_ACTIVATE            0x004
#define FLAG_AUTO_ATRPARSE            0x008

#define FLAG_VOLTAGE_50V              0x010
#define FLAG_VOLTAGE_33V              0x020
#define FLAG_VOLTAGE_18V              0x040
#define FLAG_VOLTAGE_AUTO             0x080
#define FLAG_PROTOCOL_T0              0x100
#define FLAG_PROTOCOL_T1              0x200
#define FLAG_PROTOCOL_ESCAPE          0x400

#define USB_CCID_DESCRIPTOR_LENGTH    54

// Slot Error register values then bmCommandStatus == 1

#define CCID_ERR_ABORTED                    0xFF    /* CMD ABORTED */
#define CCID_ERR_ICC_MUTE                   0xFE
#define CCID_ERR_XFR_PARITY                 0xFD    /* XFR PARITY ERROR */
#define CCID_ERR_OVERRUN                    0xFC    /* XFR OVERRUN */
#define CCID_ERR_HW_ERROR                   0xFB
#define CCID_ERR_BAD_ATR_TS                 0xF8
#define CCID_ERR_BAD_ATR_TCK                0xF7
#define CCID_ERR_PROT_NOSUP                 0xF6    /* ICC PROTOCOL NOT SUPPORTED */
#define CCID_ERR_CLASS_NOSUP                0xF5    /* ICC CLASS NOT SUPPORTED */
#define CCID_ERR_BAD_PROC_BYTE              0xF4    /* PROCEDURE BYTE CONFLICT */
#define CCID_ERR_XXX                        0xF3    /* DEACTIVATED PROTOCOL (?) */
#define CCID_ERR_BUSY_AUTO_SEQ              0xF2    /* BUSY WITH AUTO SEQUENCE */
#define CCID_ERR_PIN_TIMEOUT                0xF0
#define CCID_ERR_PIN_CANCELED               0xEF
#define CCID_ERR_SLOT_BUSY                  0xE0    /* CMD SLOT BUSY */

// bmIccStatus
#define CCID_STATUS_ICC_PRESENT_ACTIVE      0
#define CCID_STATUS_ICC_PRESENT_INACTIVE    1
#define CCID_STATUS_ICC_NOT_PRESENT         2

#define CCID_RESPONSE_NO_ERROR              0
#define CCID_RESPONSE_ERROR                 1
#define CCID_RESPONSE_MORE_TIME             2


#define CCID_OFFSET_MSGTYPE                 0
#define CCID_OFFSET_LENGTH                  1
#define CCID_OFFSET_SLOT                    5
#define CCID_OFFSET_SEQ                     6

#define CCID_REQ_ABORT                      1
#define CCID_REQ_GETCLOCKRATE               2
#define CCID_REQ_GETDATARATE                3

#define CCID_CMD_FIRST                      0x60

#define CCID_CMD_ICCPOWERON                 0x62
#define CCID_CMD_ICCPOWEROFF                0x63
#define CCID_CMD_GETSLOTSTAT                0x65
#define CCID_CMD_XFRBLOCK                   0x6F
#define CCID_CMD_GETPARAMS                  0x6C
#define CCID_CMD_RESETPARAMS                0x6D
#define CCID_CMD_SETPARAMS                  0x61
#define CCID_CMD_ESCAPE                     0x6B
#define CCID_CMD_ICCCLOCK                   0x6E
#define CCID_CMD_T0APDU                     0x6A
#define CCID_CMD_SECURE                     0x69
#define CCID_CMD_MECHANICAL                 0x71
#define CCID_CMD_ABORT                      0x72
#define CCID_CMD_SET_DR_FREQ                0x73

#define CCID_RESP_DATA                      0x80
#define CCID_RESP_SLOTSTAT                  0x81
#define CCID_RESP_PARAMS                    0x82
#define CCID_RESP_ESCAPE                    0x83
#define CCID_RESP_DR_FREQ                   0x84

/* maximum sensical size:
 *  10 bytes ccid header + 4 bytes command header +
 *  1 byte Lc + 255 bytes data + 1 byte Le = 271
 */
#define CCID_MAX_MSG_LEN                    271



typedef UINT8 CCID_ERROR_STATUS_REGISTER;

#pragma pack(1)
typedef struct _CCID_PROTOCOL_DATA_STRUCTURE_T0 {
  union {
    UINT8 bmFindexDindex;
    struct {
      UINT8 Findex:4;
      UINT8 Dindex:4;
    } s;
  };
  UINT8 bmTCCKST0;
  UINT8 bGuardTimeT0;
  UINT8 bWaitingIntegersT0;
  UINT8 bClockStop;
} CCID_PROTOCOL_DATA_STRUCTURE_T0;

typedef struct _CCID_PROTOCOL_DATA_STRUCTURE_T1 {
  union {
    struct {
      UINT8 Findex:4;
      UINT8 Dindex:4;
    } s;
    UINT8 bmFindexDindex;
  };

  struct {
#define PARAMS_T1_CS_CRC 1
#define PARAMS_T1_CS_LRC 0

    UINT8 CheckSumType:1;           // B0
    UINT8 Convertion:1;             // B1
    UINT8 ProtocolSpecific:6;       // B2-7
  } bmTCCKST1;
  UINT8 bGuardTimeT1;
  UINT8 bWaitingIntegersT1;
  UINT8 bClockStop;
  UINT8 bIFCS;
  UINT8 bNadValue;
} CCID_PROTOCOL_DATA_STRUCTURE_T1;


typedef struct _CCID_CTL {
  UINT8 Data[3];
} CCID_CTL;


typedef struct _CCID_ICCPOWERON {
  UINT8    bPowerSelect;
  UINT8    abRFU[2];
} CCID_ICCPOWERON;

typedef struct _CCID_PC_TO_RDR_SETPARAMETERS {
  UINT8 bProtocolNum;
  UINT8 abRFU[2];
} CCID_PC_TO_RDR_SETPARAMETERS;

typedef struct _CCID_PC_TO_RDR_XFRBLOCK {
  UINT8 bBWI;
  UINT16 wLevelParameter;
} CCID_PC_TO_RDR_XFRBLOCK;

typedef struct _CCID_CMD_HEADER {
  UINT8    Command;
  UINT32   Length;
  UINT8    Slot;
  UINT8    Sequence;
} CCID_CMD_HEADER;

/* (CLA INS P1 P2) = 4, Lc = 1, Data = 255, Le = 1 */
#define CCID_MAX_MSG_DATA 4 + 1 + 255 + 1

typedef struct _CCID_PIN_VERIFICATION {
  UINT8 bTimeOut;

  struct {
    UINT8 Type:2; // 00 - Binary 01 - BCD 02 - ASCII
    UINT8 Justification:1; // 0 - Left 1 - Right
    UINT8 Position:4; // Pin position in the APDU command
    UINT8 Units:1; // Units  0 - bits 1 - bytes;
  } bmFormatString;

  struct {
    UINT8 SizeInBytes:4;
    UINT8 SizeInBits:4;
  } bmPINBlockString;
  struct {
    UINT8 Length:4;
    UINT8 Units:1;
    UINT8 RFU:3;
  } bmPINLengthFormat;

  UINT16 wPINMaxExtraDigit;
  UINT8 bEntryValidationCondition;
  UINT8 bNumberMessage;
  UINT8 wLangId;
  UINT8 bMsgIndex;
  UINT8 bTeoPrologue[3];
  UINT8 abPINApdu[1];
} CCID_PIN_VERIFICATION;


typedef struct _CCID_PIN_MODIFICATION {
  UINT8 bTimeOut;

  struct {
    UINT8 Type:2; // 00 - Binary 01 - BCD 02 - ASCII
    UINT8 Justification:1; // 0 - Left 1 - Right
    UINT8 Position:4; // Pin position in the APDU command
    UINT8 Units:1; // Units  0 - bits 1 - bytes;
  } bmFormatString;

  struct {
    UINT8 SizeInBytes:4;
    UINT8 SizeInBits:4;
  } bmPINBlockString;
  struct {
    UINT8 Length:4;
    UINT8 Units:1;
    UINT8 RFU:3;
  } bmPINLengthFormat;


  UINT8 bInsertionOffsetOld;
  UINT8 bInsertionOffsetNew;
  UINT16 wPINMaxExtraDigit;

  struct {
    UINT8 ConformationRequested:1;
    UINT8 CurrentPINEntryRequested:1;
    UINT8 RFU:6;
  } bConfirmPIN;

  UINT8 bEntryValidationCondition;
  UINT8 bNumberMessage;
  UINT8 wLangId;
  UINT8 bMsgIndex1;
  UINT8 bMsgIndex2;
  UINT8 bMsgIndex3;
  UINT8 bTeoPrologue[3];
  UINT8 abPINApdu[1];
} CCID_PIN_MODIFICATION;



typedef struct _CCID_CMD {
  CCID_CMD_HEADER Header;
  union {
    CCID_CTL Raw;
    CCID_ICCPOWERON IccPowerOn;
    CCID_PC_TO_RDR_SETPARAMETERS SetParameters;
    CCID_PC_TO_RDR_XFRBLOCK XfrBlock;
  } Ctl;

  union {
    UINT8 abCommandRawData[CCID_MAX_MSG_DATA];

    struct {
      union {
        CCID_PROTOCOL_DATA_STRUCTURE_T0 T0;
        CCID_PROTOCOL_DATA_STRUCTURE_T1 T1;
      };
    } SetParams;

    struct {
      UINT8 bPINOperation;
      union {
        CCID_PIN_VERIFICATION Verification;
        CCID_PIN_MODIFICATION Modification;
      };
    } PINOperations;
  };

} CCID_CMD;


typedef struct _CCID_SLOT_STATUS_REGISTER {
  UINT8 bmICCStatus:2;
  UINT8 bmRFU:4;
  UINT8 bmCommandStatus:2;
} CCID_SLOT_STATUS_REGISTER;

typedef struct _CCID_RESPONSE_MSG_HEADER {
  UINT8    Command;
  UINT32   Length;
  UINT8    Slot;
  UINT8    Sequence;
  CCID_SLOT_STATUS_REGISTER bStatus;
  CCID_ERROR_STATUS_REGISTER bError;
} CCID_RESPONSE_MSG_HEADER;


// RDR_to_PC_IccPowerOff
// RDR_to_PC_GetSlotStatus
// RDR_to_PC_IccClock
// RDR_to_PC_T0APDU
// RDR_to_PC_Mechanical

typedef struct _CCID_RESPONSE_SLOT_STATUS {
  UINT8 bClockStatus;
} CCID_RESPONSE_SLOT_STATUS;



//
// response for  PC_to_RDR_GetParameters
//               PC_to_RDR_ResetParameters
//               PC_to_RDR_SetParameters

typedef enum {
  PROTOCOL_T0 = 0x00,
  PROTOCOL_T1 = 0x01,
  PROTOCOL_2W = 0x80,
  PROTOCOL_3W = 0x81,
  PROTOCOL_I2C = 0x82,
} PROTOCOL_NUMBER;



typedef struct _CCID_RDR_TO_PC_PARAMETERS {
  UINT8 bProtocolNum;
  union {
    UINT8 abProtocolDataStructure[1];
    CCID_PROTOCOL_DATA_STRUCTURE_T0 T0;
    CCID_PROTOCOL_DATA_STRUCTURE_T1 T1;
  };
} CCID_RDR_TO_PC_PARAMETERS;

typedef struct _CCID_RDR_TO_PC_DATA_BLOCK {
  UINT8 bChainParameter;
//  UINT8 abData[2];
} CCID_RDR_TO_PC_DATA_BLOCK;

// A generic response message
typedef struct _CCID_RESPONSE_MESSAGE {
  CCID_RESPONSE_MSG_HEADER Header;
  union {
    UINT8 RawData[CCID_MAX_MSG_DATA];
    CCID_RDR_TO_PC_PARAMETERS Params;
    CCID_RESPONSE_SLOT_STATUS SlotStatus;
    CCID_RDR_TO_PC_DATA_BLOCK DataBlock;
  };
} CCID_RESPONSE_MESSAGE;


typedef enum {
  CCID_PROTOCOL_NONE = 0,
  CCID_PROTOCOL_T0 = 1,
  CCID_PROTOCOL_T1 = 2,
  CCID_PROTOCOL_ESCAPE = 8
} CCID_PROTOCOL;

typedef struct __PPS0 {
  UINT8 T:4;
  UINT8 PPS1_Present:1;
  UINT8 PPS2_Present:1;
  UINT8 PPS3_Present:1;
  UINT8 RFU:1;
} _PPS0;

#define PPS1_INDEX 0
#define PPS2_INDEX 1
#define PPS3_INDEX 2

typedef struct {
  UINT8 PPSS;
  union {
    UINT8 PPS0_Raw;
    _PPS0 PPS0;
  };
  UINT8 Optional[4];
} PPS;

#define ATR_NONE 0xFF

typedef struct _ATR_BYTE_T0 {
  UINT8 K:4;
  UINT8 Y:4;
} ATR_BYTE_T0;

typedef struct _ATR_BYTE_TDI {
  UINT8 T:4;
  UINT8 Y:4;
} ATR_BYTE_TDI;

typedef struct _ATR_BYTE ATR_BYTE;
#define ATR_NEXT(X) (X) = (ATR_BYTE*) &(X)->Data;

enum {
  ATR_TA = 0x10,
  ATR_TB = 0x20,
  ATR_TC = 0x40,
  ATR_TCK = 0x80
};

struct _ATR_BYTE {
  union {
    ATR_BYTE_T0 T0;
    ATR_BYTE_TDI TDi;
    UINT8 TDByte[1];
  };
  UINT8 Data;
};

#pragma pack()

#define CCID_MAX_SLOTS 25

typedef struct _PDU {
  UINT8 *Buffer;
  UINTN Length;
} PDU;



typedef struct _CCID_ATR_INFO {
  UINT8 TA[4];
  UINT8 TB[4];
  UINT8 TC[4];
  UINT32 SupportedProtocols;
  CCID_PROTOCOL DefaultProtocol;
} CCID_ATR_INFO;

#define ATR_BLOB_MAX_SIZE 54

typedef struct _CCID_SLOT_STATE {
  CCID_PROTOCOL Protocol;
  CCID_ATR_INFO Atr;
  UINT8 AtrBlob[ATR_BLOB_MAX_SIZE];
  UINTN AtrBlobLength;
} CCID_SLOT_STATE;




#pragma pack(1)
typedef struct _USB_CCID_DESCRIPTOR {
  UINT8  bLength;
  UINT8  bDescriptorType;
  UINT16 bcdCCID;
  UINT8  bMaxSlotIndex;
  UINT8  bVoltageSupport;
  UINT32 dwProtocols;
  UINT32 dwDefaultClock;
  UINT32 dwMaximumClock;
  UINT8  bNumClockRatesSupported;
  UINT32 dwDataRate;
  UINT32 dwMaxDataRate;
  UINT8  bNumDataRatesSupported;
  UINT32 dwMaxIFSD;
  UINT32 dwSynchProtocols;
  UINT32 dwMechanical;
  UINT32 dwFeatures;
  UINT32 dwMaxCCIDMessageLength;
  UINT8  bClassGetResponse;
  UINT8  bClassEnvelope;
  UINT16 wLcdLayout;
  UINT8  bPINSupport;
  UINT8  bMaxCCIDBusySlots;
} USB_CCID_DESCRIPTOR;
#pragma pack()


EFI_STATUS
CcidBuildCommand(
  IN OUT CCID_CMD *CcidCmd,
  IN UINTN CommandLen,
  IN UINT8 Slot,
  IN UINT8 Cmd,
  IN CCID_CTL *Ctl,
  IN UINT8 *SendData,
  IN UINTN SendDataLen,
  IN OUT UINT8 *Sequence
  );

EFI_STATUS
CcidCheckRespone(
  IN CCID_RESPONSE_MSG_HEADER *ResultMessage,
  IN UINTN Length
  );

EFI_STATUS
CcidParseAtr(
  OUT    CCID_ATR_INFO *AtrInfo,
  IN     UINT8 *Atr,
  IN     UINTN AtrLength
  );


#endif /* #ifndef __CCID__H */

