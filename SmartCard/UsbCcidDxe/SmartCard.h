/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef SMARTCARD_H
#define SMARTCARD_H

#define CLASS_SMARTCARD 0xB
#define PROTOCOL_CCID   0x0

#include <SomeCompilerFixes.h>

#include <Uefi.h>

#include <Protocol/SimpleTextIn.h>
#include <Protocol/SimpleTextInEx.h>
#include <Protocol/HiiDatabase.h>
#include <Protocol/UsbIo.h>
#include <Protocol/DevicePath.h>
//#include <Protocol/SimpleTextInExNotify.h>
//#include <Protocol/HotPlugDevice.h>


#include <Library/DebugLib.h>
#include <Library/ReportStatusCodeLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiDriverEntryPoint.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PcdLib.h>
#include <Library/UefiUsbLib.h>

#include <IndustryStandard/Usb.h>


#include <Protocol/SmartCard.h>
#define USB_CCID_DEV_SIGNATURE  SIGNATURE_32 ('c', 'c', 'i', 'd')


//
// Global Variables
//
extern EFI_DRIVER_BINDING_PROTOCOL   gUsbCcidDriverBinding;
extern EFI_COMPONENT_NAME_PROTOCOL   gUsbCcidComponentName;
extern EFI_COMPONENT_NAME2_PROTOCOL  gUsbCcidComponentName2;

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

typedef enum {
  TYPE_APDU,
  TYPE_TPDU,
  TYPE_CHAR
} READER_TYPE;

// dwFeatures
#define AUTOMATIC_ICC_CLOCK_FRQ_CHG 0x10
#define AUTOMATIC_ICC_BAUD_RATE_CHG 0x20
#define TPDU_EXCHANGE_LEVEL         0x10000
#define APDU_EXCHANGE_LEVEL         0x20000
#define APDU_EXT_EXCHANGE_LEVEL     0x40000
#define AUTO_CONFIG_ATR_PARSE       0x2
#define AUTO_ACTIVATE               0x4
#define AUTO_VOLTAGE                0x8
#define AUTO_PARAM_NEG              0x40
#define AUTO_PPS                    0x80

#define SUPPORT_T0      0x1
#define SUPPORT_T1      0x2
#define SUPPORT_ESCAPE  0x80

#define SUPPORT_VOLTAGE_50V      0x1
#define SUPPORT_VOLTAGE_33V      0x2
#define SUPPORT_VOLTAGE_18V      0x4


#define FLAG_NO_PTS                 0x001
#define FLAG_NO_SETPARAM            0x002
#define FLAG_AUTO_ACTIVATE          0x004
#define FLAG_AUTO_ATRPARSE          0x008

#define FLAG_VOLTAGE_50V            0x010
#define FLAG_VOLTAGE_33V            0x020
#define FLAG_VOLTAGE_18V            0x040
#define FLAG_VOLTAGE_AUTO           0x080
#define FLAG_PROTOCOL_T0            0x100
#define FLAG_PROTOCOL_T1            0x200
#define FLAG_PROTOCOL_ESCAPE        0x400

#define USB_CCID_DESCRIPTOR_LENGTH 54

// Slot Error register values then bmCommandStatus == 1

#define CCID_ERR_ABORTED        0xFF    /* CMD ABORTED */
#define CCID_ERR_ICC_MUTE       0xFE
#define CCID_ERR_XFR_PARITY     0xFD    /* XFR PARITY ERROR */
#define CCID_ERR_OVERRUN        0xFC    /* XFR OVERRUN */
#define CCID_ERR_HW_ERROR       0xFB
#define CCID_ERR_BAD_ATR_TS     0xF8
#define CCID_ERR_BAD_ATR_TCK    0xF7
#define CCID_ERR_PROT_NOSUP     0xF6    /* ICC PROTOCOL NOT SUPPORTED */
#define CCID_ERR_CLASS_NOSUP    0xF5    /* ICC CLASS NOT SUPPORTED */
#define CCID_ERR_BAD_PROC_BYTE  0xF4    /* PROCEDURE BYTE CONFLICT */
#define CCID_ERR_XXX            0xF3    /* DEACTIVATED PROTOCOL (?) */
#define CCID_ERR_BUSY_AUTO_SEQ  0xF2    /* BUSY WITH AUTO SEQUENCE */
#define CCID_ERR_PIN_TIMEOUT    0xF0
#define CCID_ERR_PIN_CANCELED   0xEF
#define CCID_ERR_SLOT_BUSY      0xE0    /* CMD SLOT BUSY */

// bmIccStatus
#define CCID_STATUS_ICC_PRESENT_ACTIVE 0
#define CCID_STATUS_ICC_PRESENT_INACTIVE 1
#define CCID_STATUS_ICC_NOT_PRESENT 2

#ifdef _MSC_VER
#pragma warning (disable: 4201)
#endif

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

#define CCID_RESPONSE_NO_ERROR  0
#define CCID_RESPONSE_ERROR     1
#define CCID_RESPONSE_MORE_TIME 2

typedef UINT8 CCID_ERROR_STATUS_REGISTER;

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

struct _USB_CCID_DEV {
  UINT32                            Signature;
  UINT8                             Sequence;
//  UINT8                             Protocols;
  READER_TYPE                       ReaderType;
//  UINT8                             VoltageSupport;
  UINT32                            Flags;
  UINT32                            MaxMsgLength;
  UINT32                            Slots;
  CCID_SLOT_STATE                   State[CCID_MAX_SLOTS];
  PDU                               Send[CCID_MAX_SLOTS];
  EFI_DEVICE_PATH_PROTOCOL          *DevicePath;
  EFI_USB_IO_PROTOCOL               *UsbIo;
  EFI_USB_INTERFACE_DESCRIPTOR      InterfaceDescriptor;
  EFI_USB_ENDPOINT_DESCRIPTOR       IntEndpointDescriptor;
  EFI_USB_ENDPOINT_DESCRIPTOR       InEndpointDescriptor;
  EFI_USB_ENDPOINT_DESCRIPTOR       OutEndpointDescriptor;
  USB_CCID_DESCRIPTOR               CcidDescriptor;
  EFI_UNICODE_STRING_TABLE          *ControllerNameTable;
  SMART_CARD_READER_PROTOCOL        SmartCardReaderIo;
  SMART_CARD_PROTOCOL               SmartCard;
  BOOLEAN                           Locked;
  EFI_HANDLE                        hController;
  EFI_HANDLE                        AgentHandle;
  EFI_LOCK                          UsbCcidLock;
  BOOLEAN                           bDriverStopped;
};

#define EFI_ERROR_ACTION(S, X, A) \
  do {                                                                         \
    /* Ensure that S is evaluated just once (so, it might be an expression) */ \
    EFI_STATUS S_ = S;                                                         \
                                                                               \
    if (EFI_ERROR(S_)) {                                                       \
      DEBUG ((                                                                 \
        EFI_D_ERROR,                                                           \
        "%d: " X "%sStatus: (0x%08X) %r\n",                                    \
        __LINE__,                                                              \
        sizeof (X) > 1 ? L", " : L"",                                          \
        (S_),                                                                  \
        (S_))                                                                  \
        );                                                                     \
      A;                                                                       \
    }                                                                          \
  } while(0)

#define EFI_ERROR_RET(S, X)     EFI_ERROR_ACTION(S, X, goto OnError)
#define EFI_ERROR_REALRET(S, X) EFI_ERROR_ACTION(S, X, return S_)

#define CHECKED_CALL(F, P)      EFI_ERROR_REALRET(F P, #F #P " is failed")

#define CHECK_USB_STATUS(X) ((X) ==  EFI_USB_NOERROR ? EFI_SUCCESS : EFI_DEVICE_ERROR)

#ifndef FIELD_OFFSET
#define FIELD_OFFSET(t,f) ((UINTN)&(((t*)0)->f))
#endif

#endif /* SMARTCARD_H */
