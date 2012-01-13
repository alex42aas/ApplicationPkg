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
#include <Library/Ccid.h>



//
// Global Variables
//
extern EFI_DRIVER_BINDING_PROTOCOL   gUsbCcidDriverBinding;
extern EFI_COMPONENT_NAME_PROTOCOL   gUsbCcidComponentName;
extern EFI_COMPONENT_NAME2_PROTOCOL  gUsbCcidComponentName2;

typedef enum {
  TYPE_APDU,
  TYPE_TPDU,
  TYPE_CHAR
} READER_TYPE;

#ifdef _MSC_VER
#pragma warning (disable: 4201)
#endif


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

#ifndef EFI_ERROR_RET
#define EFI_ERROR_RET(S, X)     EFI_ERROR_ACTION(S, X, goto OnError)
#endif
#define EFI_ERROR_REALRET(S, X) EFI_ERROR_ACTION(S, X, return S_)

#define CHECKED_CALL(F, P)      EFI_ERROR_REALRET(F P, #F #P " is failed")

#define CHECK_USB_STATUS(X) ((X) ==  EFI_USB_NOERROR ? EFI_SUCCESS : EFI_DEVICE_ERROR)

#ifndef FIELD_OFFSET
#define FIELD_OFFSET(t,f) ((UINTN)&(((t*)0)->f))
#endif

#endif /* SMARTCARD_H */
