/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __HISTORY__HANDLER__PROTO__H
#define __HISTORY__HANDLER__PROTO__H


#include <Library/BaseLib.h>


#define HISTORY_HANDLER_PROTOCOL_GUID \
  { \
    0xecb3de6b, 0xecc9, 0x4572, { 0x9d, 0xba, 0x81, 0x8a, 0x52, 0x53, 0xd, 0x1e } \
  }


typedef struct _HISTORY_HANDLER_PROTOCOL HISTORY_HANDLER_PROTOCOL;

typedef 
EFI_STATUS
(EFIAPI *HISTORY_HANDLER_ADD_RECORD) (
  IN HISTORY_HANDLER_PROTOCOL *This,
  IN UINT16 EventCode,
  IN UINT8 Severity,
  IN UINT8 Flags
  );

typedef 
EFI_STATUS
(EFIAPI *HISTORY_HANDLER_GET_PARAMS) (
  IN HISTORY_HANDLER_PROTOCOL *This,
  IN OUT UINT8 *Severity,
  IN OUT UINT8 *Flags
  );

typedef 
EFI_STATUS
(EFIAPI *HISTORY_HANDLER_SET_PARAMS) (
  IN HISTORY_HANDLER_PROTOCOL *This,
  IN UINT8 Severity,
  IN UINT8 Flags
  );

typedef 
EFI_STATUS
(EFIAPI *HISTORY_HANDLER_UNLOAD_CSV) (
  IN HISTORY_HANDLER_PROTOCOL *This,
  IN OUT CHAR16 **CsvStr16
  );

typedef 
EFI_STATUS
(EFIAPI *HISTORY_HANDLER_GET_CSV) (
  IN HISTORY_HANDLER_PROTOCOL *This,
  IN OUT CHAR16 **CsvStr16
  );

typedef 
EFI_STATUS
(EFIAPI *HISTORY_HANDLER_MARK_AS_UNLOADED) (
  IN HISTORY_HANDLER_PROTOCOL *This,
  IN UINT32 Num,
  IN UINT32 RecNum[]
  );



typedef 
EFI_STATUS
(EFIAPI *HISTORY_HANDLER_LOCK_OPERATIONS) (
  IN HISTORY_HANDLER_PROTOCOL *This
  );

typedef 
EFI_STATUS
(EFIAPI *HISTORY_HANDLER_UNLOCK_OPERATIONS) (
  IN HISTORY_HANDLER_PROTOCOL *This
  );



struct _HISTORY_HANDLER_PROTOCOL {
  HISTORY_HANDLER_ADD_RECORD    AddRecord;
  HISTORY_HANDLER_GET_PARAMS    GetParams;
  HISTORY_HANDLER_SET_PARAMS    SetParams;
  HISTORY_HANDLER_UNLOAD_CSV    UnloadCsv16;
  HISTORY_HANDLER_LOCK_OPERATIONS   LockOp;
  HISTORY_HANDLER_UNLOCK_OPERATIONS UnLockOp;
  HISTORY_HANDLER_GET_CSV       GetCsv16;
  HISTORY_HANDLER_MARK_AS_UNLOADED MarkAsUnloaded;
};

extern EFI_GUID gHistoryHandlerProtocolGuid;


#endif /* #ifndef __HISTORY__HANDLER__PROTO__H */

