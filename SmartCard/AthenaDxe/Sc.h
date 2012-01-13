/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __SC__H
#define __SC__H

#define USB_REQUEST_TYPE(Dir, Type, Target) \
          ((UINT8)((((Dir) == EfiUsbDataIn ? 0x01 : 0) << 7) | (Type) | (Target)))

#define ATHENA_DEFAULT_TIMEOUT              10000
#define BULK_BUFFER_SIZE                    300

#define ASE_LONG_RESPONSE_PID               0x90
#define ASE_RESPONSE_PID                    0x10
#define ASE_ACK_PID                         0x20
#define ASE_LONG_RESPONSE_WITH_STATUS_PID   0xF0
#define ASE_RESPONSE_WITH_STATUS_PID        0x70


#endif  /* #ifndef __SC__H */
