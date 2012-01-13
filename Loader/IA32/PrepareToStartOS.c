/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "Loader.h"
#include "Multiboot.h"

#define STACK_SIZE 1024
UINT32 Stack[STACK_SIZE];
// VOID _StartOsKernel( VOID );   
VOID StartOsKernel (
  IN      VOID                      *Context1,  OPTIONAL
  IN      VOID                      *Context2   OPTIONAL
  );
#pragma pack(1)
typedef struct _RELOCATION_INFO {
  UINT32 MultibootHeader;
  UINT32 BaseAddress; // Base physical address
  UINT32 LoadAddress; // current kernel position
  UINT32 LoadSize;    // kernel Size
  UINT32 KernelEntry; // 
} RELOCATION_INFO;
#pragma pack()
RELOCATION_INFO gRelocationInfo;

VOID 
PrepareToStartOS(
    MULTIBOOT_HEADER *Header, 
    UINT32 BaseAddress,
    UINT32 LoadAddress, 
    UINT32 LoadSize,
    UINT32 KernelEntry )
{
  DEBUG((EFI_D_ERROR, "PrepareToStartOS: Entry:10:%x Param1(MbInfo):%x Param2(RelocInfo):%x Stack:%x\n", 
	StartOsKernel,
	gMultibootInfo,
	&gRelocationInfo,
	&Stack[STACK_SIZE-1]
      	));

  gRelocationInfo.MultibootHeader = (UINT32)(UINTN) Header;
  gRelocationInfo.BaseAddress = BaseAddress;
  gRelocationInfo.LoadAddress = LoadAddress;
  gRelocationInfo.LoadSize    = LoadSize;
  gRelocationInfo.KernelEntry = KernelEntry;

  AsmDisablePaging32(
      StartOsKernel, 	  		                // EntryPoint
      (VOID*) (UINTN) (gMultibootInfo), 		// Param 1
      (VOID*) (UINTN) &gRelocationInfo,  		// Param 2
      (VOID*) (UINTN) &Stack[STACK_SIZE-1]  // Stack
      );
}
