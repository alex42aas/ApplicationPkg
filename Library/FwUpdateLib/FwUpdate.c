/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Library/FwUpdate.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PrintLib.h>
#include <Library/BaseLib.h>
#include <Protocol/PcdHelperProtocol.h>


#if	1
#define LOG(MSG)
#else
#define LOG(MSG)          DEBUG(MSG)
#endif


static CHAR16 *Str16Write, *Str16Erase, *Str16Rest;
static EFI_FIRMWARE_VOLUME_HEADER *FwVolHeader;
extern EFI_BOOT_SERVICES *gBS;
extern EFI_SYSTEM_TABLE  *gST;
STATIC PCD_HELPER_PROTOCOL *gPcdHelperProtocol;

STATIC
EFI_STATUS
CommonInit (
  VOID
  )
{
  EFI_STATUS Status;

  if (gPcdHelperProtocol) {
    return EFI_SUCCESS;
  }

  Status = gBS->LocateProtocol (
        &gPcdHelperProtocolGuid,
        NULL,
        (VOID **)&gPcdHelperProtocol
        );
  if (EFI_ERROR(Status)) {
    gPcdHelperProtocol = NULL;
    DEBUG((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
  }
  return Status;
}

EFI_STATUS
InitFlashRanges (
  VOID
  )
{
  EFI_STATUS Status;
  EFI_HANDLE *HandleBuffer;
  UINTN HandleCount;
  UINTN Index;
  EFI_PHYSICAL_ADDRESS FvbBaseAddress;
  EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL *Fvb;

  //
  // Locate all handles of Fvb protocol
  //
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiFirmwareVolumeBlockProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer
                  );
  if (EFI_ERROR (Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n",
      __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  LOG((EFI_D_ERROR, "%a.%d HandleCount=%d\n",
    __FUNCTION__, __LINE__, HandleCount));

  if (NULL == FwVolHeader) {
    FwVolHeader = AllocateZeroPool(sizeof(EFI_FIRMWARE_VOLUME_HEADER) 
      * HandleCount);
    if (NULL == FwVolHeader) {
      return EFI_OUT_OF_RESOURCES;
    }
  }

  //
  // Get the FVB to access variable store
  //
  for (Index = 0; Index < HandleCount; Index++) {
    Status = gBS->HandleProtocol (
                    HandleBuffer[Index],
                    &gEfiFirmwareVolumeBlockProtocolGuid,
                    (VOID **) &Fvb
                    );
    if (EFI_ERROR (Status)) {
      LOG((EFI_D_ERROR, "%a.%d Error!\n",
        __FUNCTION__, __LINE__));     
      return EFI_NOT_FOUND;
    }

    //
    // Compare the address and select the right one
    //
    Status = Fvb->GetPhysicalAddress (Fvb, &FvbBaseAddress);
    if (EFI_ERROR (Status)) {
      LOG((EFI_D_ERROR, "%a.%d Error!\n",
        __FUNCTION__, __LINE__));
      continue;
    }

    CopyMem(&FwVolHeader[Index], 
      (EFI_FIRMWARE_VOLUME_HEADER*) ((UINTN) FvbBaseAddress),
      sizeof(EFI_FIRMWARE_VOLUME_HEADER));

    LOG((EFI_D_ERROR, "FvbBaseAddress=0x%llX Len=0x%llX\n",
      FvbBaseAddress, FwVolHeader[Index].FvLength));    
  }

  FreePool (HandleBuffer);
  return Status;
}




EFI_STATUS
GetFvbHandleByAddressSize (
  IN EFI_PHYSICAL_ADDRESS Address,
  IN OUT UINTN *Limit,
  OUT EFI_HANDLE *FvbHandle
  )
{
  EFI_STATUS Status;
  EFI_HANDLE *HandleBuffer;
  UINTN HandleCount;
  UINTN Index;
  EFI_PHYSICAL_ADDRESS FvbBaseAddress;
  EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL *Fvb;  
  EFI_FVB_ATTRIBUTES_2 Attributes;

  if (NULL == FwVolHeader) {
    return EFI_ABORTED;
  }

  *FvbHandle = NULL;
  //
  // Locate all handles of Fvb protocol
  //
  Status = gBS->LocateHandleBuffer (
                  ByProtocol,
                  &gEfiFirmwareVolumeBlockProtocolGuid,
                  NULL,
                  &HandleCount,
                  &HandleBuffer
                  );
  if (EFI_ERROR (Status)) {
    LOG((EFI_D_ERROR, "%a.%d Error!\n",
      __FUNCTION__, __LINE__));
    return EFI_NOT_FOUND;
  }

  LOG((EFI_D_ERROR, "%a.%d HandleCount=%d\n",
    __FUNCTION__, __LINE__, HandleCount));  

  //
  // Get the FVB to access variable store
  //
  for (Index = 0; Index < HandleCount; Index++) {
    Status = gBS->HandleProtocol (
                    HandleBuffer[Index],
                    &gEfiFirmwareVolumeBlockProtocolGuid,
                    (VOID **) &Fvb
                    );
    if (EFI_ERROR (Status)) {
      LOG((EFI_D_ERROR, "%a.%d Error!\n",
        __FUNCTION__, __LINE__));     
      return EFI_NOT_FOUND;
    }

    //
    // Compare the address and select the right one
    //
    Status = Fvb->GetPhysicalAddress (Fvb, &FvbBaseAddress);
    if (EFI_ERROR (Status)) {
      LOG((EFI_D_ERROR, "%a.%d Error!\n",
        __FUNCTION__, __LINE__));
      continue;
    }

    LOG((EFI_D_ERROR, "Address=0x%llX FvbBaseAddress=0x%llX Len=0x%llX\n",
      Address, FvbBaseAddress, FwVolHeader[Index].FvLength));

    Status = Fvb->GetAttributes (Fvb, &Attributes);
    LOG((EFI_D_ERROR, "Status=0x%X Attributes=0x%llX\n", Status, Attributes));
    if (EFI_ERROR (Status) || ((Attributes & EFI_FVB2_WRITE_STATUS) == 0)) {
      LOG((EFI_D_ERROR, "%a.%d Error! Status=%X {%llX}\n",
        __FUNCTION__, __LINE__, Status, Attributes & EFI_FVB2_WRITE_STATUS));
      Attributes |= EFI_FVB2_WRITE_STATUS;
      Fvb->SetAttributes(Fvb, &Attributes);
      Fvb->GetAttributes (Fvb, &Attributes);
      if (((Attributes & EFI_FVB2_WRITE_STATUS) == 0)) {
        LOG((EFI_D_ERROR, "%a.%d Error! %llX}\n",
        __FUNCTION__, __LINE__, Attributes & EFI_FVB2_WRITE_STATUS));        
      }      
      continue;
    }

    if ((Address < FvbBaseAddress) || 
        (Address >= (FvbBaseAddress + FwVolHeader[Index].FvLength))) {
      continue;  
    }    
    *FvbHandle  = HandleBuffer[Index];
    *Limit = (UINTN)((FvbBaseAddress + FwVolHeader[Index].FvLength) & (UINTN)(-1));
    Status      = EFI_SUCCESS;
    break;
  }

  FreePool (HandleBuffer);
  return Status;
}


EFI_STATUS
UnlockFlashRegion(
  EFI_PHYSICAL_ADDRESS DeviceBaseAddress,
  EFI_PHYSICAL_ADDRESS Address,
  UINTN Size
)
{
  volatile UINT8 *LockReg;
  UINT8 Tmp;
  EFI_PHYSICAL_ADDRESS BlockAddress;

  if( Address < DeviceBaseAddress ) {
    return EFI_INVALID_PARAMETER;
  }

  for(BlockAddress = Address; 
      BlockAddress < (Address + Size); 
      BlockAddress += SIZE_64KB) {

    LockReg = (UINT8*) (UINTN) (((BlockAddress - DeviceBaseAddress) & 0xf0000) | 0xffb00000 | 2);
    Tmp = *LockReg;
    *LockReg = 0;

    LOG((EFI_D_ERROR, "UnlockFlashRegion 0x%llx Size: 0x%p LockReg:%p State:%x:%x\n", 
      BlockAddress, Size, LockReg, Tmp, *LockReg));
  }
  return EFI_SUCCESS;
}


VOID 
BiosUpdateSetHelperStrings(
  IN CHAR16 *WrStr, 
  IN CHAR16 *EraseStr, 
  IN CHAR16 *RestStr
  )
{
  Str16Write = WrStr;
  Str16Erase = EraseStr;
  Str16Rest = RestStr;
}


EFI_STATUS
BiosUpdateFromByteBuf(
  IN UINT8 *ByteBuf,
  IN UINTN BufSize,
  IN BOOLEAN bUpdateEfiVars
  )
{
  EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL *Fvb;
  EFI_STATUS Status;
  EFI_HANDLE FvbHandle;
  UINTN FwAddress, FwSize, Offset, NumBytes, Limit;
  UINTN NumBlocks, BlockSize, LbaNum;
  UINT64 PhAddr;
  UINT8 *TmpBuf = NULL, *ByteBufPtr;
  CHAR16 TmpStr[250];
  
  ByteBufPtr = ByteBuf;

  CommonInit();
  if (gPcdHelperProtocol == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }

  InitFlashRanges();

  if (bUpdateEfiVars) {
    FwAddress = (UINTN) gPcdHelperProtocol->PcdGet32PcdFlashNvStorageVariableBase(gPcdHelperProtocol);
  } else {
    FwAddress = (UINTN) gPcdHelperProtocol->PcdGet32PcdFlashNvStorageFtwSpareBase(gPcdHelperProtocol) +
        (UINTN) gPcdHelperProtocol->PcdGet32PcdFlashNvStorageFtwSpareSize(gPcdHelperProtocol);
  }

  FwSize = (UINTN)((SIZE_4GB - FwAddress) & (UINTN)(-1));
  LOG ((EFI_D_INFO, "%a.%d FwSize=%X\n", __FUNCTION__, __LINE__, FwSize));

  if (FwSize > BufSize) {
    DEBUG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_INVALID_PARAMETER;
  }

  while (BufSize != 0) {
    LOG ((EFI_D_INFO, "%a.%d FwAddress=%X\n", __FUNCTION__, __LINE__, FwAddress));

    Status = GetFvbHandleByAddressSize(FwAddress, &Limit, &FvbHandle);

    if (EFI_ERROR (Status)) {
      DEBUG ((EFI_D_ERROR, "%a.%d Error! Status=0x%X, FwAddres = %lx\n", __FUNCTION__, __LINE__, Status, FwAddress));
      return Status;
    }

    LOG ((EFI_D_INFO, "%a.%d Limit=%X\n", __FUNCTION__, __LINE__, Limit));

    Status = gBS->HandleProtocol (
                    FvbHandle,
                    &gEfiFirmwareVolumeBlockProtocolGuid,
                    (VOID **) &Fvb
                    );
    if (EFI_ERROR (Status)) {
      DEBUG ((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n", __FUNCTION__, __LINE__, Status));
      return Status;
    }

    Fvb->GetPhysicalAddress(Fvb, &PhAddr);
    LOG((EFI_D_INFO, "PhAddr=%llX\n", PhAddr));
    Fvb->GetBlockSize(Fvb, 0, &BlockSize, &NumBlocks);
    LOG((EFI_D_INFO, "BlockSize=%X NumBlocks=%X\n", 
      BlockSize, NumBlocks));
    if (Str16Erase != NULL) {
      UnicodeSPrint(TmpStr, sizeof(TmpStr), 
        L"\n%s 0x%llX 0x%llX ... ",
        Str16Erase,
        PhAddr, (UINT64)(NumBlocks * BlockSize));
      gST->ConOut->OutputString( gST->ConOut, TmpStr );
    }
    
    Fvb->GetPhysicalAddress(Fvb, &PhAddr);
    LOG((EFI_D_INFO, "%a.%d Start erase at %llX\n", __FUNCTION__, __LINE__, PhAddr));
    Status = Fvb->EraseBlocks(Fvb, (EFI_LBA)0, NumBlocks, 
      EFI_LBA_LIST_TERMINATOR);
    LOG((EFI_D_INFO, "EraseBlocks Status=0x%X\n", Status));
    if (EFI_ERROR(Status)) {
      return Status;
    }
    if (Str16Erase != NULL) {
      UnicodeSPrint(TmpStr, sizeof(TmpStr), L"OK\n");
      gST->ConOut->OutputString( gST->ConOut, TmpStr );
    }

    LbaNum = 0;
      
    if (ByteBufPtr == ByteBuf) {
      Offset = (UINTN)((FwAddress - PhAddr) & (UINTN)(-1));
      ByteBufPtr += (BufSize - FwSize);
      BufSize = FwSize;
      while (Offset >= BlockSize) {
        Offset -= BlockSize;
        LbaNum++;
      }
      LOG((EFI_D_INFO, "Offset=%X\n", Offset));      
    } else {
      Offset = 0;
    }
    
    NumBytes = BlockSize;
    if (TmpBuf == NULL) {
      TmpBuf = AllocateZeroPool(BlockSize);
      if (TmpBuf == NULL) {
        return EFI_OUT_OF_RESOURCES;
      }
    }    
    
    for (; BufSize != 0; ) {
      if (Limit > 0 && (FwAddress + Offset + LbaNum * BlockSize) >= Limit) {
        FwAddress = Limit;
        break;
      }
            
      NumBytes = (BufSize > FW_CHUNK_SIZE) ? FW_CHUNK_SIZE : BufSize;
      
      //Status = Fvb->Read(Fvb, LbaNum, Offset, &NumBytes, TmpBuf);
      //if (EFI_ERROR(Status)) {        
      if (Offset >= BlockSize) {
        LbaNum++;
        Offset -= BlockSize;
        //NumBytes = (BufSize > FW_CHUNK_SIZE) ? FW_CHUNK_SIZE : BufSize;      
      }

      if (Str16Write != NULL) {
        if(((PhAddr + LbaNum * BlockSize + Offset) & 0xffff) == 0)
	{
		UnicodeSPrint(TmpStr, sizeof(TmpStr), L"\r%s 0x%llX ",
				Str16Write,
			          PhAddr + LbaNum * BlockSize + Offset);
		gST->ConOut->OutputString( gST->ConOut, TmpStr );
	}
      }
      
      LOG ((EFI_D_INFO, "Write block - 0x%08x:\n", PhAddr + LbaNum * BlockSize + Offset));

      Status = Fvb->Write(Fvb, LbaNum, Offset, &NumBytes, ByteBufPtr);
      if (EFI_ERROR(Status)) {
        DEBUG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n",
          __FUNCTION__, __LINE__, Status));
        FreePool(TmpBuf);
        return EFI_ABORTED;
      }
      Status = Fvb->Read(Fvb, LbaNum, Offset, &NumBytes, TmpBuf);
      if (EFI_ERROR(Status)) {
        DEBUG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n",
          __FUNCTION__, __LINE__, Status));
        FreePool(TmpBuf);
        return EFI_ABORTED;
      }
      if (CompareMem(TmpBuf, ByteBufPtr, NumBytes) != 0) {
        DEBUG((EFI_D_ERROR, "Verify failed!\n"));
        return EFI_ABORTED;
      } else {
        LOG ((EFI_D_INFO, "Verify ok!\n"));
      }
      BufSize -= NumBytes;
      ByteBufPtr += NumBytes;
      Offset += NumBytes;
    }
    LOG ((EFI_D_INFO, "\n"));
  } 
  if (TmpBuf) {
    FreePool(TmpBuf);
  }
  return EFI_SUCCESS;
}


EFI_STATUS
BiosUpdateFromByteBufFsm(
  IN UINT8 *ByteBuf,
  IN UINTN Size,
  IN BOOLEAN bUpdateEfiVars,
  IN OUT CHAR16 *ProgressStr,
  IN BOOLEAN bRestart,
  IN OUT BOOLEAN *bUpdateDone
  )
{
  STATIC EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL *Fvb;
  EFI_STATUS Status;
  STATIC EFI_HANDLE FvbHandle;
  STATIC UINTN FwAddress, FwSize, Offset, NumBytes, Limit;
  STATIC UINTN NumBlocks, BlockSize, LbaNum, StrOffs, BufSize;
  STATIC UINT64 PhAddr;
  STATIC UINT8 *TmpBuf = NULL, *ByteBufPtr;
  STATIC CHAR16 TmpStr[250];
  STATIC UINT8 State = 0;

  if (bRestart) {
    State = 0;
  }

  CommonInit();

  if (gPcdHelperProtocol == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d Error!\n", __FUNCTION__, __LINE__));
    return EFI_ABORTED;
  }

  switch (State) {
  case 0:
    ByteBufPtr = ByteBuf;
    BufSize = Size;
    
    InitFlashRanges();

    if (bUpdateEfiVars) {
      
      FwAddress = (UINTN) gPcdHelperProtocol->PcdGet32PcdFlashNvStorageVariableBase(gPcdHelperProtocol);
    } else {
      FwAddress = (UINTN) gPcdHelperProtocol->PcdGet32PcdFlashNvStorageFtwSpareBase(gPcdHelperProtocol) + 
          (UINTN) gPcdHelperProtocol->PcdGet32PcdFlashNvStorageFtwSpareSize(gPcdHelperProtocol);
    }

    FwSize = (UINTN)((SIZE_4GB - FwAddress) & (UINTN)(-1));
    LOG((EFI_D_ERROR, "%a.%d FwSize=%X\n", 
      __FUNCTION__, __LINE__, FwSize));
    State = 1;

  case 1:
    if (BufSize == 0) {
      *bUpdateDone = TRUE;
      return EFI_SUCCESS;
    }
    
    LOG((EFI_D_ERROR, "%a.%d FwAddress=%X\n", 
      __FUNCTION__, __LINE__, FwAddress));
    Status = GetFvbHandleByAddressSize(FwAddress, &Limit, &FvbHandle);
    if (EFI_ERROR (Status)) {
      LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n",
        __FUNCTION__, __LINE__, Status));
      return Status;
    }    

    LOG((EFI_D_ERROR, "%a.%d Limit=%X\n", 
      __FUNCTION__, __LINE__, Limit));

    Status = gBS->HandleProtocol (
                    FvbHandle,
                    &gEfiFirmwareVolumeBlockProtocolGuid,
                    (VOID **) &Fvb
                    );
    if (EFI_ERROR (Status)) {
      LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n",
        __FUNCTION__, __LINE__, Status));
      return Status;
    }

    Fvb->GetPhysicalAddress(Fvb, &PhAddr);
    LOG((EFI_D_ERROR, "PhAddr=%llX\n", PhAddr));
    Fvb->GetBlockSize(Fvb, 0, &BlockSize, &NumBlocks);
    LOG((EFI_D_ERROR, "BlockSize=%X NumBlocks=%X\n", 
      BlockSize, NumBlocks));
    StrOffs = UnicodeSPrint(ProgressStr, sizeof(TmpStr),
      L"\n%s 0x%llX 0x%llX ... ",
      Str16Erase == NULL ? L"Erase: " : Str16Erase,
      PhAddr, (UINT64)(NumBlocks * BlockSize));


    Status = Fvb->EraseBlocks(Fvb, (EFI_LBA)0, NumBlocks, 
      EFI_LBA_LIST_TERMINATOR);
    LOG((EFI_D_ERROR, "EraseBlocks Status=0x%X\n", Status));
    if (EFI_ERROR(Status)) {
      UnicodeSPrint(ProgressStr + StrOffs, 255, L"FAIL\n");
      return Status;
    }

    UnicodeSPrint(ProgressStr + StrOffs, 255, L"OK\n");
    State = 2;
    break;

  case 2:
    LbaNum = 0;
      
    if (ByteBufPtr == ByteBuf) {
      Offset = (UINTN)((FwAddress - PhAddr) & (UINTN)(-1));
      ByteBufPtr += (BufSize - FwSize);
      BufSize = FwSize;
      while (Offset >= BlockSize) {
        Offset -= BlockSize;
        LbaNum++;
      }
      LOG((EFI_D_ERROR, "Offset=%X\n", Offset));      
    } else {
      Offset = 0;
    }

    NumBytes = BlockSize;
    if (TmpBuf == NULL) {
      TmpBuf = AllocateZeroPool(BlockSize);
      if (TmpBuf == NULL) {
        return EFI_OUT_OF_RESOURCES;
      }
    }    
    
    for (; BufSize != 0; ) {
      if (Limit > 0 && (FwAddress + Offset + LbaNum * BlockSize) >= Limit) {
        FwAddress = Limit;
        break;
      }
            
      NumBytes = (BufSize > FW_CHUNK_SIZE) ? FW_CHUNK_SIZE : BufSize;      
      LOG((EFI_D_ERROR, "Offset=%d BlockSize=%d\n", Offset, BlockSize));      
      LOG((EFI_D_ERROR, "%a.%d NumBytes=%d\n", 
        __FUNCTION__, __LINE__, NumBytes));      
      
      //Status = Fvb->Read(Fvb, LbaNum, Offset, &NumBytes, TmpBuf);
      //if (EFI_ERROR(Status)) {        
      if (Offset >= BlockSize) {
        LbaNum++;
        Offset -= BlockSize;
        //NumBytes = (BufSize > FW_CHUNK_SIZE) ? FW_CHUNK_SIZE : BufSize;      
      }

      UnicodeSPrint(TmpStr, sizeof(TmpStr), L"%s 0x%llX ",
        Str16Write == NULL ? L"Write: " : Str16Write,
        PhAddr + LbaNum * BlockSize + Offset);

      Status = Fvb->Write(Fvb, LbaNum, Offset, &NumBytes, ByteBufPtr);
      if (EFI_ERROR(Status)) {
        LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n",
          __FUNCTION__, __LINE__, Status));
        FreePool(TmpBuf);
        return EFI_ABORTED;
      }
      Status = Fvb->Read(Fvb, LbaNum, Offset, &NumBytes, TmpBuf);
      if (EFI_ERROR(Status)) {
        LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n",
          __FUNCTION__, __LINE__, Status));
        FreePool(TmpBuf);
        return EFI_ABORTED;
      }
      if (CompareMem(TmpBuf, ByteBufPtr, NumBytes)) {
        LOG((EFI_D_ERROR, "Verify failed!\n"));
        return EFI_ABORTED;
      } else {
        LOG((EFI_D_ERROR, "Verify ok!\n"));
      }
      BufSize -= NumBytes;
      ByteBufPtr += NumBytes;
      Offset += NumBytes;
      LOG((EFI_D_ERROR, "%a.%d BufSize=%d\n", 
        __FUNCTION__, __LINE__, BufSize));
    }

    StrCpy (ProgressStr, TmpStr);
    State = 1;
    break;
  }
  if (TmpBuf) {
    FreePool(TmpBuf);
  }
  return EFI_SUCCESS;
}



VOID
BiosRdWrTest(
  VOID
  )
{
  EFI_FIRMWARE_VOLUME_BLOCK_PROTOCOL *Fvb;
  EFI_STATUS Status;
  EFI_HANDLE FvbHandle;
  //EFI_FVB_ATTRIBUTES_2 Attr;
  UINTN FwAddress, FwSize, Offset, NumBytes, Limit;
  UINTN NumBlocks, BlockSize;
  UINT8 Buffer[1024];
  UINT64 PhAddr;

  CommonInit ();
  if (gPcdHelperProtocol == NULL) {
    return;
  }
  FwAddress = (UINTN)gPcdHelperProtocol->
      PcdGet32PcdFlashNvStorageVariableBase (gPcdHelperProtocol);  
  FwSize = (UINTN)((SIZE_4GB - FwAddress) & (UINTN)(-1));
  LOG((EFI_D_ERROR, "%a.%d FwSize=%X\n", 
    __FUNCTION__, __LINE__, FwSize));  
  
  Offset = 0;

  while (Offset < FwSize) {
    LOG((EFI_D_ERROR, "%a.%d FwAddress=%X\n", 
      __FUNCTION__, __LINE__, FwAddress));
    Status = GetFvbHandleByAddressSize(FwAddress, &Limit, &FvbHandle);
    if (EFI_ERROR (Status)) {
      LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n",
        __FUNCTION__, __LINE__, Status));
      return;
    }    

    LOG((EFI_D_ERROR, "%a.%d Limit=%X\n", 
      __FUNCTION__, __LINE__, Limit));

    Status = gBS->HandleProtocol (
                    FvbHandle,
                    &gEfiFirmwareVolumeBlockProtocolGuid,
                    (VOID **) &Fvb
                    );
    if (EFI_ERROR (Status)) {
      LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n",
        __FUNCTION__, __LINE__, Status));
      return;
    }

    Fvb->GetPhysicalAddress(Fvb, &PhAddr);
    LOG((EFI_D_ERROR, "PhAddr=%llX\n", PhAddr));
    Fvb->GetBlockSize(Fvb, 0, &BlockSize, &NumBlocks);
    LOG((EFI_D_ERROR, "BlockSize=%X NumBlocks=%X\n", 
      BlockSize, NumBlocks));
    
    NumBytes = sizeof(Buffer);    
    
    for (; Offset < FwSize; Offset += sizeof(Buffer)) {
      if (FwAddress + Offset >= Limit) {
        FwAddress = Limit;
        break;
      }
      Status = Fvb->Read(Fvb, 0, Offset, &NumBytes, Buffer);
      if (EFI_ERROR(Status)) {
         LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n",
          __FUNCTION__, __LINE__, Status));
        return;
      }
      //DumpBytes(Buffer, NumBytes);
      //WaitForKP();
      Buffer[0] = 'T';
      Buffer[1] = 'E';
      Buffer[2] = 'S';
      Buffer[3] = 'T';
      Status = Fvb->Write(Fvb, 0, Offset, &NumBytes, Buffer);
      if (EFI_ERROR(Status)) {
         LOG((EFI_D_ERROR, "%a.%d Error! Status=0x%X\n",
          __FUNCTION__, __LINE__, Status));
        return;
      }
    }    
  }
}
