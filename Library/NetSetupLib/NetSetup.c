/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include <Uefi.h>
#include <Library/NetLib.h>
#include <Library/UefiLib.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
#include <Library/PrintLib.h>
#include <Library/CommonUtils.h>
#include <Library/DevicePathLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include <Guid/NicIp4ConfigNvData.h>
#include <Protocol/Dns4Config.h>

#include <Protocol/HiiConfigRouting.h>
#include <Protocol/HiiConfigAccess.h>
#include <Protocol/ManagedNetwork.h>
#include <Protocol/Ip4.h>
#include <Protocol/DevicePath.h>

#include <Library/NetSetupLib/NetSetupLib.h>

#include "NetSetupInternal.h"

#define NIC_ITEM_CONFIG_SIZE   (sizeof (NIC_IP4_CONFIG_INFO) + sizeof (EFI_IP4_ROUTE_TABLE) * MAX_IP4_CONFIG_IN_VARIABLE + sizeof (EFI_DNS4_CONFIG_DATA))

STATIC EFI_HII_CONFIG_ROUTING_PROTOCOL  *mHiiConfigRouting = NULL;

STATIC LIST_ENTRY  NicInfoList;

STATIC CONST UINTN SecondsToNanoSeconds = 10000000;

typedef struct {
  LIST_ENTRY                  Link;
  EFI_HANDLE                  Handle;
  NIC_ADDR                    NicAddress;
  CHAR16                      Name[IP4_NIC_NAME_LENGTH];
  BOOLEAN                     MediaPresentSupported;
  BOOLEAN                     MediaPresent;
  EFI_IP4_CONFIG_PROTOCOL     *Ip4Config;
  NIC_IP4_CONFIG_INFO         *ConfigInfo;
} NIC_INFO;

static
EFI_STATUS
EFIAPI
IfconfigGetAllNicInfoByHii (
  VOID
  );

static
EFI_STATUS
EFIAPI
IfConfigGetNicMacInfo (
  IN  EFI_HANDLE                    Handle,
  OUT NIC_ADDR                      *NicAddr
  );

static
EFI_STATUS
EFIAPI
SetNicAddrByHii (
  IN CONST NIC_INFO                 *NicInfo,
  IN CONST NIC_IP4_CONFIG_INFO      *Config
  );


//------------------------------------------------------------------------------
/**
  Append OFFSET/WIDTH/VALUE items at the beginning of string.

  @param[in, out]  String      The pointer to the string to append onto.
  @param[in]       Offset      Offset value.
  @param[in]       Width       Width value.
  @param[in]       Block       Point to data buffer.

  @return The count of unicode character that were appended.
**/
//------------------------------------------------------------------------------
UINTN
EFIAPI
AppendOffsetWidthValue (
  IN OUT CHAR16               *String,
  IN UINTN                    Offset,
  IN UINTN                    Width,
  IN CONST UINT8              *Block
  )

{
  CHAR16                      *OriString;

  OriString = String;

  StrCpy (String, L"&OFFSET=");
  String += StrLen (L"&OFFSET=");
  String += UnicodeSPrint (String, 20, L"%x", Offset);

  StrCpy (String,L"&WIDTH=");
  String += StrLen (L"&WIDTH=");
  String += UnicodeSPrint (String, 20, L"%x", Width);

  if (Block != NULL) {
    StrCpy (String,L"&VALUE=");
    String += StrLen (L"&VALUE=");
    while ((Width--) != 0) {
      String += UnicodeSPrint (String, 20, L"%x", Block[Width]);
    }
  }
  
  return String - OriString;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
  Converts the unicode character of the string from uppercase to lowercase.
  This is a internal function.

  @param ConfigString  String to be converted
**/
//------------------------------------------------------------------------------
CHAR16* 
EFIAPI
HiiToLower (
  IN CHAR16   *ConfigString
  )
{
  CHAR16      *String;
  BOOLEAN     Lower;

  //
  // Convert all hex digits in range [A-F] in the configuration header to [a-f]
  //
  for (String = ConfigString, Lower = FALSE; String != NULL && *String != L'\0'; String++) {
    if (*String == L'=') {
      Lower = TRUE;
    } else if (*String == L'&') {
      Lower = FALSE;
    } else if (Lower && *String >= L'A' && *String <= L'F') {
      *String = (CHAR16) (*String - L'A' + L'a');
    }
  }

  return (ConfigString);
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
  Tests whether a child handle is a child device of the controller.

  @param[in] ControllerHandle   A handle for a (parent) controller to test.
  @param[in] ChildHandle        A child handle to test.
  @param[in] ProtocolGuid       Supplies the protocol that the child controller
                                opens on its parent controller.

  @retval EFI_SUCCESS         ChildHandle is a child of the ControllerHandle.
  @retval EFI_UNSUPPORTED     ChildHandle is not a child of the ControllerHandle.
**/
//------------------------------------------------------------------------------
EFI_STATUS
EFIAPI
TestChildHandle (
  IN CONST EFI_HANDLE       ControllerHandle,
  IN CONST EFI_HANDLE       ChildHandle,
  IN CONST EFI_GUID         *ProtocolGuid
  )
{
  EFI_STATUS                            Status;
  EFI_OPEN_PROTOCOL_INFORMATION_ENTRY   *OpenInfoBuffer;
  UINTN                                 EntryCount;
  UINTN                                 Index;

  ASSERT (ProtocolGuid != NULL);

  //
  // Retrieve the list of agents that are consuming the specific protocol
  // on ControllerHandle.
  //
  Status = gBS->OpenProtocolInformation (
                 ControllerHandle,
                 (EFI_GUID *) ProtocolGuid,
                 &OpenInfoBuffer,
                 &EntryCount
                 );
  if (EFI_ERROR (Status)) {
    return EFI_UNSUPPORTED;
  }

  //
  // Inspect if ChildHandle is one of the agents.
  //
  Status = EFI_UNSUPPORTED;
  for (Index = 0; Index < EntryCount; Index++) {
    if ((OpenInfoBuffer[Index].ControllerHandle == ChildHandle) &&
        (OpenInfoBuffer[Index].Attributes & EFI_OPEN_PROTOCOL_BY_CHILD_CONTROLLER) != 0) {
      Status = EFI_SUCCESS;
      break;
    }
  }

  FreePool (OpenInfoBuffer);
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
  Get the child handle of the NIC handle.

  @param[in] Controller     Routing information: GUID.
  @param[out] ChildHandle   Returned child handle.

  @retval EFI_SUCCESS         Successfully to get child handle.
**/
//------------------------------------------------------------------------------
EFI_STATUS 
GetChildHandle (
  IN EFI_HANDLE         Controller,
  OUT EFI_HANDLE        *ChildHandle
  )
{
  EFI_STATUS                 Status;
  EFI_HANDLE                 *Handles;
  UINTN                      HandleCount;
  UINTN                      Index;
  EFI_DEVICE_PATH_PROTOCOL   *ChildDeviceDevicePath;
  VENDOR_DEVICE_PATH         *VendorDeviceNode;

  //
  // Locate all EFI Hii Config Access protocols
  //
  Status = gBS->LocateHandleBuffer (
                 ByProtocol,
                 &gEfiHiiConfigAccessProtocolGuid,
                 NULL,
                 &HandleCount,
                 &Handles
                 );
  if (EFI_ERROR (Status) || (HandleCount == 0)) {
    return Status;
  }

  Status = EFI_NOT_FOUND;

  for (Index = 0; Index < HandleCount; Index++) {
  
    Status = TestChildHandle (Controller, Handles[Index], &gEfiManagedNetworkServiceBindingProtocolGuid);
    if (!EFI_ERROR (Status)) {
      //
      // Get device path on the child handle
      //
      Status = gBS->HandleProtocol (
                     Handles[Index],
                     &gEfiDevicePathProtocolGuid,
                     (VOID **) &ChildDeviceDevicePath
                     );
      
      if (!EFI_ERROR (Status)) {
        while (!IsDevicePathEnd (ChildDeviceDevicePath)) {
          ChildDeviceDevicePath = NextDevicePathNode (ChildDeviceDevicePath);
          //
          // Parse one instance
          //
          if (ChildDeviceDevicePath->Type == HARDWARE_DEVICE_PATH && 
              ChildDeviceDevicePath->SubType == HW_VENDOR_DP) {
            VendorDeviceNode = (VENDOR_DEVICE_PATH *) ChildDeviceDevicePath;
            if (CompareMem (&VendorDeviceNode->Guid, &gEfiNicIp4ConfigVariableGuid, sizeof (EFI_GUID)) == 0) {
              //
              // Found item matched gEfiNicIp4ConfigVariableGuid
              //
              *ChildHandle = Handles[Index];
              FreePool (Handles);
              return EFI_SUCCESS;
            }
          }
        }
      }      
    }
  }

  FreePool (Handles);
  return Status;  
}
//------------------------------------------------------------------------------

VOID
ShowLongStr (
  IN CHAR16 *Str16
  )
{
  while (*Str16) {
    CHAR16 Tmp[2];
    Tmp[0] = *Str16;
    Tmp[1] = 0;
    DEBUG ((EFI_D_INFO, "%s", Tmp));
    Str16++;
  }
  DEBUG ((EFI_D_INFO, "\n"));
}

//------------------------------------------------------------------------------
/**
  Construct <ConfigHdr> using routing information GUID/NAME/PATH.

  @param[in] Guid         Routing information: GUID.
  @param[in] Name         Routing information: NAME.
  @param[in] DriverHandle Driver handle which contains the routing information: PATH.

  @retval NULL            An error occured.
  @return                 The pointer to configHdr string.
**/
//------------------------------------------------------------------------------
CHAR16 *
EFIAPI
ConstructConfigHdr (
  IN CONST EFI_GUID          *Guid,
  IN CONST CHAR16            *Name,
  IN EFI_HANDLE              DriverHandle
  )
{
  EFI_STATUS                 Status;
  CHAR16                     *ConfigHdr;
  EFI_DEVICE_PATH_PROTOCOL   *DevicePath;
  CHAR16                     *String;
  UINTN                      Index;
  UINT8                      *Buffer;
  UINTN                      DevicePathLength;
  UINTN                      NameLength, AllocLen;

  DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  //
  // Get the device path from handle installed EFI HII Config Access protocol
  //
  Status = gBS->HandleProtocol (
                 DriverHandle,
                 &gEfiDevicePathProtocolGuid,
                 (VOID **) &DevicePath
                 );
  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return NULL;
  }

  DevicePathLength = GetDevicePathSize (DevicePath);
  NameLength = StrLen (Name);
  AllocLen = (5 + sizeof (EFI_GUID) * 2 + 6 + NameLength * 4 + 6 + 
    DevicePathLength * 2 + 1) * sizeof (CHAR16);
  ConfigHdr = AllocateZeroPool (AllocLen);
  DEBUG ((EFI_D_INFO, "%a.%d AllocLen=%d\n", __FUNCTION__, __LINE__, AllocLen));
  if (ConfigHdr == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
    return NULL;
  } 

  String = ConfigHdr;
  StrCpy (String, L"GUID=");
  String += StrLen (L"GUID=");

  DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  ShowLongStr (ConfigHdr);
  DEBUG ((EFI_D_INFO, "\nStrLen (ConfigHdr) = %d\n", StrLen (ConfigHdr)));

  //
  // Append Guid converted to <HexCh>32
  //
  for (Index = 0, Buffer = (UINT8 *)Guid; Index < sizeof (EFI_GUID); Index++) {
    String += UnicodeSPrint (String, 6, L"%02x", *Buffer++);
  }

  DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  ShowLongStr (ConfigHdr);
  DEBUG ((EFI_D_INFO, "\nStrLen (ConfigHdr) = %d\n", StrLen (ConfigHdr)));

  //
  // Append L"&NAME="
  //
  StrCpy (String, L"&NAME=");
  String += StrLen (L"&NAME=");
  for (Index = 0; Index < NameLength ; Index++) {
    String += UnicodeSPrint (String, 10, L"00%x", Name[Index]);
  }

  DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  ShowLongStr (ConfigHdr);
  DEBUG ((EFI_D_INFO, "\nStrLen (ConfigHdr) = %d\n", StrLen (ConfigHdr)));
  
  //
  // Append L"&PATH="
  //
  StrCpy (String, L"&PATH=");
  String += StrLen (L"&PATH=");
  for (Index = 0, Buffer = (UINT8 *) DevicePath; Index < DevicePathLength; Index++) {
    String += UnicodeSPrint (String, 6, L"%02x", *Buffer++);
  }

  DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  ShowLongStr (ConfigHdr);
  DEBUG ((EFI_D_INFO, "\nStrLen (ConfigHdr) = %d\n", StrLen (ConfigHdr)));
  String = (HiiToLower(ConfigHdr));
  DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  ShowLongStr (ConfigHdr);
  DEBUG ((EFI_D_INFO, "\nStrLen (ConfigHdr) = %d\n", StrLen (ConfigHdr)));
  return String;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
  Waits specified time for network configuration.

  @param[in] Timeout  Timeout in seconds. 0 - infinite wait.
**/
//------------------------------------------------------------------------------
EFI_STATUS
EFIAPI
WaitForNetworkConfigured (
  UINTN Timeout
  )
{
  EFI_STATUS Status, ReturnStatus;
  EFI_HANDLE *Handles;
  EFI_HANDLE *Ip4Handles;
  EFI_IP4_PROTOCOL **Ip4Protos;
  EFI_IP4_MODE_DATA Ip4Mode;
  EFI_IP4_CONFIG_DATA Ip4ConfigData;
  UINTN HandleCount, Ip4HandleCount;
  UINTN Index;
  EFI_EVENT Timer;

  DEBUG ((EFI_D_INFO, "%a.%d Timeout = %d\n", __FUNCTION__, __LINE__, Timeout));

  ReturnStatus = EFI_TIMEOUT;
  Handles = NULL;
  Ip4Handles = NULL;
  Ip4Protos = NULL;
  Timer = NULL;

  ZeroMem (&Ip4ConfigData, sizeof (Ip4ConfigData));
  Ip4ConfigData.DefaultProtocol = EFI_IP_PROTO_ICMP;
  Ip4ConfigData.UseDefaultAddress = TRUE;
  Ip4ConfigData.TimeToLive = 1;

  Status = gBS->LocateHandleBuffer (
                 ByProtocol,
                 &gEfiManagedNetworkServiceBindingProtocolGuid,
                 NULL,
                 &HandleCount,
                 &Handles
                 );
  if (EFI_ERROR (Status) || (HandleCount == 0)) {
    DEBUG ((EFI_D_ERROR, "%a.%d Status = %r, HandleCount = %d\n", __FUNCTION__, __LINE__, Status, HandleCount));
    ReturnStatus = EFI_NOT_FOUND;
    goto _EXIT;
  }

  Ip4Handles = AllocateZeroPool (sizeof(EFI_HANDLE) * HandleCount);
  Ip4Protos = AllocateZeroPool (sizeof(EFI_IP4_PROTOCOL *) * HandleCount);
  if (Ip4Handles == NULL) {
    DEBUG ((EFI_D_ERROR, "%a.%d Ip4Handles = 0x%X, Ip4Protos = 0x%X\n", __FUNCTION__, __LINE__, Ip4Handles, Ip4Protos));
    ReturnStatus = EFI_OUT_OF_RESOURCES;
    goto _EXIT;
  }

  DEBUG ((EFI_D_INFO, "%a.%d HandleCount = %d\n", __FUNCTION__, __LINE__, HandleCount));
  for (Index = 0, Ip4HandleCount = 0; Index < HandleCount; Index++) {
    Status = NetLibCreateServiceChild (Handles[Index], gImageHandle, &gEfiIp4ServiceBindingProtocolGuid, &Ip4Handles[Index]);
    if (EFI_ERROR(Status)) {
      DEBUG ((EFI_D_INFO, "%a.%d NetLibCreateServiceChild: Index = %d, Status = %r\n", __FUNCTION__, __LINE__, Index, Status));
      Ip4Handles[Index] = NULL;
      continue;
    }

    Status = gBS->OpenProtocol (Ip4Handles[Index], &gEfiIp4ProtocolGuid, (VOID **) &Ip4Protos[Index], Handles[Index], gImageHandle, EFI_OPEN_PROTOCOL_GET_PROTOCOL);
    if (EFI_ERROR(Status)) {
      DEBUG ((EFI_D_ERROR, "%a.%d OpenProtocol: Index = %d, Status = %r\n", __FUNCTION__, __LINE__, Index, Status));
      Ip4Protos[Index] = NULL;
      continue;
    }

    Status = Ip4Protos[Index]->Configure (Ip4Protos[Index], &Ip4ConfigData);
    if (Status != EFI_SUCCESS && Status != EFI_NO_MAPPING) {
      DEBUG ((EFI_D_ERROR, "%a.%d Ip4->Configure: Index = %d, Status = %r\n", __FUNCTION__, __LINE__, Index, Status));
      Ip4Protos[Index] = NULL;
      continue;
    }

    Ip4HandleCount++;
  }
  DEBUG ((EFI_D_INFO, "%a.%d Ip4HandleCount = %d\n", __FUNCTION__, __LINE__, Ip4HandleCount));
  if (Ip4HandleCount == 0) {
    ReturnStatus = EFI_NOT_FOUND;
    goto _EXIT;
  }

  if (Timeout != 0) {
    Status = gBS->CreateEvent (EVT_TIMER, TPL_CALLBACK, NULL, NULL, &Timer);
    if (EFI_ERROR(Status)) {
      DEBUG ((EFI_D_ERROR, "%a.%d CreateEvent: Status = %r\n", __FUNCTION__, __LINE__, Status));
      ReturnStatus = EFI_OUT_OF_RESOURCES;
      goto _EXIT;
    }

    Status = gBS->SetTimer (Timer, TimerPeriodic, Timeout * TICKS_PER_SECOND);
    if (EFI_ERROR(Status)) {
      DEBUG ((EFI_D_ERROR, "%a.%d SetTimer: Status = %r\n", __FUNCTION__, __LINE__, Status));
      ReturnStatus = EFI_OUT_OF_RESOURCES;
      goto _EXIT;
    }
  }

  do {
    for (Index = 0; Index < HandleCount; Index++) {
      if (Ip4Protos[Index] != NULL) {
        Status = Ip4Protos[Index]->Poll (Ip4Protos[Index]);
        if (Status != EFI_SUCCESS && Status != EFI_NOT_READY) {
          DEBUG ((EFI_D_ERROR, "%a.%d Ip4->Poll: Index = %d, Status = %r\n", __FUNCTION__, __LINE__, Index, Status));
          Ip4Protos[Index] = NULL;
          Ip4HandleCount--;
        }

        Status = Ip4Protos[Index]->GetModeData (Ip4Protos[Index], &Ip4Mode, NULL, NULL);
        if (Status == EFI_SUCCESS) {
          if (Ip4Mode.IsConfigured) {
            DEBUG((EFI_D_INFO, "%a.%d Ip4Mode.IsConfigured = %d\n", __FUNCTION__, __LINE__, Ip4Mode.IsConfigured));
            DEBUG((EFI_D_INFO, "%a.%d Ip: %d.%d.%d.%d\n",
               __FUNCTION__, __LINE__,
              (UINTN)Ip4Mode.ConfigData.StationAddress.Addr[0],
              (UINTN)Ip4Mode.ConfigData.StationAddress.Addr[1],
              (UINTN)Ip4Mode.ConfigData.StationAddress.Addr[2],
              (UINTN)Ip4Mode.ConfigData.StationAddress.Addr[3]
              ));
            ReturnStatus = EFI_SUCCESS;
            goto _EXIT;
          }
        } else {
          DEBUG ((EFI_D_ERROR, "%a.%d Ip4->GetModeData: Index = %d, Status = %r\n", __FUNCTION__, __LINE__, Index, Status));
          Ip4Protos[Index] = NULL;
          Ip4HandleCount--;
        }
      }
    }
    if (Ip4HandleCount == 0) {
      DEBUG ((EFI_D_ERROR, "%a.%d Ip4HandleCount = %d\n", __FUNCTION__, __LINE__, Ip4HandleCount));
      break;
    }
  } while ((Timeout == 0) || (Timer != NULL && gBS->CheckEvent(Timer) == EFI_NOT_READY));

_EXIT:
  DEBUG ((EFI_D_INFO, "%a.%d ReturnStatus = %r\n", __FUNCTION__, __LINE__, ReturnStatus));
  if (Timer != NULL) {
    gBS->CloseEvent (Timer);
  }
  if (Ip4Handles != NULL) {
    for (Index = 0; Index < HandleCount; Index++) {
      if (Ip4Handles[Index] != NULL) {
        Status = NetLibDestroyServiceChild (Handles[Index], gImageHandle, &gEfiIp4ServiceBindingProtocolGuid, Ip4Handles[Index]);
        if (EFI_ERROR(Status)) {
          DEBUG ((EFI_D_ERROR, "%a.%d Index = %d, Status = %r\n", __FUNCTION__, __LINE__, Index, Status));
        }
      }
    }
    FreePool (Ip4Handles);
  }
  if (Handles != NULL) {
    FreePool (Handles);
  }
  return ReturnStatus;
}

//------------------------------------------------------------------------------
/**
  Create an IP child, use it to start the auto configuration, then destory it.

  @param[in] NicInfo    The pointer to the NIC_INFO of the Nic to be configured.

  @retval EFI_SUCCESS         The configuration is done.
**/
//------------------------------------------------------------------------------
EFI_STATUS
EFIAPI
StartIp4(
  IN EFI_HANDLE                   NicHandle
  )
{
  EFI_IP4_PROTOCOL              *Ip4 = NULL;
  EFI_HANDLE                    Ip4Handle = NULL;
  EFI_IP4_CONFIG_DATA           Ip4ConfigData;
  EFI_IP4_MODE_DATA             Ip4Mode;
  EFI_STATUS                    Status;

  DEBUG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  //
  // Get the Ip4ServiceBinding Protocol
  //
  Status = NetLibCreateServiceChild (
             NicHandle,
             gImageHandle,
             &gEfiIp4ServiceBindingProtocolGuid,
             &Ip4Handle
             );

  if (EFI_ERROR (Status)) {
    DEBUG ((EFI_D_ERROR, "%a.%d Status = %r\n", __FUNCTION__, __LINE__, Status));
    return Status;
  }

  Status = gBS->OpenProtocol (
                 Ip4Handle,
                 &gEfiIp4ProtocolGuid,
                 (VOID **) &Ip4,
                 NicHandle,
                 gImageHandle,
                 EFI_OPEN_PROTOCOL_GET_PROTOCOL
                 );

  if (EFI_ERROR (Status)) {
    goto ON_EXIT;
  }
  
  Ip4ConfigData.DefaultProtocol          = EFI_IP_PROTO_ICMP;
  Ip4ConfigData.AcceptAnyProtocol        = FALSE;
  Ip4ConfigData.AcceptIcmpErrors         = FALSE;
  Ip4ConfigData.AcceptBroadcast          = FALSE;
  Ip4ConfigData.AcceptPromiscuous        = FALSE;
  Ip4ConfigData.UseDefaultAddress        = TRUE;
  ZeroMem (&Ip4ConfigData.StationAddress, sizeof (EFI_IPv4_ADDRESS));
  ZeroMem (&Ip4ConfigData.SubnetMask, sizeof (EFI_IPv4_ADDRESS));
  Ip4ConfigData.TypeOfService            = 0;
  Ip4ConfigData.TimeToLive               = 1;
  Ip4ConfigData.DoNotFragment            = FALSE;
  Ip4ConfigData.RawData                  = FALSE;
  Ip4ConfigData.ReceiveTimeout           = 0;
  Ip4ConfigData.TransmitTimeout          = 0;

  Status = Ip4->Configure (Ip4, &Ip4ConfigData);
  DEBUG ((EFI_D_INFO, "%a.%d Ip4->Configure(): Status = %r\n", __FUNCTION__, __LINE__, Status));

  if (Status == EFI_SUCCESS) {
    Status = Ip4->GetModeData (Ip4, &Ip4Mode, NULL, NULL);

    if (Status == EFI_SUCCESS) {
      if (Ip4Mode.IsConfigured) {
        DEBUG((EFI_D_INFO, "%a.%d Ip: %d.%d.%d.%d\n",
           __FUNCTION__, __LINE__,
          (UINTN)Ip4Mode.ConfigData.StationAddress.Addr[0],
          (UINTN)Ip4Mode.ConfigData.StationAddress.Addr[1],
          (UINTN)Ip4Mode.ConfigData.StationAddress.Addr[2],
          (UINTN)Ip4Mode.ConfigData.StationAddress.Addr[3]
          ));
      } else {
        DEBUG ((EFI_D_INFO, "%a.%d Ip4Mode.IsConfigured = %d\n", __FUNCTION__, __LINE__, Ip4Mode.IsConfigured));
      }
    } else {
      DEBUG ((EFI_D_INFO, "%a.%d Ip4->GetModeData(): Status = %r\n", __FUNCTION__, __LINE__, Status));
    }
  }
  
ON_EXIT: 

  NetLibDestroyServiceChild (
    NicHandle,
    gImageHandle,
    &gEfiIp4ServiceBindingProtocolGuid,
    Ip4Handle
    );

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/**
  Get network physical device NIC information.

  @param[in] Handle         The network physical device handle.
  @param[out] MediaPresentSupported
                            Upon successful return, TRUE is media present 
                            is supported.  FALSE otherwise.
  @param[out] MediaPresent  Upon successful return, TRUE is media present 
                            is enabled.  FALSE otherwise.

  @retval EFI_SUCCESS       The operation was successful.
**/
//------------------------------------------------------------------------------
EFI_STATUS
EFIAPI
GetNicMediaStatus (
  IN  EFI_HANDLE                    Handle,
  OUT BOOLEAN                       *MediaPresentSupported,
  OUT BOOLEAN                       *MediaPresent
  )    
                  
{
  EFI_STATUS                    Status;
  EFI_HANDLE                    MnpHandle;
  EFI_SIMPLE_NETWORK_MODE       SnpMode;
  EFI_MANAGED_NETWORK_PROTOCOL  *Mnp;

  MnpHandle = NULL;
  Mnp       = NULL;

  Status = NetLibCreateServiceChild (
             Handle,
             gImageHandle, 
             &gEfiManagedNetworkServiceBindingProtocolGuid,
             &MnpHandle
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = gBS->HandleProtocol (
                  MnpHandle,
                  &gEfiManagedNetworkProtocolGuid,
                  (VOID **) &Mnp
                  );
  if (EFI_ERROR (Status)) {
    goto ON_ERROR;
  }

  Status = Mnp->GetModeData (Mnp, NULL, &SnpMode);
  if (EFI_ERROR (Status) && (Status != EFI_NOT_STARTED)) {
    goto ON_ERROR;
  }
 
  *MediaPresentSupported = SnpMode.MediaPresentSupported;
  *MediaPresent = SnpMode.MediaPresent;

ON_ERROR:

  NetLibDestroyServiceChild (
    Handle,
    gImageHandle, 
    &gEfiManagedNetworkServiceBindingProtocolGuid,
    MnpHandle
    );

  return Status;

}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set up all NICs */
//------------------------------------------------------------------------------
EFI_STATUS
SetupNetworkInterfaces (
  VOID 
  )
{
  EFI_STATUS   Status = EFI_SUCCESS;
  
  EFI_HANDLE           *Handles;
  UINTN                HandleCount       = 0;
  UINTN                Index;
  EFI_HANDLE           ChildHandle;
  BOOLEAN              MediaPresentSupported;
  BOOLEAN              MediaPresent;
    
  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  
  //
  // Locate all network device handles
  //
  Status = gBS->LocateHandleBuffer (
                 ByProtocol,
                 &gEfiManagedNetworkServiceBindingProtocolGuid,
                 NULL,
                 &HandleCount,
                 &Handles
                 );
  if (EFI_ERROR (Status) || (HandleCount == 0)) {
    return EFI_NOT_FOUND;
  }
  
  DEBUG((EFI_D_INFO, "%a.%d HandleCount: %d\n", __FUNCTION__, __LINE__, HandleCount));
  
  //
  // Get an info for an each NIC and config each one
  //
  for (Index = 0; Index < HandleCount; Index++) {
    Status = GetChildHandle (Handles[Index], &ChildHandle);
    if (EFI_ERROR (Status)) {
      //
      // If failed to get Child handle, try NIC controller handle for back-compatibility.
      //
      ChildHandle = Handles[Index];
    }
      
    //
    // Get media status
    //
    Status = GetNicMediaStatus (Handles[Index], &MediaPresentSupported, &MediaPresent);
    if (Status != EFI_SUCCESS && Status != EFI_NOT_STARTED) {
      DEBUG ((EFI_D_ERROR, "%a.%d GetNicMediaStatus() Status = %r\n", __FUNCTION__, __LINE__, Status));
    } else {
      if (TRUE == MediaPresent) {
        DEBUG((EFI_D_INFO, "%a.%d Media is presented\n", __FUNCTION__, __LINE__));
      } else {
        DEBUG((EFI_D_INFO, "%a.%d Media isn't presented\n", __FUNCTION__, __LINE__));
      }
    }

    Status = StartIp4 (Handles[Index]);
    DEBUG ((EFI_D_INFO, "%a.%d StartIp4() Status = %r\n", __FUNCTION__, __LINE__, Status));
  }
  
  FreePool (Handles);
  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Get IP adresses for NICs which have been configured */
/*! \param[out] *numActiveNICs Number of configured NICs 
    \param[out] *Status Status of operation */
/*! \return A pointer to an array of NICs ip config */
//------------------------------------------------------------------------------
NIC_IP_CONFIG*
GetLocalIPforActiveNICs (
  OUT UINTN *numActiveNICs,
  OUT EFI_STATUS *Status
  )
{
  LIST_ENTRY     *Entry;
  LIST_ENTRY     *NextEntry;
  NIC_INFO       *NicInfo;
  UINTN          nicCount = 0;
  NIC_IP_CONFIG  *configList = NULL, *startStruct = NULL;

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));
  
  *Status = IfconfigGetAllNicInfoByHii();
  if (EFI_ERROR(*Status)) {
    return NULL;
  }

  NET_LIST_FOR_EACH_SAFE (Entry, NextEntry, &NicInfoList) {
    nicCount++;
  }

  if (0 == nicCount) {
    *Status = EFI_NOT_FOUND;
    return NULL;
  }

  DEBUG((EFI_D_INFO, "%a.%d Cards found: %d\n", __FUNCTION__, __LINE__, nicCount));

  configList = AllocateZeroPool(sizeof(NIC_IP_CONFIG)*nicCount);
  if (NULL == configList) {
    *Status = EFI_OUT_OF_RESOURCES;
    return NULL;
  }

  nicCount = 0;
  startStruct = configList;

  NET_LIST_FOR_EACH_SAFE (Entry, NextEntry, &NicInfoList) {
    NicInfo = BASE_CR (Entry, NIC_INFO, Link);
    if (NicInfo == NULL)
      goto _exit;

    configList->StationLocalAddress[0] = NicInfo->ConfigInfo->Ip4Info.StationAddress.Addr[0];
    configList->StationLocalAddress[1] = NicInfo->ConfigInfo->Ip4Info.StationAddress.Addr[1];
    configList->StationLocalAddress[2] = NicInfo->ConfigInfo->Ip4Info.StationAddress.Addr[2];
    configList->StationLocalAddress[3] = NicInfo->ConfigInfo->Ip4Info.StationAddress.Addr[3];
    configList->isMediaPresent = NicInfo->MediaPresent;

    if (TRUE == CheckPcdDebugPropertyMask()) {
      CHAR8 *addr1, *addr2, *addr3, *addr4;
      DEBUG((EFI_D_INFO, "%a.%d IP address: \n", __FUNCTION__, __LINE__));
      addr1 = UINTNToAsciiString(configList->StationLocalAddress[0]);
      addr2 = UINTNToAsciiString(configList->StationLocalAddress[1]);
      addr3 = UINTNToAsciiString(configList->StationLocalAddress[2]);
      addr4 = UINTNToAsciiString(configList->StationLocalAddress[3]);
      DEBUG((EFI_D_INFO, "%a.%a.%a.%a\n", addr1, addr2, addr3, addr4));

      FreePool(addr1);
      FreePool(addr2);
      FreePool(addr3);
      FreePool(addr4);

      addr1 = UINTNToAsciiString(NicInfo->ConfigInfo->Ip4Info.SubnetMask.Addr[0]);
      addr2 = UINTNToAsciiString(NicInfo->ConfigInfo->Ip4Info.SubnetMask.Addr[1]);
      addr3 = UINTNToAsciiString(NicInfo->ConfigInfo->Ip4Info.SubnetMask.Addr[2]);
      addr4 = UINTNToAsciiString(NicInfo->ConfigInfo->Ip4Info.SubnetMask.Addr[3]);

      DEBUG((EFI_D_INFO, "NetMask: %a.%a.%a.%a\n", addr1, addr2, addr3, addr4));

      FreePool(addr1);
      FreePool(addr2);
      FreePool(addr3);
      FreePool(addr4);
    }

    nicCount++;
    configList++;
  }
_exit:
  *numActiveNICs = nicCount;

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  return startStruct;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/** Get all Nic's information through HII service.
    @retval EFI_SUCCESS         All the nic information is collected. **/
//------------------------------------------------------------------------------
static
EFI_STATUS
EFIAPI
IfconfigGetAllNicInfoByHii (
  VOID
  )
{
  EFI_STATUS                    Status;
  EFI_HANDLE                    *Handles;
  UINTN                         HandleCount;
  CHAR16                        *ConfigResp;
  CHAR16                        *ConfigHdr;
  UINTN                         Index;
  CHAR16                        *AccessProgress;
  CHAR16                        *AccessResults;
  UINTN                         BufferSize;
  NIC_INFO                      *NicInfo;
  NIC_IP4_CONFIG_INFO           *NicConfigRequest;
  NIC_IP4_CONFIG_INFO           *NicConfig;
  CHAR16                        *String;
  UINTN                         Length;
  UINTN                         Offset;
  EFI_HANDLE                    ChildHandle;

  AccessResults    = NULL;
  ConfigHdr        = NULL;
  ConfigResp       = NULL;
  NicConfigRequest = NULL;
  NicInfo          = NULL;

  InitializeListHead (&NicInfoList);

  //
  // Check if HII Config Routing protocol available.
  //
  Status = gBS->LocateProtocol (
                &gEfiHiiConfigRoutingProtocolGuid,
                NULL,
                (VOID**)&mHiiConfigRouting
                );
  if (EFI_ERROR (Status)) {
    return EFI_NOT_FOUND;
  }

  //
  // Locate all network device handles
  //
  Status = gBS->LocateHandleBuffer (
                 ByProtocol,
                 &gEfiManagedNetworkServiceBindingProtocolGuid,
                 NULL,
                 &HandleCount,
                 &Handles
                 );
  if (EFI_ERROR (Status) || (HandleCount == 0)) {
    return EFI_NOT_FOUND;
  }

  for (Index = 0; Index < HandleCount; Index++) {
    Status = GetChildHandle (Handles[Index], &ChildHandle);
    if (EFI_ERROR (Status)) {
      //
      // If failed to get Child handle, try NIC controller handle for back-compatibility.
      //
      ChildHandle = Handles[Index];
    }
    //
    // Construct configuration request string header
    //
    ConfigHdr = ConstructConfigHdr (&gEfiNicIp4ConfigVariableGuid, EFI_NIC_IP4_CONFIG_VARIABLE, ChildHandle);
    if (ConfigHdr != NULL) {
      Length = StrLen (ConfigHdr);
    } else {
      Length = 0;
    }
    ConfigResp = AllocateZeroPool ((Length + NIC_ITEM_CONFIG_SIZE * 2 + 100) * sizeof (CHAR16));
    if (ConfigResp == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      goto ON_ERROR;
    }
    if (ConfigHdr != NULL) {
      StrCpy (ConfigResp, ConfigHdr);
    }
 
    //
    // Append OFFSET/WIDTH pair
    //
    String = ConfigResp + Length;
    Offset = 0;
    AppendOffsetWidthValue (String, Offset, NIC_ITEM_CONFIG_SIZE, NULL);

    NicInfo = AllocateZeroPool (sizeof (NIC_INFO));
    if (NicInfo == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      goto ON_ERROR;
    }
    NicInfo->Handle       = Handles[Index];

    //
    // Get network physical device MAC information
    //
    IfConfigGetNicMacInfo (Handles[Index], &NicInfo->NicAddress);
    if (NicInfo->NicAddress.Type == NET_IFTYPE_ETHERNET) {
      UnicodeSPrint (NicInfo->Name, IP4_NIC_NAME_LENGTH, L"eth%d", Index);
    } else {
      UnicodeSPrint (NicInfo->Name, IP4_NIC_NAME_LENGTH, L"unk%d", Index);
    }

    //
    // Get media status
    //
    GetNicMediaStatus (Handles[Index], &NicInfo->MediaPresentSupported, &NicInfo->MediaPresent);

    NicConfigRequest = AllocateZeroPool (NIC_ITEM_CONFIG_SIZE);
    if (NicConfigRequest == NULL) {
      Status = EFI_OUT_OF_RESOURCES;
      goto ON_ERROR;
    }

    //
    // Get network parameters by HII service
    //
    Status = mHiiConfigRouting->ExtractConfig (
                                  mHiiConfigRouting,
                                  ConfigResp,
                                  &AccessProgress,
                                  &AccessResults
                                  );
    if (!EFI_ERROR (Status)) {
      BufferSize = NIC_ITEM_CONFIG_SIZE;
      Status = mHiiConfigRouting->ConfigToBlock (
                                    mHiiConfigRouting,
                                    AccessResults,
                                    (UINT8 *) NicConfigRequest,
                                    &BufferSize,
                                    &AccessProgress
                                    );
      if (!EFI_ERROR (Status)) {
        BufferSize = sizeof (NIC_IP4_CONFIG_INFO) + sizeof (EFI_IP4_ROUTE_TABLE) * NicConfigRequest->Ip4Info.RouteTableSize + sizeof (EFI_DNS4_CONFIG_DATA);
        NicConfig = AllocateZeroPool (BufferSize);
        if (NicConfig == NULL) {
          Status = EFI_OUT_OF_RESOURCES;
          goto ON_ERROR;
        }
        CopyMem (NicConfig, NicConfigRequest, BufferSize);

        //
        // If succeeds to get NIC configuration, fix up routetable pointer.
        //
        NicConfig->Ip4Info.RouteTable = (EFI_IP4_ROUTE_TABLE *) (&NicConfig->Ip4Info + 1);
        NicInfo->ConfigInfo   = NicConfig;

      } else {
        NicInfo->ConfigInfo   = NULL;
      }

      FreePool (AccessResults);

    } else {
      NicInfo->ConfigInfo   = NULL;
    }

    //
    // Add the Nic's info to the global NicInfoList.
    //
    InsertTailList (&NicInfoList, &NicInfo->Link);

    FreePool (NicConfigRequest);
    FreePool (ConfigResp);
    FreePool (ConfigHdr);
  }

  FreePool (Handles);

  return EFI_SUCCESS;
 
ON_ERROR:
  if (AccessResults != NULL) {
    FreePool (AccessResults);
  }
  if (NicConfigRequest != NULL) {
    FreePool (NicConfigRequest);
  }
  if (NicInfo != NULL) {
    FreePool (NicInfo);
  }
  if (ConfigResp != NULL) {
    FreePool (ConfigResp);
  }
  if (ConfigHdr != NULL) {
    FreePool (ConfigHdr);
  }

  FreePool (Handles);

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
VOID
EFIAPI
IfConfigFree (
  IN NIC_CONFIG_T *Config
)
{
  if (Config == NULL)
    return;

  if (Config->localAddr != NULL)
    FreePool(Config->localAddr);

  if (Config->netMask != NULL)
    FreePool(Config->netMask);

  if (Config->gateway != NULL)
    FreePool(Config->gateway);

  if (Config->primaryDns != NULL)
    FreePool(Config->primaryDns);

  if (Config->secondaryDns != NULL)
    FreePool(Config->secondaryDns);

  if (Config->dnsDomainName != NULL)
    FreePool(Config->dnsDomainName);

  FreePool(Config);

  return;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/** Get Nic count. **/
//------------------------------------------------------------------------------
EFI_STATUS
EFIAPI
IfconfigGetAllNicCount (
  IN OUT UINTN      *NicCount
  )
{
  EFI_STATUS                    Status;
  EFI_HANDLE                    *Handles;
  UINTN                         HandleCount;

  if (NicCount == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Locate all network device handles
  //
  Status = gBS->LocateHandleBuffer (
                 ByProtocol,
                 &gEfiManagedNetworkServiceBindingProtocolGuid,
                 NULL,
                 &HandleCount,
                 &Handles
                 );
  if (EFI_ERROR (Status)) {
    return EFI_NOT_FOUND;
  }

  FreePool (Handles);
  *NicCount = HandleCount;
  return EFI_SUCCESS;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/** Get Nic's information by index.
    @retval EFI_SUCCESS         All the nic information is collected. **/
//------------------------------------------------------------------------------
EFI_STATUS
EFIAPI
IfconfigGetNicInfoByIndex (
  IN UINTN            nicIndex,
  IN OUT NIC_CONFIG_T **Config
  )
{
  EFI_STATUS                    Status;
  EFI_HANDLE                    *Handles;
  UINTN                         HandleCount;
  CHAR16                        *ConfigResp;
  CHAR16                        *ConfigHdr;
  CHAR16                        *AccessProgress;
  CHAR16                        *AccessResults;
  UINTN                         BufferSize;
  NIC_IP4_CONFIG_INFO           *NicConfigRequest;
  NIC_IP4_CONFIG_INFO           *NicConfig;
  CHAR16                        *String;
  UINTN                         Length;
  UINTN                         Offset;
  EFI_HANDLE                    ChildHandle;
  NIC_CONFIG_T                  *LocalConfig;
  NIC_IP4_CONFIG_INFO           ZeroConfig;
  EFI_IPv4_ADDRESS              ZeroAddr;
  EFI_DNS4_CONFIG_DATA          *DnsConfig;
  UINTN                         Index;

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  AccessResults    = NULL;
  ConfigHdr        = NULL;
  ConfigResp       = NULL;
  NicConfigRequest = NULL;
  NicConfig        = NULL;
  LocalConfig      = NULL;

  ZeroMem (&ZeroConfig, sizeof(ZeroConfig));
  ZeroMem (&ZeroAddr, sizeof(ZeroAddr));

  if (Config == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  //
  // Check if HII Config Routing protocol available.
  //
  Status = gBS->LocateProtocol (
                &gEfiHiiConfigRoutingProtocolGuid,
                NULL,
                (VOID**)&mHiiConfigRouting
                );
  if (EFI_ERROR (Status)) {
    return EFI_NOT_FOUND;
  }

  //
  // Locate all network device handles
  //
  Status = gBS->LocateHandleBuffer (
                 ByProtocol,
                 &gEfiManagedNetworkServiceBindingProtocolGuid,
                 NULL,
                 &HandleCount,
                 &Handles
                 );
  if (EFI_ERROR (Status) || (HandleCount == 0)) {
    return EFI_NOT_FOUND;
  }

  if (nicIndex >= HandleCount) {
    Status = EFI_INVALID_PARAMETER;
    goto ON_ERROR;
  }

  LocalConfig = AllocateZeroPool (sizeof(NIC_CONFIG_T));
  if (LocalConfig == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto ON_ERROR;
  }

  Status = GetChildHandle (Handles[nicIndex], &ChildHandle);
  if (EFI_ERROR (Status)) {
    //
    // If failed to get Child handle, try NIC controller handle for back-compatibility.
    //
    ChildHandle = Handles[nicIndex];
  }
  //
  // Construct configuration request string header
  //
  ConfigHdr = ConstructConfigHdr (&gEfiNicIp4ConfigVariableGuid, EFI_NIC_IP4_CONFIG_VARIABLE, ChildHandle);
  if (ConfigHdr != NULL) {
    Length = StrLen (ConfigHdr);
  } else {
    Length = 0;
  }
  ConfigResp = AllocateZeroPool ((Length + NIC_ITEM_CONFIG_SIZE * 2 + 100) * sizeof (CHAR16));
  if (ConfigResp == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto ON_ERROR;
  }
  if (ConfigHdr != NULL) {
    StrCpy (ConfigResp, ConfigHdr);
  }
 
  //
  // Append OFFSET/WIDTH pair
  //
  String = ConfigResp + Length;
  Offset = 0;
  AppendOffsetWidthValue (String, Offset, NIC_ITEM_CONFIG_SIZE, NULL);

  NicConfigRequest = AllocateZeroPool (NIC_ITEM_CONFIG_SIZE);
  if (NicConfigRequest == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto ON_ERROR;
  }

  //
  // Get network parameters by HII service
  //
  Status = mHiiConfigRouting->ExtractConfig (
                                mHiiConfigRouting,
                                ConfigResp,
                                &AccessProgress,
                                &AccessResults
                                );
  if (!EFI_ERROR (Status)) {
    BufferSize = NIC_ITEM_CONFIG_SIZE;
    Status = mHiiConfigRouting->ConfigToBlock (
                                  mHiiConfigRouting,
                                  AccessResults,
                                  (UINT8 *) NicConfigRequest,
                                  &BufferSize,
                                  &AccessProgress
                                  );
    if (!EFI_ERROR (Status)) {
      BufferSize = sizeof (NIC_IP4_CONFIG_INFO) + sizeof (EFI_IP4_ROUTE_TABLE) * NicConfigRequest->Ip4Info.RouteTableSize + sizeof (EFI_DNS4_CONFIG_DATA);
      NicConfig = AllocateZeroPool (BufferSize);
      if (NicConfig == NULL) {
        Status = EFI_OUT_OF_RESOURCES;
        goto ON_ERROR;
      }
      CopyMem (NicConfig, NicConfigRequest, BufferSize);

      //
      // If succeeds to get NIC configuration, fix up routetable pointer.
      //
      NicConfig->Ip4Info.RouteTable = (EFI_IP4_ROUTE_TABLE *) (&NicConfig->Ip4Info + 1);
    }

    FreePool (AccessResults);

  }

  DEBUG((EFI_D_INFO, "%a.%d NicConfig = 0x%X\n", __FUNCTION__, __LINE__, NicConfig));
  if ((NicConfig != NULL) && (CompareMem (NicConfig, &ZeroConfig, sizeof(ZeroConfig)) != 0)) {
    DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

    LocalConfig->enable = TRUE;
    LocalConfig->useDHCP = (NicConfig->Source == IP4_CONFIG_SOURCE_DHCP) ? TRUE: FALSE;
    if (!LocalConfig->useDHCP) {
      if (CompareMem (&NicConfig->Ip4Info.StationAddress, &ZeroAddr, sizeof(ZeroAddr)) != 0) {
        LocalConfig->localAddr = AllocateZeroPool (IP4_STR_MAX_SIZE * sizeof(CHAR16));
        if (LocalConfig->localAddr == NULL) {
          Status = EFI_OUT_OF_RESOURCES;
          goto ON_ERROR;
        }
        UnicodeSPrint (LocalConfig->localAddr, 2 * IP4_STR_MAX_SIZE, L"%d.%d.%d.%d", 
          NicConfig->Ip4Info.StationAddress.Addr[0], NicConfig->Ip4Info.StationAddress.Addr[1],  
          NicConfig->Ip4Info.StationAddress.Addr[2], NicConfig->Ip4Info.StationAddress.Addr[3]);
      }

      if (CompareMem (&NicConfig->Ip4Info.SubnetMask, &ZeroAddr, sizeof(ZeroAddr)) != 0) {
        LocalConfig->netMask = AllocateZeroPool (IP4_STR_MAX_SIZE * sizeof(CHAR16));
        if (LocalConfig->netMask == NULL) {
          Status = EFI_OUT_OF_RESOURCES;
          goto ON_ERROR;
        }
        UnicodeSPrint (LocalConfig->netMask, 2 * IP4_STR_MAX_SIZE, L"%d.%d.%d.%d", 
          NicConfig->Ip4Info.SubnetMask.Addr[0], NicConfig->Ip4Info.SubnetMask.Addr[1],  
          NicConfig->Ip4Info.SubnetMask.Addr[2], NicConfig->Ip4Info.SubnetMask.Addr[3]);
      }

      for (Index = 0; Index < NicConfig->Ip4Info.RouteTableSize; Index++) {
        if ((CompareMem (&NicConfig->Ip4Info.RouteTable[Index].SubnetAddress, &ZeroAddr, sizeof(ZeroAddr)) == 0) &&
            (CompareMem (&NicConfig->Ip4Info.RouteTable[Index].SubnetMask, &ZeroAddr, sizeof(ZeroAddr)) == 0) &&
            (CompareMem (&NicConfig->Ip4Info.RouteTable[Index].GatewayAddress, &ZeroAddr, sizeof(ZeroAddr)) != 0)) {
          LocalConfig->gateway = AllocateZeroPool (IP4_STR_MAX_SIZE * sizeof(CHAR16));
          if (LocalConfig->gateway == NULL) {
            Status = EFI_OUT_OF_RESOURCES;
            goto ON_ERROR;
          }
          UnicodeSPrint (LocalConfig->gateway, 2 * IP4_STR_MAX_SIZE, L"%d.%d.%d.%d", 
            NicConfig->Ip4Info.RouteTable[Index].GatewayAddress.Addr[0], NicConfig->Ip4Info.RouteTable[Index].GatewayAddress.Addr[1],  
            NicConfig->Ip4Info.RouteTable[Index].GatewayAddress.Addr[2], NicConfig->Ip4Info.RouteTable[Index].GatewayAddress.Addr[3]);
          break;
        }
      }

      DnsConfig = DNS4_CONFIG_FROM_IP4_CONFIG_INFO (NicConfig);
      if (CompareMem (&DnsConfig->PrimaryDns, &ZeroAddr, sizeof(ZeroAddr)) != 0) {
        LocalConfig->primaryDns = AllocateZeroPool (IP4_STR_MAX_SIZE * sizeof(CHAR16));
        if (LocalConfig->primaryDns == NULL) {
          Status = EFI_OUT_OF_RESOURCES;
          goto ON_ERROR;
        }
        UnicodeSPrint (LocalConfig->primaryDns, 2 * IP4_STR_MAX_SIZE, L"%d.%d.%d.%d", 
          DnsConfig->PrimaryDns.Addr[0], DnsConfig->PrimaryDns.Addr[1],  
          DnsConfig->PrimaryDns.Addr[2], DnsConfig->PrimaryDns.Addr[3]);
      }
      if (CompareMem (&DnsConfig->SecondaryDns, &ZeroAddr, sizeof(ZeroAddr)) != 0) {
        LocalConfig->secondaryDns = AllocateZeroPool (IP4_STR_MAX_SIZE * sizeof(CHAR16));
        if (LocalConfig->secondaryDns == NULL) {
          Status = EFI_OUT_OF_RESOURCES;
          goto ON_ERROR;
        }
        UnicodeSPrint (LocalConfig->secondaryDns, 2 * IP4_STR_MAX_SIZE, L"%d.%d.%d.%d", 
          DnsConfig->SecondaryDns.Addr[0], DnsConfig->SecondaryDns.Addr[1],  
          DnsConfig->SecondaryDns.Addr[2], DnsConfig->SecondaryDns.Addr[3]);
      }
      Index = AsciiStrLen (DnsConfig->DomainName);
      if (Index > 0) {
        LocalConfig->dnsDomainName = AllocateZeroPool ((Index + 1) * sizeof(CHAR16));
        if (LocalConfig->dnsDomainName == NULL) {
          Status = EFI_OUT_OF_RESOURCES;
          goto ON_ERROR;
        }
        AsciiStrToUnicodeStr (DnsConfig->DomainName, LocalConfig->dnsDomainName);
      }
    }

    FreePool (NicConfig);
  }
  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  FreePool (NicConfigRequest);
  FreePool (ConfigResp);
  FreePool (ConfigHdr);

  FreePool (Handles);

  *Config = LocalConfig;

  return EFI_SUCCESS;
 
ON_ERROR:
  if (AccessResults != NULL) {
    FreePool (AccessResults);
  }
  if (NicConfigRequest != NULL) {
    FreePool (NicConfigRequest);
  }
  if (ConfigResp != NULL) {
    FreePool (ConfigResp);
  }
  if (ConfigHdr != NULL) {
    FreePool (ConfigHdr);
  }
  if (LocalConfig != NULL) {
    if (LocalConfig->localAddr != NULL) {
      FreePool (LocalConfig->localAddr);
    }
    if (LocalConfig->netMask != NULL) {
      FreePool (LocalConfig->netMask);
    }
    if (LocalConfig->gateway != NULL) {
      FreePool (LocalConfig->gateway);
    }
    if (LocalConfig->primaryDns != NULL) {
      FreePool (LocalConfig->primaryDns);
    }
    if (LocalConfig->secondaryDns != NULL) {
      FreePool (LocalConfig->secondaryDns);
    }
    if (LocalConfig->dnsDomainName != NULL) {
      FreePool (LocalConfig->dnsDomainName);
    }
    FreePool (LocalConfig);
  }

  FreePool (Handles);

  return Status;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/** Get network physical device NIC information.

  @param[in] Handle         The network physical device handle.
  @param[out] NicAddr       NIC information.

  @retval EFI_SUCCESS         Get NIC information successfully. **/
//------------------------------------------------------------------------------
static
EFI_STATUS
EFIAPI
IfConfigGetNicMacInfo (
  IN  EFI_HANDLE                    Handle,
  OUT NIC_ADDR                      *NicAddr
  )
{
  EFI_STATUS                    Status;
  EFI_HANDLE                    MnpHandle;
  EFI_SIMPLE_NETWORK_MODE       SnpMode;
  EFI_MANAGED_NETWORK_PROTOCOL  *Mnp;

  MnpHandle = NULL;
  Mnp       = NULL;

  Status = NetLibCreateServiceChild (
             Handle,
             gImageHandle, 
             &gEfiManagedNetworkServiceBindingProtocolGuid,
             &MnpHandle
             );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Status = gBS->HandleProtocol (
                  MnpHandle,
                  &gEfiManagedNetworkProtocolGuid,
                  (VOID **) &Mnp
                  );
  if (EFI_ERROR (Status)) {
    goto ON_ERROR;
  }

  Status = Mnp->GetModeData (Mnp, NULL, &SnpMode);
  if (EFI_ERROR (Status) && (Status != EFI_NOT_STARTED)) {
    goto ON_ERROR;
  }
 
  NicAddr->Type    = (UINT16) SnpMode.IfType;
  NicAddr->Len     = (UINT8) SnpMode.HwAddressSize;
  CopyMem (&NicAddr->MacAddr, &SnpMode.CurrentAddress, NicAddr->Len);

ON_ERROR:

  NetLibDestroyServiceChild (
    Handle,
    gImageHandle, 
    &gEfiManagedNetworkServiceBindingProtocolGuid,
    MnpHandle
    );

  return Status;

}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set NIC settings for specified controller */
/*! \param[in] *NicInfo NIC Controller info
    \param[in] *Config Configuration to apply */
//------------------------------------------------------------------------------
EFI_STATUS
EFIAPI
SetNicAddrByHii (
  IN CONST NIC_INFO                 *NicInfo,
  IN CONST NIC_IP4_CONFIG_INFO      *Config
  )
{
  EFI_STATUS                    Status;
  NIC_IP4_CONFIG_INFO           *NicConfig;
  CHAR16                        *ConfigResp;
  CHAR16                        *ConfigHdr;
  CHAR16                        *AccessProgress;
  CHAR16                        *AccessResults;
  CHAR16                        *String;
  UINTN                         Length;
  UINTN                         Offset;
  EFI_HANDLE                    ChildHandle;

  AccessResults  = NULL;
  ConfigHdr      = NULL;
  ConfigResp     = NULL;
  NicConfig      = NULL;
  Status         = EFI_SUCCESS;

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  Status = GetChildHandle (NicInfo->Handle, &ChildHandle);
  if (EFI_ERROR (Status)) {
    //
    // If failed to get Child handle, try NIC controller handle for back-compatibility
    //
    ChildHandle = NicInfo->Handle;
  }
  //
  // Construct config request string header
  //
  ConfigHdr = ConstructConfigHdr (&gEfiNicIp4ConfigVariableGuid, EFI_NIC_IP4_CONFIG_VARIABLE, ChildHandle);
  if (ConfigHdr != NULL) {
    Length = StrLen (ConfigHdr);
  } else {
    Status = EFI_OUT_OF_RESOURCES;
    goto ON_EXIT;
  }
  ConfigResp = AllocateZeroPool ((Length + NIC_ITEM_CONFIG_SIZE * 2 + 100) * sizeof (CHAR16));
  if (ConfigResp == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto ON_EXIT;
  }
  if (ConfigHdr != NULL) {
    StrCpy (ConfigResp, ConfigHdr);
  }

  NicConfig = AllocateZeroPool (NIC_ITEM_CONFIG_SIZE);
  if (NicConfig == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto ON_EXIT;
  }

  if (Config != NULL) {
    CopyMem (NicConfig, Config, sizeof (NIC_IP4_CONFIG_INFO) + sizeof (EFI_IP4_ROUTE_TABLE) * Config->Ip4Info.RouteTableSize + sizeof (EFI_DNS4_CONFIG_DATA));
  }

  //
  // Append OFFSET/WIDTH pair
  //
  String = ConfigResp + Length;
  Offset = 0;
  AppendOffsetWidthValue (String, Offset, NIC_ITEM_CONFIG_SIZE, NULL);

  //
  // Call HII helper function to generate configuration string
  //
  Status = mHiiConfigRouting->BlockToConfig (
                                mHiiConfigRouting,
                                ConfigResp,
                                (UINT8 *) NicConfig,
                                NIC_ITEM_CONFIG_SIZE,
                                &AccessResults,
                                &AccessProgress
                                );
  if (EFI_ERROR (Status)) {
    Status = EFI_NOT_FOUND;
    goto ON_EXIT;
  }

  //
  // Set IP setting by HII servie
  //
  Status = mHiiConfigRouting->RouteConfig (
                                mHiiConfigRouting,
                                AccessResults,
                                &AccessProgress
                                );
  if (EFI_ERROR(Status))
    Status = EFI_ACCESS_DENIED;

ON_EXIT:
  if (AccessResults != NULL)
    FreePool(AccessResults);
  if (NicConfig != NULL)
    FreePool(NicConfig);
  if (ConfigResp != NULL)
    FreePool(ConfigResp);
  if (ConfigHdr != NULL)
    FreePool(ConfigHdr);

  return Status;
}

//------------------------------------------------------------------------------
/*! \brief Is NIC config presented in the variable */
/*! \param[in] Handle Driver handle for the NIC */
//------------------------------------------------------------------------------
BOOLEAN
IsNicConfigPresentedForHandle (
  IN EFI_HANDLE Handle
)
{
  CHAR16    *ConfigResp       = NULL;
  CHAR16    *ConfigHdr        = NULL;
  CHAR16    *AccessProgress   = NULL;
  CHAR16    *AccessResults    = NULL;
  CHAR16    *String;
  UINTN     Length;
  UINTN     Offset;

  BOOLEAN   retval            = FALSE;

  EFI_STATUS Status;

  //
  // Construct configuration request string header
  //
  ConfigHdr = ConstructConfigHdr (&gEfiNicIp4ConfigVariableGuid, EFI_NIC_IP4_CONFIG_VARIABLE, Handle);
  if (ConfigHdr != NULL)
    Length = StrLen (ConfigHdr);
  else
    Length = 0;

  ConfigResp = AllocateZeroPool ((Length + NIC_ITEM_CONFIG_SIZE * 2 + 100) * sizeof (CHAR16));
  if (ConfigResp == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto ON_ERROR;
  }
  if (ConfigHdr != NULL) {
    StrCpy (ConfigResp, ConfigHdr);
  }

  //
  // Append OFFSET/WIDTH pair
  //
  String = ConfigResp + Length;
  Offset = 0;
  AppendOffsetWidthValue (String, Offset, NIC_ITEM_CONFIG_SIZE, NULL);

  //
  // Get network parameters by HII service
  //
  Status = mHiiConfigRouting->ExtractConfig (
                                mHiiConfigRouting,
                                ConfigResp,
                                &AccessProgress,
                                &AccessResults
                                );
  if (!EFI_ERROR (Status))
    retval =  TRUE;
  else
    retval =  FALSE;

ON_ERROR:

  if (AccessResults != NULL) {
    FreePool (AccessResults);
  }
  if (ConfigResp != NULL) {
    FreePool (ConfigResp);
  }
  if (ConfigHdr != NULL) {
    FreePool (ConfigHdr);
  }

  return retval;
}
//------------------------------------------------------------------------------

//------------------------------------------------------------------------------
/*! \brief Set NIC config by index */
/*! Find NIC info and apply IP4 config */
/*! \param[in] nicIndex Index of NIC in the Handles array
    \param[in] config NIC config to set */
//------------------------------------------------------------------------------
EFI_STATUS
SetNicConfigByIndex (
  IN UINTN nicIndex,
  IN NIC_CONFIG_T config
)
{
  EFI_STATUS   Status = EFI_SUCCESS;
  
  EFI_HANDLE           *Handles;
  UINTN                HandleCount = 0;
  NIC_IP4_CONFIG_INFO  *NicConfig = NULL;
  EFI_DNS4_CONFIG_DATA *DnsConfig = NULL;
  NIC_INFO             *NicInfo   = NULL;
  EFI_HANDLE           ChildHandle;
  
  EFI_IP_ADDRESS       Ip;
  EFI_IP_ADDRESS       Mask;
  EFI_IP_ADDRESS       Gateway;
  EFI_IP_ADDRESS       PrimaryDns;
  EFI_IP_ADDRESS       SecondaryDns;
  CHAR8								 *DnsDomainName = NULL;

  DEBUG((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  //
  // Check if HII Config Routing protocol available.
  //
  Status = gBS->LocateProtocol (
                &gEfiHiiConfigRoutingProtocolGuid,
                NULL,
                (VOID**)&mHiiConfigRouting
                );
  if (EFI_ERROR (Status))
    return EFI_NOT_FOUND;

  //
  // Locate all network device handles
  //
  Status = gBS->LocateHandleBuffer (
                 ByProtocol,
                 &gEfiManagedNetworkServiceBindingProtocolGuid,
                 NULL,
                 &HandleCount,
                 &Handles
                 );
  if (EFI_ERROR (Status) || (HandleCount == 0))
    return EFI_NOT_FOUND;

  if (nicIndex >= HandleCount)
    return EFI_INVALID_PARAMETER;

  Status = GetChildHandle (Handles[nicIndex], &ChildHandle);
  if (EFI_ERROR (Status)) {
    //
    // If failed to get Child handle, try NIC controller handle for back-compatibility.
    //
    ChildHandle = Handles[nicIndex];
  }

  if (config.enable == FALSE) {
    if (IsNicConfigPresentedForHandle(ChildHandle) == FALSE) {
      DEBUG((EFI_D_INFO, "%a.%d No need to unconfigure\n", __FUNCTION__, __LINE__));
      return EFI_SUCCESS;
    }
  }

  NicInfo = AllocateZeroPool (sizeof (NIC_INFO));
  if (NicInfo == NULL)
    return EFI_OUT_OF_RESOURCES;

  NicInfo->Handle = Handles[nicIndex];

  NicConfig = AllocateZeroPool (sizeof (NIC_IP4_CONFIG_INFO) + 2 * sizeof (EFI_IP4_ROUTE_TABLE) + sizeof (EFI_DNS4_CONFIG_DATA));
  if (NicConfig == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto _exit;
  }

  if (config.enable == TRUE) {
    //
    // Get network physical device MAC information
    //
    IfConfigGetNicMacInfo (NicInfo->Handle, &NicInfo->NicAddress);
    if (NicInfo->NicAddress.Type == NET_IFTYPE_ETHERNET) {
      UnicodeSPrint (NicInfo->Name, IP4_NIC_NAME_LENGTH, L"eth%d", nicIndex);
    } else {
      UnicodeSPrint (NicInfo->Name, IP4_NIC_NAME_LENGTH, L"unk%d", nicIndex);
    }
  
    // Fill NicConfig
    NicConfig->Ip4Info.RouteTable = (EFI_IP4_ROUTE_TABLE *) (NicConfig + 1);
  
    if (config.useDHCP == TRUE) {
      NicConfig->Source = IP4_CONFIG_SOURCE_DHCP;
    } else {
      NicConfig->Source = IP4_CONFIG_SOURCE_STATIC;
      NicConfig->Ip4Info.RouteTableSize = 2;
  
      if (config.localAddr == NULL || config.netMask == NULL || config.gateway == NULL) {
        Status = EFI_INVALID_PARAMETER;
        goto _exit;
      }
      if (EFI_ERROR (NetLibStrToIp4 (config.localAddr, &Ip.v4))) {
        Status = EFI_INVALID_PARAMETER;
        goto _exit;
      }
      if (EFI_ERROR (NetLibStrToIp4 (config.netMask, &Mask.v4))) {
        Status = EFI_INVALID_PARAMETER;
        goto _exit;
      }
      if (config.gateway != NULL) {
        if (EFI_ERROR (NetLibStrToIp4 (config.gateway, &Gateway.v4))) {
          Status = EFI_INVALID_PARAMETER;
          goto _exit;
        }
      } else {
        ZeroMem (&Gateway, sizeof(Gateway));
      }
      if (config.primaryDns != NULL && *config.primaryDns != 0) {
        DEBUG ((EFI_D_INFO, "%a.%d config.primaryDns=%a\n", 
          __FUNCTION__, __LINE__, config.primaryDns));
        if (EFI_ERROR (NetLibStrToIp4 (config.primaryDns, &PrimaryDns.v4))) {
          Status = EFI_INVALID_PARAMETER;
          DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
          goto _exit;
        }
      } else {
        ZeroMem (&PrimaryDns, sizeof(PrimaryDns));
      }
      if (config.secondaryDns != NULL && *config.secondaryDns != 0) {
        DEBUG ((EFI_D_INFO, "%a.%d config.secondaryDns=%a\n", 
          __FUNCTION__, __LINE__, config.secondaryDns));
        if (EFI_ERROR (NetLibStrToIp4 (config.secondaryDns, &SecondaryDns.v4))) {
          Status = EFI_INVALID_PARAMETER;
          DEBUG ((EFI_D_ERROR, "%a.%d\n", __FUNCTION__, __LINE__));
          goto _exit;
        }
      } else {
        ZeroMem (&SecondaryDns, sizeof(SecondaryDns));
      }
      if (config.dnsDomainName != NULL) {
        DnsDomainName = AllocateZeroPool (sizeof(CHAR8)*StrLen(config.dnsDomainName) + sizeof(CHAR8));
        if (DnsDomainName == NULL) {
          Status = EFI_OUT_OF_RESOURCES;
          goto _exit;
        }
        UnicodeStrToAsciiStr (config.dnsDomainName, DnsDomainName);
      } else {
        DnsDomainName = AllocateZeroPool (sizeof(CHAR8));
        if (DnsDomainName == NULL) {
          Status = EFI_OUT_OF_RESOURCES;
          goto _exit;
        }
      }
  
      CopyMem (&NicConfig->Ip4Info.StationAddress, &Ip.v4, sizeof (EFI_IPv4_ADDRESS));
      CopyMem (&NicConfig->Ip4Info.SubnetMask, &Mask.v4, sizeof (EFI_IPv4_ADDRESS));
  
      Ip.Addr[0] = Ip.Addr[0] & Mask.Addr[0];
  
      CopyMem (&NicConfig->Ip4Info.RouteTable[0].SubnetAddress, &Ip.v4, sizeof (EFI_IPv4_ADDRESS));
      CopyMem (&NicConfig->Ip4Info.RouteTable[0].SubnetMask, &Mask.v4, sizeof (EFI_IPv4_ADDRESS));
      CopyMem (&NicConfig->Ip4Info.RouteTable[1].GatewayAddress, &Gateway.v4, sizeof (EFI_IPv4_ADDRESS));

      DnsConfig = DNS4_CONFIG_FROM_IP4_CONFIG_INFO (NicConfig);
      CopyMem (&DnsConfig->PrimaryDns, &PrimaryDns.v4, sizeof (EFI_IPv4_ADDRESS));
      CopyMem (&DnsConfig->SecondaryDns, &SecondaryDns.v4, sizeof (EFI_IPv4_ADDRESS));
      AsciiStrnCpy (DnsConfig->DomainName, DnsDomainName, MAX_DOMAIN_NAME_SIZE);
    }

    CopyMem (&NicConfig->NicAddr, &NicInfo->NicAddress, sizeof (NIC_ADDR));

  } else {
    DEBUG((EFI_D_INFO, "%a.%d Have to remove config\n", __FUNCTION__, __LINE__));
  }
  NicConfig->Permanent = TRUE;

  // Apply NicConfig 
  Status = SetNicAddrByHii (NicInfo, NicConfig);
  if (EFI_ERROR(Status)) {
    Status = EFI_ACCESS_DENIED;
    goto _exit;
  }

_exit:

  if (NicInfo != NULL)
    FreePool (NicInfo);
  if (NicConfig != NULL)
    FreePool(NicConfig);
  if (DnsDomainName != NULL)
    FreePool(DnsDomainName);

  DEBUG((EFI_D_INFO, "%a.%d Status: %d\n", __FUNCTION__, __LINE__, Status));

  return Status;
}
//------------------------------------------------------------------------------

