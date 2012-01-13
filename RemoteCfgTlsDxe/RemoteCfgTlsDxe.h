/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __REMOTE__CFG_TLS__DXE__H
#define __REMOTE__CFG_TLS__DXE__H

#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/DebugLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/DevicePathLib.h>
#include <Library/CertStorageLib.h>
#include <Library/FsUtils.h>
#include <Library/CommonUtils.h>
#include <Library/Lib/History.h>

#include <Protocol/RemoteCfgPktProtocol.h>
#include <Protocol/TcpHelperProtocol.h>
#include <Protocol/DnsResolverProtocol.h>
#include <Protocol/RemoteCfgTlsProtocol.h>
#include <Protocol/HistoryHandlerProto.h>
#include <Protocol/GlobalConfigDxe.h>
#include <Protocol/IniParserDxe.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/HistoryHandlerProto.h>
#include <Protocol/Multiboot.h>


#include <CommonDefs.h>

typedef struct _REMOTE_CFG_TLS_PRIVATE_DATA {
  EFI_HANDLE DriverHandle;
  REMOTE_CFG_TLS_PROTOCOL HandlerProtocol;
} REMOTE_CFG_TLS_PRIVATE_DATA;

extern GUID gClientCertStorageGuid;
extern GUID gClientPKeyStorageGuid;
extern GUID gChainStorageGuid;
#define TLS_CERT_STORAGE  L"TlsCertStorage"
#define TLS_PKEY_STORAGE  L"TlsPkeyStorage"
#define TLS_CA_STORAGE    L"CertChainStorage"

#define REMOTE_CFG_TLS_TIMEOUT_1s           (1000*1000*10/*100ns*/)

#define REMOTE_CFG_TLS_CALLBACK_RATE_500ms  (500*1000*10/*100ns*/)
#define REMOTE_CFG_TLS_CALLBACK_RATE        REMOTE_CFG_TLS_CALLBACK_RATE_500ms//0.5 sec
#define REMOTE_CFG_TLS_CALLBACK_SLOWING     60
#define REMOTE_CFG_TLS_CALLBACK_TPL         (TPL_APPLICATION + 1)

#define REMOTE_CFG_TLS_DEFAULT_TLS_VERSION  REMOTE_CFG_USE_TLS_1_0

#define REMOTE_CFG_TLS_DEFAULT_ENABLED      TRUE
#define REMOTE_CFG_TLS_DEFAULT_PORT         8080 //31107
#define REMOTE_CFG_TLS_DEFAULT_SERVER       "192.168.5.1" //"127.0.0.1"

#define REMOTE_CFG_TLS_DEFAULT_CTIMEOUT     (60*1)
#define REMOTE_CFG_TLS_DEFAULT_ETIMEOUT     REMOTE_CFG_TLS_TIMEOUT_OFF

#define REMOTE_CFG_TLS_DEFAULT_ATTEMPTS     REMOTE_CFG_TLS_ATTEMPTS_INFINITE

extern CHAR8 RemoteCfgTlsConfigSectionName[];
extern GUID gRemoteCfgTlsConfigVarGuid;
#define REMOTE_CFG_TLS_CONFIG_VAR   L"RemoteCfgTlsConfigVar"

#define ST_CONNECTING         1
#define ST_EXCHANGING         2
#define ST_STOPPED            3
#define ST_RESTARTING         4
#define ST_RESTARTING2        5
#define ST_RESTARTING3        6

#define REMOTE_CFG_TLS_CHUNK_SIZE   1024
typedef struct _REMOTE_CFG_TLS_DATA_CHUNK{
  LIST_ENTRY Link;
  UINTN Exchanged;
  UINTN Size;
  UINT8 Data[REMOTE_CFG_TLS_CHUNK_SIZE];
}REMOTE_CFG_TLS_DATA_CHUNK;

typedef struct _REMOTE_CFG_TLS_WORK_DATA{
  UINTN State;
  EFI_STATUS Status;
  BOOLEAN IsWorked;
  EFI_EVENT CallbackRun;
  EFI_EVENT CallbackRunIdle;
  BOOLEAN ResetRate;
  EFI_EVENT StopAttempt;
  UINT32 Attempts;
  REMOTE_CFG_TLS_SETTINGS* Settings;
  TCP_SETTINGS TcpSettings;

  EFI_IPv4_ADDRESS *ServerIp;
  UINTN ServerIpNum;
  UINTN ServerIpCur;
  BOOLEAN ServerIpTryNext;

  REMOTE_CFG_PKT_PROTOCOL* RCPkt;
  EFI_HANDLE RCPktHandle;
  TCP_HELPER_PROTOCOL* Tcp;
  EFI_HANDLE TcpConn;
  DNS_RESOLVER_PROTOCOL *Dns;

  REMOTE_CFG_TLS_DATA_CHUNK* InChunk;
  LIST_ENTRY OutQueue;
  REMOTE_CFG_TLS_DATA_CHUNK* TmpChunk;
}REMOTE_CFG_TLS_WORK_DATA;


/**
  Allocate buffer and read certificate storage contents in it
  
  @param  StorageName             Storage name
  @param  StorageGuid             Storage guid
  @param  StorageBuf              A pointer to the location of pointer to the allocated buffer with storage contents
  @param  StorageLen              A pointer to the location of storage data length
  
  @retval EFI_INVALID_PARAMETER   Function got invalid pointer in parameters
  @retval EFI_NOT_FOUND           Can't read storage data
  @retval EFI_OUT_OF_RESOURCES    Not enough memory
  @retval EFI_SUCCESS             File succesfully readed
**/
EFI_STATUS
EFIAPI
LoadCertStorageDataInBuffer(
  IN CHAR16 *StorageName,
  IN GUID *StorageGuid,
  OUT VOID **StorageBuf,
  OUT UINTN *StorageLen
  );

/**
  Init FsUtils device mapping
**/
VOID
EFIAPI
InitFsUtils(
  IN EFI_HANDLE ImageHandle
  );

/**
  Allocate buffer and read file contents in it
  
  @param  FileName                File name
  @param  FileBuf                 A pointer to the location of pointer to the allocated buffer with file contents
  @param  FileLen                 A pointer to the location of file data length
  
  @retval EFI_INVALID_PARAMETER   Function got invalid pointer in parameters
  @retval EFI_NOT_FOUND           Can't read file data
  @retval EFI_OUT_OF_RESOURCES    Not enough memory
  @retval EFI_SUCCESS             File succesfully readed
**/
EFI_STATUS
EFIAPI
LoadFileDataInBuffer(
  IN CHAR8 *FileName,
  OUT VOID **FileBuf,
  OUT UINTN *FileLen
  );

/**
  Validate Remote Config Protocol settings
  
  @param  RCTSettings             A pointer to the settings struct
  
  @retval EFI_INVALID_PARAMETER   Function got invalid pointer in parameters
  @retval EFI_VOLUME_CORRUPTED    Settings structure is invalid
  @retval EFI_SUCCESS             Settings is valid
**/
EFI_STATUS
EFIAPI
RemoteCfgTlsValidateSettings(
  IN REMOTE_CFG_TLS_SETTINGS* RCTSettings
  );

/**
  Obtain Remote Config Protocol settings
  
  @param  RCTSettings             A pointer to the location of newly created settings struct
  
  @retval EFI_INVALID_PARAMETER   Function got invalid pointer in parameters
  @retval EFI_OUT_OF_RESOURCES    Cannot allocate memory for internal structures
  @retval EFI_NOT_FOUND           Settings not found
  @retval EFI_VOLUME_CORRUPTED    Settings is invalid
  @retval EFI_SUCCESS             Succesfully started
**/
EFI_STATUS
EFIAPI
RemoteCfgTlsGetSettings(
  IN REMOTE_CFG_TLS_PROTOCOL *This,
  OUT REMOTE_CFG_TLS_SETTINGS** RCTSettings
  );

/**
  Save Remote Config Protocol settings
  
  @param  RCTSettings             A pointer to the settings struct
  
  @retval EFI_INVALID_PARAMETER   Function got invalid pointer in parameters
  @retval EFI_VOLUME_CORRUPTED    Given settings is invalid
  @retval EFI_WRITE_PROTECTED     Cannot save settings
  @retval EFI_SUCCESS             Succesfully started
**/
EFI_STATUS
EFIAPI
RemoteCfgTlsSetSettings(
  IN REMOTE_CFG_TLS_PROTOCOL *This,
  IN REMOTE_CFG_TLS_SETTINGS* RCTSettings
  );

/**
  Reset Remote Config Protocol settings
  
  @retval EFI_OUT_OF_RESOURCES    Not enough memory
  @retval EFI_WRITE_PROTECTED     Cannot reset settings
  @retval EFI_SUCCESS             Succesfully started
**/
EFI_STATUS
EFIAPI
RemoteCfgTlsResetSettings(
  IN REMOTE_CFG_TLS_PROTOCOL *This
  );

/**
  Reset Remote Config Protocol settings from INI file
  
  @retval EFI_OUT_OF_RESOURCES    Not enough memory
  @retval EFI_NOT_FOUND           INI file not found/INI parser protocol not found
  @retval EFI_VOLUME_CORRUPTED    INI file has invalid settings
  @retval EFI_WRITE_PROTECTED     Cannot reset settings
  @retval EFI_ABORTED             Error occured
  @retval EFI_SUCCESS             Succesfully started
**/
EFI_STATUS
EFIAPI
RemoteCfgTlsResetSettingsFromINI(
  IN REMOTE_CFG_TLS_PROTOCOL *This
  );

/**
  Reset Remote Config Protocol settings from INI file dictionary.
**/
CONFIG_ERROR_T
RemoteCfgTlsSetConfigFromDictionary (
  IN dictionary *Dict
  );

CONFIG_ERROR_T
DumpRemoteCfgTlsToDictionary (
  IN dictionary *dict
);

/**
  Remote Config Protocol working callback
**/
VOID
EFIAPI 
RemoteCfgTlsCallback(
  IN EFI_EVENT Event,
  IN VOID *Context
  );

/**
  Load settings and start Remote Config Protocol connection via TCP/TLS
  Before starting make nonevident Stop() if currently running service is in error state
  
  @param  param                   desc
  
  @retval EFI_INVALID_PARAMETER   Settings not found/incorrect settings
  @retval EFI_NOT_FOUND           Can't locate RemoteCfgPkt/TCP/DNS protocols/OpenSSL certificates/keys/etc
  @retval EFI_OUT_OF_RESOURCES    Cannot allocate memory for internal structures
  @retval EFI_UNSUPPORTED         Service disabled
  @retval EFI_LOAD_ERROR          RemoteCfgPkt/TCP protocol initiliazing error
  @retval EFI_NO_MAPPING          Can't DNS resolve server name/Incorrect server IP address
  @retval EFI_ABORTED             Error occured
  @retval EFI_ALREADY_STARTED     Service already started
  @retval EFI_SUCCESS             Succesfully started
**/
EFI_STATUS
EFIAPI
RemoteCfgTlsStart(
  IN REMOTE_CFG_TLS_PROTOCOL *This
  );

/**
  Stop Remote Config Protocol connection
  
  @param  param                   desc
  
  @retval EFI_ABORTED             Error occured
  @retval EFI_SUCCESS             Succesfully started
**/
EFI_STATUS
EFIAPI
RemoteCfgTlsStop(
  IN REMOTE_CFG_TLS_PROTOCOL *This
  );

/**
  Return current status of connection.
  Make nonevident Stop() if service is in error state
  
  @param  param                   desc
  
  Halt errors(service can't run):
  @retval EFI_INVALID_PARAMETER   Settings not found/incorrect settings
  @retval EFI_NOT_FOUND           Can't locate RemoteCfgPkt/TCP protocols/OpenSSL certificates/keys/etc
  @retval EFI_OUT_OF_RESOURCES    Cannot allocate memory/resources for internal structures
  @retval EFI_LOAD_ERROR          RemoteCfgPkt/TCP protocol initiliazing/destroying error
  @retval EFI_UNSUPPORTED         Service disabled
  @retval EFI_ABORTED             Error occured

  Retry attempt(service autorestart):
  @retval EFI_DEVICE_ERROR        TCP protocol error
  @retval EFI_PROTOCOL_ERROR      RemoteCfgPkt protocol error
  @retval EFI_TIMEOUT             Service restarted by timeout
  @retval EFI_NO_MAPPING          Can't DNS resolve server name/Incorrect server IP address

  End of attempts(service autostop):
  @retval EFI_NO_RESPONSE         Connect failed - max number of connect attempts reached

  No error:
  @retval EFI_NOT_STARTED         Not running now
  @retval EFI_ALREADY_STARTED     Succesfully started
  @retval EFI_NOT_READY           Succesfully started and start connecting
  @retval EFI_SUCCESS             Succesfully started and connected
**/
EFI_STATUS
EFIAPI
RemoteCfgTlsGetCurrentStatus(
  IN REMOTE_CFG_TLS_PROTOCOL *This
  );

#endif /*__REMOTE__CFG_TLS__DXE__H*/
