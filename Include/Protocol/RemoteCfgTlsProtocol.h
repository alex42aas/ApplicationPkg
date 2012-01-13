/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __REMOTE__CFG__TLS__PROTOCOL__H
#define __REMOTE__CFG__TLS__PROTOCOL__H

#include <Uefi.h>
#include <Library/BaseLib.h>

typedef struct _REMOTE_CFG_TLS_PROTOCOL REMOTE_CFG_TLS_PROTOCOL;

//check for no error
#define REMOTE_CFG_TLS_GOOG_STATUS(Status)                            \
      /*in restarting*/           ((Status) == EFI_DEVICE_ERROR ||    \
                                  (Status) == EFI_PROTOCOL_ERROR ||   \
                                  (Status) == EFI_TIMEOUT        ||   \
                                  (Status) == EFI_NO_MAPPING     ||   \
      /*inactive state(no error)*/(Status) == EFI_NOT_STARTED ||      \
      /*in normal state*/         (Status) == EFI_ALREADY_STARTED ||  \
                                  (Status) == EFI_NOT_READY ||        \
                                  (Status) == EFI_SUCCESS)
//check for running now
#define REMOTE_CFG_TLS_RUNNING_STATUS(Status)                            \
      /*in restarting*/              ((Status) == EFI_DEVICE_ERROR ||    \
                                     (Status) == EFI_PROTOCOL_ERROR ||   \
                                     (Status) == EFI_TIMEOUT        ||   \
                                     (Status) == EFI_NO_MAPPING     ||   \
      /*in normal state*/            (Status) == EFI_ALREADY_STARTED ||  \
                                     (Status) == EFI_NOT_READY ||        \
                                     (Status) == EFI_SUCCESS)

#define REMOTE_CFG_TLS_FLAGS_SERVICE_ENABLED        (1 << 0)

#define REMOTE_CFG_USE_TLS_1_0              10
#define REMOTE_CFG_USE_TLS_1_1              11
#define REMOTE_CFG_USE_TLS_1_2              12
#if 0 //for debugging
#define REMOTE_CFG_USE_NO_CRYPTO            12345
#endif

#define REMOTE_CFG_TLS_TIMEOUT_OFF          0
#define REMOTE_CFG_TLS_TIMEOUT_MIN          10
#define REMOTE_CFG_TLS_TIMEOUT_CMAX         75//TCP stack realization limitation
//#define REMOTE_CFG_TLS_TIMEOUT_EMAX         (60*10)//something rational
#define REMOTE_CFG_TLS_TIMEOUT_EMAX         0x7FFFFFFF//max signed 32bit value - ini file parser limitation

#define REMOTE_CFG_TLS_ATTEMPTS_INFINITE    0
#define REMOTE_CFG_TLS_ATTEMPTS_MIN         1
#define REMOTE_CFG_TLS_ATTEMPTS_MAX         0x7FFFFFFF//max signed 32bit value - ini file parser limitation

#define REMOTE_CFG_TLS_PORT_MIN             1
#define REMOTE_CFG_TLS_PORT_MAX             65535

typedef struct _REMOTE_CFG_TLS_SETTINGS{
  UINT32 Length; //actual whole structure length
  UINT32 Flags;
  UINT32 TlsVersion;
  UINT32 TimeoutConnect;
  UINT32 TimeoutExchange;
  UINT32 Attempts;
  UINT16 Port;
  UINT32 ServerNameLen; //length without '\0' char
  CHAR8  ServerName[1]; //must contain ending '\0'
}REMOTE_CFG_TLS_SETTINGS;

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
typedef
EFI_STATUS
(EFIAPI *REMOTE_CFG_TLS_START)(
  IN REMOTE_CFG_TLS_PROTOCOL *This
  );

/**
  Stop Remote Config Protocol connection
  
  @param  param                   desc
  
  @retval EFI_ABORTED             Error occured
  @retval EFI_SUCCESS             Succesfully stopped
**/
typedef
EFI_STATUS
(EFIAPI *REMOTE_CFG_TLS_STOP)(
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

  Not error:
  @retval EFI_NOT_STARTED         Not running now
  @retval EFI_ALREADY_STARTED     Succesfully started
  @retval EFI_NOT_READY           Succesfully started and start connecting
  @retval EFI_SUCCESS             Succesfully started and connected
**/
typedef
EFI_STATUS
(EFIAPI *REMOTE_CFG_TLS_GET_CURRENT_STATUS)(
  IN REMOTE_CFG_TLS_PROTOCOL *This
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
typedef
EFI_STATUS
(EFIAPI *REMOTE_CFG_TLS_GET_SETTINGS)(
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
typedef
EFI_STATUS
(EFIAPI *REMOTE_CFG_TLS_SET_SETTINGS)(
  IN REMOTE_CFG_TLS_PROTOCOL *This,
  IN REMOTE_CFG_TLS_SETTINGS* RCTSettings
  );

struct _REMOTE_CFG_TLS_PROTOCOL {
  REMOTE_CFG_TLS_START                Start;
  REMOTE_CFG_TLS_STOP                 Stop;
  REMOTE_CFG_TLS_GET_CURRENT_STATUS   GetCurrentStatus;
  REMOTE_CFG_TLS_GET_SETTINGS         GetSettings;
  REMOTE_CFG_TLS_SET_SETTINGS         SetSettings;
};

extern EFI_GUID gRemoteCfgTlsProtocolGuid;

#endif /* #ifndef __REMOTE__CFG__TLS__PROTOCOL__H */
