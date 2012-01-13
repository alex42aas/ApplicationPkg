/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#include "RemoteCfgTlsDxe.h"

#if 1
#define LOG(MSG)
#else
#define LOG(MSG)            DEBUG(MSG)
#endif

CHAR8 RemoteCfgTlsConfigSectionName[] = "RemoteCfgTlsConfig";

STATIC CHAR8 EnabledKey[]         = "ServiceEnabled";
STATIC CHAR8 TlsVersionKey[]      = "TLSVersion";
STATIC CHAR8 ConnectTimeoutKey[]  = "ConnectingTimeout";
STATIC CHAR8 ExchangeTimeoutKey[] = "ExchangingTimeout";
STATIC CHAR8 AttemptsKey[]        = "ServiceRunAttempts";
STATIC CHAR8 PortKey[]            = "RemotePort";
STATIC CHAR8 AddressKey[]         = "RemoteAddress";

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
  )
{
  EFI_STATUS Status;
  CERTIFICATE_STORAGE *TmpStorage = NULL;

  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (StorageName == NULL || StorageGuid == NULL || StorageBuf == NULL || StorageLen == NULL) {
    LOG ((EFI_D_ERROR, "%a.%d StorageName == 0x%X, StorageGuid == 0x%X, StorageBuf == 0x%X, StorageLen == 0x%X\n", 
      __FUNCTION__, __LINE__, StorageName, StorageGuid, StorageBuf, StorageLen));
    return EFI_INVALID_PARAMETER;
  }

  *StorageBuf = NULL;
  *StorageLen = 0;

  Status = CertStorageLibGetData(StorageName, StorageGuid, CS_TYPE_GOST, &TmpStorage);
  if (EFI_ERROR(Status) || TmpStorage == NULL) {
    LOG ((EFI_D_ERROR, "%a.%d CertStorageLibGetData(): Status == %r\n", __FUNCTION__, __LINE__, Status));
    LOG ((EFI_D_ERROR, "%a.%d CertStorageLibGetData(): StorageName == %s\n", __FUNCTION__, __LINE__, StorageName));
    LOG ((EFI_D_ERROR, "%a.%d CertStorageLibGetData(): StorageGuid == %g\n", __FUNCTION__, __LINE__, StorageGuid));
    return EFI_NOT_FOUND;
  }
  *StorageLen = TmpStorage->DataLen;
  *StorageBuf = AllocatePool(*StorageLen);
  if (*StorageBuf == NULL) {
    LOG ((EFI_D_ERROR, "%a.%d AllocatePool(): StorageBuf == 0x%X\n", __FUNCTION__, __LINE__, *StorageBuf));
    FreePool(TmpStorage);
    *StorageLen = 0;
    return EFI_OUT_OF_RESOURCES;
  }
  CopyMem(*StorageBuf, TmpStorage->Data, *StorageLen);
  FreePool(TmpStorage);

  return EFI_SUCCESS;
}

/**
  Init FsUtils device mapping
**/
VOID
EFIAPI
InitFsUtils(
  IN EFI_HANDLE ImageHandle
  )
{
  STATIC BOOLEAN IsAlreadyInit = FALSE;

  EFI_STATUS Status;
  EFI_LOADED_IMAGE_PROTOCOL *ImageInfo;
  EFI_DEVICE_PATH_PROTOCOL *pDp;
  CHAR16 *PathString;
  int Result;

  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (!IsAlreadyInit) {
    Result = AllocFsDescTable(10);
    if (Result == -1) {
      LOG ((EFI_D_ERROR, "%a.%d AllocFsDescTable(): Result == %d\n", __FUNCTION__, __LINE__, Result));
      return;
    }

    Status = gBS->HandleProtocol(ImageHandle,  
                                 &gEfiLoadedImageProtocolGuid, 
                                 (VOID **)&ImageInfo);
    if (EFI_ERROR(Status)) {
      LOG ((EFI_D_ERROR, "%a.%d HandleProtocol(): Status = %r\n", __FUNCTION__, __LINE__, Status));
      return;
    }
    pDp = DevicePathFromHandle(ImageInfo->DeviceHandle);
    if (pDp == NULL) {
      LOG ((EFI_D_ERROR, "%a.%d DevicePathFromHandle(): pDp = 0x%X\n", __FUNCTION__, __LINE__, pDp));
      return;
    }

    PathString = DevPathToString(pDp, FALSE, TRUE);
    LOG ((EFI_D_ERROR, "-*-> %S\n", PathString));
    Result = AddFsDescTableItem(L"fv", PathString, FALSE);
    FreePool(PathString);
    if (Result == -1) {
      LOG ((EFI_D_ERROR, "%a.%d AddFsDescTableItem(): Result == %d\n", __FUNCTION__, __LINE__, Result));
      return;
    }
  }

  IsAlreadyInit = TRUE;
  return;
}

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
  )
{
  EFI_STATUS Status;
  EFI_FILE_HANDLE File;

  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (FileName == NULL || FileBuf == NULL || FileLen == NULL) {
    LOG ((EFI_D_ERROR, "%a.%d FileName == 0x%X, FileBuf == 0x%X, FileLen == 0x%X\n", 
      __FUNCTION__, __LINE__, FileName, FileBuf, FileLen));
    return EFI_INVALID_PARAMETER;
  }

  *FileBuf = NULL;
  *FileLen = 0;

  File = LibFsOpenFile(FileName, EFI_FILE_MODE_READ, 0);
  if (File == NULL) {
    LOG ((EFI_D_ERROR, "%a.%d LibFsOpenFile(): File == 0x%X\n", __FUNCTION__, __LINE__, File));
    return EFI_NOT_FOUND;
  }
  *FileLen = LibFsSizeFile(File);
  *FileBuf = AllocatePool(*FileLen);
  if (*FileBuf == NULL) {
    LOG ((EFI_D_ERROR, "%a.%d AllocatePool(): FileBuf == 0x%X\n", __FUNCTION__, __LINE__, *FileBuf));
    *FileLen = 0;
    return EFI_OUT_OF_RESOURCES;
  }
  Status = LibFsReadFile(File, FileLen, *FileBuf);
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_ERROR, "%a.%d LibFsReadFile(): Status = %r\n", __FUNCTION__, __LINE__, Status));
    FreePool(*FileBuf);
    *FileLen = 0;
    return EFI_NOT_FOUND;
  }

  return EFI_SUCCESS;
}


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
  )
{
  BOOLEAN IsServiceEnabled;
  UINTN ServerNameLen;

  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (RCTSettings == NULL) {
    LOG ((EFI_D_ERROR, "%a.%d RCTSettings = 0x%Xn", __FUNCTION__, __LINE__, RCTSettings));
    return EFI_INVALID_PARAMETER;
  }

  if (RCTSettings->Length < sizeof(REMOTE_CFG_TLS_SETTINGS)) {
    LOG ((EFI_D_ERROR, "%a.%d RCTSettings->Length = %d\n", __FUNCTION__, __LINE__, RCTSettings->Length));
    return EFI_VOLUME_CORRUPTED;
  }
  if (RCTSettings->Length != (sizeof(REMOTE_CFG_TLS_SETTINGS) + RCTSettings->ServerNameLen)) {
    LOG ((EFI_D_ERROR, "%a.%d RCTSettings->Length = %d\n", __FUNCTION__, __LINE__, RCTSettings->Length));
    LOG ((EFI_D_ERROR, "%a.%d RCTSettings->ServerNameLen = %d\n", __FUNCTION__, __LINE__, RCTSettings->ServerNameLen));
    return EFI_VOLUME_CORRUPTED;
  }
  if ((RCTSettings->Flags & REMOTE_CFG_TLS_FLAGS_SERVICE_ENABLED) != 0) {
    IsServiceEnabled = TRUE;
  } else {
    IsServiceEnabled = FALSE;
  }
  if (IsServiceEnabled) {//check other settings only if service enabled
    if (RCTSettings->TlsVersion != REMOTE_CFG_USE_TLS_1_0 &&
        RCTSettings->TlsVersion != REMOTE_CFG_USE_TLS_1_1 &&
        RCTSettings->TlsVersion != REMOTE_CFG_USE_TLS_1_2
#ifdef REMOTE_CFG_USE_NO_CRYPTO
        && RCTSettings->TlsVersion != REMOTE_CFG_USE_NO_CRYPTO
#endif
        ) {
      LOG ((EFI_D_ERROR, "%a.%d RCTSettings->TlsVersion = %d\n", __FUNCTION__, __LINE__, RCTSettings->TlsVersion));
      return EFI_VOLUME_CORRUPTED;
    }
    if ((RCTSettings->TimeoutConnect > REMOTE_CFG_TLS_TIMEOUT_CMAX ||
        RCTSettings->TimeoutConnect < REMOTE_CFG_TLS_TIMEOUT_MIN) &&
        RCTSettings->TimeoutConnect != REMOTE_CFG_TLS_TIMEOUT_OFF) {
      LOG ((EFI_D_ERROR, "%a.%d RCTSettings->TimeoutConnect = %d\n", __FUNCTION__, __LINE__, RCTSettings->TimeoutConnect));
      return EFI_VOLUME_CORRUPTED;
    }
    if ((RCTSettings->TimeoutExchange > REMOTE_CFG_TLS_TIMEOUT_EMAX ||
        RCTSettings->TimeoutExchange < REMOTE_CFG_TLS_TIMEOUT_MIN) &&
        RCTSettings->TimeoutExchange != REMOTE_CFG_TLS_TIMEOUT_OFF) {
      LOG ((EFI_D_ERROR, "%a.%d RCTSettings->TimeoutExchange = %d\n", __FUNCTION__, __LINE__, RCTSettings->TimeoutExchange));
      return EFI_VOLUME_CORRUPTED;
    }
    if ((RCTSettings->Attempts > REMOTE_CFG_TLS_ATTEMPTS_MAX ||
        RCTSettings->Attempts < REMOTE_CFG_TLS_ATTEMPTS_MIN) &&
        RCTSettings->Attempts != REMOTE_CFG_TLS_ATTEMPTS_INFINITE) {
      LOG ((EFI_D_ERROR, "%a.%d RCTSettings->Attempts = %d\n", __FUNCTION__, __LINE__, RCTSettings->Attempts));
      return EFI_VOLUME_CORRUPTED;
    }
    if (RCTSettings->Port == 0) {
      LOG ((EFI_D_ERROR, "%a.%d RCTSettings->Port = %d\n", __FUNCTION__, __LINE__, RCTSettings->Port));
      return EFI_VOLUME_CORRUPTED;
    }
    if (RCTSettings->ServerName[RCTSettings->ServerNameLen] != '\0') {//check for ending '\0'
      LOG ((EFI_D_ERROR, "%a.%d RCTSettings->ServerName[RCTSettings->ServerNameLen = %d] = %d\n", 
        __FUNCTION__, __LINE__, RCTSettings->ServerNameLen, RCTSettings->ServerName[RCTSettings->ServerNameLen]));
      return EFI_VOLUME_CORRUPTED;
    }
    ServerNameLen = AsciiStrLen(RCTSettings->ServerName);
    if (ServerNameLen != RCTSettings->ServerNameLen) {
      LOG ((EFI_D_ERROR, "%a.%d RCTSettings->ServerName = %a\n", __FUNCTION__, __LINE__, RCTSettings->ServerName));
      return EFI_VOLUME_CORRUPTED;
    }
  }

  return EFI_SUCCESS;
}

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
  )
{
  EFI_STATUS Status;
  UINTN SettingsLength;
  REMOTE_CFG_TLS_SETTINGS* Settings = NULL;

  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (RCTSettings == NULL) {
    LOG ((EFI_D_ERROR, "%a.%d RCTSettings = 0x%X\n", __FUNCTION__, __LINE__, RCTSettings));
    return EFI_INVALID_PARAMETER;
  }

  *RCTSettings = NULL;

  SettingsLength = 0;
  Status = gRT->GetVariable(REMOTE_CFG_TLS_CONFIG_VAR, 
                            &gRemoteCfgTlsConfigVarGuid, 
                            NULL,
                            &SettingsLength,
                            NULL);
  if (Status == EFI_BUFFER_TOO_SMALL) {
    if (SettingsLength >= sizeof(REMOTE_CFG_TLS_SETTINGS)) {
      //all ok
    } else {
      LOG ((EFI_D_ERROR, "%a.%d GetVariable(): SettingsLength = %d\n", __FUNCTION__, __LINE__, SettingsLength));
      return EFI_VOLUME_CORRUPTED;
    }
  } else if (Status == EFI_NOT_FOUND) {
    LOG ((EFI_D_ERROR, "%a.%d GetVariable(): Status = %r\n", __FUNCTION__, __LINE__, Status));
    return EFI_NOT_FOUND;
  } else {
    LOG ((EFI_D_ERROR, "%a.%d GetVariable(): Status = %r\n", __FUNCTION__, __LINE__, Status));
    return EFI_VOLUME_CORRUPTED;
  }

  Settings = AllocatePool(SettingsLength);
  if (Settings == NULL) {
    LOG ((EFI_D_ERROR, "%a.%d AllocatePool(): Settings = 0x%X\n", __FUNCTION__, __LINE__, Settings));
    return EFI_OUT_OF_RESOURCES;
  }
  Status = gRT->GetVariable(REMOTE_CFG_TLS_CONFIG_VAR, 
                            &gRemoteCfgTlsConfigVarGuid, 
                            NULL,
                            &SettingsLength,
                            Settings);
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_ERROR, "%a.%d GetVariable(): Status = %r\n", __FUNCTION__, __LINE__, Status));
    return EFI_VOLUME_CORRUPTED;
  }
  if (SettingsLength != Settings->Length) {
    LOG ((EFI_D_ERROR, "%a.%d SettingsLength = %d\n", __FUNCTION__, __LINE__, SettingsLength));
    LOG ((EFI_D_ERROR, "%a.%d Settings->Length = %d\n", __FUNCTION__, __LINE__, Settings->Length));
    FreePool(Settings);
    return EFI_VOLUME_CORRUPTED;
  }
  
  Status = RemoteCfgTlsValidateSettings(Settings);
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_ERROR, "%a.%d Status = %r\n", __FUNCTION__, __LINE__, Status));
    FreePool(Settings);
    return EFI_VOLUME_CORRUPTED;
  }

  *RCTSettings = Settings;

  return EFI_SUCCESS;
}

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
  )
{
  EFI_STATUS Status, HHStatus;
  HISTORY_HANDLER_PROTOCOL *HistoryHandlerProtocol;

  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (RCTSettings == NULL) {
    LOG ((EFI_D_ERROR, "%a.%d RCTSettings = 0x%X\n", __FUNCTION__, __LINE__, RCTSettings));
    Status = EFI_INVALID_PARAMETER;
    goto _log_exit;
  }

  Status = RemoteCfgTlsValidateSettings(RCTSettings);
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_ERROR, "%a.%d Status = %r\n", __FUNCTION__, __LINE__, Status));
    Status = EFI_VOLUME_CORRUPTED;
    goto _log_exit;
  }

  Status = gRT->SetVariable(REMOTE_CFG_TLS_CONFIG_VAR, 
                            &gRemoteCfgTlsConfigVarGuid, 
                            (EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS),
                            RCTSettings->Length,
                            RCTSettings);
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_ERROR, "%a.%d Status = %r\n", __FUNCTION__, __LINE__, Status));
    Status = EFI_WRITE_PROTECTED;
    goto _log_exit;
  }

  Status = EFI_SUCCESS;

_log_exit:
  HHStatus = gBS->LocateProtocol(&gHistoryHandlerProtocolGuid, 
                                 NULL, 
                                 (VOID **)&HistoryHandlerProtocol);
  if (HHStatus == EFI_SUCCESS && HistoryHandlerProtocol != NULL) {
    HistoryHandlerProtocol->AddRecord(HistoryHandlerProtocol,
                                      HEVENT_REMOTE_CFG_TLS_CFG_CHANGE, 
                                      EFI_ERROR(Status) ? SEVERITY_LVL_ERROR : SEVERITY_LVL_INFO,
                                      EFI_ERROR(Status) ? 0 : HISTORY_RECORD_FLAG_RESULT_OK);
  } else {
    LOG ((EFI_D_ERROR, "%a.%d LocateProtocol(): HHStatus = %r\n", __FUNCTION__, __LINE__, HHStatus));
    LOG ((EFI_D_ERROR, "%a.%d LocateProtocol(): HistoryHandlerProtocol = 0x%X\n", __FUNCTION__, __LINE__, HistoryHandlerProtocol));
  }
  return Status;
}

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
  )
{
  EFI_STATUS Status;
  REMOTE_CFG_TLS_SETTINGS* Settings = NULL;
  CHAR8 *Server = REMOTE_CFG_TLS_DEFAULT_SERVER;
  UINT32 ServerLen;

  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  ServerLen = (UINT32)AsciiStrLen(Server);
  Settings = AllocateZeroPool(sizeof(REMOTE_CFG_TLS_SETTINGS) + ServerLen);
  if (Settings == NULL) {
    LOG ((EFI_D_ERROR, "%a.%d AllocatePool(): Settings = 0x%X\n", __FUNCTION__, __LINE__, Settings));
    return EFI_OUT_OF_RESOURCES;
  }
  Settings->Length = (UINT32)(sizeof(REMOTE_CFG_TLS_SETTINGS) + ServerLen);
  if (REMOTE_CFG_TLS_DEFAULT_ENABLED) {
    Settings->Flags |= REMOTE_CFG_TLS_FLAGS_SERVICE_ENABLED;
  } else {
    Settings->Flags &= (~REMOTE_CFG_TLS_FLAGS_SERVICE_ENABLED);
  }
  Settings->TlsVersion = REMOTE_CFG_TLS_DEFAULT_TLS_VERSION;
  Settings->TimeoutConnect = REMOTE_CFG_TLS_DEFAULT_CTIMEOUT;
  Settings->TimeoutExchange = REMOTE_CFG_TLS_DEFAULT_ETIMEOUT;
  Settings->Attempts = REMOTE_CFG_TLS_DEFAULT_ATTEMPTS;
  Settings->Port = REMOTE_CFG_TLS_DEFAULT_PORT;
  Settings->ServerNameLen = ServerLen;
  AsciiStrnCpy(Settings->ServerName, 
               Server, 
               Settings->ServerNameLen + sizeof(Settings->ServerName[0]));//with ending '\0'

  Status = RemoteCfgTlsSetSettings(This, Settings);
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_ERROR, "%a.%d RemoteCfgTlsResetSettings(): Status = %r\n", __FUNCTION__, __LINE__, Status));
    return EFI_WRITE_PROTECTED;
  }

  FreePool(Settings);
  return EFI_SUCCESS;
}

/**
  Reset Remote Config Protocol settings from INI file
  
  @retval EFI_OUT_OF_RESOURCES    Not enough memory
  @retval EFI_NOT_FOUND           INI file not found/INI section not found/INI parser protocol not found
  @retval EFI_VOLUME_CORRUPTED    INI file has invalid settings
  @retval EFI_WRITE_PROTECTED     Cannot reset settings
  @retval EFI_ABORTED             Error occured
  @retval EFI_SUCCESS             Succesfully started
**/
EFI_STATUS
EFIAPI
RemoteCfgTlsResetSettingsFromINI(
  IN REMOTE_CFG_TLS_PROTOCOL *This
  )
{
  EFI_STATUS Status;
  CONFIG_ERROR_T CfgStatus;
  INI_PARSER_PROTOCOL *IniPP = NULL;
  dictionary *Dict;
  CHAR8 Fname[256];
  UINT8 *FileData;
  UINTN FileDataLen;

  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  Status = gBS->LocateProtocol(&gIniParserDxeProtocolGuid, 
                               NULL, 
                               (VOID **)&IniPP);
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_ERROR, "%a.%d LocateProtocol(): Status = %r\n", __FUNCTION__, __LINE__, Status));
    return EFI_NOT_FOUND;
  }
    
  AsciiSPrint(Fname, sizeof(Fname), "fv:%g", PcdGetPtr(RemoteCfgTlsConfigFile));
  LOG((EFI_D_ERROR, "RemoteCfgTlsConfigFile: %a\n", Fname));
  Status = LoadFileDataInBuffer(Fname, &FileData, &FileDataLen);
  if (Status == EFI_NOT_FOUND) {
    LOG ((EFI_D_ERROR, "%a.%d LoadFileDataInBuffer(): Status = %r\n", __FUNCTION__, __LINE__, Status));
    return EFI_NOT_FOUND;
  } else if (Status == EFI_OUT_OF_RESOURCES) {
    LOG ((EFI_D_ERROR, "%a.%d LoadFileDataInBuffer(): Status = %r\n", __FUNCTION__, __LINE__, Status));
    return EFI_OUT_OF_RESOURCES;
  } else if (EFI_ERROR(Status)) {
    LOG ((EFI_D_ERROR, "%a.%d LoadFileDataInBuffer(): Status = %r\n", __FUNCTION__, __LINE__, Status));
    return EFI_ABORTED;
  } else {
    //all ok
  }

  Dict = IniPP->NewIniDictionaryWithData(FileData, FileDataLen);
  FreePool(FileData);
  if (Dict == NULL) {
    LOG ((EFI_D_ERROR, "%a.%d NewIniDictionaryWithData(): Dict = 0x%X\n", __FUNCTION__, __LINE__, Dict));
    return EFI_OUT_OF_RESOURCES;
  }

  CfgStatus = RemoteCfgTlsSetConfigFromDictionary(Dict);
  if (CfgStatus == SUCCESS_TO_SET_CONFIG) {
    Status = EFI_SUCCESS;
  } else {
    LOG ((EFI_D_ERROR, "%a.%d SetConfigFromDictionary(): CfgStatus = %d\n", __FUNCTION__, __LINE__, CfgStatus));
    if (CfgStatus == CANT_LOCATE_INI_PARSER_PROTOCOL || CfgStatus == NO_CONFIG_KEY) {
      Status = EFI_NOT_FOUND;
    } else if (CfgStatus == ERROR_OUT_OF_MEMORY) {
      Status = EFI_OUT_OF_RESOURCES;
    } else if (CfgStatus == UNSUPPORTED_KEY_VALUE || CfgStatus == UNSUPPORTED_SETTING_COMBINATION) {
      Status = EFI_VOLUME_CORRUPTED;
    } else if (CfgStatus == CANT_SAVE_CONFIG_TO_VARIABLE) {
      Status = EFI_WRITE_PROTECTED;
    } else {
      Status = EFI_ABORTED;
    }
  }

  IniPP->DeleteIniDictionary(Dict);

  return Status;
}

/**
  Reset Remote Config Protocol settings from INI file dictionary.
**/
CONFIG_ERROR_T
RemoteCfgTlsSetConfigFromDictionary (
  IN dictionary *Dict
  )
{
  EFI_STATUS Status;
  CONFIG_ERROR_T CfgStatus;
  INI_PARSER_PROTOCOL *IniPP = NULL;
  REMOTE_CFG_TLS_PROTOCOL* RCTP = NULL;
  REMOTE_CFG_TLS_SETTINGS* Settings = NULL;
  CHAR8 *StrVal = NULL;
  UINT32 StrValLen;
  INT32 IntVal;
  BOOLEAN IsServiceEnabled;
  CHAR8 *Server = REMOTE_CFG_TLS_DEFAULT_SERVER;
  UINT32 ServerLen;

  LOG ((EFI_D_INFO, "%a.%d\n", __FUNCTION__, __LINE__));

  if (Dict == NULL) {
    LOG ((EFI_D_ERROR, "%a.%d Dict = 0x%X\n", __FUNCTION__, __LINE__, Dict));
    return ERROR_INVALID_PARAMETER;
  }

  Status = gBS->LocateProtocol(&gIniParserDxeProtocolGuid, 
                               NULL, 
                               (VOID **)&IniPP);
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_ERROR, "%a.%d LocateProtocol(): Status = %r\n", __FUNCTION__, __LINE__, Status));
    return CANT_LOCATE_INI_PARSER_PROTOCOL;
  }
  Status = gBS->LocateProtocol(&gRemoteCfgTlsProtocolGuid,
                               NULL,
                               (VOID **)&RCTP);
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_ERROR, "%a.%d LocateProtocol(): Status = %r\n", __FUNCTION__, __LINE__, Status));
    return CANT_LOCATE_INI_PARSER_PROTOCOL;
  }

  if (!IniPP->CheckSecPresent(Dict, RemoteCfgTlsConfigSectionName)) {
    return NO_CONFIG_SECTION;
  }

  CfgStatus = NO_CONFIG_KEY;
  do {
    Status = RCTP->GetSettings(RCTP, &Settings);
    if (Status == EFI_NOT_FOUND || Status == EFI_VOLUME_CORRUPTED || Settings == NULL) {
      LOG ((EFI_D_ERROR, "%a.%d GetSettings(): Status = %r\n", __FUNCTION__, __LINE__, Status));
      ServerLen = (UINT32)AsciiStrLen(Server);
      Settings = AllocateZeroPool(sizeof(REMOTE_CFG_TLS_SETTINGS) + ServerLen);
      if (Settings == NULL) {
        LOG ((EFI_D_ERROR, "%a.%d AllocateZeroPool(): Settings = 0x%X\n", __FUNCTION__, __LINE__, Settings));
        CfgStatus = ERROR_OUT_OF_MEMORY;
        break;//goto _exit;
      }
      Settings->Length = (UINT32)(sizeof(REMOTE_CFG_TLS_SETTINGS) + ServerLen);
      Settings->ServerNameLen = 0;
      if (REMOTE_CFG_TLS_DEFAULT_ENABLED) {
        Settings->Flags |= REMOTE_CFG_TLS_FLAGS_SERVICE_ENABLED;
      } else {
        Settings->Flags &= (~REMOTE_CFG_TLS_FLAGS_SERVICE_ENABLED);
      }
      Settings->TlsVersion = REMOTE_CFG_TLS_DEFAULT_TLS_VERSION;
      Settings->TimeoutConnect = REMOTE_CFG_TLS_DEFAULT_CTIMEOUT;
      Settings->TimeoutExchange = REMOTE_CFG_TLS_DEFAULT_ETIMEOUT;
      Settings->Attempts = REMOTE_CFG_TLS_DEFAULT_ATTEMPTS;
      Settings->Port = REMOTE_CFG_TLS_DEFAULT_PORT;
      Settings->ServerNameLen = ServerLen;
      AsciiStrnCpy(Settings->ServerName, 
                    Server, 
                    Settings->ServerNameLen + sizeof(Settings->ServerName[0]));//with ending '\0'
    } else if (Status == EFI_OUT_OF_RESOURCES) {
      LOG ((EFI_D_ERROR, "%a.%d GetSettings(): Status = %r\n", __FUNCTION__, __LINE__, Status));
      CfgStatus = ERROR_OUT_OF_MEMORY;
      break;//goto _exit;
    } else if (EFI_ERROR(Status)) {
      LOG ((EFI_D_ERROR, "%a.%d GetSettings(): Status = %r\n", __FUNCTION__, __LINE__, Status));
      CfgStatus = CANT_READ_CONFIG_FROM_VARIABLE;
      break;//goto _exit;
    } else {
      //all ok
    }

    Status = IniPP->GetBoolean(Dict,
                               RemoteCfgTlsConfigSectionName,
                               EnabledKey,
                               &IsServiceEnabled);
    if (EFI_ERROR(Status)) {
      LOG ((EFI_D_ERROR, "%a.%d GetBoolean(): Status = %r\n", __FUNCTION__, __LINE__, Status));
      CfgStatus = NO_CONFIG_KEY;
      break;//goto _exit;
    } else {
      if (IsServiceEnabled) {
        Settings->Flags |= REMOTE_CFG_TLS_FLAGS_SERVICE_ENABLED;
      } else {
        Settings->Flags &= (~(REMOTE_CFG_TLS_FLAGS_SERVICE_ENABLED));
      }
    }

    if (IsServiceEnabled) {//load & check other settings only if service enabled
      Status = IniPP->GetInteger(Dict,
                                 RemoteCfgTlsConfigSectionName,
                                 TlsVersionKey,
                                 &IntVal);
      if (EFI_ERROR(Status)) {
        LOG ((EFI_D_ERROR, "%a.%d GetInteger(): Status = %r\n", __FUNCTION__, __LINE__, Status));
        CfgStatus = NO_CONFIG_KEY;
        break;//goto _exit;
      } else {
        if (IntVal < 0) {
          LOG ((EFI_D_ERROR, "%a.%d GetInteger(): IntVal = %d\n", __FUNCTION__, __LINE__, IntVal));
          CfgStatus = UNSUPPORTED_KEY_VALUE;
          break;//goto _exit;
        }
        Settings->TlsVersion = (UINT32)IntVal;
      }

      Status = IniPP->GetInteger(Dict,
                                 RemoteCfgTlsConfigSectionName,
                                 ConnectTimeoutKey,
                                 &IntVal);
      if (EFI_ERROR(Status)) {
        LOG ((EFI_D_ERROR, "%a.%d GetInteger(): Status = %r\n", __FUNCTION__, __LINE__, Status));
        CfgStatus = NO_CONFIG_KEY;
        break;//goto _exit;
      } else {
        if (IntVal < 0) {
          LOG ((EFI_D_ERROR, "%a.%d GetInteger(): IntVal = %d\n", __FUNCTION__, __LINE__, IntVal));
          CfgStatus = UNSUPPORTED_KEY_VALUE;
          break;//goto _exit;
        }
        Settings->TimeoutConnect = (UINT32)IntVal;
      }
      Status = IniPP->GetInteger(Dict,
                                 RemoteCfgTlsConfigSectionName,
                                 ExchangeTimeoutKey,
                                 &IntVal);
      if (EFI_ERROR(Status)) {
        LOG ((EFI_D_ERROR, "%a.%d GetInteger(): Status = %r\n", __FUNCTION__, __LINE__, Status));
        CfgStatus = NO_CONFIG_KEY;
        break;//goto _exit;
      } else {
        if (IntVal < 0) {
          LOG ((EFI_D_ERROR, "%a.%d GetInteger(): IntVal = %d\n", __FUNCTION__, __LINE__, IntVal));
          CfgStatus = UNSUPPORTED_KEY_VALUE;
          break;//goto _exit;
        }
        Settings->TimeoutExchange = (UINT32)IntVal;
      }
      Status = IniPP->GetInteger(Dict,
                                 RemoteCfgTlsConfigSectionName,
                                 AttemptsKey,
                                 &IntVal);
      if (EFI_ERROR(Status)) {
        LOG ((EFI_D_ERROR, "%a.%d GetInteger(): Status = %r\n", __FUNCTION__, __LINE__, Status));
        CfgStatus = NO_CONFIG_KEY;
        break;//goto _exit;
      } else {
        if (IntVal < 0) {
          LOG ((EFI_D_ERROR, "%a.%d GetInteger(): IntVal = %d\n", __FUNCTION__, __LINE__, IntVal));
          CfgStatus = UNSUPPORTED_KEY_VALUE;
          break;//goto _exit;
        }
        Settings->Attempts = (UINT32)IntVal;
      }

      Status = IniPP->GetInteger(Dict,
                                 RemoteCfgTlsConfigSectionName,
                                 PortKey,
                                 &IntVal);
      if (EFI_ERROR(Status)) {
        LOG ((EFI_D_ERROR, "%a.%d GetInteger(): Status = %r\n", __FUNCTION__, __LINE__, Status));
        CfgStatus = NO_CONFIG_KEY;
        break;//goto _exit;
      } else {
        if (IntVal < REMOTE_CFG_TLS_PORT_MIN || IntVal > REMOTE_CFG_TLS_PORT_MAX) {
          LOG ((EFI_D_ERROR, "%a.%d GetInteger(): IntVal = %d\n", __FUNCTION__, __LINE__, IntVal));
          CfgStatus = UNSUPPORTED_KEY_VALUE;
          break;//goto _exit;
        }
        Settings->Port = (UINT16)IntVal;
      }
      StrVal = IniPP->GetString(Dict,
                                RemoteCfgTlsConfigSectionName,
                                AddressKey);
      if (StrVal == NULL) {
        LOG ((EFI_D_ERROR, "%a.%d GetString(): StrVal = 0x%X\n", __FUNCTION__, __LINE__, StrVal));
        CfgStatus = NO_CONFIG_KEY;
        break;//goto _exit;
      } else {
        StrValLen = (UINT32)AsciiStrLen(StrVal);
        if (StrValLen > Settings->ServerNameLen) {//realloc
          REMOTE_CFG_TLS_SETTINGS *SettingsNew;
          SettingsNew = AllocateZeroPool(sizeof(REMOTE_CFG_TLS_SETTINGS) + StrValLen);
          if (SettingsNew == NULL) {
            LOG ((EFI_D_ERROR, "%a.%d AllocateZeroPool(): SettingsNew = 0x%X\n", __FUNCTION__, __LINE__, SettingsNew));
            CfgStatus = ERROR_OUT_OF_MEMORY;
            break;//goto _exit;
          }
          CopyMem(SettingsNew, Settings, Settings->Length);
          FreePool(Settings);
          Settings = SettingsNew;
        }
        AsciiStrnCpy(Settings->ServerName, StrVal, StrValLen);
        Settings->ServerNameLen = StrValLen;
        Settings->Length = sizeof(REMOTE_CFG_TLS_SETTINGS) + StrValLen;
      }
    }

    Status = RCTP->SetSettings(RCTP, Settings);
    if (Status == EFI_VOLUME_CORRUPTED) {
      LOG ((EFI_D_ERROR, "%a.%d GetSettings(): Status = %r\n", __FUNCTION__, __LINE__, Status));
      CfgStatus = UNSUPPORTED_SETTING_COMBINATION;
      break;//goto _exit;
    } else if (EFI_ERROR(Status)) {
      LOG ((EFI_D_ERROR, "%a.%d GetSettings(): Status = %r\n", __FUNCTION__, __LINE__, Status));
      CfgStatus = CANT_SAVE_CONFIG_TO_VARIABLE;
      break;//goto _exit;
    } else {
      //all ok
      CfgStatus = SUCCESS_TO_SET_CONFIG;
    }
  } while (FALSE);
//_exit:
  if (Settings != NULL) {
    FreePool(Settings);
  }

  return CfgStatus;
}

STATIC
EFI_STATUS
SaveServiceEnabledToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict,
  IN REMOTE_CFG_TLS_SETTINGS *Settings
)
{
  EFI_STATUS Status = EFI_SUCCESS;

  if (Settings->Flags & REMOTE_CFG_TLS_FLAGS_SERVICE_ENABLED)
    Status = iniParserProtocol->SetBoolean(dict, RemoteCfgTlsConfigSectionName, EnabledKey, TRUE);
  else
    Status = iniParserProtocol->SetBoolean(dict, RemoteCfgTlsConfigSectionName, EnabledKey, FALSE);

  return Status;
}

STATIC
EFI_STATUS
SaveTLSVersionToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict,
  IN REMOTE_CFG_TLS_SETTINGS *Settings
)
{
  EFI_STATUS Status = EFI_SUCCESS;
  Status = iniParserProtocol->SetInteger(dict, RemoteCfgTlsConfigSectionName,
                                TlsVersionKey, Settings->TlsVersion);
  return Status;
}

STATIC
EFI_STATUS
SaveConnectingTimeoutToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict,
  IN REMOTE_CFG_TLS_SETTINGS *Settings
)
{
  EFI_STATUS Status = EFI_SUCCESS;
  Status = iniParserProtocol->SetInteger(dict, RemoteCfgTlsConfigSectionName,
                                ConnectTimeoutKey, Settings->TimeoutConnect);
  return Status;
}

STATIC
EFI_STATUS
SaveExchangingTimeoutToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict,
  IN REMOTE_CFG_TLS_SETTINGS *Settings
)
{
  EFI_STATUS Status = EFI_SUCCESS;
  Status = iniParserProtocol->SetInteger(dict, RemoteCfgTlsConfigSectionName,
                                ExchangeTimeoutKey, Settings->TimeoutExchange);
  return Status;
}

STATIC
EFI_STATUS
SaveServiceRunAttemptsToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict,
  IN REMOTE_CFG_TLS_SETTINGS *Settings
)
{
  EFI_STATUS Status = EFI_SUCCESS;
  Status = iniParserProtocol->SetInteger(dict, RemoteCfgTlsConfigSectionName,
                                AttemptsKey, Settings->Attempts);
  return Status;
}

STATIC
EFI_STATUS
SaveRemotePortToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict,
  IN REMOTE_CFG_TLS_SETTINGS *Settings
)
{
  EFI_STATUS Status = EFI_SUCCESS;
  Status = iniParserProtocol->SetInteger(dict, RemoteCfgTlsConfigSectionName,
                                PortKey, Settings->Port);
  return Status;
}

STATIC
EFI_STATUS
SaveRemoteAddressToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN OUT dictionary *dict,
  IN REMOTE_CFG_TLS_SETTINGS *Settings
)
{
  EFI_STATUS Status = EFI_SUCCESS;
  Status = iniParserProtocol->SetString(dict, RemoteCfgTlsConfigSectionName,
                                AddressKey, Settings->ServerName);
  return Status;
}

STATIC
CONFIG_ERROR_T
StoreRemoteCfgTlsConfigToDictionary (
  IN INI_PARSER_PROTOCOL *iniParserProtocol,
  IN dictionary *dict
)
{
  EFI_STATUS Status = EFI_SUCCESS;
  CONFIG_ERROR_T retval = SUCCESS_TO_SET_CONFIG;

  REMOTE_CFG_TLS_PROTOCOL *RCTP     = NULL;
  REMOTE_CFG_TLS_SETTINGS *Settings = NULL;

  Status = gBS->LocateProtocol(&gRemoteCfgTlsProtocolGuid,
                               NULL,
                               (VOID **)&RCTP);
  if (EFI_ERROR(Status)) {
    LOG ((EFI_D_ERROR, "%a.%d LocateProtocol(): Status = %r\n", __FUNCTION__, __LINE__, Status));
    return CANT_LOCATE_INI_PARSER_PROTOCOL;
  }

  Status = RemoteCfgTlsGetSettings(RCTP, &Settings);
  if (EFI_ERROR(Status) || Settings == NULL)
    return CANT_READ_CONFIG_FROM_VARIABLE;

  Status = SaveServiceEnabledToDictionary(iniParserProtocol, dict, Settings);
  if (EFI_ERROR(Status))
    retval = CANT_SAVE_CONFIG_TO_DICTIONARY;

  Status = SaveTLSVersionToDictionary(iniParserProtocol, dict, Settings);
  if (EFI_ERROR(Status))
    retval = CANT_SAVE_CONFIG_TO_DICTIONARY;

  Status = SaveConnectingTimeoutToDictionary(iniParserProtocol, dict, Settings);
  if (EFI_ERROR(Status))
    retval = CANT_SAVE_CONFIG_TO_DICTIONARY;

  Status = SaveExchangingTimeoutToDictionary(iniParserProtocol, dict, Settings);
  if (EFI_ERROR(Status))
    retval = CANT_SAVE_CONFIG_TO_DICTIONARY;

  Status = SaveServiceRunAttemptsToDictionary(iniParserProtocol, dict, Settings);
  if (EFI_ERROR(Status))
    retval = CANT_SAVE_CONFIG_TO_DICTIONARY;

  Status = SaveRemotePortToDictionary(iniParserProtocol, dict, Settings);
  if (EFI_ERROR(Status))
    retval = CANT_SAVE_CONFIG_TO_DICTIONARY;

  Status = SaveRemoteAddressToDictionary(iniParserProtocol, dict, Settings);
  if (EFI_ERROR(Status))
    retval = CANT_SAVE_CONFIG_TO_DICTIONARY;

  if (Settings != NULL)
    FreePool(Settings);

  return retval;
}

/**
  Store Remote Config Protocol settings to INI file dictionary.
**/
CONFIG_ERROR_T
DumpRemoteCfgTlsToDictionary (
  IN dictionary *dict
)
{
  CONFIG_ERROR_T status;
  INI_PARSER_PROTOCOL *iniParserProtocol = NULL;

  if (dict == NULL)
    return ERROR_INVALID_PARAMETER;

  if (gBS->LocateProtocol (
             &gIniParserDxeProtocolGuid,
             NULL,
             (VOID **) &iniParserProtocol
             ) != EFI_SUCCESS)
    return CANT_LOCATE_INI_PARSER_PROTOCOL;

  status = StoreRemoteCfgTlsConfigToDictionary(iniParserProtocol, dict);

  return status;
}

