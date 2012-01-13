/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __HISTORY__H
#define __HISTORY__H


#include <Library/CommonUtils.h>
#include <Guid/MdeModuleHii.h>
#include <Protocol/HiiConfigAccess.h>
#include <Library/ExtHdrUtils.h>
#include <Library/VarStorageUtils.h>
#include <Library/VfrCommon.h>
#include <Library/FsUtils.h>
#include <Library/MultibootDescUtils.h>
#include "vfrdata.h"


/*

*/


#define HISTORY_STORAGE_CS_TYPE             (CS_TYPE_CRC32)
#define HISTORY_STORAGE_VAR_NAME            L"HistoryStorage"
#define HISTORY_STORAGE_VAR_NAME_WITH_NUM   L"HistoryStorage_00000000"
#define HISTORY_STORAGE_MAX_NAME_LEN        (sizeof(HISTORY_STORAGE_VAR_NAME_WITH_NUM))

#define HISTORY_MAX_CARD_SIZE               (PcdGet32(PcdMaxVariableSize) - sizeof (VARIABLE_HEADER) - HISTORY_STORAGE_MAX_NAME_LEN)

#define HISTORY_STRING_LEN                  1024
#define HISTORY_RECORD_SIZE                 13
#define HISTORY_RECORDS_AMOUNT              500
#define HISTORY_SIZE                        (HISTORY_RECORDS_AMOUNT * \
                                             HISTORY_RECORD_SIZE)
#define SEVERITY_LVL_EMERGENCY              (1 << 0)
#define SEVERITY_LVL_ALERT                  (1 << 1)
#define SEVERITY_LVL_CRITICAL               (1 << 2)
#define SEVERITY_LVL_ERROR                  (1 << 3)
#define SEVERITY_LVL_WARNING                (1 << 4)
#define SEVERITY_LVL_NOTICE                 (1 << 5)
#define SEVERITY_LVL_INFO                   (1 << 6)
#define SEVERITY_LVL_DEBUG                  (1 << 7)

#define SEVERITY_LVL_DEFAULT                (SEVERITY_LVL_INFO | \
      SEVERITY_LVL_NOTICE | SEVERITY_LVL_WARNING | SEVERITY_LVL_ERROR | \
      SEVERITY_LVL_CRITICAL | SEVERITY_LVL_ALERT | SEVERITY_LVL_EMERGENCY)

//#define FLAG_OVERWRITE_DELETED              (1 << 0)

/* used for search mask */
#define HISTORY_FIELD_REC_ID                (1 << 0)
#define HISTORY_FIELD_TIME_STAMP            (1 << 1)
#define HISTORY_FIELD_EVENT_CODE            (1 << 2)
#define HISTORY_FIELD_USER_ID               (1 << 3)
#define HISTORY_FIELD_SEVERITY              (1 << 4)
#define HISTORY_FIELD_FLAGS                 (1 << 5)
#define HISTORY_SEARCH_BY_NUM               (1 << 7)


/* FLAGS */
#define HISTORY_FLAGS_AUTO_CLEAN_EN         (1 << 0)
#define HISTORY_FLAGS_OVERFLOW              (1 << 1)

#define HISTORY_MAX_LVL                     8

/* RECORD FLAGS */
#define HISTORY_RECORD_FLAG_CLEAN_EN        (1 << 0)
#define HISTORY_RECORD_FLAG_RESULT_OK       (1 << 1)
#define HISTORY_RECORD_FLAG_NO_REREAD       (1 << 2)


/* EVENT CODES */
#define HEVENT_USER_EXIT                    0x0001
#define HEVENT_USER_LOGIN                   0x0002
#define HEVENT_ADD_NEW_USER                 0x0003
#define HEVENT_DELETE_USER                  0x0004
#define HEVENT_LOAD_CA                      0x0005
#define HEVENT_LOAD_CRL                     0x0006
#define HEVENT_OUTSWAP_USERS_CARDS_TO_USB   0x0007
#define HEVENT_OUTSWAP_HISTORY_TO_USB       0x0008
#define HEVENT_FORCE_CHECK_INTEGRITY        0x0009
#define HEVENT_START_TO_LOAD_OS             0x000A
#define HEVENT_REGULAR_LOADING_MODE         0x000B
#define HEVENT_ADMIN_MODE                   0x000C
#define HEVENT_USER_UPDATE_DATA             0x000D
#define HEVENT_CHECK_MODULE                 0x000E
#define HEVENT_USERS_TO_CSV                 0x000F
#define HEVENT_ADMIN_MODE_EXIT              0x0010
#define HEVENT_CERT_MODE_ENTER              0x0011
#define HEVENT_CERT_MODE_EXIT               0x0012
#define HEVENT_USR_CTRL_MODE_ENTER          0x0013
#define HEVENT_USR_CTRL_MODE_EXIT           0x0014
#define HEVENT_DATE_TIME_MODE_ENTER         0x0015
#define HEVENT_DATE_TIME_MODE_EXIT          0x0016
#define HEVENT_RESET_SYSTEM                 0x0017
#define HEVENT_START_MEM_TEST               0x0018
#define HEVENT_ADM_MODE_EXIT                0x0019
#define HEVENT_TOKEN_EJECTED                0x001A
#define HEVENT_BIOS_UPDATE_MODE_ENTER       0x001B
#define HEVENT_BIOS_UPDATE_MODE_EXIT        0x001C
#define HEVENT_DAD_SETUP_MODE_ENTER         0x001D
#define HEVENT_DAD_SETUP_MODE_EXIT          0x001E
#define HEVENT_HISTORY_MENU_ENTER           0x001F
#define HEVENT_HISTORY_MENU_EXIT            0x0020
#define HEVENT_USR_PASS_CHANGE              0x0021
#define HEVENT_TOKEN_INSERT_NOTIFY          0x0022
#define HEVENT_USER_NAME_FAIL               0x0023
#define HEVENT_WRONG_PIN                    0x0024
#define HEVENT_NO_SUCH_USER                 0x0025
#define HEVENT_DEV_MANAGER_MODE_ENTER       0x0026
#define HEVENT_DEV_MANAGER_MODE_EXIT        0x0027

// LDAP Auth errors:

#define HEVENT_LDAP_CONNECT_ERROR           0x0028
#define HEVENT_LDAP_ROOT_ERR_CREDENTIALS    0x0029
#define HEVENT_CANT_PROC_LDAP_OPT           0x0030
#define HEVENT_CANT_INIT_LDAP_SESSION       0x0031
#define HEVENT_CANT_MAKE_REQUEST            0x0032
#define HEVENT_LDAP_AUTH_FAIL               0x0033
#define HEVENT_LDAP_SEARCH_ERROR            0x0034
#define HEVENT_LDAP_USER_ADD_ERROR          0x0035
#define HEVENT_LDAP_INTERNAL_ERROR          0x0036
#define HEVENT_LDAP_SERVER_DENY             0x0037
#define HEVENT_LDAP_TOO_MANY_USERS          0x0038
#define HEVENT_GUEST_AUTH_FAIL              0x0039
#define HEVENT_LDAP_TLS_CACERTFILE_EMPTY    0x003A
#define HEVENT_LDAP_TLS_CACERTFILE_FAIL     0x003B
#define HEVENT_LDAP_START_TLS               0x003C
#define HEVENT_LDAP_ERROR_TO_GET_PERMIT     0x003D

#define HEVENT_MAX_WRONG_PIN_REACHED        0x003E

// OpenSSL errors:

#define HEVENT_UNKNOWN_FORMAT_OF_CRL        0x003F
#define HEVENT_UNKNOWN_FORMAT_OF_CERT       0x0040
#define HEVENT_UNKNOWN_KEY_FORMAT           0x0041
#define HEVENT_ERR_CA_SIGN                  0x0042
#define HEVENT_ERR_CERT_REVOKED             0x0043
#define HEVENT_ERR_GET_CA_PUBKEY            0x0044
#define HEVENT_ERR_CRL_VERIFY               0x0045
#define HEVENT_PKCS7_NOT_SIGNED             0x0046
#define HEVENT_VERIFY_ERROR                 0x0047
#define HEVENT_ERROR_TO_LOAD_CRL            0x0048
#define HEVENT_ERROR_TO_LOAD_ISSUER_CERT    0x0049
#define HEVENT_ERROR_TO_LOAD_ISSUER_CERT_LOCALLY  0x004A
#define HEVENT_CANT_GET_TRUSTED_CERTS       0x004B
#define HEVENT_CERT_NOT_YET_VALID           0x004C
#define HEVENT_CERT_HAS_EXPIRED             0x004D
#define HEVENT_CRL_HAS_EXPIRED              0x004E
#define HEVENT_UNABLE_TO_GET_CRL            0x004F

#define HEVENT_BOOT_CFG_CHANGE              0x0050 // boot config save
#define HEVENT_BOOT_ICFL_CHANGE             0x0051 // boot integrity checking files list changed
#define HEVENT_PRIMARY_VIDEO_CHANGE         0x0052 // chipset config save
#define HEVENT_USB_LEGACY_SUPPORT_CHANGE    0x0053 // chipset config save
#define HEVENT_SATA_MODE_CHANGE             0x0054 // chipset config save  
#define HEVENT_LDAP_CFG_CHANGE              0x0055
#define HEVENT_IP4_CFG_CHANGE               0x0056
#define HEVENT_INIT_APMDZ                   0x0057
#define HEVENT_ISCSI_CFG_CHANGE             0x0058
#define HEVENT_VLAN_CFG_CHANGE              0x0059
#define HEVENT_PCI_DEVS_MONITOR_CFG_CHANGE  0x005A
#define HEVENT_HISTORY_SEVERITY_LVL_CHANGE  0x005B
#define HEVENT_HISTORY_AUTO_CLR_CHANGE      0x005C
#define HEVENT_QUICK_BOOT_START             0x005D
#define HEVENT_QUICK_BOOT_END               0x005E
#define HEVENT_REGULAR_BOOT                 0x005F
#define HEVENT_ADMIN_BOOT                   0x0060
#define HEVENT_RECOVER_BOOT                 0x0061
#define HEVENT_INSTALL_BOOT                 0x0062
#define HEVENT_BOOT_MNGR_IMPORT_OPT         0x0063
#define HEVENT_BOOT_MNGR_EXPORT_OPT         0x0064
#define HEVENT_REVOKE_CERTS_CFG_CHANGED     0x0065
#define HEVENT_AUTH_MODE_CFG_CHANGED        0x0066
#define HEVENT_EXT_NETWORK_CFG_CHANGED      0x0067

#define HEVENT_OCPS_URL_ERROR               0x0068
#define HEVENT_OCSP_RESPONSE_VERIFICATION   0x0069
#define HEVENT_OCSP_RESPONDER_QUERY_FAILED  0x006A
#define HEVENT_OCSP_CERT_UNKNOWN            0x006B
#define HEVENT_CDP_ERROR                    0x006C
#define HEVENT_ERR_INTERNAL                 0x006D
#define HEVENT_UNKNOWN_FORMAT_OF_CHAIN      0x006E
#define HEVENT_MULTIBOOT_START              0x006F
#define HEVENT_RESET_BIOS_TO_MII            0x0070
#define HEVENT_PCI_DEVS_MONITOR_FAIL        0x0071

#define HEVENT_ERROR_TO_SET_USER_DB         0x0072
#define HEVENT_REMOTE_ACCESS                0x0073
#define HEVENT_REMOTE_LOGIN                 0x0074

#define HEVENT_CDP_LDAP_CFG_CHANGE          0x0075
#define HEVENT_PASSWD_GUESSING              0x0076

#define HEVENT_PS2_PORT_CFG_CHANGE          0x0077 // chipset config save  
#define HEVENT_USB_PORT_CFG_CHANGE          0x0078 // chipset config save  
#define HEVENT_AMT_KBC_LOCK_CFG_CHANGE      0x0079 // chipset config save  
#define HEVENT_VGA_SUPPORT_CFG_CHANGE       0x007A

#define HEVENT_REMOTE_BIOS_UPDATE           0x007B
#define HEVENT_BIOS_UPDATE                  0x007C

#define HEVENT_UPD_USRS_LOCAL_DB_START      0x007D
#define HEVENT_UPD_USRS_LOCAL_CONNECT_ERR   0x007E
#define HEVENT_UPD_USRS_LOCAL_AUTH_ERR      0x007F
#define HEVENT_UPD_USRS_LOCAL_INT_ERR       0x0080
#define HEVENT_UPD_USRS_LOCAL_SUCCESS       0x0081

//RemoteCfgTlsDxe settings changed event
#define HEVENT_REMOTE_CFG_TLS_CFG_CHANGE    0x0082

#define HEVENT_CRL_REFRESH_START            0x0083
#define HEVENT_CRL_REFRESH_RESULT           0x0084

#define HEVENT_REMOTE_CHAIN_UPDATE          0x0085
#define HEVENT_REMOTE_CRL_UPDATE            0x0086
#define HEVENT_REMOTE_TLS_CERT_UPDATE       0x0087
#define HEVENT_REMOTE_TLS_PKEY_UPDATE       0x0088

#define HEVENT_REMOTE_BIOS_SUBSYSTEMS_CFG   0x0089

#define HEVENT_PCI_DEVS_MONITORING_ON       0x008A
#define HEVENT_PCI_DEVS_MONITORING_OFF      0x008B

#define HEVENT_DISABLE_SERIAL_CON_CHANGE    0x008C // chipset config save

#define HEVENT_USERS_FROM_LDAP_NON_EMPTY    0x008D
#define HEVENT_USERS_FROM_LDAP_PREPARE      0x008E
#define HEVENT_USERS_FROM_LDAP_ADD_TO_DB    0x008F

#define HEVENT_ERR_SAVING_TO_CERT_STORAGE   0x0090

#define HEVENT_USER_BLOCKED                 0x0091

#define HEVENT_PXE_OPROM_SWITCH_CHANGE    0x0092 // chipset config save
#define HEVENT_DIAGNOSTICS_CFG_CHANGED    0x0093


#pragma pack(1)
typedef struct T_HISTRORY_STORAGE {  
  UINT32 DataLen;
  UINT32 Flags;
  UINT8 CurSeverity;
  UINT8 CsType;
  UINT8 CsData[MAX_HASH_LEN];
  UINT8 Data[HISTORY_SIZE];
} HISTORY_STORAGE;

typedef struct T_HISTRORY_RECORD {
  UINT32 RecId;
  UINT32 TimeStamp;
  UINT16 EventCode;
  UINT8 UserId;
  UINT8 Severity;
  UINT8 Flags;
} HISTORY_RECORD;

#pragma pack()


extern GUID gHistoryStorageGuid;


VOID
HistoryCheckOverflow(
  VOID
  );


EFI_STATUS
HistoryPageCallback(
  IN CONST EFI_HII_CONFIG_ACCESS_PROTOCOL *This,
  IN EFI_BROWSER_ACTION Action,
  IN EFI_QUESTION_ID QuestionId,
  IN UINT8 Type,
  IN EFI_IFR_TYPE_VALUE *Value,
  OUT EFI_BROWSER_ACTION_REQUEST *ActionRequest
  );

EFI_STATUS
HistoryStoragePresent(
  VOID
  );

EFI_STATUS
HistoryStorageInitEmpty(
  VOID
  );

EFI_STATUS
HistoryStorageGetData(
  IN OUT HISTORY_STORAGE *HistoryStrorage
  );

EFI_STATUS
HistoryStorageCheckIntegrity(
  VOID
  );

EFI_STATUS
HistoryStorageSetRawData(
  IN UINT8 *RawData,
  IN UINTN RawDataLen
  );

HISTORY_RECORD *
HistoryGetLastFoundedRecord(
  VOID
  );
  
EFI_STATUS
HistoryFindRecordByRecNum(
  IN UINTN RecNum
  );

EFI_STATUS
HistoryFindRecordById(
  IN UINT32 HistoryRecId
  );

EFI_STATUS
HistoryFindRecordByUserId(
  IN UINT8 UserId
  );

EFI_STATUS
HistoryFindRecordByTimeStamp(
  IN UINT32 TimeStamp
  );

EFI_STATUS
HistoryFindRecordByEventCode(
  IN UINT16 EventCode
  );
  
EFI_STATUS
HistoryAddRecord(
  IN UINT16 EventCode,
  IN UINT8 UserId,
  IN UINT8 Severity,
  IN UINT8 Flags
  );
  
HISTORY_RECORD *
HistoryGetNextRecord(
  IN BOOLEAN bRestart 
  );

EFI_STATUS
HistoryDeleteLastFoundedRecord(
  IN BOOLEAN bUpdate
  );

EFI_STATUS
HistoryCleanByNum(
  IN UINTN RecNum,
  IN BOOLEAN bUpdate
  );

EFI_STATUS
HistoryCleanByNumRev (
  IN UINTN RecNum,
  IN BOOLEAN bUpdate
  );


EFI_STATUS
HistoryCleanOne(
  IN BOOLEAN bUpdate
  );

EFI_STATUS
HistoryCleanAll(
  VOID
  );
  
EFI_STATUS
HistoryOutswapToUSB(
  VOID
  );
  
VOID 
HistorySetCurrentConfig(
  IN EFI_HII_HANDLE HiiHandle,
  IN MULTIBOOT_CONFIG *Cfg
  );

EFI_STATUS
HistoryCtrlMenuStart(
  IN EFI_HII_HANDLE HiiHandle,
  IN CHAR8 *Language
  );

EFI_STATUS
HistoryCommonInit(
  IN EFI_HII_HANDLE HiiHandle
  );

BOOLEAN
HistoryAutoCleanEnabled(
  VOID
  );

EFI_STATUS
HistoryFlush(
  VOID
  );

BOOLEAN
HistoryOutswapped(
  VOID
  );

EFI_STATUS
HistoryGetCsv16MemFile(
  IN CHAR16 **Csv16Str
  );

EFI_STATUS
HistorySettings (
  IN UINT8 CurSeverity,
  IN BOOLEAN bAutocleanEn
  );

VOID
HistorySetAddRecordQuietFlag(
  BOOLEAN bFlag
  );


#endif  /*  #ifndef __HISTORY__H  */

