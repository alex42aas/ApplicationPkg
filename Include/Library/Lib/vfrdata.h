/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef __VFR__DATA__H
#define __VFR__DATA__H


#include <CommonDefs.h>


#define MULTIBOOTLOADER_GUID                      { 0x543cd5fe, 0x1276, 0x443d, \
  { 0x41, 0x42, 0x34, 0xc2, 0x32, 0xef, 0xa1, 0xe4 } }

#define FORMSET_MII_GUID                          MULTIBOOTLOADER_GUID
#define MII_PAGE_ID                               0x1000
#define MII_CREATE_ADMIN_CARD                     0x1001
#define MII_RESTORE_FROM_USB                      0x1002
#define MII_DATE_TIME_SETUP                       0x1003
#define MII_CERTIFICATE_CTRL                      0x1004
#define MII_DEV_MANAGER_ID                        0x1005
#define LABEL_MII_LIST_START                      0x1100
#define LABEL_MII_LIST_END                        0x1101

#define RESTORE_USERS_FROM_USB_PAGE_ID            0x1200
#define RESTORE_USERS_FROM_USB_START_QUID         0x1201
#define RESTORE_USERS_FROM_USB_END_QUID           0x12FF
#define LABEL_RECOVER_USERS_FROM_USB_LIST_START   0x1300
#define LABEL_RECOVER_USERS_FROM_USB_LIST_END     0x1301

#define FORMSET_USERS_GUID                        MULTIBOOTLOADER_GUID

#define USERS_PAGE_ID                             0x4000
#define USER_NAME_ID                              0x4001
#define USER_PASSWD_ID                            0x4002
#define USER_FIO_ID                               0x4003
#define USER_CONTACT_INFO_ID                      0x4004
#define USER_BLOCK_FLAG_ID                        0x4005
#define USER_SUSPEND_FLAG_ID                      0x4006
#define USER_COMPARE_TYPE_ID                      0x4007
#define USER_COMPARE_DATA_ID                      0x4018
#define USER_AUTHORIZATION_TYPE_ID                0x4019
#define USER_TYPE_ID                              0x401A
#define LABEL_USERS_LIST_START                    0x4100
#define LABEL_USERS_LIST_END                      0x4101
#define USER_CREATE_BUTTON_ID                     0x4102
#define USER_VIEW_START_ID                        0x4110
#define USER_DEL_START_ID                         0x4160
#define USERS_VARSTORE_VAR_ID                     0x4200
#define USERS_CREATE_PAGE_ID                      0x4211
#define USERS_DELETE_PAGE_ID                      0x4212
#define USERS_VIEW_PAGE_ID                        0x4213
#define USERS_STORE_TO_CVS_FILE_ID                0x4214
#define USERS_PASS_CREATION_TIME_ID               0x4215

#define USERS_CMP_CN_ID                           0x4215
#define USERS_CMP_SUBJECT_ID                      0x4216
#define USERS_CMP_MAIL_ID                         0x4217
#define USERS_CMP_DIGEST_ID                       0x4218

#define USERS_REMOTE_ACCESS_ID                    0x4219
#define USERS_ADMIN_ROLE_ID                       0x421A

#define USERS_LOAD_LIST_FROM_LDAP_ID              0x421B

#define USERS_FILES_START_ID                      0x4300
#define USERS_FILES_END_ID                        0x4800


#define DATE_TIME_SETUP_PAGE_GUID                 MULTIBOOTLOADER_GUID
#define DATE_TIME_SETUP_PAGE_ID                   0x5000

/* File explorer definitions */
#define FORMSET_FE_GUID                           MULTIBOOTLOADER_GUID
#define FE_PAGE_ID                                0xFE05
#define LABEL_FE_LIST_START                       0xFE06
#define LABEL_FE_LIST_END                         0xFE07
#define FE_QID_START                              0xFE08

#define FORMSET_BIOS_GUID                         MULTIBOOTLOADER_GUID
#define BIOS_PAGE_ID                             0xF000
#define LABEL_BIOS_LIST_START                    0xF100
#define LABEL_BIOS_LIST_END                      0xF101

#define FORMSET_MAIN_PAGE_GUID                    FRONT_PAGE_GUID

#define MAIN_PAGE_ID                              0x2000
#define MP_REGULAR_LOADING_MODE_ID                0x2001
#define MP_ADMIN_MODE_ID                          0x2002
#define MP_FAILURE_MODE_ID                        0x2003
#define MP_RECOVER_MODE_ID                        0x2004
#define MP_TIME_OUT_ID                            0x2005
#define MP_LOAD_FROM_USB_ID                       0x2006
#define MP_LEGACY_BIOS_ITEM1_ID                   0x2007
#define MP_ADDITIONAL_LOADING_MODE_1_ID           0x2008
#define MP_ADDITIONAL_LOADING_MODE_2_ID           0x2009
#define MP_ADDITIONAL_LOADING_MODE_3_ID           0x200A
#define LABEL_MAIN_PAGE_LIST_START                0x2100
#define LABEL_MAIN_PAGE_LIST_END                  0x2101
#define MP_VARSTORE_VAR_ID                        0x2200


/*ADMIN MAIN PAGE DEFINITIONS*/
#define FORMSET_ADM_MAIN_PAGE_GUID                MULTIBOOTLOADER_GUID
#define ADM_MAIN_PAGE_ID                          0x3000
#define ADM_MAIN_PAGE_SERT_CTRL_ID                0x3001
#define ADM_MAIN_PAGE_USRS_CTRL_ID                0x3002
#define ADM_MAIN_PAGE_BIOS_LOG_CTRL_ID            0x3003
#define ADM_MAIN_PAGE_INTEGRITY_CTRL_ID           0x3004
#define ADM_MAIN_PAGE_RESTORE_OPERATIONAL_ID      0x3005
#define ADM_MAIN_PAGE_COMPLEX_INSTALL_ID          0x3006
#define ADM_MAIN_PAGE_DATE_TIME_SETUP_ID          0x3007
#define ADM_MAIN_PAGE_ADM_VIRTUAL_ID              0x3008
#define ADM_MAIN_PAGE_BIOS_UPDATE_ID              0x3009
#define ADM_MAIN_PAGE_LOCAL_ADMIN_ID              0x300A
#define ADM_MAIN_PAGE_SU_PASS_ID                  0x300B
#define ADM_MAIN_PAGE_RECOVER_1_ID                0x300C
#define ADM_MAIN_PAGE_RECOVER_2_ID                0x300D
#define ADM_MAIN_PAGE_SET_DAD_ID                  0x300E // DAD=direct access devices
#define ADM_MAIN_PAGE_SET_TRR_ID                  0x300F // TRR=token remove reset
#define ADM_MAIN_PAGE_MEM_TEST_ID                 0x3010
#define ADM_MAIN_PAGE_ADV_MENU_ID                 0x3011
#define ADM_MAIN_PAGE_DBG_LOAD_PARAM_ID           0x3012
#define ADM_MAIN_PAGE_DEV_MANAGER_ID              0x3013
#define ADM_MAIN_LEGACY_BIOS_ITEM1_ID             0x3014
#define ADM_MAIN_BOOT_MENU_ID                     0x3015
#define ADM_MAIN_EQUIPMENT_MONITOR_ID             0x3017
#define ADM_MAIN_CHIPSET_CONFIG_ID                0x3018
#define ADM_MAIN_COMP_UNBLOCK_ID                  0x3019
#define ADM_MAIN_BOOT_1_ID                        0x301A
#define ADM_MAIN_BOOT_2_ID                        0x301B
#define ADM_MAIN_BOOT_3_ID                        0x301C
#define ADM_MAIN_AMT_FUNC                         0x301D
#define ADM_MAIN_SYS_INFO                         0x301E


#define LABEL_ADM_MAIN_PAGE_LIST_START            0x3100
#define LABEL_ADM_MAIN_PAGE_LIST_END              0x3101
#define ADM_BIOS_UPDATE_FILES_START_ID            0x3200
#define ADM_BIOS_UPDATE_FILES_END_ID              0x3800


#define COMPARE_TYPE_FLAGS_AMOUNT                 5

/* HISTORY */
#define FORMSET_HISTORY_GUID                      MULTIBOOTLOADER_GUID
#define HISTORY_PAGE_ID                           0x6000
#define HISTORY_VIEW_CLEAN_ID                     0x6001
#define HISTORY_OUTSWAP_TO_USB_ID                 0x6002
#define HISTORY_SEVERITY_LEVEL_ID                 0x6003
#define HISTORY_ENABLE_AUTO_CLEAN_ID              0x6004
#define HISTORY_CLEAN_ALL_ID                      0x6005
#define HISTORY_VIEW_DEL_REC_START                0x6020
#define HISTORY_VIEW_DEL_REC_END                  0x61FF
#define LABEL_HISTORY_LIST_START                  0x6200
#define LABEL_HISTORY_LIST_END                    0x6201
#define HISTORY_VARSTORE_VAR_ID                   0x6300

/* CERTIFICATE */
#define FORMSET_CERT_CTRL_GUID                    MULTIBOOTLOADER_GUID
#define CERT_CTRL_PAGE_ID                         0x7000
#define CERT_CTRL_LOAD_UPDATE_CA_ID               0x7001
#define CERT_CTRL_LOAD_UPDATE_CA_STATUS_ID        0x7002
#define CERT_CTRL_DELETE_CA_ID                    0x7003
#define CERT_CTRL_LOAD_UPDATE_CRL_ID              0x7004
#define CERT_CTRL_LOAD_UPDATE_CRL_STATUS_ID       0x7005
#define CERT_CTRL_DELETE_CRL_ID                   0x7006

#define CERT_CTRL_LOAD_UPDATE_CERT_ID             0x7007
#define CERT_CTRL_LOAD_UPDATE_CERT_STATUS_ID      0x7008
#define CERT_CTRL_DELETE_CERT_ID                  0x7009

#define CERT_CTRL_LOAD_UPDATE_PKEY_ID             0x700A
#define CERT_CTRL_LOAD_UPDATE_PKEY_STATUS_ID      0x700B
#define CERT_CTRL_DELETE_PKEY_ID                  0x700C

#define LABEL_CERT_CTRL_LIST_START                0x7100
#define LABEL_CERT_CTRL_LIST_END                  0x7101
#define CERT_FILES_START_QID                      0x7200
#define CERT_FILES_END_QID                        0x7900

#define FORMSET_RECOVER_MODE_GUID                 MULTIBOOTLOADER_GUID
#define RECOVER_MODE_PAGE_ID                      0x8000
#define RMP_MODE1                                 0x8001
#define RMP_MODE2                                 0x8002
#define LABEL_RECOVER_MODE_PAGE_LIST_START        0x8100
#define LABEL_RECOVER_MODE_PAGE_LIST_END          0x8101

#define FORMSET_PCI_DEV_LIST_MODE_GUID            MULTIBOOTLOADER_GUID
#define PCI_DEV_LIST_MODE_PAGE_ID                 0x9000
#define PCI_DEV_LIST_LOAD_DEFAULTS_ID             0x9001
#define PCI_DEV_LIST_START_QID                    0x9002
#define LABEL_PCI_DEV_LIST_MODE_PAGE_LIST_START   0x9100
#define LABEL_PCI_DEV_LIST_MODE_PAGE_LIST_END     0x9101

#define FORMSET_ADVANCED_MODE_GUID                MULTIBOOTLOADER_GUID
#define ADVANCED_MODE_PAGE_ID                     0xA000
#define ADVANCED_MODE_START_QID                   0xA001
#define LABEL_ADVANCED_MODE_PAGE_LIST_START       0xA100
#define LABEL_ADVANCED_MODE_PAGE_LIST_END         0xA101

/* Integrity check */
#define FORMSET_INTEGRITY_GUID                    MULTIBOOTLOADER_GUID
#define INTEGRITY_PAGE_ID                         0xA200
#define LABEL_INTEGRITY_LIST_START                0xA201
#define LABEL_INTEGRITY_LIST_END                  0xA202
#define INTEGRITY_VIEW_RES_START                  0xA203
#define INTEGRITY_VIEW_RES_END                    0xA400

/* debug loading params */
#define FORMSET_DBG_LOAD_PARAMS_GUID              MULTIBOOTLOADER_GUID
#define DBG_LOAD_PARAMS_PAGE_ID                   0xA401
#define LABEL_DBG_LOAD_PARAMS_LIST_START          0xA402
#define LABEL_DBG_LOAD_PARAMS_LIST_END            0xA403
#define DBG_LOAD_PARAMS_START                     0xA404
#define DBG_LOAD_PARAMS_END                       0xA4FF

/* BOOT Manager Lib */
#define RUN_BOOT_MANAGER                          0xA500

/* DRM params */
#define FORMSET_DRM_PARAMS_GUID              MULTIBOOTLOADER_GUID
#define DRM_PARAMS_PAGE_ID                   0xD001
#define DRM_PARAMS_ENTRY_ID                   0xD002



#endif  /* #ifndef __VFR__DATA__H */

