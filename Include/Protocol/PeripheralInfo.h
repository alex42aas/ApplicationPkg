/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef _PERIPHERAL_INFO_H_
#define _PERIPHERAL_INFO_H_

#define EFI_PERIPHERAL_INFO_PROTOCOL_GUID \
  { \
	0x285eb506, 0xe539, 0x46e5, { 0x85, 0x96, 0xa0, 0x4b, 0x0, 0x8f, 0x4, 0xe6 } \
  }
  
extern EFI_GUID gEfiPeripheralInfoProtocolGuid;

typedef struct _EFI_PERIPHERAL_INFO_PROTOCOL EFI_PERIPHERAL_INFO_PROTOCOL;

/** Текущая версия информации о периферийных устройствах */
#define PERIPHERAL_INFO_VERSION_1_0 0x00010000
/** Максимальная длина текстовых полей в структуре */
#define MAX_NAME_LENGTH 256

/** Информация об одном SATA-устройстве */
typedef struct _SataDeviceInfo
{
	/** Модель устройства */
	UINT16* _wszModel;

	/** Емкость в байтах */
	UINT64  _nSizeInBytes;

} SSataDeviceInfo, *PSSataDeviceInfo;

/** Максимальное число устройств SATA */
#define MAX_SATA_DEVICE_COUNT 8
	
/** 
* Структура с обработанной информацией о подключенных SATA-устройствах.
*/
typedef struct _SataInfo
{
	/** Версия структуры */
	UINT32 _nVersion;
	/** Количество идентифицированных устройств */
	UINT32 _nDeviceCount;
	/** Массив с описаниями подключенных устройств */
	SSataDeviceInfo _aSataDevice[MAX_SATA_DEVICE_COUNT];	
} SSataInfo, *PSSataInfo;		
	

/** 
* Структура, хранящая в себе информацию о платформе 
* (процессоре, ОЗУ, подключенных устройствах). 
*/
typedef struct _SPeripheralInfo
{
	/** Версия структуры */
	UINT32         _nVersion;

	/** Информация о подключенных устройствах интерфейса SATA */
	SSataInfo      _SataInfo;

} SPeripheralInfo, *PSPeripheralInfo;

/** Протокол предоставления информации о платформе. */
typedef struct _EFI_PERIPHERAL_INFO_PROTOCOL
{
	/** Версия протокола */
	UINT32          _Version;
	/** Информация о аппаратной платформе. */
	SPeripheralInfo _PeripheralInfo;
} EFI_PERIPHERAL_INFO_PROTOCOL;


#endif //_PERIPHERAL_INFO_H_

