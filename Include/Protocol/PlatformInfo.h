/** @file

  Copyright (c) 2008 - 2011, Intel Corporation. All rights reserved.<BR>
  This program and the accompanying materials
  are licensed and made available under the terms and conditions of the BSD License
  which accompanies this distribution.  The full text of the license may be found at
  http://opensource.org/licenses/bsd-license.php

  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/

#ifndef _PLATFORM_INFO_H_
#define _PLATFORM_INFO_H_

#define EFI_PLATFORM_INFO_PROTOCOL_GUID \
  { \
    0x69d6a824, 0xa697, 0x44bf, { 0x9d, 0x24, 0x79, 0xc3, 0x5a, 0x4e, 0x87, 0xb5 } \
  }
  
extern EFI_GUID gEfiPlatformInfoProtocolGuid;

typedef struct _EFI_PLATFORM_INFO_PROTOCOL EFI_PLATFORM_INFO_PROTOCOL;

/** Текущая версия информации о платформе */
#define PLATFORM_INFO_VERSION_1_0 0x00010000
#define PLATFORM_INFO_VERSION_1_1 0x00010100
/** Максимальная длина текстовых полей в структуре */
#define MAX_NAME_LENGTH 256

/** 
* Структура с обработанной информацией о процессоре.
*/
typedef struct _SProcessorInfo
{
	/** Версия структуры */
	UINT32 _nVersion;
	
	/** Модель (название) процессора */
	UINT16 _wszCpuModel[MAX_NAME_LENGTH];
	
	/** Текущая частота работы процессора (МГц) */
	UINT32 _nCpuFreqInMHz;

	/** Количество ядер */
	UINT32 _nCoresCount;
	
	/** Количество нитей */
	UINT32 _nThreadsCount;
	
	/** Ревизия микрокода */
	UINT32 _nMicrocodeRevision;

	/*			*/
	CHAR8  *_BrandString;
} SProcessorInfo, *PSProcessorInfo;
	
/**
* Тип установленной памяти.
* Должен соответствовать возвращаемому значению от MRC
*/
typedef enum 
{
  eDdrTypeUnknown,
  eDdrTypeDdr3,
  eDdrTypeLpDdr3
} EDdrType;
	
/** 
* Структура с обработанной информацией о памяти.
*/
typedef struct _SMemoryInfo
{
	/** Версия структуры */
	UINT32 _nVersion;
	
	/** Тип установленной оперативной памяти */
	EDdrType _nMemType;
	
	/** Общий объем установленной памяти */
	UINT32 _nTotalMemoryInMb;
	
	/** Частота работы памяти (в МГц)*/
	UINT32 _nMemFreqInMHz;

} SMemoryInfo, *PSMemoryInfo;	
	
/** 
* Структура, хранящая в себе информацию о платформе 
* (процессоре, ОЗУ, подключенных устройствах). 
*/
typedef struct _SPlatformInfo
{
	/** Версия структуры */
	UINT32         _nVersion;

	/** Информация о процессоре */
	SProcessorInfo _ProcessorInfo;
	
	/** Информация об ОЗУ */
	SMemoryInfo    _MemoryInfo;

} SPlatformInfo, *PSPlatformInfo;

/** Протокол предоставления информации о платформе. */
typedef struct _EFI_PLATFORM_INFO_PROTOCOL
{
	/** Версия протокола */
	UINT32        _Version;
	/** Информация о аппаратной платформе. */
	SPlatformInfo _PlatformInfo;
} EFI_PLATFORM_INFO_PROTOCOL;


#endif //_PLATFORM_INFO_H_

