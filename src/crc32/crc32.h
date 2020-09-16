/*
* 	File: crc32.h
* 	Brief: CRC32 Interface implementation
* 	Author: rampopula
* 	Date: June 2, 2020
*/

#ifndef __CRC32_H__
#define __CRC32_H__

#ifdef __cplusplus
extern "C" {  
#endif

#include <stdint.h>


uint32_t CRC32_Calculate(const uint8_t *data, int32_t size);


#ifdef __cplusplus  
} // extern "C"  
#endif

#endif /* __CRC32_H__ */
