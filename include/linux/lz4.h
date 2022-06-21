/* LZ4 Kernel Interface
 *
 * Copyright (C) 2013, LG Electronics, Kyungsik Lee <kyungsik.lee@lge.com>
 * Copyright (C) 2016, Sven Schmidt <4sschmid@informatik.uni-hamburg.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This file is based on the original header file
 * for LZ4 - Fast LZ compression algorithm.
 *
 * LZ4 - Fast LZ compression algorithm
 * Copyright (C) 2011-2016, Yann Collet.
 * BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *	* Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *	* Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * You can contact the author at :
 *	- LZ4 homepage : http://www.lz4.org
 *	- LZ4 source repository : https://github.com/lz4/lz4
 */

#ifndef __LZ4_H__
#define __LZ4_H__

#include <linux/types.h>
#include <linux/string.h>	 /* memset, memcpy */

/*-************************************************************************
 *	CONSTANTS
 **************************************************************************/
/*
 * LZ4_MEMORY_USAGE :
 * Memory usage formula : N->2^N Bytes
 * (examples : 10 -> 1KB; 12 -> 4KB ; 16 -> 64KB; 20 -> 1MB; etc.)
 * Increasing memory usage improves compression ratio
 * Reduced memory usage can improve speed, due to cache effect
 * Default value is 14, for 16KB, which nicely fits into Intel x86 L1 cache
 */
#define LZ4_MEMORY_USAGE 14

#define LZ4_MAX_INPUT_SIZE	0x7E000000 /* 2 113 929 216 bytes */
#define LZ4_COMPRESSBOUND(isize)	(\
	(unsigned int)(isize) > (unsigned int)LZ4_MAX_INPUT_SIZE \
	? 0 \
	: (isize) + ((isize)/255) + 16)

#define LZ4_ACCELERATION_DEFAULT 1
#define LZ4_HASHLOG	 (LZ4_MEMORY_USAGE-2)
#define LZ4_HASHTABLESIZE (1 << LZ4_MEMORY_USAGE)
#define LZ4_HASH_SIZE_U32 (1 << LZ4_HASHLOG)

#define LZ4HC_MIN_CLEVEL			3
#define LZ4HC_DEFAULT_CLEVEL			9
#define LZ4HC_MAX_CLEVEL			16

#define LZ4HC_DICTIONARY_LOGSIZE 16
#define LZ4HC_MAXD (1<<LZ4HC_DICTIONARY_LOGSIZE)
#define LZ4HC_MAXD_MASK (LZ4HC_MAXD - 1)
#define LZ4HC_HASH_LOG (LZ4HC_DICTIONARY_LOGSIZE - 1)
#define LZ4HC_HASHTABLESIZE (1 << LZ4HC_HASH_LOG)
#define LZ4HC_HASH_MASK (LZ4HC_HASHTABLESIZE - 1)

/*-************************************************************************
 *	STREAMING CONSTANTS AND STRUCTURES
 **************************************************************************/
#define LZ4_STREAMSIZE_U64 ((1 << (LZ4_MEMORY_USAGE - 3)) + 4)
#define LZ4_STREAMSIZE	(LZ4_STREAMSIZE_U64 * sizeof(unsigned long long))

#define LZ4_STREAMHCSIZE        262192
#define LZ4_STREAMHCSIZE_SIZET (262192 / sizeof(size_t))

#define LZ4_STREAMDECODESIZE_U64	4
#define LZ4_STREAMDECODESIZE		 (LZ4_STREAMDECODESIZE_U64 * \
	sizeof(unsigned long long))

/*
 * LZ4_stream_t - information structure to track an LZ4 stream.
 */
typedef struct {
	uint32_t hashTable[LZ4_HASH_SIZE_U32];
	uint32_t currentOffset;
	uint32_t initCheck;
	const uint8_t *dictionary;
	uint8_t *bufferStart;
	uint32_t dictSize;
} LZ4_stream_t_internal;
typedef union {
	unsigned long long table[LZ4_STREAMSIZE_U64];
	LZ4_stream_t_internal internal_donotuse;
} LZ4_stream_t;

/*
 * LZ4_streamHC_t - information structure to track an LZ4HC stream.
 */
typedef struct {
	unsigned int	 hashTable[LZ4HC_HASHTABLESIZE];
	unsigned short	 chainTable[LZ4HC_MAXD];
	/* next block to continue on current prefix */
	const unsigned char *end;
	/* All index relative to this position */
	const unsigned char *base;
	/* alternate base for extDict */
	const unsigned char *dictBase;
	/* below that point, need extDict */
	unsigned int	 dictLimit;
	/* below that point, no more dict */
	unsigned int	 lowLimit;
	/* index from which to continue dict update */
	unsigned int	 nextToUpdate;
	unsigned int	 compressionLevel;
} LZ4HC_CCtx_internal;
typedef union {
	size_t table[LZ4_STREAMHCSIZE_SIZET];
	LZ4HC_CCtx_internal internal_donotuse;
} LZ4_streamHC_t;

/*
 * LZ4_streamDecode_t - information structure to track an
 *	LZ4 stream during decompression.
 *
 * init this structure using LZ4_setStreamDecode (or memset()) before first use
 */
typedef struct {
	const uint8_t *externalDict;
	size_t extDictSize;
	const uint8_t *prefixEnd;
	size_t prefixSize;
} LZ4_streamDecode_t_internal;
typedef union {
	unsigned long long table[LZ4_STREAMDECODESIZE_U64];
	LZ4_streamDecode_t_internal internal_donotuse;
} LZ4_streamDecode_t;

/*-************************************************************************
 *	SIZE OF STATE
 **************************************************************************/
#define LZ4_MEM_COMPRESS	LZ4_STREAMSIZE
#define LZ4HC_MEM_COMPRESS	LZ4_STREAMHCSIZE

/*-************************************************************************
 *	Compression Functions
 **************************************************************************/

/**
 * LZ4_compressBound() - Max. output size in worst case szenarios
 * @isize: Size of the input data
 *
 * Return: Max. size LZ4 may output in a "worst case" szenario
 * (data not compressible)
 */
static inline int LZ4_compressBound(size_t isize)
{
	return LZ4_COMPRESSBOUND(isize);
}

/**
 * LZ4_compress_default() - Compress data from source to dest
 * @source: source address of the original data
 * @dest: output buffer address of the compressed data
 * @inputSize: size of the input data. Max supported value is LZ4_MAX_INPUT_SIZE
 * @maxOutputSize: full or partial size of buffer 'dest'
 *	which must be already allocated
 * @wrkmem: address of the working memory.
 *	This requires 'workmem' of LZ4_MEM_COMPRESS.
 *
 * Compresses 'sourceSize' bytes from buffer 'source'
 * into already allocated 'dest' buffer of size 'maxOutputSize'.
 * Compression is guaranteed to succeed if
 * 'maxOutputSize' >= LZ4_compressBound(inputSize).
 * It also runs faster, so it's a recommended setting.
 * If the function cannot compress 'source' into a more limited 'dest' budget,
 * compression stops *immediately*, and the function result is zero.
 * As a consequence, 'dest' content is not valid.
 *
 * Return: Number of bytes written into buffer 'dest'
 *	(necessarily <= maxOutputSize) or 0 if compression fails
 */
int LZ4_compress_default(const char *source, char *dest, int inputSize,
	int maxOutputSize, void *wrkmem);

/*-************************************************************************
 *	Decompression Functions
 **************************************************************************/

/**
 * LZ4_decompress_fast() - Decompresses data from 'source' into 'dest'
 * @source: source address of the compressed data
 * @dest: output buffer address of the uncompressed data
 *	which must be already allocated with 'originalSize' bytes
 * @originalSize: is the original and therefore uncompressed size
 *
 * Decompresses data from 'source' into 'dest'.
 * This function fully respect memory boundaries for properly formed
 * compressed data.
 * It is a bit faster than LZ4_decompress_safe().
 * However, it does not provide any protection against intentionally
 * modified data stream (malicious input).
 * Use this function in trusted environment only
 * (data to decode comes from a trusted source).
 *
 * Return: number of bytes read from the source buffer
 *	or a negative result if decompression fails.
 */
int LZ4_decompress_fast(const char *source, char *dest, int originalSize);

/**
 * LZ4_decompress_safe() - Decompression protected against buffer overflow
 * @source: source address of the compressed data
 * @dest: output buffer address of the uncompressed data
 *	which must be already allocated
 * @compressedSize: is the precise full size of the compressed block
 * @maxDecompressedSize: is the size of 'dest' buffer
 *
 * Decompresses data from 'source' into 'dest'.
 * If the source stream is detected malformed, the function will
 * stop decoding and return a negative result.
 * This function is protected against buffer overflow exploits,
 * including malicious data packets. It never writes outside output buffer,
 * nor reads outside input buffer.
 *
 * Return: number of bytes decompressed into destination buffer
 *	(necessarily <= maxDecompressedSize)
 *	or a negative result in case of error
 */
int LZ4_decompress_safe(const char *source, char *dest, int compressedSize,
	int maxDecompressedSize);

/**
 * LZ4_decompress_safe_partial() - Decompress a block of size 'compressedSize'
 *	at position 'source' into buffer 'dest'
 * @source: source address of the compressed data
 * @dest: output buffer address of the decompressed data which must be
 *	already allocated
 * @compressedSize: is the precise full size of the compressed block.
 * @targetOutputSize: the decompression operation will try
 *	to stop as soon as 'targetOutputSize' has been reached
 * @maxDecompressedSize: is the size of destination buffer
 *
 * This function decompresses a compressed block of size 'compressedSize'
 * at position 'source' into destination buffer 'dest'
 * of size 'maxDecompressedSize'.
 * The function tries to stop decompressing operation as soon as
 * 'targetOutputSize' has been reached, reducing decompression time.
 * This function never writes outside of output buffer,
 * and never reads outside of input buffer.
 * It is therefore protected against malicious data packets.
 *
 * Return: the number of bytes decoded in the destination buffer
 *	(necessarily <= maxDecompressedSize)
 *	or a negative result in case of error
 *
 */
int LZ4_decompress_safe_partial(const char *source, char *dest,
	int compressedSize, int targetOutputSize, int maxDecompressedSize);

/*-************************************************************************
 *	LZ4 HC Compression
 **************************************************************************/

/**
 * LZ4_compress_HC() - Compress data from `src` into `dst`, using HC algorithm
 * @src: source address of the original data
 * @dst: output buffer address of the compressed data
 * @srcSize: size of the input data. Max supported value is LZ4_MAX_INPUT_SIZE
 * @dstCapacity: full or partial size of buffer 'dst',
 *	which must be already allocated
 * @compressionLevel: Recommended values are between 4 and 9, although any
 *	value between 1 and LZ4HC_MAX_CLEVEL will work.
 *	Values >LZ4HC_MAX_CLEVEL behave the same as 16.
 * @wrkmem: address of the working memory.
 *	This requires 'wrkmem' of size LZ4HC_MEM_COMPRESS.
 *
 * Compress data from 'src' into 'dst', using the more powerful
 * but slower "HC" algorithm. Compression is guaranteed to succeed if
 * `dstCapacity >= LZ4_compressBound(srcSize)
 *
 * Return : the number of bytes written into 'dst' or 0 if compression fails.
 */
int LZ4_compress_HC(const char *src, char *dst, int srcSize, int dstCapacity,
	int compressionLevel, void *wrkmem);

/*-*********************************************
 *	Streaming Compression Functions
 ***********************************************/

/**
 * LZ4_resetStream() - Init an allocated 'LZ4_stream_t' structure
 * @LZ4_stream: pointer to the 'LZ4_stream_t' structure
 *
 * An LZ4_stream_t structure can be allocated once
 * and re-used multiple times.
 * Use this function to init an allocated `LZ4_stream_t` structure
 * and start a new compression.
 */
static __always_inline void LZ4_resetStream(LZ4_stream_t *LZ4_stream);

/**
 * LZ4_loadDict() - Load a static dictionary into LZ4_stream
 * @streamPtr: pointer to the LZ4_stream_t
 * @dictionary: dictionary to load
 * @dictSize: size of dictionary
 *
 * Use this function to load a static dictionary into LZ4_stream.
 * Any previous data will be forgotten, only 'dictionary'
 * will remain in memory.
 * Loading a size of 0 is allowed.
 *
 * Return : dictionary size, in bytes (necessarily <= 64 KB)
 */
int LZ4_loadDict(LZ4_stream_t *streamPtr, const char *dictionary,
	int dictSize);

/**
 * LZ4_saveDict() - Save static dictionary from LZ4_stream
 * @streamPtr: pointer to the 'LZ4_stream_t' structure
 * @safeBuffer: buffer to save dictionary to, must be already allocated
 * @dictSize: size of 'safeBuffer'
 *
 * If previously compressed data block is not guaranteed
 * to remain available at its memory location,
 * save it into a safer place (char *safeBuffer).
 * Note : you don't need to call LZ4_loadDict() afterwards,
 * dictionary is immediately usable, you can therefore call
 * LZ4_compress_fast_continue().
 *
 * Return : saved dictionary size in bytes (necessarily <= dictSize),
 *	or 0 if error.
 */
int LZ4_saveDict(LZ4_stream_t *streamPtr, char *safeBuffer, int dictSize);

#endif
