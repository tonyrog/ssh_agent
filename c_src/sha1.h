/*
 *  sha1.h
 *
 *  Description:
 *      This is the header file for code which implements the Secure
 *      Hashing Algorithm 1 as defined in FIPS PUB 180-1 published
 *      April 17, 1995.
 *
 *      Many of the variable names in this code, especially the
 *      single character names, were used because those were the names
 *      used in the publication.
 *
 *      Please read the file sha1.c for more information.
 *
 */

#ifndef _SHA1_H_
#define _SHA1_H_

#include <stdint.h>
#include <stdlib.h>

enum
{
    shaSuccess = 0,
    shaNull,            /* Null pointer parameter */
    shaInputTooLong,    /* input data too long */
    shaStateError       /* called Input after Result */
};

#define SHA1_HASH_SIZE 20

typedef struct sha1_ctx_t
{
    uint64_t length;                     // message length in bits
    uint32_t digest[SHA1_HASH_SIZE/4];   // Message Digest
    int8_t   pos;                        // current pos in block
    uint8_t  block[64];                  // 512-bit message blocks
    int computed;                        // Is the digest computed?
    int corrupted;                       // Is the message digest corrupted?
} sha1_ctx_t;

int sha1_init(sha1_ctx_t*);
int sha1_update(sha1_ctx_t*, uint8_t *, size_t);
int sha1_final(sha1_ctx_t*, uint8_t* digest);

// Local Function Prototyptes
static void sha1_pad_message(sha1_ctx_t *);
static void sha1_digest(sha1_ctx_t *);

static inline uint32_t shift(int n, uint32_t w)
{
    return (w << n) | (w >> (32-n));
}

static inline uint32_t bytes_to_uint32(uint8_t* ptr)
{
    uint32_t value = ptr[0];
    value = (value << 8) | ptr[1];
    value = (value << 8) | ptr[2];
    value = (value << 8) | ptr[3];
    return value;
}

// store uint32 as bigendian bytes
static inline void uint32_to_bytes(uint32_t x, uint8_t* ptr)
{
    ptr[0] = x >> 24;
    ptr[1] = x >> 16;
    ptr[2] = x >> 8;
    ptr[3] = x >> 0;
}

// store uint64 as bigendian bytes
static inline void uint64_to_bytes(uint64_t x, uint8_t* ptr)
{
    uint32_t v = x >> 32;
    uint32_to_bytes(v, ptr);
    v = x;
    uint32_to_bytes(v, ptr + 4);
}

// initialize sha1 contex

int sha1_init(sha1_ctx_t* ctx)
{
    ctx->length      = 0;
    ctx->pos         = 0;
    ctx->digest[0]   = 0x67452301;
    ctx->digest[1]   = 0xEFCDAB89;
    ctx->digest[2]   = 0x98BADCFE;
    ctx->digest[3]   = 0x10325476;
    ctx->digest[4]   = 0xC3D2E1F0;
    ctx->computed    = 0;
    ctx->corrupted   = 0;
    return 0;
}

int sha1_final(sha1_ctx_t *ctx, uint8_t* digest)
{
    int i;
    uint8_t* dptr;
    
    if (ctx->corrupted)
	return -1;
    if (!ctx->computed) {
        sha1_pad_message(ctx);
        for(i = 0; i < 64; i++)
            ctx->block[i] = 0; // clear sensitive data
        ctx->length = 0;       // clear length
        ctx->computed = 1;
    }
    dptr = digest;
    for(i=0; i < SHA1_HASH_SIZE/4; i++) {
	uint32_to_bytes(ctx->digest[i], dptr);
	dptr += sizeof(uint32_t);
    }
    return 0;
}

int sha1_update(sha1_ctx_t* ctx, uint8_t* data, size_t length)
{
    if (ctx->computed)
        ctx->corrupted = shaStateError;
    while(length && !ctx->corrupted) {
	length--;
	ctx->block[ctx->pos++] = *data++;
	ctx->length += 8;
	if (ctx->length == 0) // wrap
	    ctx->corrupted = shaInputTooLong;
	if (ctx->pos == 64) {
	    sha1_digest(ctx);
	    ctx->pos = 0;
	}
    }
    return ctx->corrupted;
}

void sha1_digest(sha1_ctx_t* ctx)
{
    const uint32_t K[] = { 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };
    int           i;
    uint32_t      temp;
    uint32_t      W[80];
    uint32_t      A, B, C, D, E;

    for(i=0; i<16; i++)
	W[i] = bytes_to_uint32(ctx->block + i*4);

    for(i=16; i<80; i++)
	W[i] = shift(1,W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16]);

    A = ctx->digest[0];
    B = ctx->digest[1];
    C = ctx->digest[2];
    D = ctx->digest[3];
    E = ctx->digest[4];

    for(i = 0; i < 20; i++) {
        temp =  shift(5,A) + ((B & C) | ((~B) & D)) + E + W[i] + K[0];
        E = D;
        D = C;
        C = shift(30,B);
        B = A;
        A = temp;
    }

    for(i = 20; i < 40; i++) {
        temp = shift(5,A) + (B ^ C ^ D) + E + W[i] + K[1];
        E = D;
        D = C;
        C = shift(30,B);
        B = A;
        A = temp;
    }

    for(i = 40; i < 60; i++) {
        temp = shift(5,A) + ((B & C) | (B & D) | (C & D)) + E + W[i] + K[2];
        E = D;
        D = C;
        C = shift(30,B);
        B = A;
        A = temp;
    }

    for(i = 60; i < 80; i++) {
        temp = shift(5,A) + (B ^ C ^ D) + E + W[i] + K[3];
        E = D;
        D = C;
        C = shift(30,B);
        B = A;
        A = temp;
    }

    ctx->digest[0] += A;
    ctx->digest[1] += B;
    ctx->digest[2] += C;
    ctx->digest[3] += D;
    ctx->digest[4] += E;
}

static void sha1_pad_message(sha1_ctx_t* ctx)
{
    if (ctx->pos > 55) {
        ctx->block[ctx->pos++] = 0x80;
        while(ctx->pos < 64)
            ctx->block[ctx->pos++] = 0;
        sha1_digest(ctx);
	ctx->pos = 0;	
        while(ctx->pos < 56)
            ctx->block[ctx->pos++] = 0;
    }
    else {
        ctx->block[ctx->pos++] = 0x80;
        while(ctx->pos < 56)
	    ctx->block[ctx->pos++] = 0;
    }
    uint64_to_bytes(ctx->length, ctx->block+56);
    sha1_digest(ctx);
    ctx->pos = 0;    
}

#endif
