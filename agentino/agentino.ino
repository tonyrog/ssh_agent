/* -*- c++ -*- */

#define BIGNUM_HEAP_SIZE 512
#include "bignum.h"
#include "sha1.h"

#define K1024

#ifdef  K1024
#include "key_1024.h"
#endif

#ifdef  K2048
#include "key_2048.h"
#endif

#ifdef  K4096
#include "key_4096.h"
#endif

#include "pincode.h"

#define REQ_ECHO  0
#define REQ_LIST  1
#define REQ_SIGN  2

#define RSP_OK    0
#define RSP_ERROR 1
#define RSP_INFO  2

#define NUM_RSA_KEYS 1

// p1*p2 = n
typedef struct
{
    bignum_t d;     // private exponent
    bignum_t p1;    // prime1
    bignum_t p2;    // prime2
    bignum_t n;     // modulus
    bignum_t e;     // public exponent
} rsakey_t;

#define PIN_LIFE_TIME  120000
uint8_t master_pin[] = {1,2,3,4,3,2};

rsakey_t key[NUM_RSA_KEYS];
pincode_t key_pin[NUM_RSA_KEYS] = {{ sizeof(master_pin),
				     master_pin,
				     PIN_LIFE_TIME, 0 }};
uint8_t key_locked[NUM_RSA_KEYS];

int read_uint8(uint8_t* vp)
{
    while(Serial.available() <= 0)
      ;
    *vp = Serial.read();
    return 1;
}

int write_uint8(uint8_t v)
{
 //   while(Serial.availableForWrite() < 1)
 //    ;
    Serial.write(v);
    return 1;
}

int write_bytes(uint8_t* data, int len)
{
    return ((int)Serial.write(data, len) == len);
}

// return number of bytes for a non negative number
int mpint_size(bignum_t* x)
{
    uint32_t size=0;
    digit_t d;
    uint8_t msb=0;
    
    if (bignum_is_zero(x))
	return 1;
    d = x->digits[x->size-1];
    while(d) {
	msb = d;  // save msb
	size++;
	d >>= 8;
    }
    if ((msb & 0x80) != 0)
	size++;   // must add a zero (mpint is negative otherwise)
    return size + (x->size-1)*sizeof(digit_t);
}

// read bigendian 32-bit unsigned int from stdin
int read_uint32(uint32_t* vp)
{
    int i;
    uint32_t v = 0;
    for (i=0; i < (int)sizeof(uint32_t); i++) {
      uint8_t x;
      if (!read_uint8(&x)) return 0;
      v = (v<<8)|x;
    }
    *vp = v;
    return 1;
}

int read_digit(digit_t* vp)
{
    int i;
    digit_t v = 0;
    for (i=0; i < (int)sizeof(digit_t); i++) {
	uint8_t x;
	if (!read_uint8(&x)) return 0;
	v = (v<<8)|x;
    }
    *vp = v;
    return 1;
}

// write bigendian 16 bit
int write_uint16(uint16_t v)
{
    if (!write_uint8(v >> 8)) return 0;
    if (!write_uint8(v)) return 0;
    return 1;
}

// write bigendian 32 bit
int write_uint32(uint32_t v)
{
    if (!write_uint8(v >> 24)) return 0;
    if (!write_uint8(v >> 16)) return 0;
    if (!write_uint8(v >> 8)) return 0;        
    if (!write_uint8(v)) return 0;
    return 1;
}

int write_digit(digit_t d)
{
    int i;
    for (i = DEXP-8; i >= 0; i -= 8) {
    	if (!write_uint8(d >> i)) return 0;
    }
    return 1;
}

// write bigendian digits as bigendian
int write_mpint(digit_t* digit, int len)
{
    int i = len-1;
    int j;
    uint8_t msb;
    digit_t d;

    d = digit[i--];
    msb = 0;
    j = DEXP-8;
    while(j >= 0) { // skip leading zeros
	msb = d >> j;
	if (msb != 0) break;
	j -= 8;
    }
    if ((msb & 0x80) != 0) //  check if negative
	if (!write_uint8(0)) return 0;
    if (!write_uint8(msb)) return 0;
    j -= 8;
    while(j >= 0) {
	uint8_t b = d >> j;
	if (!write_uint8(b)) return 0;
	j -= 8;
    } 
    while(i >= 0) {
	if (!write_digit(digit[i])) return 0;
	i--;
    }
    return 1;
}

uint32_t blob_len(int vsn, rsakey_t* kp)
{
    if (vsn == 1) {
	return 1+4+
	    2+mpint_size(&kp->e)+
	    2+mpint_size(&kp->n);
    }
    else if (vsn == 2) {
	return 1+4+7+
	    4+mpint_size(&kp->e)+
	    4+mpint_size(&kp->n);
    }
    return 0;
}

// write v2 blob
void write_blob(int vsn, rsakey_t* kp)
{
    uint32_t blen = blob_len(vsn, kp);
    uint32_t esize = mpint_size(&kp->e);
    uint32_t nsize = mpint_size(&kp->n);    
    write_uint32(blen);
    if (vsn == 1) {
	uint32_t keysize = nsize*8;
	write_uint8(vsn);
	write_uint32(keysize);
	write_uint16(esize*8);          // number of bits!
	write_mpint(kp->e.digits, kp->e.size);
	write_uint16(nsize*8);  	// number of bits!
	write_mpint(kp->n.digits, kp->n.size);
    }
    else if (vsn == 2) {
	write_uint8(vsn);
	write_uint32(7);
	write_bytes((uint8_t*)"ssh-rsa", 7);
	write_uint32(esize);             // number of bytes
	write_mpint(kp->e.digits, kp->e.size);
	write_uint32(nsize);            // number of bytes
	write_mpint(kp->n.digits, kp->n.size);
    }
}

void setup()
{
#ifdef  K1024
    bignum_const(&key[0].d, key_1024_d, sizeof(key_1024_d)/sizeof(digit_t));
    bignum_const(&key[0].n, key_1024_n, sizeof(key_1024_n)/sizeof(digit_t));
    bignum_const(&key[0].p1, key_1024_p1, sizeof(key_1024_p1)/sizeof(digit_t));
    bignum_const(&key[0].p2, key_1024_p2, sizeof(key_1024_p2)/sizeof(digit_t));
    bignum_const(&key[0].e, key_1024_e, sizeof(key_1024_e)/sizeof(digit_t));
#endif

#ifdef  K2048
    bignum_const(&key[0].d, key_2048_d, sizeof(key_2048_d)/sizeof(digit_t));
    bignum_const(&key[0].n, key_2048_n, sizeof(key_2048_n)/sizeof(digit_t));
    bignum_const(&key[0].p1, key_2048_p1, sizeof(key_2048_p1)/sizeof(digit_t));
    bignum_const(&key[0].p2, key_2048_p2, sizeof(key_2048_p2)/sizeof(digit_t));
    bignum_const(&key[0].e, key_2048_e, sizeof(key_2048_e)/sizeof(digit_t));
#endif

#ifdef K4096
    bignum_const(&key[0].d, key_4096_d, sizeof(key_4096_d)/sizeof(digit_t));
    bignum_const(&key[0].n, key_4096_n, sizeof(key_4096_n)/sizeof(digit_t));
    bignum_const(&key[0].p1, key_4096_p1, sizeof(key_4096_p1)/sizeof(digit_t));
    bignum_const(&key[0].p2, key_4096_p2, sizeof(key_4096_p2)/sizeof(digit_t));
    bignum_const(&key[0].e, key_4096_e, sizeof(key_4096_e)/sizeof(digit_t));
#endif
    key_locked[0] = 1;

    pincode_init();
    
    Serial.begin(9600);
    while (!Serial)
	; // wait for serial port to connect. Needed for native USB port only
}

static const uint8_t sha1_prefix[15] = {
    0x30,0x21,  // sequence, length 33
    0x30,0x09,
    0x06,0x05,  // oid length 5
    0x2b,0x0e,0x03,0x02,0x1a,  // OID
    0x05,0x00,  // NULL */
    0x04,0x14   // octet string, length (20) !
};

// encode digest using EMSA PKCS1 V1.5 (asn1 encoded with padding)
// <<0,1,255:N,prefix/binary,hash:20>>
int encode_v15_sha1(uint8_t* hash, bignum_t* m, int key_size)
{
    int key_bytes = (key_size+7)>>3;
    unsigned pos;
    int n,i;

    pos = key_bytes-1;
    bignum_byte_set(m, pos--, 0x00, m);
    bignum_byte_set(m, pos--, 0x01, m);
    n = key_bytes-(SHA1_HASH_SIZE+sizeof(sha1_prefix))-3;
    while(n--) // PAD
	bignum_byte_set(m, pos--, 0xff, m);
    bignum_byte_set(m, pos--, 0x00, m);
    for (i = 0; i < (int)sizeof(sha1_prefix); i++) // ASN1 prefix
	bignum_byte_set(m, pos--, sha1_prefix[i], m);
    for (i = 0; i < SHA1_HASH_SIZE; i++)      // Hash
	bignum_byte_set(m, pos--, hash[i], m);
    return 0;
}

static void send_data(uint8_t code, const char* msg)
{
    int len = strlen(msg);
    write_uint32(1+len);
    write_uint8(code);
    write_bytes((uint8_t*)msg, len);
}

static void send_error(const char* msg)
{
    send_data(RSP_ERROR, msg);
}

void loop() 
{
    uint8_t  req;
    uint32_t reqlen;
    uint32_t rsplen;
    const char* code = "";

    check_pincode(key_pin, key_locked, NUM_RSA_KEYS);
    
    if (Serial.available() <= 0)
	return;
    if (!read_uint32(&reqlen)) return;
    if (!read_uint8(&req)) return;
    reqlen--;
    switch(req) {
    case REQ_ECHO: {
	write_uint32(1+reqlen);
	write_uint8(RSP_OK);
	while(reqlen--) {
	    uint8_t b;
	    read_uint8(&b);
	    write_uint8(b);
	}
	break;
    }
    case REQ_LIST: {
	int i;
	if (reqlen) goto einval;
	rsplen = 1+1;
	for (i = 0; i < NUM_RSA_KEYS; i++)
	    rsplen += (4+blob_len(2, &key[i]));
	write_uint32(rsplen);
	write_uint8(RSP_OK);
	write_uint8(NUM_RSA_KEYS);
	for (i = 0; i < NUM_RSA_KEYS; i++) {
	    write_blob(2, &key[i]);
	}
	break;
    }
      
    case REQ_SIGN: {
        uint32_t mlen;
	uint8_t k;
	int i;
        sha1_ctx_t ctx;
        uint8_t hash[SHA1_HASH_SIZE];

	if (reqlen < 1) goto einval;
        if (!read_uint8(&k)) goto eio;
	reqlen--;
        if (k >= NUM_RSA_KEYS) goto einval;

        if (key_locked[k]) {
	    beep(250); beep(250); beep(250);
            goto eaccess;
        }
	
	if (reqlen < 4) goto einval;
        if (!read_uint32(&mlen)) goto eio;
        reqlen -= 4;

	if (reqlen < mlen) goto einval;
	
	// process message bytes one at the time
	sha1_init(&ctx);

	for (i = 0; i < (int)mlen; i++) {
	    uint8_t mbuf[1];
	    if (!read_uint8(mbuf)) goto eio;
	    sha1_update(&ctx, mbuf, 1);
	    reqlen--;
	}
	
	sha1_final(&ctx, hash);
	
	AUTO_BEGIN {
	    BIGNUM_AUTO(r, key[k].n.size);
	    // BIGNUM_AUTO(m, key[k].n.size);
	    uint32_t rsize;
	    
	    encode_v15_sha1(hash, &r, key[k].n.size*sizeof(digit_t)*8);
	    bignum_powmod(&r, &key[k].d, &key[k].n, &r);

	    //bignum_powmod_two_prime(&r, &key[k].d, &key[k].p1, &key[k].p2, &r);
	    rsize = mpint_size(&r);
	    write_uint32(1 + 4 + rsize);
	    write_uint8(RSP_OK);
	    write_uint32(rsize);
	    write_mpint(r.digits, r.size);
	    Serial.flush();

	    beep(300);
		    
	    
	} AUTO_END;
	break;
    }
    default:
        goto einval;
    }
    return;
    
einval:
    code = "einval";
    goto error;
eaccess:
    code = "eaccess";
    goto error;
eio:
    code = "eio";
    goto emit_error;

error:
    while(reqlen) {
	if (!read_uint8(&req)) return;
	reqlen--;
    }

emit_error:
    send_error(code);
}
