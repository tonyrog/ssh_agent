//
//  Bignum library test
// 
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../c_src/bignum.h"
#include "../c_src/sha1.h"

// numbers used in some tests below

#define P1 "4205092373"
#define P2 "2648892151"
#define N  "11138836181069664323"  // N  = P1*P2 
#define L  "11138836174215679800"  // L = (P1-1)*(P2-1)
#define E  "65537"
#define D  "8048237016610999673"   // D = modinv(E,L)
//
// Message = <<"HELLO",0,0,0>> = 5207652434750472192
//
#define M    "5207652434750472192"
#define MDN  "1783597635534869275"  // M^D mod N (encrypted)

#define MDP1 "1797691939"           // M^D mod P1
#define MDP2 "882983471"            // M^D mod P2

#include <sys/time.h>
uint64_t time_tick(void)
{
    struct timeval t;
    gettimeofday(&t, 0);
    return t.tv_sec*(uint64_t)1000000 + t.tv_usec;
}

int hex(uint8_t* data, char* buf, size_t length)
{
    int i;
    for (i = 0; i < length; i++) {
	uint8_t h = data[i];
	buf[3*i]   = "0123456789abcdef"[h>>4];
	buf[3*i+1] = "0123456789abcdef"[h & 0xf];
	buf[3*i+2] = ' ';
    }
    buf[3*length-1] = '\0';
    return 3*length;
}


void test_1()
{
    AUTO_BEGIN {
	BIGNUM_AUTO(x, 3);
	BIGNUM_AUTO(y, 3);

	// fixme make bignum_from_string more precise with need
	bignum_from_string("12345678", &x);
	bignum_from_string("12345679", &y);
	if (!(bignum_comp(&x, &y) < 0)) { printf("ERROR\n"); return; }

	bignum_from_string("12345678", &x);
	bignum_from_string("12345678", &y);    
	if (!(bignum_comp(&x, &y) == 0)) { printf("ERROR\n"); return; }

	bignum_from_string("-12345678", &x);
	bignum_from_string("-12345678", &y);    
	if (!(bignum_comp(&x, &y) == 0)) { printf("ERROR\n"); return; }

	bignum_from_string("-12345678", &x);
	bignum_from_string("12345678", &y);    
	if (!(bignum_comp(&x, &y) < 0)) { printf("ERROR\n"); return; }
	
	printf("OK\n");
    } AUTO_END;	
}

// some bit stuff
void test_2()
{
    AUTO_BEGIN {    
	BIGNUM_AUTO(m, 9);

	bignum_from_string(M, &m);

	bignum_printf("m = %s\n", &m);
	printf("m #digits = %d\n", m.size);
	printf("m #bytes = %d\n", bignum_byte_size(&m));
	printf("m #bits  = %d\n", bignum_bit_size(&m));
	printf("m popcount = %d\n", bignum_popcount(&m));
	printf("n parity = %d\n", bignum_parity(&m));
    } AUTO_END;
}

void test_123456789()
{
    bignum_t a, b, c;

    bignum_halloc(&a, 8);
    bignum_halloc(&b, 8);
    bignum_halloc(&c, 8);

    bignum_from_string("3803", &a);
    bignum_from_string("3607", &b);
    bignum_multiply(&a, &b, &c);
    bignum_from_string("3", &a);
    bignum_multiply(&a, &c, &c);
    bignum_multiply(&a, &c, &c);
    bignum_printf("c = %s\n", &c);
}

void square(bignum_t* x , bignum_t* r, char* xs, char* rs)
{
    char* ptr;
    char  rbuf[64];
    
    bignum_from_string(xs, x);
    bignum_square(x, r);
    ptr = bignum_to_string(r, rbuf, sizeof(rbuf));
    if (strcmp(ptr, rs) == 0)
	printf("OK\n");
    else {
	bignum_printf("x*x = %s\n", r);
	printf("ERROR\n");
    }    
}

void test_sqr()
{
    AUTO_BEGIN {
	BIGNUM_AUTO(x, 8);
	BIGNUM_AUTO(r, 17);

	square(&x, &r, "3910", "15288100");
	square(&x, &r, "8199566", "67232882588356");
	square(&x, &r, "619663994", "383983465460032036");
	square(&x, &r, "62914277015", "3958206252320157310225");
	square(&x, &r, "140808825446040", "19827125323493361804951681600");

	square(&x, &r, "65535", "4294836225");
	square(&x, &r, "4294967295", "18446744065119617025");

	square(&x, &r, "65536", "4294967296");
	square(&x, &r, "4294967296","18446744073709551616");
    } AUTO_END;
}

void test_gcd()
{
    AUTO_BEGIN {
	BIGNUM_AUTO(x, 8);
	BIGNUM_AUTO(y, 8);
	BIGNUM_DYNAMIC(gcd);

	bignum_from_string("123456789123456789", &x);
	bignum_from_string("10000001", &y);

	bignum_printf("x = %s\n", &x);
	bignum_printf("y = %s\n", &y);
	
	bignum_gcd(&x, &y, &gcd);
	bignum_printf("gcd = %s\n", &gcd);

	bignum_gcd(&y, &x, &gcd);
	bignum_printf("gcd = %s\n", &gcd);    
    } AUTO_END;
}

void test_gcd2()
{
    AUTO_BEGIN {    
	BIGNUM_AUTO(x, 8);
	BIGNUM_AUTO(y, 8);
	BIGNUM_DYNAMIC(q);
	BIGNUM_DYNAMIC(r);

	bignum_from_string("12345677677", &x);
	bignum_from_string("7779112", &y);
	
	bignum_printf("x = %s\n", &x);
	bignum_printf("y = %s\n", &y);

	bignum_divrem(&x, &y, &q, &r);
	
	bignum_printf("q = %s\n", &q);
	bignum_printf("r = %s\n", &r);
    } AUTO_END;
}

void test_egcd()
{
    AUTO_BEGIN {    
	BIGNUM_AUTO(x, 8);
	BIGNUM_AUTO(y, 8);
	BIGNUM_DYNAMIC(m1);
	BIGNUM_DYNAMIC(m2);
	BIGNUM_DYNAMIC(gcd);    

	bignum_from_string("123456789123456789", &x);
	bignum_from_string("10000001", &y);

	bignum_printf("x = %s\n", &x);
	bignum_printf("y = %s\n", &y);
	
	bignum_egcd(&x, &y, &gcd, &m1, &m2);
	bignum_printf("gcd = %s\n", &gcd);
	bignum_printf("m1 = %s\n", &m1);
	bignum_printf("m2 = %s\n", &m2);
    } AUTO_END;
}

//
// Calculate: powmod(M,D,N)
// M is message "HELLO\0\0\0"
//

void test_powmod()
{
    AUTO_BEGIN {
	BIGNUM_AUTO(d, 9);
	BIGNUM_AUTO(n, 9);
	BIGNUM_AUTO(m, 9);
	BIGNUM_AUTO(r, 9);
	char* ptr;
	char  rbuf[64];

	printf("test_powmod\n");
	bignum_from_string(D, &d);
	bignum_from_string(N, &n);
	bignum_from_string(M, &m);
    
	bignum_printf("m = %s\n", &m);
	bignum_printf("d = %s\n", &d);
	bignum_printf("n = %s\n", &n);
	
	bignum_powmod(&m, &d, &n, &r);

	ptr = bignum_to_string(&r, rbuf, sizeof(rbuf));
	if (strcmp(ptr, MDN) == 0)
	    printf("OK\n");
	else {
	    bignum_printf("r = %s\n", &r);
	    printf("ERROR\n");
	}
    } AUTO_END;
}

//
// Calculate: powmod(M,D,N) = powmod_two_prime(M,D,P1,P2)
// M is message "HELLO\0\0\0"
//

void test_powmod_two_prime()
{
    AUTO_BEGIN {
	BIGNUM_AUTO(d, 9);
	BIGNUM_AUTO(p1, 5);
	BIGNUM_AUTO(p2, 5);
	BIGNUM_AUTO(m, 9);
	BIGNUM_AUTO(r, 9);
	char* ptr;
	char  rbuf[64];

	printf("test_powmod_two_prime\n");    
	bignum_from_string(D, &d);
	bignum_from_string(P1, &p1);
	bignum_from_string(P2, &p2);
	bignum_from_string(M, &m);

	bignum_printf("m = %s\n", &m);
	bignum_printf("d = %s\n", &d);
	bignum_printf("p1 = %s\n", &p1);
	bignum_printf("p2 = %s\n", &p2);        
    
	bignum_powmod_two_prime(&m, &d, &p1, &p2, &r);

	ptr = bignum_to_string(&r, rbuf, sizeof(rbuf));
	if (strcmp(ptr, MDN) == 0)
	    printf("OK\n");
	else {
	    bignum_printf("r = %s\n", &r);
	    printf("ERROR\n");
	}
    } AUTO_END;
}

void test_powmod_prime()
{
    AUTO_BEGIN {
	BIGNUM_AUTO(d, 9);
	BIGNUM_AUTO(p1, 5);
	BIGNUM_AUTO(p2, 5);
	BIGNUM_AUTO(m, 9);
	BIGNUM_AUTO(r, 4);
	char* ptr;
	char  rbuf[64];

	printf("test_powmod_prime\n");    
	bignum_from_string(D, &d);
	bignum_from_string(P1, &p1);
	bignum_from_string(P2, &p2);
	bignum_from_string(M, &m);
	
	bignum_printf("m = %s\n", &m);
	bignum_printf("d = %s\n", &d);
	bignum_printf("p1 = %s\n", &p1);
	bignum_printf("p2 = %s\n", &p2);

	bignum_powmod_prime(&m, &d, &p1, &r);
	ptr = bignum_to_string(&r, rbuf, sizeof(rbuf));
	if (strcmp(ptr, MDP1) == 0)
	    printf("OK\n");
	else {
	    bignum_printf("m^d mod p1 = %s\n", &r);
	    printf("ERROR\n");
	}
	
	bignum_powmod_prime(&m, &d, &p2, &r);
	ptr = bignum_to_string(&r, rbuf, sizeof(rbuf));
	if (strcmp(ptr, MDP2) == 0)
	    printf("OK\n");
	else {
	    bignum_printf("m^d mod p2 = %s\n", &r);
	    printf("ERROR\n");
	}
    } AUTO_END;
}

#define K4096

#ifdef K1024
#include "key_1024.h"  // 0,12s, (-O = 0,03s )
#include "message_1024.h"
#endif

#ifdef K2048
#include "key_2048.h"  // 0,12s, (-O = 0,03s )
#include "message_2048.h"
#endif

#ifdef K4096
#include "key_4096.h"  // 0,12s, (-O = 0,03s )
#include "message_4096.h"
#endif

#define NUM_RSA_KEYS 1

// p1*p2 = n
typedef struct _rsakey_t {
    bignum_t d;     // private exponent
    bignum_t p1;    // prime1
    bignum_t p2;    // prime2
    bignum_t n;     // modulus
    bignum_t e;     // public exponent
} rsakey_t;

rsakey_t key[NUM_RSA_KEYS];

void key_init()
{
#ifdef  K1024
    bignum_const(&key[0].d, key_1024_d, sizeof(key_1024_d)/sizeof(digit_t));
    bignum_const(&key[0].n, key_1024_n, sizeof(key_1024_n)/sizeof(digit_t));
    bignum_const(&key[0].p1, key_1024_p1, sizeof(key_1024_p1)/sizeof(digit_t));
    bignum_const(&key[0].p2, key_1024_p2, sizeof(key_1024_p2)/sizeof(digit_t));
    bignum_const(&key[0].e, key_1024_e, sizeof(key_1024_e)/sizeof(digit_t));
#endif

#ifdef K2048
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
    for (i = 0; i < sizeof(sha1_prefix); i++) // ASN1 prefix
	bignum_byte_set(m, pos--, sha1_prefix[i], m);
    for (i = 0; i < SHA1_HASH_SIZE; i++)      // Hash
	bignum_byte_set(m, pos--, hash[i], m);
    printf("pos = %d\n", pos);
    return 0;
}

int test_sign()
{
    uint64_t t0, t1;
    bignum_t msg;
    int rsz = key[0].n.size;
    sha1_ctx_t ctx;
    uint8_t hash[SHA1_HASH_SIZE];
    char hexbuf[SHA1_HASH_SIZE*3+1];    
    char* message = "Hello world";
    
    bignum_const(&msg, m_ds, sizeof(m_ds)/sizeof(digit_t));
    printf("G[%lu] = ", msg.size*sizeof(digit_t)*8);
    bignum_xprintf("%s\r\n", &msg);

    printf("message = %s\r\n", message);
    sha1_init(&ctx);
    sha1_update(&ctx, (uint8_t*) message, strlen(message));
    sha1_final(&ctx, hash);

    hex(hash, hexbuf, SHA1_HASH_SIZE);
    printf("SHA1(message) = %s\r\n", hexbuf);    

    AUTO_BEGIN {
	BIGNUM_AUTO(r, key[0].n.size);
	BIGNUM_AUTO(m, key[0].n.size);

	encode_v15_sha1(hash, &m, key[0].n.size*sizeof(digit_t)*8);
	printf("M[%lu] = ", msg.size*sizeof(digit_t)*8);
	bignum_xprintf("%s\n", &m);

	printf("D[%lu] = ", key[0].d.size*sizeof(digit_t)*8);
	bignum_xprintf("%s\n", &key[0].d);

	printf("N[%lu] = ", key[0].n.size*sizeof(digit_t)*8);
	bignum_xprintf("%s\n", &key[0].n);		

	t0 = time_tick();
	bignum_powmod(&m, &key[0].d, &key[0].n, &r);
	//bignum_powmod_two_prime(&msg, &key[0].d, &key[0].p1, &key[0].p2, &r);
	t1 = time_tick();
	printf("time = %lus, %luus\n",(t1-t0) / 1000000, (t1-t0) % 1000000);
	printf("S[%ld] = ", r.size*sizeof(digit_t)*8);
	bignum_xprintf("%s\n", &r);
    } AUTO_END;
    return 0;
}

int test_alloc()
{
    char* ptr;
    char  rbuf[64];
    
    AUTO_BEGIN {    
	BIGNUM_AUTO(x, 8);
	BIGNUM_AUTO(y, 8);
    
	bignum_from_string("3803", &x);
	bignum_from_string("4002", &y);
	AUTO_BEGIN {	
	    BIGNUM_DYNAMIC(z);
	    bignum_multiply(&x, &y, &z);

	    ptr = bignum_to_string(&z, rbuf, sizeof(rbuf));
	    if (strcmp(ptr, "15219606") == 0)
		printf("OK\n");
	    else {
		bignum_printf("z = %s\n", &z);
		printf("ERROR\n");
	    }
	} AUTO_END;
    } AUTO_END;
    return 0;
}

int main()
{
    test_1();
    test_2();
    test_123456789();
    test_sqr();
    test_powmod();
    test_powmod_prime();
    test_powmod_two_prime();    

    test_gcd2();
    test_gcd();
    test_egcd();
    test_alloc();

    key_init(); test_sign();

    bignum_hinfo();
    exit(0);
}
