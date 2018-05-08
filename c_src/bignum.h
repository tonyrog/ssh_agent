#ifndef __BIGNUM_H__
#define __BIGNUM_H__

#include <stdint.h>
#include <stdarg.h>
#include <errno.h>

typedef uint16_t digit_t;
typedef uint32_t ddigit_t;

// defines to be used outside of this file
// #define BIGNUM_TUNE              // extra tuning info
// #define BIGNUM_DEBUG

#define BIGNUM_USE_MUL_SQUARE

typedef struct
{
    uint16_t size;     // bignum length (number of digits)
    uint16_t asize;    // allocated size
    uint8_t  dynamic;  // allow dynamic allocation (count)
    uint8_t  sign;     // sign
    digit_t* digits;   // digit LSB ... MSB (little endian)
} bignum_t;

int bignum_copy(bignum_t* src, bignum_t* dst);
int bignum_copy_resize(bignum_t* src, bignum_t* dst, int min_size);
int bignum_small(bignum_t* x, digit_t d);

int bignum_is_zero(bignum_t* x);
int bignum_is_one(bignum_t* x);
int bignum_is_odd(bignum_t* x);
int bignum_is_even(bignum_t* x);

int bignum_comp(bignum_t* x, bignum_t* y);
int bignum_abs_comp(bignum_t* x, bignum_t* y);

int bignum_add(bignum_t* x, bignum_t* y, bignum_t* r);
int bignum_subtract(bignum_t* x, bignum_t* y, bignum_t* r);
int bignum_square(bignum_t* x, bignum_t* r);
int bignum_multiply(bignum_t* x, bignum_t* y, bignum_t* r);
int bignum_div(bignum_t* x, bignum_t* y, bignum_t* q);
int bignum_rem(bignum_t* x, bignum_t* y, bignum_t* r);
int bignum_mod(bignum_t* x, bignum_t* y, bignum_t* r);
int bignum_divrem(bignum_t* x, bignum_t* y, bignum_t* q, bignum_t* r);
int bignum_bsl(bignum_t* x, int y, bignum_t* r);
int bignum_bsr(bignum_t* x, int y, bignum_t* r);
int bignum_negate(bignum_t* x, bignum_t* r);
int bignum_abs(bignum_t* x, bignum_t* r);
int bignum_band(bignum_t* x, bignum_t* y, bignum_t* r);
int bignum_bor(bignum_t* x, bignum_t* y, bignum_t* r);
int bignum_bxor(bignum_t* x, bignum_t* y, bignum_t* r);
int bignum_bnot(bignum_t* x, bignum_t* r);
int bignum_bit_test(bignum_t* x, unsigned pos);
int bignum_bit_set(bignum_t* x, unsigned pos, bignum_t* r);
int bignum_byte_set(bignum_t* x, unsigned pos, uint8_t b, bignum_t* r);
int bignum_bit_clear(bignum_t* x, unsigned pos, bignum_t* r);
int bignum_bit_toggle(bignum_t* x, unsigned pos, bignum_t* r);
int bignum_ffs(bignum_t* x);
int bignum_clz(bignum_t* x);     // number of leading 0-bits from MSB, or 0
int bignum_ctz(bignum_t* x);     // number of trailing 0-bits from LSB, or 0
int bignum_clrsb(bignum_t* x);   // number of redunant bits from MSB
int bignum_popcount(bignum_t* x);
int bignum_parity(bignum_t* x);
int bignum_byte_size(bignum_t* x);
int bignum_bit_size(bignum_t* x);
int bignum_powmod(bignum_t* x, bignum_t* n, bignum_t* m, bignum_t* r);
int bignum_powmod_prime(bignum_t* a, bignum_t* b, bignum_t* p, bignum_t* r);
int bignum_powmod_two_prime (bignum_t* a,bignum_t* b, bignum_t* p1,bignum_t* p2,
			     bignum_t* r);
int bignum_gcd(bignum_t* x, bignum_t* y, bignum_t* gcd);
int bignum_egcd(bignum_t* a, bignum_t* b, bignum_t* gcd,
		bignum_t* x,bignum_t* y);
int bignum_from_strn(char* ptr, int len, bignum_t* x);
int bignum_from_string(char* ptr, bignum_t* x);
char* bignum_to_string(bignum_t* x, char* ptr, int sz);
char* bignum_to_xstring(bignum_t* x, char* ptr, int sz);

// advanced or less useful
digit_t* bignum_hsave(void);
void bignum_hrestore(digit_t* saved);
int bignum_push_htop(void);
int bignum_pop_htop(void);
int bignum_halloc(bignum_t* xp, int ndigits);
int bignum_halloc_copy(bignum_t* src, bignum_t* dst);
int bignum_init(bignum_t* bp, digit_t* ds, int ndigits);
int bignum_const(bignum_t* bp, const digit_t* ds, int ndigits);

#define CAT_HELPER2(x,y) x ## y
#define CAT2(x,y) CAT_HELPER2(x,y)

#define BIGNUM_INIT(sz,asz,dnm,sgn,dgts)				\
    {.size=(sz),.asize=(asz),.dynamic=(dnm),.sign=(sgn),.digits=(dgts)}

// stack allocated small bignumber
#define BIGNUM_SMALL(n, v)						\
    digit_t CAT2(n,_ds) = ((v)<0)?-(v):(v);				\
    bignum_t n=BIGNUM_INIT(1,1,0,((v)<0),&CAT2(n,_ds))

#define BIGNUM_CONST_SMALL(n, v)					\
    const digit_t CAT2(n,_ds) = ((v)<0)?-(v):(v);			\
    const bignum_t n = BIGNUM_INIT(1,0,0,((v)<0),&CAT2(n,_ds))

// stack allocated bignum
/*
 * #define BIGNUM_AUTO(n, s)						\
 * digit_t CAT2(n,_ds)[(s)]; bignum_t n=BIGNUM_INIT(0,(s),0,0,CAT2(n,_ds))
 */

// heap allocated auto bignum ( auto must be in AUTO_BEGIN / AUTO_END block )
#define BIGNUM_AUTO(n, s) \
    bignum_t n=BIGNUM_INIT(0,(s),0,0,bignum_halloc_digits((s)))

// dynamic bignum, heap allocate on first check
#define BIGNUM_DYNAMIC(n) \
    bignum_t n=BIGNUM_INIT(0,0,1,0,(digit_t*)0)

// swap bignum pointers
#define BIGNUM_SWAP(a,b) do { bignum_t* __t = (a); a = (b); b = __t; } while(0)

#define AUTO_BEGIN   do { bignum_push_htop(); do {

// break inner "dummy loop"
#define AUTO_LEAVE   break

#define AUTO_END     } while(0); bignum_pop_htop(); } while(0)


#define DEXP  (sizeof(digit_t)*8) // number of bits per digit
#define DMASK ((digit_t)-1)       // mask for digit bits

#ifndef BIGNUM_HEAP_SIZE
#define BIGNUM_HEAP_SIZE 8192
#endif

#ifndef BIGNUM_HSTACK_SIZE
#define BIGNUM_HSTACK_SIZE 16
#endif

static digit_t  bignum_heap[BIGNUM_HEAP_SIZE];
static digit_t* bignum_htop = bignum_heap;
static digit_t* bignum_hend = bignum_heap + BIGNUM_HEAP_SIZE;
static digit_t* bignum_hstack[BIGNUM_HSTACK_SIZE];
static int bignum_hsp = -1;
#ifdef BIGNUM_TUNE
static int bignum_max_hsp = -1;
static digit_t* bignum_max_htop = bignum_heap;
#endif

BIGNUM_SMALL(bignum_zer0, 0);
BIGNUM_SMALL(bignum_one,  1);
BIGNUM_SMALL(bignum_two,  2);
BIGNUM_SMALL(bignum_ten,  10);

#define MIN(a,b) (((a)<(b)) ? (a) : (b))
#define MAX(a,b) (((a)>(b)) ? (a) : (b))

/* add a and b with carry in + out */
#define DSUMc(a,b,c,s) do {						\
	digit_t ___cr = (c);					\
	digit_t ___xr = (a)+(___cr);				\
	digit_t ___yr = (b);						\
	___cr = (___xr < ___cr);					\
	___xr = ___yr + ___xr;						\
	___cr += (___xr < ___yr);					\
	s = ___xr;							\
	c = ___cr;							\
    }  while(0)

/* add a and b with carry out */
#define DSUM(a,b,c,s) do {						\
	digit_t ___xr = (a);					\
	digit_t ___yr = (b);						\
	___xr = ___yr + ___xr;						\
	s = ___xr;							\
	c = (___xr < ___yr);						\
    }  while(0)

#define DSUBb(a,b,r,d) do {						\
	digit_t ___cr = (r);						\
	digit_t ___xr = (a);						\
	digit_t ___yr = (b)+___cr;					\
	___cr = (___yr < ___cr);					\
	___yr = ___xr - ___yr;						\
	___cr += (___yr > ___xr);					\
	d = ___yr;							\
	r = ___cr;							\
    } while(0)

#define DSUB(a,b,r,d) do {				\
	digit_t ___xr = (a);				\
	digit_t ___yr = (b);				\
	___yr = ___xr - ___yr;				\
	r = (___yr > ___xr);				\
	d = ___yr;					\
    } while(0)

#define DLOW(x)        ((digit_t)(x))
#define DHIGH(x)       ((digit_t)(((ddigit_t)(x)) >> DEXP))

#define DLOW2HIGH(x)   (((ddigit_t)(x)) << DEXP)
#define DDIGIT(a1,a0)  (DLOW2HIGH(a1) + (a0))

#define DMULc(a,b,c,p) do {					\
	ddigit_t _t = ((ddigit_t)(a))*(b) + (c);		\
	p = DLOW(_t);						\
	c = DHIGH(_t);						\
    } while(0)

#define DMUL(a,b,c1,c0) do {				\
	ddigit_t _t = ((ddigit_t)(a))*(b);		\
	c0 = DLOW(_t);					\
	c1 = DHIGH(_t);					\
    } while(0)

#define DDIV(a1,a0,b,q) do {						\
	ddigit_t _t = DDIGIT((a1),(a0));				\
	q = _t / (b);							\
    } while(0)

#define DDIV2(a1,a0,b1,b0,q) do {					\
	ddigit_t _t = DDIGIT((a1),(a0));				\
	q = _t / DDIGIT((b1),(b0));					\
    } while(0)

#define DREM(a1,a0,b,r) do {				\
	ddigit_t _t = DDIGIT((a1),(a0));		\
	r = _t % (b);					\
    } while(0)

#ifdef BIGNUM_DEBUG
#define DBGPRINT(...) emit_error(__FILE__,__LINE__,__VA_ARGS__)
#else
#define DBGPRINT(...)
#endif

#define bignum_enomem() do {				\
	DBGPRINT("bignum heap out of memory\r\n");	\
	break_here();					\
	return -1;					\
    } while(0)

#define bignum_enospc() do {				\
	DBGPRINT("bignum destination out of memory");	\
	break_here();					\
	return -1;					\
    } while(0)

#define bignum_eoverflow() do {			\
	DBGPRINT("bignum blocks to deep");	\
	break_here();				\
	return -1;				\
    } while(0)

#define bignum_enobufs() do {			\
	DBGPRINT("bignum stack underflow");	\
	break_here();				\
	return -1;				\
    } while(0)

#define bignum_einval() do {			\
	DBGPRINT("bignum bad argument");	\
	break_here();				\
	return -1;				\
    } while(0)

#ifdef BIGNUM_DEBUG
void emit_error(char* file, int line, ...)
{
    va_list ap;
    char* fmt;
    int save_errno = errno;
    va_start(ap, line);
    fmt = va_arg(ap, char*);
    fprintf(stderr, "%s:%d: ", file, line); 
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\r\n");
    va_end(ap);
    errno = save_errno;
}
#endif

void break_here()
{
    DBGPRINT("break here");
}

static digit_t* bignum_halloc_digits(int n)
{
    if (bignum_htop + n <= bignum_hend) {
	digit_t* xs = bignum_htop;
	bignum_htop += n;
#ifdef BIGNUM_TUNE	
	if (bignum_htop > bignum_max_htop) {
	    bignum_max_htop = bignum_htop;
	    // DBGPRINT("heap grow, size = %d", bignum_max_htop - bignum_heap);
	}
#endif	
	return xs;
    }
    DBGPRINT("bignum heap out of memory, alloc %d digit", n);
    break_here();
    return (digit_t*) 0;
}

int bignum_halloc(bignum_t* x, int n)
{
    digit_t* xs = bignum_halloc_digits(n);
    if (xs != (digit_t*) 0) {
	x->digits = xs;
	x->asize  = n;
	return 0;
    }
    return -1;
}

int bignum_resize(bignum_t* xp, int ndigits)
{
    if ((int)xp->asize >= ndigits) // allocated size if ok
	return 0;
    if (xp->dynamic) { // allow dynamic allocation (n times!)
	xp->dynamic--;
	return bignum_halloc(xp, ndigits);
    }
    bignum_enospc();
}

int bignum_push_htop()
{
    if (bignum_hsp >= BIGNUM_HSTACK_SIZE-1) bignum_eoverflow();
    bignum_hstack[++bignum_hsp] = bignum_htop;
#ifdef BIGNUM_TUNE
    if (bignum_hsp > bignum_max_hsp) bignum_max_hsp = bignum_hsp;
#endif
    return 0;
}

int bignum_pop_htop()
{
    if (bignum_hsp <= -1) bignum_enobufs();
    bignum_htop = bignum_hstack[bignum_hsp--];
    return 0;
}

digit_t* bignum_hsave()
{
    return bignum_htop;
}

void bignum_hrestore(digit_t* saved)
{
    bignum_htop = saved;
}

void bignum_hinfo()
{
#ifdef BIGNUM_TUNE
    DBGPRINT("hinfo: heap total=%ld", BIGNUM_HEAP_SIZE);
    DBGPRINT("hinfo: heap free=%ld", bignum_hend - bignum_htop);
    DBGPRINT("hinfo: heap max use=%ld", bignum_max_htop - bignum_heap);
    DBGPRINT("hinfo: stack total=%ld", BIGNUM_HSTACK_SIZE);
    DBGPRINT("hinfo: stack free=%ld", BIGNUM_HSTACK_SIZE-(bignum_hsp+1));
    DBGPRINT("hinfo: stack max use=%ld", bignum_max_hsp+1);
#endif
}

int bignum_is_zero(bignum_t* x)
{
    return (x->size==1) && (x->digits[0]==0);
}

int bignum_is_one(bignum_t* x)
{
    return !x->sign && (x->size==1) && (x->digits[0]==1);
}

int bignum_is_odd(bignum_t* x)
{
    return ((x->digits[0] & 1) == 1);
}

int bignum_is_even(bignum_t* x)
{
    return ((x->digits[0] & 1) == 0);
}

// n is number of digits
int bignum_init(bignum_t* bp, digit_t* ds, int n)
{
    bp->size = 0;
    bp->asize = n;
    bp->dynamic = 0;
    bp->sign = 0;
    bp->digits = ds;
    return 0;
}

// n is number of digits
int bignum_const(bignum_t* bp, const digit_t* ds, int n)
{
    bp->size = n;
    bp->asize = 0;
    bp->dynamic = 0;
    bp->sign = 0;
    bp->digits = (digit_t*) ds;
    return 0;
}

// setup bignum as a small constant
int bignum_small(bignum_t* x, digit_t d)
{
    if (bignum_resize(x, 1) < 0) return -1;
    x->sign  = 0;
    x->size  = 1;
    x->digits[0] = d;
    return 1;
}

static void b_zero(digit_t* dst, int n)
{
    int i;
    for (i = 0; i < n; i++) dst[i] = 0;
}

static void b_copy(digit_t* src, digit_t* dst, int n)
{
    int i;
    for (i = 0; i < n; i++) dst[i] = src[i];
}

int bignum_copy(bignum_t* src, bignum_t* dst)
{
    if (dst == (bignum_t*) 0)
	return 0;
    else if (src != dst) {
	if (bignum_resize(dst, src->size) < 0) return -1;    	
	dst->sign = src->sign;    
	dst->size = src->size;
	b_copy(src->digits, dst->digits, src->size);
    }
    return src->size;
}

int bignum_copy_resize(bignum_t* src, bignum_t* dst, int min_size)
{
    digit_t* xp = src->digits;  // save digit pointer & size
    int xl      = src->size;

    if (bignum_resize(dst, min_size) < 0) return -1;
    if (xp != dst->digits) {
	dst->sign = src->sign;
	b_copy(xp, dst->digits, MIN(xl,min_size));
    }
    if (xl < min_size)
	b_zero(dst->digits+xl, min_size-xl);
    if ((int)dst->size < min_size)
	dst->size = min_size;
    return dst->size;
}

// allocate a new copy of dst
int bignum_halloc_copy(bignum_t* src, bignum_t* dst)
{
    digit_t* xp = src->digits;
    int xl      = src->size;
    if (bignum_halloc(dst, src->size) < 0) return -1;
    b_copy(xp, dst->digits, xl);
    dst->size = xl;
    dst->sign = src->sign;
    return xl;
}

// calculate dst = src1 + src2 ( + carry)
static digit_t b_add3(digit_t* src1, digit_t* src2, digit_t* dst, 
		       digit_t carry, int n)
{
    int i = 0;
    while(i < n) {
	digit_t x = *src2++;
	digit_t y = *src1++ + carry;
	carry = (y < carry);
	y = x + y;
	carry += (y < x);
	*dst++ = y;
	i++;
    }
    return carry;
}

static digit_t b_add2(digit_t* src, digit_t* dst, digit_t d, int n)
{
    int i = 0;
    while(i < n) {
	digit_t y = *src++ + d;
	d = (y < d);
	*dst++ = y;
	i++;
    }
    return d;
}

static digit_t b_sub3(digit_t* src1, digit_t* src2, digit_t* dst,
		      digit_t borrow, int n)
{
    int i=0;
    while(i < n) {
	digit_t x = *src1++;
	digit_t y = *src2++ + borrow;
	borrow = (y < borrow);
	y = x - y;
	borrow += (y > x);
	*dst++ = y;
	i++;
    }
    return borrow;
}

static digit_t b_sub2(digit_t* src,digit_t* dst, digit_t d, int n)
{
    int i=0;
    while(i < n) {
	digit_t x = *src++;
	digit_t y = x - d;
	d = (y > x);
	*dst++ = y;
	i++;
    }
    return d;
}

static int d_mul(digit_t* x, int xl, digit_t d, digit_t* r)
{
    digit_t c = 0;
    int rl = xl;
    digit_t p;

    while(xl--) {
	DMULc(d, *x, c, p);
	*r++ = p;
	x++;
    }
    if (c == 0)
	return rl;
    *r = c;
    return rl+1;
}

// r = d*(y0...yn) - (x0..xm)
static int d_mulsub(digit_t* x, int xl, digit_t d,
		    digit_t* y, int yl, digit_t* r)
{
    digit_t c = 0;
    digit_t b = 0;
    digit_t c0;
    digit_t* r0 = r;
    digit_t s;

    xl -= yl;
    while(yl--) {
	DMULc(d, *y, c, c0);
	DSUBb(*x, c0, b, s);
	*r++ = s;
	x++;
	y++;
    }
    if (xl == 0) {
	if ((c != 0) || (b != 0))
	    return 0;
    }
    else { // xl == 1
	DSUBb(*x, c, b, s);
	*r++ = s;
    }
    if (b != 0) return 0;

    do {
	r--;
    } while((*r == 0) && (r != r0));
    return (r - r0) + 1;
}


// Square digits in x store in r (x & r may point into a common area)
// Assumption: x is destroyed if common area and digits in r are zero
// to the size of xl+1

static int b_sqr(digit_t* x, int xl, digit_t* r)
{
    digit_t d_next = *x;
    digit_t d;
    digit_t* r0 = r;
    digit_t* s = r;

    if ((r + xl) == x)	/* "Inline" operation */
	*x = 0;
    x++;
	
    while(xl--) {
	digit_t* y = x;
	digit_t y_0 = 0, y_1 = 0, y_2 = 0, y_3 = 0;
	digit_t b0, b1;
	digit_t z0, z1, z2;
	digit_t t;
	int y_l = xl;
		
	s = r;
	d = d_next;
	d_next = *x; 
	x++;

	DMUL(d, d, b1, b0);
	DSUMc(*s, b0, y_3, t);
	*s++ = t;
	z1 = b1;
	while(y_l--) {
	    DMUL(d, *y, b1, b0);
	    y++;
	    DSUMc(b0, b0, y_0, z0);
	    DSUMc(z0, z1, y_2, z2);
	    DSUMc(*s, z2, y_3, t);
	    *s++ = t;
	    DSUMc(b1, b1, y_1, z1);
	}
	z0 = y_0;
	DSUMc(z0, z1, y_2, z2);
	DSUMc(*s, z2, y_3, t);
	*s = t;
	if (xl != 0) {
	    s++;
	    t = (y_1+y_2+y_3);
	    *s = t;
	    r += 2;
	}
    }
    if (*s == 0)
	return (s - r0);
    else
	return (s - r0) + 1;
}

// Multiply digits in x with digits in y and store in r
// Assumption: digits in r must be 0 (upto the size of x)

static int b_mul(digit_t* x, int xl, digit_t* y, int yl, digit_t* r)
{
    digit_t* r0 = r;
    digit_t* rt = r;

    while(xl--) {
	digit_t cp = 0;
	digit_t c = 0;
	int n = yl;
	digit_t* yt = y;
	digit_t d;
	digit_t p;

	d = *x; 
	x++;
	rt = r;

	while(n--) {
	    DMULc(d,*yt, cp, p);
	    DSUMc(p,*rt, c, p);
	    *rt++ = p;
	    yt++;
	}
	*rt = c + cp;
	r++;
    }
    if (*rt == 0)
	return (rt - r0);
    else
	return (rt - r0) + 1;
}


static int b_comp(digit_t* xp, int xl, digit_t* yp, int yl)
{
    if (xl < yl)
	return -1;
    else if (xl > yl)
	return 1;
    else {
	if (xp == yp)
	    return 0;
	xp += (xl-1);
	yp += (yl-1);
	while((xl > 0) && (*xp == *yp)) {
	    xp--;
	    yp--;
	    xl--;
	}
	if (xl == 0)
	    return 0;
	return (*xp < *yp) ? -1 : 1;
    }
}

// sign(|x|-|y|)
int bignum_abs_comp(bignum_t* x, bignum_t* y)
{
    return b_comp(x->digits, x->size, y->digits, y->size);
}

// sign(x-y)
int bignum_comp(bignum_t* x, bignum_t* y)
{
    if (!x->sign && !y->sign)
	return b_comp(x->digits, x->size, y->digits, y->size);
    else if (x->sign && !y->sign)
	return -1;
    else if (!x->sign && y->sign)
	return 1;
    else
	return -b_comp(x->digits, x->size, y->digits, y->size);
}

// remove trailing zeros from src
static int bu_trail(digit_t* src, int n)
{
    while((n>1) && !src[n-1])
	n--;
    return n;
}

// Remove trailing digits from bitwise operations
// convert negative numbers to one complement

static int b_trail(digit_t* src,int n,int sign)
{
    if (sign) { 
	int i;
	digit_t d;

	while((n>1) && ((d = src[n-1]) == DMASK))
	    n--;
	if (d == DMASK)
	    src[n-1] = 0;
	else {
	    digit_t prev_mask = 0;
	    digit_t  mask = (1 << (DEXP-1));

	    while((d & mask) == mask) {
		prev_mask = mask;
		mask = (prev_mask >> 1) | (1 << (DEXP-1));
	    }
	    src[n-1] = ~d & ~prev_mask;
	}
	for (i=0; i < n-1; i++)
	    src[i] = ~src[i];
	b_add2(src, src, 1, n);
	return n;
    }
    return bu_trail(src, n);
}

// Assume xl >= yl
static int b_band(digit_t* xp, int sign1, int xl,
		  digit_t* yp, int sign2, int yl,
		  bignum_t* dst)
{
    digit_t* r;

    if (bignum_resize(dst, MAX(xl, yl)) < 0) return -1;
    r = dst->digits;
    xl -= yl;

    if (!sign1) {
	if (!sign2) {
	    while(yl--)
		*r++ = *xp++ & *yp++;
	}
	else {
	    digit_t b;
	    digit_t c;

	    DSUB(*yp,1,b,c);
	    *r++ = *xp++ & ~c;
	    yp++;
	    yl--;
	    while(yl--) {
		DSUBb(*yp,0,b,c);
		*r++ = *xp++ & ~c;
		yp++;
	    }
	    while (xl--) {
		*r++ = *xp++;
	    }
	}
    }
    else {
	if (!sign2) {
	    digit_t b;
	    digit_t c;

	    DSUB(*xp,1,b,c);
	    *r = ~c & *yp;
	    xp++; yp++; r++;
	    yl--;
	    while(yl--) {
		DSUBb(*xp,0,b,c);
		*r++ = ~c & *yp++;
		xp++;
	    }
	}
	else {
	    digit_t b1, b2;
	    digit_t c1, c2;

	    DSUB(*xp,1,b1,c1);
	    DSUB(*yp,1,b2,c2);
	    *r++ = ~c1 & ~c2;
	    xp++; yp++;
	    yl--;
	    while(yl--) {
		DSUBb(*xp,0,b1,c1);
		DSUBb(*yp,0,b2,c2);
		*r++ = ~c1 & ~c2;
		xp++; yp++;
	    }
	    while(xl--)
		*r++ = ~*xp++;
	}
    }
    dst->sign = sign1 && sign2;
    dst->size = b_trail(dst->digits,(r - dst->digits), dst->sign);
    return 0;
}

// Assume xl >= yl
static int b_bor(digit_t* xp, int sign1, int xl,
		 digit_t* yp, int sign2, int yl,
		 bignum_t* dst)
{
    digit_t* r;
    if (bignum_resize(dst, MAX(xl, yl)) < 0) return -1;    
    r = dst->digits;
    xl -= yl;

    if (!sign1) {
	if (!sign2) {
	    while(yl--)
		*r++ = *xp++ | *yp++;
	    while(xl--)
		*r++ = *xp++;
	}
	else {
	    digit_t b;
	    digit_t c;

	    DSUB(*yp,1,b,c);
	    *r++ = *xp++ | ~c;
	    yp++;
	    yl--;
	    while(yl--) {
		DSUBb(*yp,0,b,c);
		*r++ = *xp++ | ~c;
		yp++;
	    }
	}
    }
    else {
	if (!sign2) {
	    digit_t b;
	    digit_t c;

	    DSUB(*xp,1,b,c);
	    *r++ = ~c | *yp++;
	    xp++;
	    yl--;
	    while(yl--) {
		DSUBb(*xp,0,b,c);
		*r++ = ~c | *yp++;
		xp++;
	    }
	    while(xl--) {
		DSUBb(*xp,0,b,c);
 		*r++ = ~c;
 		xp++;
	    }
	}
	else {
	    digit_t b1, b2;
	    digit_t c1, c2;

	    DSUB(*xp,1,b1,c1);
	    DSUB(*yp,1,b2,c2);
	    *r++ = ~c1 | ~c2;
	    xp++; yp++;
	    yl--;
	    while(yl--) {
		DSUBb(*xp,0,b1,c1);
		DSUBb(*yp,0,b2,c2);
		*r++ = ~c1 | ~c2;
		xp++; yp++;
	    }
	}
    }
    dst->sign = sign1 || sign2;
    dst->size = b_trail(dst->digits, (r - dst->digits), dst->sign);
    return 0;
}

// Assume xl >= yl
static int b_bxor(digit_t* xp, int sign1, int xl,
		  digit_t* yp, int sign2, int yl,
		  bignum_t* dst)
{
    digit_t* r;
    if (bignum_resize(dst, MAX(xl, yl)) < 0) return -1;
    r = dst->digits;
    xl -= yl;

    if (!sign1) {
	if (!sign2) {
	    while(yl--)
		*r++ = *xp++ ^ *yp++;
	    while(xl--)
		*r++ = *xp++;
	}
	else {
	    digit_t b;
	    digit_t c;

	    DSUB(*yp,1,b,c);
	    *r++ = *xp++ ^ ~c;
	    yp++;
	    yl--;
	    while(yl--) {
		DSUBb(*yp,0,b,c);
		*r++ = *xp++ ^ ~c;
		yp++;
	    }
	    while(yl--)
		*r++ = ~*xp++;
	}
    }
    else {
	if (!sign2) {
	    digit_t b;
	    digit_t c;

	    DSUB(*xp,1,b,c);
	    *r++ = ~c ^ *yp++;
	    xp++;
	    yl--;
	    while(yl--) {
		DSUBb(*xp,0,b,c);
		*r++ = ~c ^ *yp++;
		xp++;
	    }
	    while(xl--)
 		*r++ = ~*xp++;
	}
	else {
	    digit_t b1, b2;
	    digit_t c1, c2;

	    DSUB(*xp,1,b1,c1);
	    DSUB(*yp,1,b2,c2);
	    *r++ = ~c1 ^ ~c2;
	    xp++; yp++;
	    yl--;
	    while(yl--) {
		DSUBb(*xp,0,b1,c1);
		DSUBb(*yp,0,b2,c2);
		*r++ = ~c1 ^ ~c2;
		xp++; yp++;
	    }
	    while(xl--) {
		*r++ = *xp++;
	    }	    
	}
    }
    dst->sign =  sign1 != sign2;
    dst->size = b_trail(dst->digits,(r - dst->digits), dst->sign);
    return 0;
}

static int b_addsub(digit_t* xp,int sign1,int xl,
		    digit_t* yp,int sign2,int yl,
		    bignum_t* dst)
{
    if (sign1 == sign2) {
	digit_t carry = 0;

	if (bignum_resize(dst, MAX(xl, yl)+1) < 0) return -1;    

	if (xl < yl) {
	    carry = b_add3(xp, yp, dst->digits, carry, xl);
	    carry = b_add2(yp+xl, dst->digits+xl, carry, yl-xl);
	    dst->size = yl;
	}
	else {
	    carry = b_add3(yp, xp, dst->digits, carry, yl);
	    carry = b_add2(xp+yl, dst->digits+yl, carry, xl-yl);
	    dst->size = xl;
	}
	if (carry)
	    dst->digits[dst->size++] = carry;
	dst->sign = sign1;
    }
    else {
	int cmp = b_comp(xp, xl, yp, yl);
	if (cmp == 0) {
	    bignum_small(dst, 0);
	}
	else {
	    if (bignum_resize(dst, MAX(xl, yl)) < 0) return -1;
	    if (cmp > 0) {
		digit_t borrow = 0;

		borrow = b_sub3(xp,yp,dst->digits,borrow,yl);
		b_sub2(xp+yl,dst->digits+yl,borrow,xl-yl);
		dst->size = bu_trail(dst->digits,xl);
		dst->sign = bignum_is_zero(dst) ? 0 : sign1;
	    }
	    else {
		digit_t borrow = 0;
		
		borrow = b_sub3(yp,xp,dst->digits,borrow,xl);
		b_sub2(yp+xl,dst->digits+xl,borrow,yl-xl);
		dst->size = bu_trail(dst->digits,yl);
		dst->sign = bignum_is_zero(dst) ? 0 : sign2;
	    }
	}
    }
    return 0;
}

static int b_bnot(digit_t* xp, int sign, int xl,
		  bignum_t* dst)
{
    digit_t one = 1;
    int r;
    if (!sign)
	r=b_addsub(xp, sign, xl, &one, 1, 0, dst);
    else
	r=b_addsub(xp, sign, xl, &one, 1, 1, dst);
    if (r < 0)
	return -1;
    dst->sign = !sign;
    return 0;
}


static int d_div(digit_t* x, int xl, digit_t d, digit_t* q, digit_t* r)
{
    digit_t* xp = x + (xl-1);
    digit_t* qp = q + (xl-1);
    int qsz = xl;
    digit_t a1;
	
    a1 = *xp; 
    xp--;

    if (d > a1) {
	if (xl == 1) {
	    *r = a1;
	    *qp = 0;
	    return 1;
	}
	qsz--;
	qp--;
    }

    do {
	digit_t q0, a0, b0;
	digit_t b;
	digit_t b1;
	(void) b;
	(void) b1;

	if (d > a1) {
	    a0 = *xp; 
	    xp--;
	}
	else {
	    a0 = a1; a1 = 0;
	}
	DDIV(a1, a0, d, q0);
	DMUL(d, q0, b1, b0);
	DSUB(a0,b0, b, a1);
	*qp = q0;
	qp--;
    } while (xp >= x);

    *r = a1;
    return qsz;
}

static int d_sub(digit_t* x, int xl, digit_t c, digit_t* r)
{
    digit_t* r0 = r;
    digit_t yr, xr;

    while(xl--) {
	// DSUB(*x++,c,c,*r++)
	xr = *x++;
	yr = xr - c;
	c = (yr > xr);
	*r++ = yr;
    }
    do {
	r--;
    } while((*r == 0) && (r != r0));

    return (r - r0) + 1;
}

// fixme: xp, yp, rp
static int d_add(digit_t* x, int xl, digit_t c, digit_t* r)
{
    int sz = xl;
    register digit_t xr;

    while(xl--) {
	// DSUM(*x++,c,c,*r++)
	xr = *x++ + c;
	c = (xr < c);
	*r++ = xr;
    }
    if (c) {
	*r = 1;
	return sz+1;
    }
    return sz;
}

// fixme: xp, yp, rp
static int b_sub(digit_t* x, int xl, digit_t* y, int yl, digit_t* r)
{
    digit_t* r0 = r;
    digit_t yr, xr;
    digit_t c = 0;

    xl -= yl;
    do {
	yr = *y++ + c;
	xr = *x++;
	c = (yr < c);
	yr = xr - yr;
	c += (yr > xr);
	*r++ = yr;
    } while(--yl);

    while(xl--) {
	xr = *x++;
	yr = xr - c;
	c = (yr > xr);
	*r++ = yr;
    }
    do {
	r--;
    } while(*r == 0 && r != r0);

    return (r - r0) + 1;
}

// fixme: yp, rp
static int z_sub(digit_t* y, int yl, digit_t* r)
{
    digit_t* r0 = r;
    digit_t yr;
    digit_t c = 0;

    while(yl--) {
	yr = *y++ + c;
	c = (yr < c);
	yr = 0 - yr;
	c += (yr > 0);
	*r++ = yr;
    }
    do {
	r--;
    } while(*r == 0 && r != r0);
    return (r - r0) + 1;
}

// arithmetic left shift or right
static int b_lshift(digit_t* x, int xl, int y, int sign, digit_t* r)
{
    if (y == 0) {
	b_copy(x, r, xl);
	return xl;
    }
    else if ((xl == 1) && (*x == 0)) {
	*r = 0;
	return 1;
    }
    else {
	int ay = (y < 0) ? -y : y;
	unsigned bw = ay / DEXP;
	unsigned sw = ay % DEXP;
	int rl;
	digit_t a1=0;
	digit_t a0=0;

	if (y > 0) {		// shift left
	    rl = xl + bw + 1;

	    while(bw--)
		*r++ = 0;
	    if (sw) {
		while(xl--) {
		    a0 = (*x << sw) | a1;
		    a1 = (*x >> (DEXP - sw));
		    *r++ = a0;
		    x++;
		}
	    }
	    else {
		while(xl--) {
		    *r++ = *x++;
		}
	    }
	    if (a1 == 0)
		return rl-1;
	    *r = a1;
	    return rl;
	}
	else {	// shift right
	    digit_t* r0 = r;
	    int add_one = 0;

	    if (xl <= (int)bw) {
		if (sign)
		    *r = 1;
		else
		    *r = 0;
		return 1;
	    }

	    if (sign) {
		unsigned zl = bw;
		digit_t* z = x;

		while(zl--) {
		    if (*z != 0) {
			add_one = 1;
			break;
		    }
		    z++;
		}
	    }

	    rl = xl - bw;
	    x += (xl-1);
	    r += (rl-1);
	    xl -= bw;
	    if (sw) {
		while(xl--) {
		    a1 = (*x >> sw) | a0;
		    a0 = (*x << (DEXP-sw));
		    *r-- = a1;
		    x--;
		}
	    }
	    else {
		while(xl--) {
		    *r-- = *x--;
		}
	    }

	    if (sign && (a0 != 0))
		add_one = 1;

	    if (r[rl] == 0) {
		if (rl == 1) {
		    if (sign)
			r[1] = 1;
		    return 1;
		}
		rl--;
	    }
	    if (add_one)
		return d_add(r0, rl, 1, r0);
	    return rl;
	}
    }
}

static int b_div(digit_t* xp, int xl, digit_t* yp, int yl,
		 digit_t* q, digit_t* r, int* rlp)
{
    digit_t* rp;
    digit_t* qp;
    digit_t b1 = yp[yl-1];
    digit_t b2 = yp[yl-2];
    digit_t a1;
    digit_t a2;
    int r_signed = 0;
    int ql;
    int rl;

    if (xp != r)
	b_copy(xp, r, xl);
    rp = r + (xl-yl);
    rl = xl;
	
    b_zero(q, xl-yl+1);
    qp = q + (xl-yl);
    ql = 0;
	
    a1 = rp[yl-1];
    a2 = rp[yl-2];
    if ((b1 < a1) || ((b1 == a1) && (b2 <= a2)))
	ql = 1;

    do {
	digit_t q0;
	int nsz = yl;
	int nnsz;

	a1 = rp[yl-1];
	a2 = rp[yl-2];

	if (b1 < a1)
	    DDIV2(a1,a2,b1,b2,q0);
	else if (b1 > a1) {
	    DDIV(a1,a2,b1,q0);
	    nsz++;
	    rp--;
	    qp--;
	    ql++;
	}
	else {
	    if (b2 <= a2)
		q0 = 1;
	    else {
		q0 = DMASK;
		nsz++;
		rp--;
		qp--;
		ql++;
	    }
	}

	if (r_signed)
	    ql = d_sub(qp, ql, q0, qp);
	else
	    ql = d_add(qp, ql, q0, qp);

	if ((nnsz = d_mulsub(rp, nsz, q0, yp, yl, rp)) == 0) {
	    nnsz = z_sub(r, rl, r);
	    if (nsz > (rl-nnsz))
		nnsz = nsz - (rl-nnsz);
	    else
		nnsz = 1;
	    r_signed = !r_signed;
	}
		
	if ((nnsz == 1) && (*rp == 0))
	    nnsz = 0;
	rp = rp - (yl-nnsz);
	rl -= (nsz-nnsz);
	qp = qp - (yl-nnsz);
	ql += (yl-nnsz);
    } while (b_comp(r, rl, yp, yl) >= 0);

    ql -= (q - qp);
    qp = q;

    if (rl == 0)
	rl = 1;

    while(rl > 1 && r[rl-1] == 0)
      --rl;

    if (r_signed && ((rl > 1) || (*r != 0))) {
	rl = b_sub(yp, yl, r, rl, r);
	ql = d_sub(qp, ql, 1, qp);
    }

    *rlp = rl;
    return ql;
}

static digit_t d_rem(digit_t* xp, int xl, digit_t d)
{
    digit_t rem = 0;

    xp += (xl-1);
    do {
	if (rem != 0)
	    DREM(rem, *xp, d, rem);
	else
	    DREM(0, *xp, d, rem);
	xp--;
	xl--;
    } while(xl > 0);
    return rem;
}

static int b_rem(digit_t* xp, int xl, digit_t* yp, int yl, digit_t* r)
{
    digit_t* rp;
    digit_t b1 = yp[yl-1];
    digit_t b2 = yp[yl-2];
    digit_t a1;
    digit_t a2;
    int r_signed = 0;
    int rl;
	
    if (xp != r)
	b_copy(xp, r, xl);
    rp = r + (xl-yl);
    rl = xl;

    do {
	digit_t q0;
	int nsz = yl;
	int nnsz;
		
	a1 = rp[yl-1];
	a2 = rp[yl-2];

	if (b1 < a1)
	    DDIV2(a1,a2,b1,b2,q0);
	else if (b1 > a1) {
	    DDIV(a1,a2,b1,q0);
	    nsz++;
	    rp--;
	}
	else {
	    if (b2 <= a2)
		q0 = 1;
	    else {
		q0 = DMASK;
		nsz++;
		rp--;
	    }
	}

	if ((nnsz = d_mulsub(rp, nsz, q0, yp, yl, rp)) == 0) {
	    nnsz = z_sub(r, rl, r);
	    if (nsz > (rl-nnsz))
		nnsz = nsz - (rl-nnsz);
	    else
		nnsz = 1;
	    r_signed = !r_signed;
	}

	if ((nnsz == 1) && (*rp == 0))
	    nnsz = 0;

	rp = rp - (yl-nnsz);
	rl -= (nsz-nnsz);
    } while (b_comp(r, rl, yp, yl) >= 0);

    if (rl == 0)
	rl = 1;

    while((rl > 1) && (r[rl-1] == 0))
      --rl;

    if (r_signed && ((rl > 1) || (*r != 0)))
	rl = b_sub(yp, yl, r, rl, r);
    return rl;
}


int bignum_add(bignum_t* x, bignum_t* y, bignum_t* r)
{
    return b_addsub(x->digits, x->sign, x->size,
		    y->digits, y->sign, y->size, r);
}

int bignum_subtract(bignum_t* x, bignum_t* y, bignum_t* r)
{
    return b_addsub(x->digits, x->sign, x->size,
		    y->digits, !y->sign, y->size, r);
}

int bignum_square(bignum_t* x, bignum_t* r)
{
    int rsz;

    if (bignum_is_zero(x))
	rsz = bignum_small(r, 0);
    else if (bignum_is_one(x))
	rsz = bignum_copy(x, r);
    else {
	if (bignum_resize(r, 2*x->size) < 0)
	    return -1;
	if (x->size == 1) {
	    rsz = d_mul(x->digits, x->size, x->digits[0], r->digits);
	}
	else if (x==r) {
	    AUTO_BEGIN {
		BIGNUM_AUTO(tmp, 2*x->size);
		b_zero(tmp.digits, x->size);
		rsz = b_sqr(x->digits,x->size,tmp.digits);
		b_copy(tmp.digits, r->digits, rsz);
	    } AUTO_END;
	}
	else {
	    b_zero(r->digits, x->size);
	    rsz = b_sqr(x->digits, x->size, r->digits);
	}
    }
    r->size = rsz;
    r->sign = 0;
    return 1;	
}

int bignum_multiply(bignum_t* x, bignum_t* y, bignum_t* r)
{
    int rsz;
    int rsign = 0;
    if (y->size > x->size) BIGNUM_SWAP(x,y);
    if (bignum_is_zero(y))
	rsz = bignum_small(r, 0);
    else if (bignum_is_one(y)) {
	rsz = bignum_copy(x, r);
	rsign = x->sign;
    }
    else {
	rsign = x->sign != y->sign;
	if (bignum_resize(r, x->size+y->size) < 0)
	    return -1;
	// x->size >= y->size
	if (y->size == 1) {
	    rsz = d_mul(x->digits, x->size, y->digits[0], r->digits);
	}
	else if ((x==r)||(y==r)) {
	    AUTO_BEGIN {
		BIGNUM_AUTO(tmp, x->size+y->size);
		b_zero(tmp.digits, x->size);
#ifdef BIGNUM_USE_MUL_SQUARE
		if (x==y)
		    rsz = b_sqr(x->digits,x->size,tmp.digits);
		else
#endif
		    rsz = b_mul(x->digits,x->size,y->digits,y->size,tmp.digits);
		b_copy(tmp.digits, r->digits, rsz);
	    } AUTO_END;
	}
	else {
	    b_zero(r->digits, x->size);
#ifdef BIGNUM_USE_MUL_SQUARE	    
	    if (x==y)
		rsz = b_sqr(x->digits, x->size, r->digits);
	    else
#endif
		rsz = b_mul(x->digits, x->size, y->digits, y->size, r->digits);
	}
    }
    r->size = rsz;
    r->sign = rsign;
    return 1;
}

int bignum_divrem(bignum_t* x, bignum_t* y, bignum_t* q, bignum_t* r)
{
    int qsz, rsz, cmp;

    if (bignum_is_zero(y))
	bignum_einval();
    cmp = b_comp(x->digits,x->size,y->digits,y->size);
    if (cmp == 0) {
	qsz = bignum_small(q, 1);
	rsz = bignum_small(r, 0);
    }
    else if (cmp < 0) {
	qsz = bignum_small(q, 0);
	rsz = bignum_copy(x, r);
    }
    else if (y->size == 1) {
	AUTO_BEGIN {	
	    BIGNUM_AUTO(tmp, x->size);
	    if (bignum_resize(r, 1) < 0) return -1;
	    qsz = d_div(x->digits,x->size,y->digits[0],tmp.digits,r->digits);
	    rsz = 1;
	    if (bignum_resize(q, qsz) < 0) return -1;
	    b_copy(tmp.digits, q->digits, qsz);
	} AUTO_END;
    }
    else {
	AUTO_BEGIN {		
	    digit_t* rp;
	    BIGNUM_AUTO(tmp, x->size-y->size+1+x->size);
	    qsz = x->size-y->size+1;
	    rp  = tmp.digits + qsz;
	    qsz = b_div(x->digits,x->size,y->digits,y->size,tmp.digits,rp,&rsz);	
	    if (bignum_resize(q, qsz) < 0) return -1;	    
	    b_copy(tmp.digits, q->digits, qsz);
	    if (bignum_resize(r, rsz) < 0) return -1;
	    b_copy(rp, r->digits, rsz);
	} AUTO_END;
    }
    if ((qsz <= 0) || (rsz <= 0))
	return -1;
    q->size = qsz;
    q->sign = bignum_is_zero(q)?0:(x->sign != y->sign);
    r->size = rsz;
    r->sign = x->sign;	
    return 0;
}

int bignum_div(bignum_t* x, bignum_t* y, bignum_t* q)
{
    int qsz, cmp;

    if (bignum_is_zero(y))
	bignum_einval();
    cmp = b_comp(x->digits,x->size,y->digits,y->size);
    if (cmp == 0)
	qsz = bignum_small(q, 1);
    else if (cmp < 0)
	qsz = bignum_small(q, 0);
    else if (y->size == 1) {
	AUTO_BEGIN {
	    digit_t rem;
	    BIGNUM_AUTO(tmp, x->size);
	    qsz = d_div(x->digits,x->size,y->digits[0],tmp.digits,&rem);
	    if (bignum_resize(q, qsz) < 0) return -1;
	    b_copy(tmp.digits, q->digits, qsz);
	} AUTO_END;	    
    }
    else {
	AUTO_BEGIN {
	    digit_t* rp;
	    int rsz;
	    BIGNUM_AUTO(tmp, x->size-y->size+1+x->size);
	    qsz = x->size-y->size + 1;
	    rp  = tmp.digits + qsz;
	    qsz = b_div(x->digits, x->size, y->digits, y->size,tmp.digits,
			rp,&rsz);
	    if (bignum_resize(q, qsz) < 0) return -1;	    
	    b_copy(tmp.digits, q->digits, qsz);
	} AUTO_END;
    }
    if (qsz <= 0)
	return -1;
    q->size = qsz;
    q->sign = bignum_is_zero(q)?0:(x->sign != y->sign);
    return 0;
}

int bignum_rem(bignum_t* x, bignum_t* y, bignum_t* r)
{
    int rsz, cmp;

    if (bignum_is_zero(y))
	bignum_einval();
    cmp = b_comp(x->digits,x->size,y->digits,y->size);
    if (cmp == 0)
	rsz=bignum_small(r, 0);
    else if (cmp < 0)
	rsz=bignum_copy(x, r);
    else if (y->size == 1) {
	digit_t d = d_rem(x->digits, x->size, y->digits[0]);
	rsz = bignum_small(r, d);
    }
    else {
	AUTO_BEGIN {	
	    BIGNUM_AUTO(tmp, x->size);
	    rsz=b_rem(x->digits,x->size,y->digits,y->size,tmp.digits);
	    if (bignum_resize(r, rsz) < 0) return -1;	    
	    b_copy(tmp.digits, r->digits, rsz);
	} AUTO_END;	    
    }
    if (rsz <= 0)
	return -1;
    r->size = rsz;
    r->sign = x->sign;
    return 0;
}

int bignum_mod(bignum_t* x, bignum_t* y, bignum_t* r)
{
    int res;
    AUTO_BEGIN {	
	BIGNUM_AUTO(tmp, y->size);
    
	bignum_rem(x, y, &tmp);
	if (tmp.sign)
	    res=bignum_add(&tmp, y, r);
	else
	    res=bignum_copy(&tmp, r);
    } AUTO_END;
    return res;
}

// FIXME: x == r
int bignum_bsl(bignum_t* x, int y, bignum_t* r)
{
    int need_bits = x->size*DEXP;
    int need;
    need_bits += y;
    if (need_bits <= 0)
	need=1;
    else
	need = (need_bits+DEXP-1)/DEXP;
    if (bignum_resize(r, need) < 0) return -1;
    r->size = b_lshift(x->digits, x->size, y, x->sign, r->digits);
    r->sign = x->sign;
    return 0;
}

// FIXME: x == r
int bignum_bsr(bignum_t* x, int y, bignum_t* r)
{
    int need_bits = x->size*DEXP;
    int need;
    need_bits += (-y);
    if (need_bits <= 0)
	need=1;
    else
	need = (need_bits+DEXP-1)/DEXP;
    if (bignum_resize(r, need) < 0) return -1;    
    r->size = b_lshift(x->digits, x->size, -y, x->sign, r->digits);
    r->sign = x->sign;
    return 0;
}

int bignum_negate(bignum_t* x, bignum_t* r)
{
    if (x != r) {
	if (bignum_copy(x, r) < 0) return -1;
    }
    r->sign = !x->sign;
    return 0;    
}

int bignum_abs(bignum_t* x, bignum_t* r)
{
    if (x != r) {
	if (bignum_copy(x, r) < 0) return -1;
    }
    r->sign = 0;
    return 0;
}

int bignum_band(bignum_t* x, bignum_t* y, bignum_t* r)
{
    if (x->size >= y->size)
	return b_band(x->digits, x->sign, x->size, 
		      y->digits, y->sign, y->size,
		      r);
    else
	return b_band(y->digits, y->sign, y->size,
		      x->digits, x->sign, x->size,
		      r);
}

int bignum_bor(bignum_t* x, bignum_t* y, bignum_t* r)
{
    if (x->size >= y->size)
	return b_bor(x->digits, x->sign, x->size, 
		     y->digits, y->sign, y->size, 
		     r);
    else
	return b_bor(y->digits, y->sign, y->size,
		     x->digits, x->sign, x->size, 
		     r);
}

int bignum_bxor(bignum_t* x, bignum_t* y, bignum_t* r)
{
    if (x->size >= y->size)
	return b_bxor(x->digits, x->sign, x->size, 
		      y->digits, y->sign, y->size, 
		      r);
    else
	return b_bxor(y->digits, y->sign, y->size,
		      x->digits, x->sign, x->size,
		      r);
}

int bignum_bnot(bignum_t* x, bignum_t* r)
{
    return b_bnot(x->digits, x->sign, x->size, r);
}

// x must be non-negative!
int bignum_bit_test(bignum_t* x, unsigned pos)
{
    int d;
    if (x->sign) bignum_einval();
    d = pos / DEXP;   // digit
    pos %= DEXP;      // bit
    if (d >= (int)x->size)
	return 0;     // definied as zero
    return (x->digits[d] & (1 << pos)) != 0;
}

int bignum_bit_set(bignum_t* x, unsigned pos, bignum_t* r)
{
    int d;
    if (x->sign) bignum_einval();
    d = pos / DEXP;
    pos %= DEXP;
    if (bignum_copy_resize(x, r, d+1) < 0) return -1;
    r->digits[d] |= (1 << pos);
    return 0;
}

int bignum_bit_clear(bignum_t* x, unsigned pos, bignum_t* r)
{
    int d;
    if (x->sign) bignum_einval();
    d = pos / DEXP;      // digit pos
    if (d >= (int)x->size) {  // already 0
	if (bignum_copy(x, r) < 0) return -1;
    }
    pos %= DEXP;
    r->digits[d] &= ~(1 << pos);
    r->size = bu_trail(r->digits, r->size);
    return 0;
}

int bignum_bit_toggle(bignum_t* x, unsigned pos, bignum_t* r)
{
    int d;
    if (x->sign) bignum_einval();
    d = pos / DEXP;
    pos %= DEXP;
    if (bignum_copy_resize(x, r, d+1) < 0) return -1;
    r->digits[d] ^= (1 << pos);
    r->size = bu_trail(r->digits, r->size);
    return 0;
}

// set byte in digit by pos (not same as set_bit, clear byte first!)
int bignum_byte_set(bignum_t* x, unsigned pos, uint8_t b, bignum_t* r)
{
    int d;
    if (x->sign) bignum_einval();
    d = pos / sizeof(digit_t);       // digit number
    pos = (pos % sizeof(digit_t))*8; // bit number in digit
    if (bignum_copy_resize(x, r, (d+1)) < 0) return -1;
    r->digits[d] = ((r->digits[d] & ~(0xff<<pos)) | (b<<pos));
    return 0;
}

int bignum_digit_set(bignum_t* x, unsigned pos, digit_t d, bignum_t* r)
{
    if (bignum_copy_resize(x, r, (pos+1)) < 0) return -1;
    r->digits[pos] = d;
    return 0;
}

digit_t bignum_digit_get(bignum_t* x, unsigned pos)
{
    if (pos >= x->size) return 0;
    return x->digits[pos];
}

uint8_t bignum_byte_get(bignum_t* x, unsigned pos)
{
    int d;
    d = pos / sizeof(digit_t);       // digit number
    if (d >= (int)x->size) return 0;
    pos = (pos % sizeof(digit_t))*8; // bit number in digit
    return (x->digits[d] >> pos) & 0xff;
}

static int inline d_ffs(digit_t d)
{
    return __builtin_ffs(d);
}

static int inline d_clz(digit_t d)
{
    return __builtin_clz(d)-((sizeof(unsigned)-sizeof(digit_t))*8);
}

static int inline d_popcount(digit_t d)
{
    return __builtin_popcount(d);
}

static int inline d_parity(digit_t d)
{
    return __builtin_parity(d);
}

// return bit position + 1 to the least significant 1-bit of x
// or zero if x is zero
int bignum_ffs(bignum_t* x)
{
    int i;
    if (x->sign) bignum_einval();
    for (i=0; (i < (int)x->size) && (x->digits[i] == 0); i++) ;
    if (i == (int)x->size)
	return 0;
    return (i*DEXP) + d_ffs(x->digits[i]);
}
  
int bignum_clz(bignum_t* x)
{
    if (x->sign) bignum_einval();
    if (bignum_is_zero(x)) return -1;
    return d_clz(x->digits[x->size-1]);
}

int bignum_ctz(bignum_t* x)
{
    int i;
    if (x->sign) bignum_einval();
    if ((i = bignum_ffs(x)) < 0) return -1;
    return i-1;
}

int bignum_clrsb(bignum_t* x)
{
    if (x->sign) bignum_einval();
    // same as ctz since we only accept non negative number now
    return bignum_ctz(x);
}

int bignum_popcount(bignum_t* x)
{
    int count = 0;
    int i;
    if (x->sign) bignum_einval();
    for (i = 0; i < (int)x->size; i++)
	count += d_popcount(x->digits[i]);
    return count;
}

int bignum_parity(bignum_t* x)
{
    int parity = 0;
    int i;
    if (x->sign) bignum_einval();
    for (i = 0; i < (int)x->size; i++)
	parity += d_parity(x->digits[i]);
    return parity & 1;
}

// return byte size of bignum (x must be normalised)
// fixme: what about negative numbers sizeof two complement form?
int bignum_byte_size(bignum_t* x)
{
    if (bignum_is_zero(x))
	return 1;
    else {
	int size = d_clz(x->digits[x->size-1]);
	return (((DEXP-size)+7)>>3) + (x->size-1)*sizeof(digit_t);
    }
}

// return bit size of bignum (x must be normalised)
// fixme: negative numbers
int bignum_bit_size(bignum_t* x)
{
    if (bignum_is_zero(x))
	return 1;
    else {
	int size = d_clz(x->digits[x->size-1]);
	return (DEXP-size) + (x->size-1)*DEXP;
    }
}

int bignum_from_strn(char* ptr, int len, bignum_t* x)
{
    char* ptr1 = ptr + len;
    int sign = 0;

    if (bignum_small(x, 0) < 0)
	return -1;
    if ((ptr < ptr1) && (*ptr == '-')) {
	sign = 1;
	ptr++;
    }
    while((ptr < ptr1) && (*ptr >= '0') && (*ptr <= '9')) {
	digit_t d = *ptr++ - '0';
	// fixme better pre calculate the need!
	if (bignum_resize(x, x->size+1) < 0) return 1;
	x->size = d_mul(x->digits, x->size, 10, x->digits);
	x->size = d_add(x->digits, x->size, d, x->digits);
    }
    x->sign = sign;
    return len-(ptr1-ptr);

}

int bignum_from_string(char* ptr, bignum_t* x)
{
    int len = 0;
    char* ptr1 = ptr;
    while(*ptr1++) len++;
    return bignum_from_strn(ptr, len, x);
}

// fixme: range check
char* bignum_to_string(bignum_t* x, char* ptr, int sz)
{
    AUTO_BEGIN {    
	BIGNUM_AUTO(q, x->size);
	char* ptr0 = ptr;

	bignum_copy(x, &q);
	ptr = ptr0+sz-1;
	*ptr = '\0';
	do {
	    digit_t r;
	    q.size = d_div(q.digits, q.size, 10, q.digits, &r);
	    *--ptr = (r+'0');
	} while((ptr > ptr0) && ((q.size > 1) || (q.digits[0] != 0)));

	if (x->sign)
	    *--ptr = '-';
    } AUTO_END;
    return ptr;
}

char* bignum_to_xstring(bignum_t* x, char* ptr, int sz)
{
    char* ptr0 = ptr;
    char* ptr1 = ptr + sz - 1;
    int i;
    if (x->sign && (ptr < ptr1)) *ptr++ = '-';
    if (ptr < ptr1) *ptr++ = '0';
    if (ptr < ptr1) *ptr++ = 'x';
    for (i = x->size-1; i >= 0; i--) {
	digit_t d = x->digits[i];
	int s = sizeof(digit_t)*8-4;
	while(s >= 0) {
	    if (ptr < ptr1)
		*ptr++ = "0123456789abcdef"[(d>>s)&0xf];
	    s -= 4;
	}
    }
    *ptr = '\0';
    return ptr0;
}

#ifdef BIGNUM_DEBUG
// debug only? (1233 decimal digits are about 4096 bits)
void bignum_fprintf(FILE* f, char* fmt, bignum_t* x)
{
    char buf[1240];
    char* ptr;
    ptr = bignum_to_string(x, buf, sizeof(buf));
    fprintf(f, fmt, ptr);
}

void bignum_xfprintf(FILE* f, char* fmt, bignum_t* x)
{
    char buf[1240];
    char* ptr;
    ptr = bignum_to_xstring(x, buf, sizeof(buf));
    fprintf(f, fmt, ptr);
}

// print bignum as hex big-endian format
void bignum_xprintf(char* fmt, bignum_t* x)
{
    bignum_xfprintf(stdout, fmt, x);
}


void bignum_printf(char* fmt, bignum_t* x)
{
    bignum_fprintf(stdout, fmt, x);
}

void bignum_print(bignum_t* x)
{
    bignum_fprintf(stdout, "%s", x);
}

void bignum_println(bignum_t* x)
{
    bignum_fprintf(stdout, "%s\n", x);
}
#endif

// gcd(x,y)
int bignum_gcd(bignum_t* x, bignum_t* y, bignum_t* r)
{
    if (bignum_abs_comp(x,y) < 0)
	BIGNUM_SWAP(x, y);
    AUTO_BEGIN {
	bignum_t* rp1;
	bignum_t* rp2;
	bignum_t* qp;
	BIGNUM_AUTO(q1, x->size);
	BIGNUM_AUTO(r1, y->size);
	BIGNUM_AUTO(r2, x->size);

	bignum_copy(x, &q1);
	bignum_copy(y, &r1);

	bignum_abs(&r1, &r1);
	bignum_abs(&q1, &q1);

	qp = &q1;
	rp1 = &r1;
	rp2 = &r2;
	while(!bignum_is_zero(rp1)) {
	    bignum_rem(qp, rp1, rp2);
	    qp = rp1;
	    BIGNUM_SWAP(rp1, rp2);
	}
	if (bignum_copy(qp, r) < 0) return -1;
    } AUTO_END;
    return 0;
}

// egcd(a,b,gcd,&x,&y)  gcd = a*x + b*y
int bignum_egcd(bignum_t* a, bignum_t* b, bignum_t* gcd,
		bignum_t* x,bignum_t* y)
{
    if (bignum_abs_comp(a,b) < 0)
	BIGNUM_SWAP(a,b);

    AUTO_BEGIN {    
	BIGNUM_AUTO(q1, a->size);
	BIGNUM_AUTO(r1, b->size);
	BIGNUM_AUTO(x1,  a->size+1);
	BIGNUM_AUTO(lx, a->size+1);
	BIGNUM_AUTO(y1,  a->size+1);	
	BIGNUM_AUTO(ly, a->size+1);
	
	bignum_copy(a, &q1);
	bignum_copy(b, &r1);

	bignum_abs(&q1, &q1);
	bignum_abs(&r1, &r1);	

	bignum_small(&x1, 0); bignum_small(&y1, 1);
	bignum_small(&lx, 1); bignum_small(&ly, 0);	
    
	while(!bignum_is_zero(&r1)) {
	    AUTO_BEGIN {
		BIGNUM_AUTO(q2, q1.size-r1.size+1);
		BIGNUM_AUTO(r2, r1.size);

		bignum_divrem(&q1,&r1,&q2,&r2);

		AUTO_BEGIN {
		    BIGNUM_AUTO(q2x, q2.size+x1.size);
		    bignum_multiply(&q2,&x1,&q2x);
		    AUTO_BEGIN {
			BIGNUM_AUTO(t, MAX(lx.size, q2x.size)+1);
			bignum_subtract(&lx,&q2x,&t);
			bignum_copy(&x1, &lx);	    	    
			bignum_copy(&t, &x1);
		    } AUTO_END;
		} AUTO_END;

		AUTO_BEGIN {
		    BIGNUM_AUTO(q2y, q2.size+y1.size);
		    bignum_multiply(&q2,&y1,&q2y);
		    AUTO_BEGIN {
			BIGNUM_AUTO(t, MAX(ly.size, q2y.size)+1);
			bignum_subtract(&ly,&q2y,&t);
			bignum_copy(&y1, &ly);
			bignum_copy(&t, &y1);
		    } AUTO_END;
		} AUTO_END;

		bignum_copy(&r1, &q1);
		bignum_copy(&r2, &r1);
	    } AUTO_END;
	}
	bignum_copy(&lx, x);	
	bignum_copy(&ly, y);
	bignum_copy(&q1, gcd);
    } AUTO_END;
    return 0;
}

// calculate r = x^n (mod m)
int bignum_powmod(bignum_t* x, bignum_t* n, bignum_t* m, bignum_t* r)
{
    AUTO_BEGIN {    
	BIGNUM_AUTO(p,   m->size);
	BIGNUM_AUTO(a,   m->size);
	BIGNUM_AUTO(tmp, MAX(n->size, m->size+m->size+1));
	int i, nbits;

	bignum_small(&p, 1);
	bignum_rem(x, m, &a);            // a = x mod m
	nbits = bignum_bit_size(n)-1;
	for (i = 0; i < nbits; i++) {
	    if (bignum_bit_test(n, i)) {
		bignum_multiply(&a, &p, &tmp);
		bignum_rem(&tmp, m, &p);
	    }
	    bignum_multiply(&a, &a, &tmp);    // tmp = a*a
	    bignum_rem(&tmp, m, &a);          // a = tmp mod m
	}
	bignum_multiply(&a, &p, &tmp);        // tmp = a*p
	bignum_rem(&tmp, m, r);               // r = a*p mod m
    } AUTO_END;
    return 0;
}

// calculate a^b mod p where p is prime
// simplify a^b mod p by using fermats little:
// a^p = a (mod p)  
// Set b = qp + r ( r = b rem p )
// a^b = a^(kp+r) = a^(q+r) 
// 
int bignum_powmod_prime(bignum_t* a, bignum_t* b, bignum_t* p, bignum_t* r)
{
    if (a->sign || b->sign || p->sign || bignum_is_zero(p))
	bignum_einval();
    if (bignum_is_one(a))
	return bignum_small(r, 1);
    else {
	int res;
	AUTO_BEGIN {
	    BIGNUM_AUTO(bq, p->size);
	    BIGNUM_AUTO(b1, p->size+1);

	    bignum_divrem(b, p, &bq, &b1);
	    bignum_add(&bq, &b1, &b1); 	// b1 = (b div p)+(b rem p),
	    res = bignum_powmod(a, &b1, p, r);
	} AUTO_END;
	return res;
    }
}

// calculate a^b mod p1*p2 (p1 and p2 prime)
int bignum_powmod_two_prime (bignum_t* a,bignum_t* b,
			     bignum_t* p1,bignum_t* p2,
			     bignum_t* r)
{
    int res;
    AUTO_BEGIN {    
	BIGNUM_AUTO(a1, p1->size);
	BIGNUM_AUTO(a2, p2->size);
	BIGNUM_AUTO(n,  p1->size+p2->size);
	uint16_t msz = MAX(a->size,b->size)+1;
	BIGNUM_AUTO(m1, msz);
	BIGNUM_AUTO(m2, msz);
    
	bignum_powmod_prime(a, b, p1, &a1);
	bignum_powmod_prime(a, b, p2, &a2);
	bignum_egcd(p1, p2, (bignum_t*) 0, &m1, &m2); // fixme check = 1
    
	bignum_multiply(p1, p2, &n);
	AUTO_BEGIN {
	    uint16_t sz1 = a1.size+m2.size+p2->size;
	    uint16_t sz2 = a2.size+m1.size+p1->size;
	    BIGNUM_AUTO(t1, sz1);
	    BIGNUM_AUTO(t2, MAX(sz1,sz2)+1);
    
	    bignum_multiply(&a1,&m2, &t1);  // t1 = a1*m2
	    bignum_multiply(&t1,p2, &t1);   // t1 = a1*m2*p2

	    bignum_multiply(&a2,&m1,&t2);  // t2 = a2*m1
	    bignum_multiply(&t2,p1,&t2);    // t2 = a2*m1*p1

	    bignum_add(&t1,&t2,&t2);       // t1 = a1*m2*p2 + a2*m1*p1
	    res = bignum_mod(&t2,&n,r);
	} AUTO_END;
    } AUTO_END;
    return res;
}

#endif
