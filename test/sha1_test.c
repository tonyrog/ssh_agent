//
// TEST:
//
// SHA1("") =
//   DA39A3EE 5E6B4B0D 3255BFEF 95601890 AFD80709
//
// SHA1("The quick brown fox jumps over the lazy dog") =
//  2FD4E1C6 7A2D28FC ED849EE1 BB76E7391 B93EB12
//
// SHA1("The quick brown fox jumps over the lazy cog") =
//  DE9F2C7F D25E1B3A FAD3E85A 0BD17D9B 100DB4B3
//
// SHA1("hello world") = 
//   2AAE6C35 C94FCFB4 15DBE95F 408B9CE9 1EE846ED
//
//

#include <stdio.h>
#include <string.h>
#include "../c_src/sha1.h"

#define TEST1   "abc"
#define TEST2a  "abcdbcdecdefdefgefghfghighijhi"
#define TEST2b  "jkijkljklmklmnlmnomnopnopq"
#define TEST2   TEST2a TEST2b
#define TEST3   "a"
#define TEST4a  "01234567012345670123456701234567"
#define TEST4b  "01234567012345670123456701234567"
#define TEST4   TEST4a TEST4b

#define TEST5 ""
#define TEST6 "The quick brown fox jumps over the lazy dog"
#define TEST7 "The quick brown fox jumps over the lazy cog"
#define TEST8 "hello world"

char* testarray[8] =
{
    TEST1,
    TEST2,
    TEST3,
    TEST4,
    
    TEST5,
    TEST6,
    TEST7,
    TEST8
};

long repeatcount[8] = { 1, 1, 1000000, 10, 1, 1, 1, 1 };

char* resultarray[8] =
{
    "A9 99 3E 36 47 06 81 6A BA 3E 25 71 78 50 C2 6C 9C D0 D8 9D",
    "84 98 3E 44 1C 3B D2 6E BA AE 4A A1 F9 51 29 E5 E5 46 70 F1",
    "34 AA 97 3C D4 C4 DA A4 F6 1E EB 2B DB AD 27 31 65 34 01 6F",
    "DE A3 56 A2 CD DD 90 C7 A7 EC ED C5 EB B5 63 93 4F 46 04 52",

    "DA 39 A3 EE 5E 6B 4B 0D 32 55 BF EF 95 60 18 90 AF D8 07 09",
    "2F D4 E1 C6 7A 2D 28 FC ED 84 9E E1 BB 76 E7 39 1B 93 EB 12",
    "DE 9F 2C 7F D2 5E 1B 3A FA D3 E8 5A 0B D1 7D 9B 10 0D B4 B3",
    "2A AE 6C 35 C9 4F CF B4 15 DB E9 5F 40 8B 9C E9 1E E8 46 ED"   
};

int hex(uint8_t* data, char* buf, size_t length)
{
    int i;
    for (i = 0; i < length; i++) {
	uint8_t h = data[i];
	buf[3*i]   = "0123456789ABCDEF"[h>>4];
	buf[3*i+1] = "0123456789ABCDEF"[h & 0xf];
	buf[3*i+2] = ' ';
    }
    buf[3*length-1] = '\0';
    return 3*length;
}

int compare(char* str1, char* str2)
{
    int i = 0;

    while(*str1 && *str2 && (*str1 == *str2)) {
	str1++;
	str2++;
	i++;
    }
    if (!*str1 && !*str2)
	return 0;
    // printf("%d != %d\n", *str1, *str2);
    return i+1;
}

#include <sys/time.h>
uint64_t time_tick(void)
{
    struct timeval t;
    gettimeofday(&t, 0);
    return t.tv_sec*(uint64_t)1000000 + t.tv_usec;
}

int test(int t)
{
    sha1_ctx_t ctx;
    uint8_t digest[SHA1_HASH_SIZE];
    char hexbuf[SHA1_HASH_SIZE*3+1];
    long i;
    size_t len = strlen(testarray[t]);
    long count = repeatcount[t];
    int pos;
    uint64_t t0, t1;

    t0 = time_tick();
    sha1_init(&ctx);
    for (i = 0; i < count; i++) 
	sha1_update(&ctx, (uint8_t*)testarray[t], len);
    sha1_final(&ctx, digest);
    t1 = time_tick();    

    hex(digest, hexbuf, SHA1_HASH_SIZE);
    if ((pos = compare(resultarray[t], hexbuf)) == 0) {
	printf("OK (%lu)\n", t1-t0);
	return 1;
    }
    else {
	printf("ERROR: %s (%d)\n", testarray[t], pos-1);
	printf("    %s\n", hexbuf);
	printf("    %s\n", resultarray[t]);
	return 0;
    }
}

int main(int argc, char** argv)
{
    int t;
    
    for (t = 0; t < 8; t++) {
	printf("TEST%d: ", t+1);
	test(t);
    }
    exit(0);
}
