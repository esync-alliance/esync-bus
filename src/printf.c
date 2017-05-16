/*
File: printf.c

Copyright (C) 2004  Kustaa Nyholm

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

*/

// XL4 changes:
// - wired to our malloc
// - always support long
// - added support for long long

#ifdef SELF_TEST
#include <stdlib.h>
#include <stdio.h>
#endif

#include "internal.h"

#if NEED_PRINTF

typedef void (*putcf) (void*,char);
static putcf stdout_putf;
static void* stdout_putp;

struct buf_count {
    void * ptr;
    int limit;
    int used;
};

static void ulli2a(unsigned long long num, unsigned int base, int uc,char * bf)
    {
    int n=0;
    unsigned long long d=1;
    while (num/d >= base)
        d*=base;
    while (d!=0) {
        int dgt = num / d;
        num%=d;
        d/=base;
        if (n || dgt>0|| d==0) {
            *bf++ = dgt+(dgt<10 ? '0' : (uc ? 'A' : 'a')-10);
            ++n;
            }
        }
    *bf=0;
    }

static void lli2a (long long num, char * bf)
    {
    if (num<0) {
        num=-num;
        *bf++ = '-';
        }
    ulli2a(num,10,0,bf);
    }

static void uli2a(unsigned long int num, unsigned int base, int uc,char * bf)
    {
    int n=0;
    unsigned int d=1;
    while (num/d >= base)
        d*=base;
    while (d!=0) {
        int dgt = num / d;
        num%=d;
        d/=base;
        if (n || dgt>0|| d==0) {
            *bf++ = dgt+(dgt<10 ? '0' : (uc ? 'A' : 'a')-10);
            ++n;
            }
        }
    *bf=0;
    }

static void li2a (long num, char * bf)
    {
    if (num<0) {
        num=-num;
        *bf++ = '-';
        }
    uli2a(num,10,0,bf);
    }

static void ui2a(unsigned int num, unsigned int base, int uc,char * bf)
    {
    int n=0;
    unsigned int d=1;
    while (num/d >= base)
        d*=base;
    while (d!=0) {
        int dgt = num / d;
        num%= d;
        d/=base;
        if (n || dgt>0 || d==0) {
            *bf++ = dgt+(dgt<10 ? '0' : (uc ? 'A' : 'a')-10);
            ++n;
            }
        }
    *bf=0;
    }

static void i2a (int num, char * bf)
    {
    if (num<0) {
        num=-num;
        *bf++ = '-';
        }
    ui2a(num,10,0,bf);
    }

static int a2d(char ch)
    {
    if (ch>='0' && ch<='9')
        return ch-'0';
    else if (ch>='a' && ch<='f')
        return ch-'a'+10;
    else if (ch>='A' && ch<='F')
        return ch-'A'+10;
    else return -1;
    }

static char a2i(char ch, char** src,int base,int* nump)
    {
    char* p= *src;
    int num=0;
    int digit;
    while ((digit=a2d(ch))>=0) {
        if (digit>base) break;
        num=num*base+digit;
        ch=*p++;
        }
    *src=p;
    *nump=num;
    return ch;
    }

static void putchw(void* putp,putcf putf,int n, char z, char* bf)
    {

        if (!bf) {
            putf(putp, '(');
            putf(putp, 'n');
            putf(putp, 'u');
            putf(putp, 'l');
            putf(putp, 'l');
            putf(putp, ')');
            return;
        }

    char fc=z? '0' : ' ';
    char ch;
    char* p=bf;
    while (*p++ && n > 0)
        n--;
    while (n-- > 0)
        putf(putp,fc);
    while ((ch= *bf++))
        putf(putp,ch);
    }

void tfp_format(void* putp,putcf putf,char *fmt, va_list va)
    {
    char bf[24];

    char ch;


    while ((ch=*(fmt++))) {
        if (ch!='%')
            putf(putp,ch);
        else {
            char lz=0;
            char lng=0;
            int w=0;
            ch=*(fmt++);
            if (ch=='0') {
                ch=*(fmt++);
                lz=1;
                }
            if (ch>='0' && ch<='9') {
                ch=a2i(ch,&fmt,10,&w);
                }
            if (ch=='l') {
                ch=*(fmt++);
                lng=1;
                if (ch=='l') {
                    ch=*(fmt++);
                    lng=2;
                }
            }
            switch (ch) {
                case 0:
                    goto abort;
                case 'u' : {
                    if (lng == 2) {
                        ulli2a(va_arg(va, unsigned long long),10,0,bf);
                    } else if (lng)
                        uli2a(va_arg(va, unsigned long int),10,0,bf);
                    else
                    ui2a(va_arg(va, unsigned int),10,0,bf);
                    putchw(putp,putf,w,lz,bf);
                    break;
                    }
                case 'd' :  {
                    if (lng == 2) {
                        lli2a(va_arg(va, unsigned long long),bf);
                    } else if (lng)
                        li2a(va_arg(va, unsigned long int),bf);
                    else
                    i2a(va_arg(va, int),bf);
                    putchw(putp,putf,w,lz,bf);
                    break;
                    }
                case 'x': case 'X' : case 'p':
                    if (ch == 'p') {
                        putf(putp, '0');
                        putf(putp, 'x');
                        lng = 1;
                    }
                    if (lng == 2) {
                        ulli2a(va_arg(va, unsigned long long),16,(ch=='X'),bf);
                    } else if (lng)
                        uli2a(va_arg(va, unsigned long int),16,(ch=='X'),bf);
                    else
                    ui2a(va_arg(va, unsigned int),16,(ch=='X'),bf);
                    putchw(putp,putf,w,lz,bf);
                    break;
                case 'c' :
                    putf(putp,(char)(va_arg(va, int)));
                    break;
                case 's' :
                    putchw(putp,putf,w,0,va_arg(va, char*));
                    break;
                case '%' :
                    putf(putp,ch);
                default:
                    // we need to waste the arg, since we don't
                    // know how to handle it!
                    va_arg(va, char*);
                    break;
                }
            }
        }
    abort:;
    }


void init_printf(void* putp,void (*putf) (void*,char))
    {
    stdout_putf=putf;
    stdout_putp=putp;
    }

void tfp_printf(char *fmt, ...)
    {
    va_list va;
    va_start(va,fmt);
    tfp_format(stdout_putp,stdout_putf,fmt,va);
    va_end(va);
    }

static void putcp(void* p,char c)
    {
    *(*((char**)p))++ = c;
    }


static void putcpn(void* p,char c)
    {
        struct buf_count * bc = (struct buf_count*)p;
        if (bc->used++ < bc->limit) {
            *((char*)bc->ptr++) = c;
        }
    }

void tfp_sprintf(char* s,char *fmt, ...)
    {
    va_list va;
    va_start(va,fmt);
    tfp_format(&s,putcp,fmt,va);
    putcp(&s,0);
    va_end(va);
    }

int tfp_snprintf(char* s,int size,char *fmt, ...)
    {
    struct buf_count bc;
    bc.ptr = s;
    bc.limit = size;
    bc.used = 0;
    va_list va;
    va_start(va,fmt);
    tfp_format(&bc,putcpn,fmt,va);
    putcpn(&bc,0);
    va_end(va);
    return bc.used - 1;
    }

int tfp_vasprintf(char ** s, const char *fmt, va_list ap) {

    struct buf_count bc;
    bc.limit = 0;
    bc.used = 0;

    va_list va;

    va_copy(va, ap);
    tfp_format(&bc,putcpn,(char*)fmt,va);
    putcpn(&bc,0);
    va_end(va);

    if (!(*s = bc.ptr = f_malloc(bc.used))) {
        return -1;
    }

    bc.limit = bc.used;
    bc.used = 0;

    // nobody better have changed any values
    // that could've made them longer than during
    // our first scan.

    va_copy(va, ap);
    tfp_format(&bc,putcpn,(char*)fmt,va);
    putcpn(&bc,0);
    va_end(va);

    return bc.used - 1;
}

int tfp_asprintf(char** s, char * fmt, ...) {

    int r;
    va_list va;
    va_start(va, fmt);
    r = tfp_vasprintf(s, fmt, va);
    va_end(va);
    return r;

}

#ifdef SELF_TEST

#undef printf

    int main(int argc, char ** argv) {

        char * txt;
        char tst1[1024];

        int len = tfp_snprintf(tst1, 1024, "Integer %d, long %ld, uber long %llu, string %s, null string %s, pointer %p",
                    12, 14, 0x7FFFFFFFFFFFFFFFull, "too", 0, &main);
        if (len >= 1024) {
            printf("snprintf too long!\n");
            return 1;
        }

        printf("snprintf: %s\n", tst1);

        if (tfp_asprintf(&txt, "Integer %d, long %ld, uber long %llu, string %s, null string %s, pointer %p",
                    12, 14, 0x7FFFFFFFFFFFFFFFull, "too", 0, &main) < 0) {
            printf("asprintf failed!\n");
            return 1;
        }

        printf("asprintf: %s\n", txt);
        free(txt);

        return 0;

    }


#endif /* SELF_TEST */

#endif /* NEED_PRINTF */
