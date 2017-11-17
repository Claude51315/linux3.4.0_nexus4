#ifndef TRACE_BIO_H
#define TRACE_BIO_H
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/backing-dev.h>
#include <linux/bio.h>
#include <linux/blkdev.h>
#include <linux/highmem.h>
#include <linux/mm.h>
#include <linux/kernel_stat.h>
#include <linux/string.h>
#include <linux/init.h>
#include <linux/completion.h>
#include <linux/slab.h>
#include <linux/swap.h>
#include <linux/writeback.h>
#include <linux/task_io_accounting_ops.h>
#include <linux/fault-inject.h>
#include <linux/list_sort.h>
#include <linux/delay.h>

/* lzo */

#include<linux/lzo.h>

/* SHA1 */
#define SHA1CircularShift(bits,word) \
                (((word) << (bits)) | ((word) >> (32-(bits))))

#ifndef _SHA_enum_
#define _SHA_enum_
enum
{
    shaSuccess = 0,
    shaNull,            /* Null pointer parameter */
    shaInputTooLong,    /* input data too long */
    shaStateError       /* called Input after Result */
};
#endif

#define SHA1HashSize 20


typedef struct SHA1Context
{
    unsigned int  Intermediate_Hash[SHA1HashSize/4]; /* Message Digest  */

    unsigned int Length_Low;            /* Message length in bits      */
    unsigned int Length_High;           /* Message length in bits      */

                               /* Index into message block array   */
    unsigned int Message_Block_Index;
    unsigned char Message_Block[64];      /* 512-bit message blocks      */

    int Computed;               /* Is the digest computed?         */
    int Corrupted;             /* Is the message digest corrupted? */
} SHA1Context;

void SHA1PadMessage(SHA1Context *);
void SHA1ProcessMessageBlock(SHA1Context *);

int SHA1Reset(SHA1Context *context);
int SHA1Result( SHA1Context *context,
                unsigned char Message_Digest[SHA1HashSize]);
int SHA1Input(    SHA1Context    *context,
                  const unsigned char  *message_array,
                  unsigned       length);
void compute_sha(unsigned char* input, int size, unsigned char* output);
/*  CRC16  */
/*  
 * Copyright 2001-2010 Georges Menie (www.menie.org)
 * All rights reserved.
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of the University of California, Berkeley nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


/* CRC16 implementation acording to CCITT standards */
extern const unsigned short crc16tab[];

unsigned short crc16_ccitt(const void *buf, int len);
/* crc32!! */
extern const unsigned long crc32Table[]; 
unsigned long Crc32_ComputeBuf( unsigned long inCrc32, const void *buf,
                                       size_t bufLen, int stripe );

unsigned long crc32_hash (char *in_buf, int in_len, int stripe);
/* md5!*/

#define F1(x, y, z)	(z ^ (x & (y ^ z)))
#define F2(x, y, z)	F1(z, x, y)
#define F3(x, y, z)	(x ^ y ^ z)
#define F4(x, y, z)	(y ^ (x | ~z))

#define MD5STEP(f, w, x, y, z, in, s) \
	(w += f(x, y, z) + in, w = (w<<s | w>>(32-s)) + x)
void md5(uint32_t *hash, uint32_t *input);

/* adler 32*/
#define BASE 65521U
#define NMAX 5552
#define MOD28(a) a %= BASE
#define MOD(a) a %= BASE
#define DO1(buf,i)  {adler += (buf)[i]; sum2 += adler;}
#define DO2(buf,i)  DO1(buf,i); DO1(buf,i+1);
#define DO4(buf,i)  DO2(buf,i); DO2(buf,i+2);
#define DO8(buf,i)  DO4(buf,i); DO4(buf,i+4);
#define DO16(buf)   DO8(buf,0); DO8(buf,8);

#define DO4v2(buf,i)  DO1(buf,i); DO1(buf,i+2);
#define DO8v2(buf,i)  DO4v2(buf,i); DO4v2(buf,i+4);
#define DO16v2(buf)   DO8v2(buf,0); DO8v2(buf,8);

#define DO16v3(buf)   DO1(buf,0); DO1(buf,8);

#define ATOM(val, u32buf, i) {val += ((u32buf>>(i << 3)) & 0xff);}
#define SUM_4CHAR(val, u32buf)  do{ ATOM(val, u32buf, 0); \
                                    ATOM(val, u32buf, 1); \
                                    ATOM(val, u32buf, 2); \
                                    ATOM(val, u32buf, 3); \
                                }while(0)


unsigned long adler32_z(unsigned long adler,char* buf,int  len);

unsigned long adler32_z2(unsigned long adler,char* buf,int  len);
unsigned long adler32_z3(unsigned long adler,char* buf,int  len);
unsigned long adler_hash(char *in_buf, int in_len);
unsigned long adler_hash2(char *in_buf, int in_len);
unsigned long adler_hash3(char *in_buf, int in_len);
/*
static void print_page_inode(struct page *bio_page)
{
    struct address_space *bio_space; 
    struct inode *bio_inode;
    struct dentry *p;
    struct list_head *next ; 
    bio_space = bio_page->mapping;
    if(bio_space != NULL){
        if( ((unsigned long)bio_space & PAGE_MAPPING_ANON )  == 0) {
            bio_inode = bio_space->host;
            if(bio_inode != NULL){
                if(! list_empty(&(bio_inode->i_dentry))){
                    //p = list_first_entry(&(bio_inode->i_dentry), struct dentry, d_alias);
                    next = bio_inode->i_dentry.next;
                    p = list_entry(next, struct dentry, d_alias);
                    if(p!=NULL){
                        printk("%lu,%s,", bio_inode->i_ino,p->d_iname);                     
                    } else {
                        printk("%lu,NULL,", bio_inode->i_ino);                     
                    }
                } else {
                     printk("%lu,NULL2,", bio_inode->i_ino);                     
                }
            }else {
                printk("i_node not found \n");                     
            }
        }else{
            printk("this page is not ppint to inode\n");
        }


    }
}
*/

void print_bio(struct bio *print_bio,int flag);
void timespec_diff(struct timespec *start, struct timespec *stop, struct timespec *result);
void init_bio_time(struct bio *bio);
void print_bio2(struct bio *bio);
void get_filename(struct bio *print_bio, char* output);
////////////////////////////////////////////////////////////
int lzo_compress(struct page* p);

#endif
