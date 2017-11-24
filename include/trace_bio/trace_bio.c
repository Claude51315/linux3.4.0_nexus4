#include "trace_bio.h"

#include <trace/events/block.h>
int SHA1Reset(SHA1Context *context)
{
    if (!context)
    {
        return shaNull;
    }

    context->Length_Low             = 0;
    context->Length_High            = 0;
    context->Message_Block_Index    = 0;

    context->Intermediate_Hash[0]   = 0x67452301;
    context->Intermediate_Hash[1]   = 0xEFCDAB89;
    context->Intermediate_Hash[2]   = 0x98BADCFE;
    context->Intermediate_Hash[3]   = 0x10325476;
    context->Intermediate_Hash[4]   = 0xC3D2E1F0;

    context->Computed   = 0;
    context->Corrupted  = 0;

    return shaSuccess;
}
int SHA1Result( SHA1Context *context,
        unsigned char Message_Digest[SHA1HashSize])
{
    int i;

    if (!context || !Message_Digest)
    {
        return shaNull;
    }

    if (context->Corrupted)
    {
        return context->Corrupted;
    }

    if (!context->Computed)
    {
        SHA1PadMessage(context);
        for(i=0; i<64; ++i)
        {
            /* message may be sensitive, clear it out */
            context->Message_Block[i] = 0;
        }
        context->Length_Low = 0;    /* and clear length */
        context->Length_High = 0;
        context->Computed = 1;

    }

    for(i = 0; i < SHA1HashSize; ++i)
    {
        Message_Digest[i] = context->Intermediate_Hash[i>>2]
            >> 8 * ( 3 - ( i & 0x03 ) );
    }

    return shaSuccess;
}
int SHA1Input(    SHA1Context    *context,
        const unsigned char  *message_array,
        unsigned       length)
{
    if (!length)
    {
        return shaSuccess;
    }

    if (!context || !message_array)
    {
        return shaNull;
    }

    if (context->Computed)
    {
        context->Corrupted = shaStateError;

        return shaStateError;
    }

    if (context->Corrupted)
    {
        return context->Corrupted;
    }
    while(length-- && !context->Corrupted)
    {
        context->Message_Block[context->Message_Block_Index++] =
            (*message_array & 0xFF);

        context->Length_Low += 8;
        if (context->Length_Low == 0)
        {
            context->Length_High++;
            if (context->Length_High == 0)
            {
                /* Message is too long */
                context->Corrupted = 1;
            }
        }

        if (context->Message_Block_Index == 64)
        {
            SHA1ProcessMessageBlock(context);
        }

        message_array++;
    }

    return shaSuccess;
}
void SHA1ProcessMessageBlock(SHA1Context *context)
{
    const unsigned int K[] =    {       /* Constants defined in SHA-1   */
        0x5A827999,
        0x6ED9EBA1,
        0x8F1BBCDC,
        0xCA62C1D6
    };
    int           t;                 /* Loop counter                */
    unsigned int      temp;              /* Temporary word value        */
    unsigned int       W[80];             /* Word sequence               */
    unsigned int       A, B, C, D, E;     /* Word buffers                */

    /*
     *  Initialize the first 16 words in the array W
     */
    for(t = 0; t < 16; t++)
    {
        W[t] = context->Message_Block[t * 4] << 24;
        W[t] |= context->Message_Block[t * 4 + 1] << 16;
        W[t] |= context->Message_Block[t * 4 + 2] << 8;
        W[t] |= context->Message_Block[t * 4 + 3];
    }

    for(t = 16; t < 80; t++)
    {
        W[t] = SHA1CircularShift(1,W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
    }

    A = context->Intermediate_Hash[0];
    B = context->Intermediate_Hash[1];
    C = context->Intermediate_Hash[2];
    D = context->Intermediate_Hash[3];
    E = context->Intermediate_Hash[4];

    for(t = 0; t < 20; t++)
    {
        temp =  SHA1CircularShift(5,A) +
            ((B & C) | ((~B) & D)) + E + W[t] + K[0];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);

        B = A;
        A = temp;
    }

    for(t = 20; t < 40; t++)
    {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[1];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for(t = 40; t < 60; t++)
    {
        temp = SHA1CircularShift(5,A) +
            ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    for(t = 60; t < 80; t++)
    {
        temp = SHA1CircularShift(5,A) + (B ^ C ^ D) + E + W[t] + K[3];
        E = D;
        D = C;
        C = SHA1CircularShift(30,B);
        B = A;
        A = temp;
    }

    context->Intermediate_Hash[0] += A;
    context->Intermediate_Hash[1] += B;
    context->Intermediate_Hash[2] += C;
    context->Intermediate_Hash[3] += D;
    context->Intermediate_Hash[4] += E;

    context->Message_Block_Index = 0;
}
void SHA1PadMessage(SHA1Context *context)
{
    /*
     *  Check to see if the current message block is too small to hold
     *  the initial padding bits and length.  If so, we will pad the
     *  block, process it, and then continue padding into a second
     *  block.
     */
    if (context->Message_Block_Index > 55)
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while(context->Message_Block_Index < 64)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }

        SHA1ProcessMessageBlock(context);

        while(context->Message_Block_Index < 56)
        {
            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    }
    else
    {
        context->Message_Block[context->Message_Block_Index++] = 0x80;
        while(context->Message_Block_Index < 56)
        {

            context->Message_Block[context->Message_Block_Index++] = 0;
        }
    }

    /*
     *  Store the message length as the last 8 octets
     */
    context->Message_Block[56] = context->Length_High >> 24;
    context->Message_Block[57] = context->Length_High >> 16;
    context->Message_Block[58] = context->Length_High >> 8;
    context->Message_Block[59] = context->Length_High;
    context->Message_Block[60] = context->Length_Low >> 24;
    context->Message_Block[61] = context->Length_Low >> 16;
    context->Message_Block[62] = context->Length_Low >> 8;
    context->Message_Block[63] = context->Length_Low;

    SHA1ProcessMessageBlock(context);
}

void compute_sha(unsigned char* input, int size, unsigned char* output)
{

    SHA1Context sha;
    SHA1Reset(&sha);
    SHA1Input(&sha, input, size);    
    SHA1Result(&sha, output);
}
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

const unsigned short crc16tab[256]= {
    0x0000,0x1021,0x2042,0x3063,0x4084,0x50a5,0x60c6,0x70e7,
    0x8108,0x9129,0xa14a,0xb16b,0xc18c,0xd1ad,0xe1ce,0xf1ef,
    0x1231,0x0210,0x3273,0x2252,0x52b5,0x4294,0x72f7,0x62d6,
    0x9339,0x8318,0xb37b,0xa35a,0xd3bd,0xc39c,0xf3ff,0xe3de,
    0x2462,0x3443,0x0420,0x1401,0x64e6,0x74c7,0x44a4,0x5485,
    0xa56a,0xb54b,0x8528,0x9509,0xe5ee,0xf5cf,0xc5ac,0xd58d,
    0x3653,0x2672,0x1611,0x0630,0x76d7,0x66f6,0x5695,0x46b4,
    0xb75b,0xa77a,0x9719,0x8738,0xf7df,0xe7fe,0xd79d,0xc7bc,
    0x48c4,0x58e5,0x6886,0x78a7,0x0840,0x1861,0x2802,0x3823,
    0xc9cc,0xd9ed,0xe98e,0xf9af,0x8948,0x9969,0xa90a,0xb92b,
    0x5af5,0x4ad4,0x7ab7,0x6a96,0x1a71,0x0a50,0x3a33,0x2a12,
    0xdbfd,0xcbdc,0xfbbf,0xeb9e,0x9b79,0x8b58,0xbb3b,0xab1a,
    0x6ca6,0x7c87,0x4ce4,0x5cc5,0x2c22,0x3c03,0x0c60,0x1c41,
    0xedae,0xfd8f,0xcdec,0xddcd,0xad2a,0xbd0b,0x8d68,0x9d49,
    0x7e97,0x6eb6,0x5ed5,0x4ef4,0x3e13,0x2e32,0x1e51,0x0e70,
    0xff9f,0xefbe,0xdfdd,0xcffc,0xbf1b,0xaf3a,0x9f59,0x8f78,
    0x9188,0x81a9,0xb1ca,0xa1eb,0xd10c,0xc12d,0xf14e,0xe16f,
    0x1080,0x00a1,0x30c2,0x20e3,0x5004,0x4025,0x7046,0x6067,
    0x83b9,0x9398,0xa3fb,0xb3da,0xc33d,0xd31c,0xe37f,0xf35e,
    0x02b1,0x1290,0x22f3,0x32d2,0x4235,0x5214,0x6277,0x7256,
    0xb5ea,0xa5cb,0x95a8,0x8589,0xf56e,0xe54f,0xd52c,0xc50d,
    0x34e2,0x24c3,0x14a0,0x0481,0x7466,0x6447,0x5424,0x4405,
    0xa7db,0xb7fa,0x8799,0x97b8,0xe75f,0xf77e,0xc71d,0xd73c,
    0x26d3,0x36f2,0x0691,0x16b0,0x6657,0x7676,0x4615,0x5634,
    0xd94c,0xc96d,0xf90e,0xe92f,0x99c8,0x89e9,0xb98a,0xa9ab,
    0x5844,0x4865,0x7806,0x6827,0x18c0,0x08e1,0x3882,0x28a3,
    0xcb7d,0xdb5c,0xeb3f,0xfb1e,0x8bf9,0x9bd8,0xabbb,0xbb9a,
    0x4a75,0x5a54,0x6a37,0x7a16,0x0af1,0x1ad0,0x2ab3,0x3a92,
    0xfd2e,0xed0f,0xdd6c,0xcd4d,0xbdaa,0xad8b,0x9de8,0x8dc9,
    0x7c26,0x6c07,0x5c64,0x4c45,0x3ca2,0x2c83,0x1ce0,0x0cc1,
    0xef1f,0xff3e,0xcf5d,0xdf7c,0xaf9b,0xbfba,0x8fd9,0x9ff8,
    0x6e17,0x7e36,0x4e55,0x5e74,0x2e93,0x3eb2,0x0ed1,0x1ef0
};

unsigned short crc16_ccitt(const void *buf, int len)
{
    register int counter;
    register unsigned short crc = 0;
    for( counter = 0; counter < len; counter++)
        crc = (crc<<8) ^ crc16tab[((crc>>8) ^ *(char *)buf++)&0x00FF];
    return crc;
}
/* crc32!! */
const unsigned long crc32Table[256] = {
    0x00000000,0x77073096,0xEE0E612C,0x990951BA,0x076DC419,0x706AF48F,0xE963A535,
    0x9E6495A3,0x0EDB8832,0x79DCB8A4,0xE0D5E91E,0x97D2D988,0x09B64C2B,0x7EB17CBD,
    0xE7B82D07,0x90BF1D91,0x1DB71064,0x6AB020F2,0xF3B97148,0x84BE41DE,0x1ADAD47D,
    0x6DDDE4EB,0xF4D4B551,0x83D385C7,0x136C9856,0x646BA8C0,0xFD62F97A,0x8A65C9EC,
    0x14015C4F,0x63066CD9,0xFA0F3D63,0x8D080DF5,0x3B6E20C8,0x4C69105E,0xD56041E4,
    0xA2677172,0x3C03E4D1,0x4B04D447,0xD20D85FD,0xA50AB56B,0x35B5A8FA,0x42B2986C,
    0xDBBBC9D6,0xACBCF940,0x32D86CE3,0x45DF5C75,0xDCD60DCF,0xABD13D59,0x26D930AC,
    0x51DE003A,0xC8D75180,0xBFD06116,0x21B4F4B5,0x56B3C423,0xCFBA9599,0xB8BDA50F,
    0x2802B89E,0x5F058808,0xC60CD9B2,0xB10BE924,0x2F6F7C87,0x58684C11,0xC1611DAB,
    0xB6662D3D,0x76DC4190,0x01DB7106,0x98D220BC,0xEFD5102A,0x71B18589,0x06B6B51F,
    0x9FBFE4A5,0xE8B8D433,0x7807C9A2,0x0F00F934,0x9609A88E,0xE10E9818,0x7F6A0DBB,
    0x086D3D2D,0x91646C97,0xE6635C01,0x6B6B51F4,0x1C6C6162,0x856530D8,0xF262004E,
    0x6C0695ED,0x1B01A57B,0x8208F4C1,0xF50FC457,0x65B0D9C6,0x12B7E950,0x8BBEB8EA,
    0xFCB9887C,0x62DD1DDF,0x15DA2D49,0x8CD37CF3,0xFBD44C65,0x4DB26158,0x3AB551CE,
    0xA3BC0074,0xD4BB30E2,0x4ADFA541,0x3DD895D7,0xA4D1C46D,0xD3D6F4FB,0x4369E96A,
    0x346ED9FC,0xAD678846,0xDA60B8D0,0x44042D73,0x33031DE5,0xAA0A4C5F,0xDD0D7CC9,
    0x5005713C,0x270241AA,0xBE0B1010,0xC90C2086,0x5768B525,0x206F85B3,0xB966D409,
    0xCE61E49F,0x5EDEF90E,0x29D9C998,0xB0D09822,0xC7D7A8B4,0x59B33D17,0x2EB40D81,
    0xB7BD5C3B,0xC0BA6CAD,0xEDB88320,0x9ABFB3B6,0x03B6E20C,0x74B1D29A,0xEAD54739,
    0x9DD277AF,0x04DB2615,0x73DC1683,0xE3630B12,0x94643B84,0x0D6D6A3E,0x7A6A5AA8,
    0xE40ECF0B,0x9309FF9D,0x0A00AE27,0x7D079EB1,0xF00F9344,0x8708A3D2,0x1E01F268,
    0x6906C2FE,0xF762575D,0x806567CB,0x196C3671,0x6E6B06E7,0xFED41B76,0x89D32BE0,
    0x10DA7A5A,0x67DD4ACC,0xF9B9DF6F,0x8EBEEFF9,0x17B7BE43,0x60B08ED5,0xD6D6A3E8,
    0xA1D1937E,0x38D8C2C4,0x4FDFF252,0xD1BB67F1,0xA6BC5767,0x3FB506DD,0x48B2364B,
    0xD80D2BDA,0xAF0A1B4C,0x36034AF6,0x41047A60,0xDF60EFC3,0xA867DF55,0x316E8EEF,
    0x4669BE79,0xCB61B38C,0xBC66831A,0x256FD2A0,0x5268E236,0xCC0C7795,0xBB0B4703,
    0x220216B9,0x5505262F,0xC5BA3BBE,0xB2BD0B28,0x2BB45A92,0x5CB36A04,0xC2D7FFA7,
    0xB5D0CF31,0x2CD99E8B,0x5BDEAE1D,0x9B64C2B0,0xEC63F226,0x756AA39C,0x026D930A,
    0x9C0906A9,0xEB0E363F,0x72076785,0x05005713,0x95BF4A82,0xE2B87A14,0x7BB12BAE,
    0x0CB61B38,0x92D28E9B,0xE5D5BE0D,0x7CDCEFB7,0x0BDBDF21,0x86D3D2D4,0xF1D4E242,
    0x68DDB3F8,0x1FDA836E,0x81BE16CD,0xF6B9265B,0x6FB077E1,0x18B74777,0x88085AE6,
    0xFF0F6A70,0x66063BCA,0x11010B5C,0x8F659EFF,0xF862AE69,0x616BFFD3,0x166CCF45,
    0xA00AE278,0xD70DD2EE,0x4E048354,0x3903B3C2,0xA7672661,0xD06016F7,0x4969474D,
    0x3E6E77DB,0xAED16A4A,0xD9D65ADC,0x40DF0B66,0x37D83BF0,0xA9BCAE53,0xDEBB9EC5,
    0x47B2CF7F,0x30B5FFE9,0xBDBDF21C,0xCABAC28A,0x53B39330,0x24B4A3A6,0xBAD03605,
    0xCDD70693,0x54DE5729,0x23D967BF,0xB3667A2E,0xC4614AB8,0x5D681B02,0x2A6F2B94,
    0xB40BBE37,0xC30C8EA1,0x5A05DF1B,0x2D02EF8D };
unsigned long Crc32_ComputeBuf( unsigned long inCrc32, const void *buf,
        size_t bufLen, int stripe )
{
    unsigned long crc32;
    unsigned char *byteBuf;
    size_t i;

    /** accumulate crc32 for buffer **/
    crc32 = inCrc32 ^ 0xFFFFFFFF;
    byteBuf = (unsigned char*) buf;
    for (i=0; i < bufLen; i+= stripe) {
        crc32 = (crc32 >> 8) ^ crc32Table[ (crc32 ^ byteBuf[i]) & 0xFF ];
    }
    return( crc32 ^ 0xFFFFFFFF );
}
unsigned long crc32_hash (char *in_buf, int in_len, int stripe){
    unsigned long crc32_result=0;
    crc32_result = Crc32_ComputeBuf(crc32_result, in_buf, in_len, stripe);
    return crc32_result;
}
/* md5!*/
void md5(uint32_t *hash, uint32_t *input)
{
    uint32_t a, b, c, d;
    uint32_t *in,t, max =64;
    a = hash[0];
    b = hash[1];
    c = hash[2];
    d = hash[3];
    in = input;
    t = 0;
    while(t++ < max){
        MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
        MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
        MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
        MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
        MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
        MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
        MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
        MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
        MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
        MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
        MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
        MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
        MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
        MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
        MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
        MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

        MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
        MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
        MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
        MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
        MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
        MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
        MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
        MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
        MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
        MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
        MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
        MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
        MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
        MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
        MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
        MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

        MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
        MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
        MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
        MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
        MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
        MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
        MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
        MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
        MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
        MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
        MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
        MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
        MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
        MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
        MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
        MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);

        MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
        MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
        MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
        MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
        MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
        MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
        MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
        MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
        MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
        MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
        MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
        MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
        MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
        MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
        MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
        MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);

        hash[0] += a;
        hash[1] += b;
        hash[2] += c;
        hash[3] += d;
        in = in +16;
    }
}
/* adler 32*/


unsigned long adler32_z(unsigned long adler,char* buf,int  len)
{
    unsigned long sum2;
    unsigned n;

    /* split Adler-32 into component sums */
    sum2 = (adler >> 16) & 0xffff;
    adler &= 0xffff;

    /* in case user likes doing a byte at a time, keep it fast */
    if (len == 1) {
        adler += buf[0];
        if (adler >= BASE)
            adler -= BASE;
        sum2 += adler;
        if (sum2 >= BASE)
            sum2 -= BASE;
        return adler | (sum2 << 16);
    }

    /* initial Adler-32 value (deferred check for len == 1 speed) */
    if (buf == NULL)
        return 1L;

    /* in case short lengths are provided, keep it somewhat fast */
    if (len < 16) {
        while (len--) {
            adler += *buf++;
            sum2 += adler;
        }
        if (adler >= BASE)
            adler -= BASE;
        MOD28(sum2);            /* only added so many BASE's */
        return adler | (sum2 << 16);
    }

    /* do length NMAX blocks -- requires just one modulo operation */
    while (len >= NMAX) {
        len -= NMAX;
        n = NMAX / 16;          /* NMAX is divisible by 16 */
        do {
            DO16(buf);          /* 16 sums unrolled */
            buf += 16;
        } while (--n);
        MOD(adler);
        MOD(sum2);
    }

    /* do remaining bytes (less than NMAX, still just one modulo) */
    if (len) {                  /* avoid modulos if none remaining */
        while (len >= 16) {
            len -= 16;
            DO16(buf);
            buf += 16;
        }
        while (len--) {
            adler += *buf++;
            sum2 += adler;
        }
        MOD(adler);
        MOD(sum2);
    }

    /* return recombined sums */
    return adler | (sum2 << 16);
}
unsigned long adler32_z2(unsigned long adler,char* buf,int  len)
{
    unsigned long sum2 = 0;/////
    int prime1 = 37;
    int prime2 = 4099;
    int index = 1;
    int count = 0;
    int limit = (len >>2)*3; // 50%

    /* do remaining bytes (less than NMAX, still just one modulo) */

    if (len) {                  // avoid modulos if none remaining 
        while (count < limit ) {
            if(index < len -16){
                adler += buf[index];
                sum2+= adler;
                count ++;
            }
            index = (index + prime1)%prime2;
        }
        sum2 += adler;
        MOD(adler);
        MOD(sum2);
    }

    /* return recombined sums */
    return adler | (sum2 << 16);
}

unsigned long adler32_z3(unsigned long adler,char* buf,int  len)
{
    unsigned long sum2 = 0;/////
    int prime1 = 37;
    int prime2 = 4099;
    int index = 1;
    int count = 0;
    int limit = len >>1; // 50%

    /* do remaining bytes (less than NMAX, still just one modulo) */

    if (len) {                  // avoid modulos if none remaining 
        while (count < limit ) {
            if(index < len -16){
                adler += buf[index];
                sum2+= adler;
                count ++;
            }
            index = (index + prime1)%prime2;
        }
        sum2 += adler;
        MOD(adler);
        MOD(sum2);
    }

    /* return recombined sums */
    return adler | (sum2 << 16);
}
unsigned long adler32_z4(unsigned long adler,char* buf,int  len)
{
    //unsigned int *u32_buf = (unsigned int*)(buf+1);

    unsigned long sum2 = 0;/////
    int prime1 = 37;
    int prime2 = 4099;
    int index = 1;
    int count = 0;
    int limit = len >>2; // 25%

    /* do remaining bytes (less than NMAX, still just one modulo) */

    if (len) {                  // avoid modulos if none remaining 
        while (count < limit ) {
            if(index < len -16){
                adler += buf[index];
                sum2+= adler;
                count ++;
            }
            index = (index + prime1)%prime2;
        }
        sum2 += adler;
        MOD(adler);
        MOD(sum2);
    }

    /* return recombined sums */
    //return 0;
    return adler | (sum2 << 16);
}
unsigned long adler32_z5(unsigned long adler,char* buf,int  len)
{
    unsigned long sum2 = 0;/////
    int prime1 = 37;
    int prime2 = 1031;
    int index = 1;
    int count = 0;
    int limit = (len >>2) *3 ; // 75 %
    int *ptr ;
    limit = (1024 >>2 )*3;
    ptr = (int*)buf;
    /* do remaining bytes (less than NMAX, still just one modulo) */

    if (len) {                  // avoid modulos if none remaining 
        while (count < limit ) {
            if(index < 1024){
                SUM_4CHAR(adler, ptr[index]);
                //adler += buf[index];
                //sum2+= adler;
                count ++;
            }
            index = (index + prime1)%prime2;
        }
        //sum2 += adler;
        MOD(adler);
        MOD(sum2);
    }
    /* return recombined sums */
    return adler | (sum2 << 16);
}
unsigned long adler32_z6(unsigned long adler,char* buf,int  len)
{
    unsigned long sum2 = 0;/////
    int prime1 = 37;
    int prime2 = 1031;
    int index = 1;
    int count = 0;
    int limit = (len >>1) ; // 50 %
    int *ptr ;
    limit = (1024 >>1 );
    ptr = (int*)buf;
    /* do remaining bytes (less than NMAX, still just one modulo) */

    if (len) {                  // avoid modulos if none remaining 
        while (count < limit ) {
            if(index < 1024){
                SUM_4CHAR(adler, ptr[index]);
                //adler += buf[index];
                //sum2+= adler;
                count ++;
            }
            index = (index + prime1)%prime2;
        }
        //sum2 += adler;
        MOD(adler);
        MOD(sum2);
    }
    /* return recombined sums */
    return adler | (sum2 << 16);
}
unsigned long adler32_z7(unsigned long adler,char* buf,int  len)
{
    unsigned long sum2 = 0;/////
    //int prime1 = 37;
    //int prime2 = 1031;
    unsigned int  tmp;
    //int limit = (len >>2),i;  // 25 %
    int i;
    unsigned int *ptr ;
    //limit = (1024 >>2 );
    ptr = (int*)buf;
    /* do remaining bytes (less than NMAX, still just one modulo) */

    if (len) {                  // avoid modulos if none remaining 
        for(  i = 0 ; i < 1024 ; i +=4){
            tmp = *ptr++;
            adler += ((tmp) & 0xff);
            sum2  += adler;
            adler += ((tmp >>  16 ) & 0xff);
            sum2  += (adler);
            tmp = *ptr++;
            adler += ((tmp >> 8 ) & 0xff);
            sum2  += adler;
            adler += ((tmp >>  24 ) & 0xff);
            sum2  += (adler);
            tmp = *ptr++;
            adler += ((tmp >> 8) & 0xff);
            sum2  += adler;
            adler += ((tmp >>  16 ) & 0xff);
            sum2  += (adler);
            tmp = *ptr++;
            adler += ((tmp) & 0xff);
            sum2  += adler;
            adler += ((tmp >>  24 ) & 0xff);
            sum2  += (adler);


        }
        /*
           while (count < limit ) {
           if(index < 1024){
           SUM_4CHAR(adler, ptr[index]);
    //adler += buf[index];
    //sum2+= adler;
    count ++;
    }
    index = (index + prime1)%prime2;
    }
         */
        //sum2 += adler;
        MOD(adler);
        MOD(sum2);
    }
    /* return recombined sums */
    return adler | (sum2 << 16);
}
unsigned long adler_hash(char *in_buf, int in_len){
    unsigned long  adler =0;
    adler = adler32_z(adler,in_buf, in_len );
    return adler;
}
unsigned long adler_hash2(char *in_buf, int in_len){
    unsigned long  adler =0;
    adler = adler32_z2(adler,in_buf, in_len );
    return adler;
}
unsigned long adler_hash3(char *in_buf, int in_len){
    unsigned long  adler =0;
    adler = adler32_z3(adler,in_buf, in_len );
    return adler;
}
unsigned long adler_hash4(char *in_buf, int in_len){
    unsigned long  adler =0;
    adler = adler32_z4(adler,in_buf, in_len );
    return adler;
}
unsigned long adler_hash5(char *in_buf, int in_len){
    unsigned long  adler =0;
    adler = adler32_z5(adler,in_buf, in_len );
    return adler;
}
unsigned long adler_hash6(char *in_buf, int in_len){
    unsigned long  adler =0;
    adler = adler32_z6(adler,in_buf, in_len );
    return adler;
}
unsigned long adler_hash7(char *in_buf, int in_len){
    unsigned long  adler =0;
    adler = adler32_z7(adler,in_buf, in_len );
    return adler;
}
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

void print_bio(struct bio *print_bio, int flag)
{
    int i ,j; 
    struct bio_vec *biovec, *tmpvec;
    void *vpp;
    static int index1 = 0,index2=0;
    int index;

    static unsigned int count = 0;
    //unsigned short crc16 = 0 ;
    //unsigned long crc32_1 = 0;
    //unsigned long crc32_2 = 0;
    //unsigned long crc32_10 = 0;
    unsigned long adler_result = 0, adler_result2=0, adler_result3=0, adler_result4=0;

    unsigned long adler_result5 = 0, adler_result6=0, adler_result7=0;
    unsigned char fp[SHA1HashSize + 1];
#define PRINT_BYTES 40 
    char data_buf[PRINT_BYTES * 2 + 1];
    char sha_buf[SHA1HashSize*2 +1 ];
    struct page *bio_page;    
    unsigned int md5_result[4] = {0};
    struct dentry *p;
    unsigned char unknown[] = "unknown";
    unsigned char *pname;
    int w_flag;
    for( i = 0 ; i < SHA1HashSize ; i++){
        fp[i] = 0;
    }
    biovec = print_bio->bi_io_vec;
    w_flag = 0;
    if(print_bio->bi_rw & WRITE || print_bio-> bi_rw & READ)
    {
        if( biovec)
        {
            if(print_bio->bi_rw & WRITE )
                w_flag = 1;
            tmpvec = biovec + print_bio->bi_idx ; 
            bio_page = tmpvec->bv_page;

            for(i = 0 ; i < print_bio->bi_vcnt ; i++){
                if(flag == 1)
                    index = index1++;
                else
                    index = index2++;
                tmpvec = biovec + i ; 
                j = 0 ;
                vpp = kmap_atomic(tmpvec->bv_page);
                if(vpp != NULL) {

                    for(j = tmpvec->bv_offset ; j < tmpvec->bv_offset + PRINT_BYTES; j++)
                        sprintf(data_buf + j*2 , "%02x",*((unsigned char*)vpp+j ));
                    //crc16 = crc16_ccitt(vpp + tmpvec->bv_offset, tmpvec->bv_len);

                    //crc32_1 = crc32_hash((char*)vpp + tmpvec->bv_offset,tmpvec->bv_len,1);
                    //crc32_2 = crc32_hash((char*)vpp + tmpvec->bv_offset,tmpvec->bv_len,2);
                    //crc32_10 = crc32_hash((char*)vpp + tmpvec->bv_offset,tmpvec->bv_len,10);
                    compute_sha((unsigned char*) vpp +tmpvec->bv_offset, tmpvec->bv_len, fp );
                    adler_result = adler_hash(( char*) vpp +tmpvec->bv_offset, tmpvec->bv_len);
                    adler_result2 = adler_hash2(( char*) vpp +tmpvec->bv_offset, tmpvec->bv_len);
                    adler_result3 = adler_hash3(( char*) vpp +tmpvec->bv_offset, tmpvec->bv_len);
                    adler_result4 = adler_hash4(( char*) vpp +tmpvec->bv_offset, tmpvec->bv_len);
                    adler_result5 = adler_hash5(( char*) vpp +tmpvec->bv_offset, tmpvec->bv_len);
                    adler_result6 = adler_hash6(( char*) vpp +tmpvec->bv_offset, tmpvec->bv_len);
                    adler_result7 = adler_hash7(( char*) vpp +tmpvec->bv_offset, tmpvec->bv_len);
                    md5(md5_result, (unsigned int*)vpp);      
                    kunmap_atomic(vpp);
                    fp[SHA1HashSize] = '\0';
                    for( j = 0 ; j < SHA1HashSize ; j++)
                        sprintf(sha_buf+ j*2 ,"%02x", (unsigned char)fp[j]);
                    sha_buf[SHA1HashSize*2] = '\0';
                    if(bio_page && 
                            bio_page->mapping && 
                            ((unsigned long) bio_page->mapping & PAGE_MAPPING_ANON) == 0  && 
                            bio_page->mapping->host 
                      ){
                        p = NULL ; 
                        if( !list_empty(&(bio_page->mapping->host->i_dentry)))
                            p = list_first_entry(&(bio_page->mapping->host->i_dentry), struct dentry, d_alias);
                        if(p != NULL ) {
                            pname = p->d_iname;
                            for(j = 0 ; j < strlen(p->d_iname); j++){
                                if( (p->d_iname[j]!= '\0')  &&  ( (p->d_iname[j] < 32) || (p->d_iname[j] > 126))){ 
                                    pname = unknown;
                                    printk("origin = %s\n",p->d_iname);
                                    break;
                                }
                            } 
                            printk(KERN_DEBUG "fidx%d&%d&%10llu&%s&%s&%lu&%s&%s\n", flag, 
                                    count, print_bio->bi_sector, pname, current->comm,bio_page->mapping->host->i_ino, sha_buf, data_buf);
                            //fpr&index&sha&crc32&md5
                        } else{
                            printk(KERN_DEBUG "fidx%d&%d&%10llu&NULL&%s&%lu&%s&%s\n", flag,
                                    count, print_bio->bi_sector, current->comm,bio_page->mapping->host->i_ino, sha_buf, data_buf);
                            //fpr&index&sha&crc32&md5
                            //printk(KERN_DEBUG "fpr&%d&%s&%lu&%u%u%u%u\n",
                            //index,sha_buf,crc32, md5_result[0], md5_result[1], md5_result[2],md5_result[3]);

                            //printk(KERN_DEBUG "fpr&%10llu&NULL&%s&%s&%lu&%s\n", 
                            // print_bio->bi_sector, current->comm, sha_buf,bio_page->mapping->host->i_ino, data_buf);
                        }
                        printk(KERN_DEBUG "fpr&%d&%s&%lu&%u%u%u%u\n",
                                count,sha_buf,adler_result, md5_result[0], md5_result[1], md5_result[2],md5_result[3]);	
                        printk(KERN_DEBUG "adlerr&%lu&%lu&%lu&%lu\n", adler_result, adler_result2, adler_result3,adler_result4);
                        printk(KERN_DEBUG "qaq22&%lu&%lu&%lu\n", adler_result5, adler_result6, adler_result7);
                        count ++;
                        // printk(KERN_DEBUG "crc_r&%d&%lu&%lu&%lu\n",
                        // index,crc32_1,crc32_2, crc32_10);	
                    }
                    if(flag == 2)
                    printk(KERN_DEBUG "qqqiq&%10llu&%s&%s\n", 
                                     print_bio->bi_sector, sha_buf, data_buf);
                     
                    //bio_page = tmpvec->bv_page;
                    //if(bio_page != NULL){
                    //    print_page_inode(bio_page);    
                    //}
                    //printk("%04X,", crc16);
                    //printk("\n");

                } else{ 
                    printk(KERN_DEBUG"kmap fail\n");
                }
            }
            //printk(KERN_DEBUG"=======\n");
        }
    }
}

void timespec_diff(struct timespec *start, struct timespec *stop, struct timespec *result)
{
    if ((stop->tv_nsec - start->tv_nsec) < 0) {
        result->tv_sec = stop->tv_sec - start->tv_sec - 1;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec + 1000000000;
    } else {
        result->tv_sec = stop->tv_sec - start->tv_sec;
        result->tv_nsec = stop->tv_nsec - start->tv_nsec;
    }
    return;
}
void init_bio_time(struct bio *bio)
{
    struct timespec ts;
    static unsigned int uniq = 0;
    getnstimeofday(&ts);
    //bio->timestamp = ts;
    //bio->uniq = uniq;
    uniq ++;
}
void print_bio2(struct bio *print_bio)
{
    int i, j, k; 
    struct bio_vec *biovec, *tmpvec;
    void *vpp;
#define NUM_PARTIAL_SHA (4)
    unsigned char fp[NUM_PARTIAL_SHA + 1][SHA1HashSize + 1];
#define PRINT_BYTES 40 
    unsigned char *tmp_buf;
    //char data_buf[PRINT_BYTES * 2 + 1];
    char sha_buf[NUM_PARTIAL_SHA+1][SHA1HashSize*2 +1 ];
    struct page *bio_page;    
    struct dentry *p;
    unsigned char unknown[] = "unknown", null[]="NULL";
    unsigned char *pname;
    int w_flag;
    for( i = 0 ; i <= NUM_PARTIAL_SHA ; i++){
        memset(fp[i], 0, SHA1HashSize +1 );
        memset(sha_buf[i], 0, SHA1HashSize*2+1);
    }
    biovec = print_bio->bi_io_vec;
    bio_page = biovec->bv_page;
    pname = null;
    vpp = NULL;
    i = j = k = 0;
    /* get filename */
    if(bio_page && 
            bio_page->mapping && 
            ((unsigned long) bio_page->mapping & PAGE_MAPPING_ANON) == 0  && 
            bio_page->mapping->host )
    {
        p = NULL ; 
        if( !list_empty(&(bio_page->mapping->host->i_dentry)))
            p = list_first_entry(&(bio_page->mapping->host->i_dentry), struct dentry, d_alias);
        if(p != NULL ) {
            pname = p->d_iname;
            for(j = 0 ; j < strlen(p->d_iname); j++){
                if( (p->d_iname[j]!= '\0')  &&  ( (p->d_iname[j] < 32) || (p->d_iname[j] > 126))){ 
                    pname = unknown;
                    printk("origin = %s\n",p->d_iname);
                    break;
                }
            } 
        }
    }

    w_flag = 0;
    if(print_bio->bi_rw & WRITE || print_bio-> bi_rw & READ)
    {
        if(!biovec) {
            goto END;
        }
        tmp_buf = kmalloc(biovec->bv_len, GFP_KERNEL);
        if(!tmp_buf)
            goto END;
        for(i = 0 ; i < print_bio->bi_vcnt ; i++) { 
            tmpvec = biovec + i;
            j = 0;
            /* compress */


            vpp = kmap_atomic(tmpvec->bv_page);
            if(!vpp){
                printk("map fail!");
                return;
            }
                
            /* calculate partial sha*/ 
            
            compute_sha((unsigned char*)vpp + tmpvec->bv_offset, tmpvec->bv_len, (unsigned char*)fp[0]);
            fp[0][SHA1HashSize] = '\0';
            
            for(j = 1 ; j <= NUM_PARTIAL_SHA ; j++)
            {

                compute_sha((unsigned char*)vpp + tmpvec->bv_offset + (tmpvec->bv_len >>2) * (j-1), tmpvec->bv_len >>2, (unsigned char*)fp[j]);
                fp[j][SHA1HashSize] = '\0';
            }
            
            for(j = 0 ; j <= NUM_PARTIAL_SHA; j++)
            {
                for( k = 0 ; k < SHA1HashSize ; k++)
                    sprintf((char*)sha_buf[j]+ k*2 ,"%02x", (unsigned char)fp[j][k]);
                sha_buf[j][SHA1HashSize*2] = '\0';
            }

            kunmap_atomic(vpp);
            
        }
       printk(KERN_DEBUG "sha_complete&%s&%s&%10llu\n", sha_buf[0], pname, print_bio->bi_sector);
        for(i = 1 ; i <= NUM_PARTIAL_SHA; i++) {
            printk(KERN_DEBUG "sha_partial%d&%s&%s&%10llu\n",i, sha_buf[i], pname, print_bio->bi_sector);
        }
        //printk(KERN_DEBUG "fidx%d&%d&%10llu&%s&%s&%lu&%s&%s\n", flag, 
                            //			count, print_bio->bi_sector, pname, current->comm,bio_page->mapping->host->i_ino, sha_buf, data_buf);
 
        kfree(tmp_buf);
        return ;
    }
END:
    printk("QAQ\n");  
    return;    
}

void get_filename(struct bio *print_bio, char *output)
{
    int i, j, k; 
    struct bio_vec *biovec;
    void *vpp;
    struct page *bio_page;    
    struct dentry *p;
    unsigned char unknown[] = "unknown", null[]="NULL";
    unsigned char *pname;
    biovec = print_bio->bi_io_vec;
    bio_page = biovec->bv_page;
    pname = null;
    vpp = NULL;
    i = j = k = 0;
    /* get filename */
    if(bio_page && 
            bio_page->mapping && 
            ((unsigned long) bio_page->mapping & PAGE_MAPPING_ANON) == 0  && 
            bio_page->mapping->host )
    {
        p = NULL ; 
        if( !list_empty(&(bio_page->mapping->host->i_dentry)))
            p = list_first_entry(&(bio_page->mapping->host->i_dentry), struct dentry, d_alias);
        if(p != NULL ) {
            pname = p->d_iname;
            for(j = 0 ; j < strlen(p->d_iname); j++){
                if( (p->d_iname[j]!= '\0')  &&  ( (p->d_iname[j] < 32) || (p->d_iname[j] > 126))){ 
                    pname = unknown;
                    break;
                }
            } 
        }
    }
    if(pname != unknown &&  pname != null)
    {
        memcpy(output, pname, DNAME_INLINE_LEN);
    }
    if(pname == unknown)
        memcpy(output, pname, 7 + 1);
    if(pname == null)
        memcpy(output, pname, 7 + 1);
        
    return;    
}

int get_page_data(struct page *p, char *output)
{
    void *vpp = NULL;
    vpp = kmap(p);
    if(!vpp)
        return -1;
    memcpy(output, (char *)vpp, PAGE_SIZE);
    kunmap(p);
    vpp = NULL;
    return 0;
}
int print_bio3(struct bio *print_bio, int flag)
{
    char *pagedata;
    char filename[DNAME_INLINE_LEN +1];
    char sha[SHA1HashSize +1];
    char sha_q[4][SHA1HashSize+1];
    char sha_hex[SHA1HashSize*2 +1];
    char sha_hex_q[4][SHA1HashSize*2 +1];
    char comments[20+1];
    unsigned short crc16;
    unsigned long crc32;
    int i, j, k, ret; 
    struct bio_vec *biovec;
   
    ret = 0;
    memset(filename, '\0', sizeof(filename));
    memset(sha, '\0', sizeof(sha));
    memset(sha_hex, '\0', sizeof(sha_hex));
    memset(comments, '\0', sizeof(comments));
    
    switch(flag){
        case RAW_BIO:
            sprintf(comments, "RAWBIO");
        break;
        case ENC_BIO:
            sprintf(comments, "ENCBIO");
        break;
    
    }

    biovec = print_bio->bi_io_vec;
    pagedata =(char*) kmalloc(PAGE_SIZE, GFP_KERNEL);
    memset(pagedata, 0, PAGE_SIZE);
    if(!pagedata || !biovec)
        goto end;

    for(i = 0 ; i < print_bio->bi_vcnt ; i++) { 
        biovec = print_bio->bi_io_vec + i;
        if(!biovec->bv_page)
            goto free;
        ret = get_page_data(biovec->bv_page, pagedata);
        if(ret < 0)
            goto free;
        printk("page offset %u len %u\n", biovec->bv_offset, biovec->bv_len);
        compute_sha((unsigned char *)pagedata + biovec->bv_offset, biovec->bv_len, sha);
        compute_sha((unsigned char *)pagedata + biovec->bv_offset, biovec->bv_len/4, sha_q[0]);
        compute_sha((unsigned char *)pagedata + biovec->bv_offset + PAGE_SIZE/4, biovec->bv_len/4, sha_q[1]);
        compute_sha((unsigned char *)pagedata + biovec->bv_offset + PAGE_SIZE/2, biovec->bv_len/4, sha_q[2]);
        compute_sha((unsigned char *)pagedata + biovec->bv_offset + (PAGE_SIZE >>2) *3, biovec->bv_len/4, sha_q[3]);
        for(j = 0; j < SHA1HashSize; j++) {
            sprintf((char*) sha_hex + j*2, "%02x", (unsigned char)sha[j]);
        }
        for(j = 0; j < 4 ; j++){
            for(k = 0 ; k < SHA1HashSize; k++){
                sprintf((char*) sha_hex_q[j] + k*2, "%02x", (unsigned char)sha_q[j][k]);
            }
        }
        crc16 = crc16_ccitt(pagedata, PAGE_SIZE);
        crc32 = crc32_hash(pagedata, PAGE_SIZE, 1);
        get_filename(print_bio, filename);    
        
        
        trace_io_fin(print_bio, filename, sha_hex, crc32, crc16, comments); 
        trace_io_sha_4(print_bio, filename, sha_hex_q[0], sha_hex_q[1], sha_hex_q[2], sha_hex_q[3], comments);
    }
    return 0;
free:
    kfree(pagedata);
end:
    printk("alloc fail");
    return -1;




}
// print ext4 journal descriptor block 

/* if( *((unsigned char*)(vpp)) == 0xc0 &&
 *((unsigned char*)(vpp+1)) == 0x3b &&
 *((unsigned char*)(vpp+2)) == 0x39 &&
 *((unsigned char*)(vpp+3)) == 0x98)
 {
#define convert(NUM) (((NUM>>24)&0xff)        | \
((NUM>>8)&0xff00)       | \
((NUM<<8)&0xff0000)     | \
((NUM<<24)&0xff000000))

base = 12; 
tmp_block =*(unsigned int*) (vpp+ base);
tmp_flag = *(unsigned int*) (vpp+ base +4);
while(1)
{
tmp_flag = convert(tmp_flag);
tmp_block = convert(tmp_block);
printk(KERN_DEBUG "ext4J&%u&%x&%u\n", tmp_block, tmp_flag, base); 
base = base + 8 ;   

base = base + 16 *((!tmp_flag)) ; 
if(tmp_flag & 0x00000008)
break;
tmp_block =*((unsigned int*) (vpp+ base));
tmp_flag = *((unsigned int*) (vpp+ base +4));
}
}*/


int lzo_compress(char *data, int len){
    unsigned char *wrkmem = NULL;
    unsigned char *dst_buf = NULL;
    int out_len = 0;
    int ret = -1;
    wrkmem = (unsigned char *) kmalloc(LZO1X_MEM_COMPRESS, GFP_KERNEL);
    dst_buf = (unsigned char *) kmalloc( lzo1x_worst_compress(4096), GFP_KERNEL);
    if(!wrkmem || !dst_buf) {
        goto END;
    }
    ret = lzo1x_1_compress(data, len, dst_buf, &out_len, wrkmem);
END:
    /* kfree is NULL-safe */
    kfree((void *)dst_buf);
    kfree((void *) wrkmem);
    if(ret == LZO_E_OK)
        return out_len;
    return ret;
}

