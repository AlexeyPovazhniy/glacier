#ifdef METTLE
    /* MetalC Dependencies */
    #include <metal/metal.h>
    #include <metal/ctype.h>
    #include <metal/stddef.h>
    #include <metal/stdio.h>
    #include <metal/stdlib.h>
    #include <metal/string.h>
    #include <metal/stdarg.h>
    #include <metal/limits.h>

    /* COMMON Dependencies */
    #include "alloc.h"          // Allocation functions
    #include "bpxnet.h"         // Sockets functionality
    #include "cldutils.h"       // Logging system
    #include "hwtj.h"           // IBM JSON parser
#else
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <stdarg.h>
    #include <stddef.h>
    #include <ctype.h>
    #include <limits.h>
#endif

/* Local Dependencies */
#include "rs_hash.h"
#include "rs_hmac.h"
#include "rs_ctxtypes.h"
#include "rs_crypto_errors.h"
#include "glacier.h"
#include "clderror.h"

char const DEFAULT_GLACIER_REGION[] = "us-east-1";

/*---------------------------- Glacier internal functions ----------------------------*/
#define MB (1024 * 1024)

char const emptyStringSHA256Value[] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
char const BaseQuery[] = "/-/vaults";

// Debug purposes only
extern unsigned long long GlobalAllocatedMemory;   // For checking memory leaks for debug only (don't forget to delete it)!!!
//

static void getDateTime(char* DateTime, char* Date)
{
#ifdef METTLE
    char stck[9];
    char stckTimestamp[27];            // yyyy-mm-dd-hr.mn.sc.millis (GMT)

    // Get and format the current time in GMT
    stck[8] = 0x00;
    __asm(" STCK  %0":: "=m"(stck));   // Get store clock time
    stck2ts(stck, stckTimestamp);
    stckTimestamp[26] = 0x00;
  
    // Create yyyymmdd format date from stckTimestamp
    sprintf(Date, "%.4s%.2s%.2s",
            stckTimestamp, stckTimestamp + 5, stckTimestamp + 8);
  
    // Compose final date header
    sprintf(DateTime, "%sT%.2s%.2s%.2sZ", Date,
            stckTimestamp + 11, stckTimestamp + 14, stckTimestamp + 17);
#endif
}

static int SHA256(char const * const buffer,                // hash will be calculated on the content of this buffer
                  const unsigned long long BufferSize,
                  char * sha256String,                      // output parameter in hexadecimal-string null-terminated form
                  const size_t sha256StringAllocatedSize    // don't forget byte for '\0' character!
                 )
{
#ifdef METTLE
    unsigned char sha256[SHA256_HASH_BYTES];
    unsigned char * sha256Ptr = sha256;
    size_t sha256Len = SHA256_HASH_BYTES;

    int retValue = rs_hash_oneshot(
                                   RS_ALG_SHA256,
                                   (unsigned char *) buffer,
                                   BufferSize,   // TODO: not supported 4 Gb sizes here (inside "rs_hash_oneshot()" function) in non-64 bit mode
                                   &sha256Ptr,
                                   &sha256Len
                                  );
    if (retValue != RS_SUCCESS)
    {
        logError("\n SHA256: error in rs_hash_oneshot() function occurred (return value: %d) \n", retValue);
        return -1;
    }

    retValue = CharToHex(sha256, sha256Len, sha256String, sha256StringAllocatedSize);

    if (retValue != 0)
    {
        logError("\n SHA256: error in CharToHex() function occurred (return value: %d) \n", retValue);
        return -1;
    }

    return 0;
#endif
}

static int HMAC(char const * const keyString,     // always in hexadecimal-string null-terminated form and should have even length (!)
                char const * const textString,    // null-terminated text buffer
                char * hmacString,                // output paramater in hexadecimal-string null-terminated form
                size_t hmacStringAllocatedSize    // don't forget byte for '\0' character!
               )
{
#ifdef METTLE
    size_t keylen = strlen(keyString);

    if (keylen < 2)
    {
        logError("\n HMAC: error, keyString is too short \n");
        return -1;
    }

    if (keylen & 1)
    {
        logError("\n HMAC: error, length(keyString) should be even \n");
        return -1;
    }

    size_t binkeyAllocatedSize = (keylen / 2) * sizeof(unsigned char);
    unsigned char * binkey = (unsigned char *) allocate(binkeyAllocatedSize, "HMAC binkey array");

    // Convert hex key to binary (necessary for Amazon Glacier)
    size_t binkeylen = 0;
    unsigned int uitemp = 0;

    for (size_t i = 0; i < keylen; i += 2)
        if (sscanf(keyString + i, "%2x", &uitemp) == 1)
        {
            binkey[binkeylen] = (unsigned char) uitemp;
            binkeylen++;
        }
        else
        {
            logError("\n HMAC: error in sscanf() function occurred \n");
            deallocate(binkey, binkeyAllocatedSize);
            return -1;
        }
    //---------------------------------------------------------

    RS_KEY_T key_struct;
    key_struct.keytype = RS_KEYTYPE_RAW;
    key_struct.algorithm = RS_ALG_SHA256;
    key_struct.ctxtype = KEY_CTX;
    key_struct.data = binkey;
    key_struct.data_length = binkeylen;

    unsigned char hmac[SHA256_HASH_BYTES];
    unsigned char * hmacPtr = hmac;

    size_t hmacLen = keylen;
    if (hmacLen < SHA256_HASH_BYTES)   // On first call for each request "hmacLen" should have length = 88,
        hmacLen = SHA256_HASH_BYTES;   // on another calls it should be 32 bytes long, so if it will be less,
                                       // some problems with correctness of "rs_hmac_oneshot()" result could be

    int retValue = rs_hmac_oneshot(
                                   &key_struct,
                                   (unsigned char *) textString,
                                   strlen(textString),
                                   &hmacPtr,
                                   &hmacLen
                                  );

    deallocate(binkey, binkeyAllocatedSize);

    if (retValue != RS_SUCCESS)
    {
        logError("\n HMAC: error in rs_hmac_oneshot() function occurred (return value: %d) \n", retValue);
        return -1;
    }

    retValue = CharToHex(hmac, SHA256_HASH_BYTES, hmacString, hmacStringAllocatedSize);
    if (retValue != 0)
    {
        logError("\n HMAC: error in CharToHex() function occurred (return value: %d) \n", retValue);
        return -1;
    }

    return 0;
#endif
}

static ptrdiff_t getCanonicalRequest(char const * const Method, char const * const Query, char const * const Region,
                                     char const * const amzParam, char const * const amzParamList,
                                     char const * const Body, const unsigned long long BodySize,
                                     char * CanonicalRequest         // output paramater in null-terminated character form
                                    )
{
#ifdef METTLE
    if ( !(Method && Query && Region && amzParam && amzParamList) )
    {
        logError("\n getCanonicalRequest: necessary parameters not specified \n");
        return -1;
    }

    char HostHead[] = "\n\nhost:glacier.";
    char HostTail[] = ".amazonaws.com\n";

    if (!CanonicalRequest)       // used for dynamic allocations, we need to know output array size firstly, before writing data to it
    {
        return
               (strlen(Method) + strlen("\n") + strlen(Query) + strlen(HostHead) + strlen(Region) + strlen(HostTail) +
                strlen(amzParam) + strlen("\n\nhost;") + strlen(amzParamList) + strlen("\n") +
                SHA256_HEX_LENGTH + 1
               );
    }

    char BodySHA256[SHA256_HEX_LENGTH + 1] = "\0";
    if (Body)
    {

        int retValue = SHA256(Body, BodySize, BodySHA256, SHA256_HEX_LENGTH + 1);

        if (retValue != 0)
        {
            logError("\n getCanonicalRequest: error in SHA256() function occurred \n");
            return -1;
        }
    }
    else
        strcat(BodySHA256, emptyStringSHA256Value);

    CanonicalRequest[0] = 0;
    strcat(CanonicalRequest, Method);
    strcat(CanonicalRequest, "\n");
    strcat(CanonicalRequest, Query);
    strcat(CanonicalRequest, HostHead);
    strcat(CanonicalRequest, Region);
    strcat(CanonicalRequest, HostTail);
    strcat(CanonicalRequest, amzParam);
    strcat(CanonicalRequest, "\n\nhost;");
    strcat(CanonicalRequest, amzParamList);
    strcat(CanonicalRequest, "\n");
    strcat(CanonicalRequest, BodySHA256);

    return 0;
#endif
}

static ptrdiff_t getStringToSign(char const * const DateTime, char const * const Date,
                                 char const * const Region, char const * const CanonicalRequest,
                                 char * StringToSign)
{
#ifdef METTLE
    if ( !(DateTime && Date && Region && CanonicalRequest) )
    {
        logError("\n getStringToSign: necessary parameters not specified \n");
        return -1;
    }

    char StringHead[] = "AWS4-HMAC-SHA256\n";
    char StringTail[] = "/glacier/aws4_request\n";

    if (!StringToSign)
    {
        return
              (
               strlen(StringHead) + strlen(DateTime) + strlen("\n") + strlen(Date) + strlen("/") + strlen(Region) +
               strlen(StringTail) + SHA256_HEX_LENGTH + 1
              );
    }

    char CanonicalRequestSHA256[SHA256_HEX_LENGTH + 1] = "\0";

    to_iso8859_1((char *) CanonicalRequest, strlen(CanonicalRequest));
    int retValue = SHA256(CanonicalRequest, strlen(CanonicalRequest), CanonicalRequestSHA256, SHA256_HEX_LENGTH + 1);
    from_iso8859_1((char *) CanonicalRequest, strlen(CanonicalRequest));

    if (retValue != 0)
    {
        logError("\n getStringToSign: error in SHA256() function occurred \n");
        return -1;
    }

    StringToSign[0] = 0;
    strcat(StringToSign, StringHead);
    strcat(StringToSign, DateTime);
    strcat(StringToSign, "\n");
    strcat(StringToSign, Date);
    strcat(StringToSign, "/");
    strcat(StringToSign, Region);
    strcat(StringToSign, StringTail);
    strcat(StringToSign, CanonicalRequestSHA256);

    return 0;
#endif
}

static int getSignature(char const * const SecretKey, char const * const Date,
                        char const * const Region, char const * const StringToSign,
                        char * Signature)
{
#ifdef METTLE
    if ( !(SecretKey && Date && Region && StringToSign) )
    {
        logError("\n getSignature: necessary parameters not specified \n");
        return -1;
    }

    char SecretKeyPrefix[] = "AWS4";
    size_t FirstKeyAllocatedSize = strlen(SecretKeyPrefix) + strlen(SecretKey) + 1;   // +1 for NULL character
    char* FirstKey = (char*) allocate(FirstKeyAllocatedSize, "First Key");

    FirstKey[0] = 0;
    strcat(FirstKey, SecretKeyPrefix);
    strcat(FirstKey, SecretKey);

    size_t FirstKeyLength = strlen(FirstKey);
    size_t FirstKeyHexLength = FirstKeyLength * 2 + 1;

    char* FirstKeyHex = (char*) allocate(FirstKeyHexLength, "First Key Hex buffer");

    to_iso8859_1(FirstKey, FirstKeyLength);
    
    int retValue = CharToHex(FirstKey, FirstKeyLength, FirstKeyHex, FirstKeyHexLength);
    deallocate(FirstKey, FirstKeyAllocatedSize);
    if (retValue != 0)
    {
        logError("\n getSignature: error in CharToHex() function occurred \n");
        deallocate(FirstKeyHex, FirstKeyHexLength);
        return -1;
    }
    
    to_iso8859_1((char *) Date, strlen(Date));
    retValue += HMAC(FirstKeyHex, Date, Signature, SHA256_HEX_LENGTH + 1);
    from_iso8859_1((char *) Date, strlen(Date));

    deallocate(FirstKeyHex, FirstKeyHexLength);

    to_iso8859_1((char *) Region, strlen(Region));
    retValue += HMAC(Signature, Region, Signature, SHA256_HEX_LENGTH + 1);
    from_iso8859_1((char *) Region, strlen(Region));

    char tmp_buf_1[] = "glacier";
    to_iso8859_1(tmp_buf_1, strlen(tmp_buf_1));
    retValue += HMAC(Signature, tmp_buf_1, Signature, SHA256_HEX_LENGTH + 1);

    char tmp_buf_2[] = "aws4_request";
    to_iso8859_1(tmp_buf_2, strlen(tmp_buf_2));
    retValue += HMAC(Signature, tmp_buf_2, Signature, SHA256_HEX_LENGTH + 1);

    to_iso8859_1((char *) StringToSign, strlen(StringToSign));
    retValue += HMAC(Signature, StringToSign, Signature, SHA256_HEX_LENGTH + 1);
    from_iso8859_1((char *) StringToSign, strlen(StringToSign));

    if (retValue != 0)
    {
        logError("\n getSignature: error in HMAC() function occurred \n");
        return -1;
    }

    return 0;
#endif
}

static size_t getDecimalDigitsQuantity(unsigned long long Value)
{
    size_t result = (Value == 0);
    while (Value)
    {
        result++;
        Value /= 10;
    }
    return result;
}

//Debug purposes only
void print_long_string(char * buf) {
    size_t LEN = strlen(buf);
    size_t ms_len = 0;
    char ms[50];

    for (size_t i=0; i < LEN; i++) {
        ms[ms_len++] = buf[i];
        if (ms_len > 30) {
            ms[ms_len] = 0;
            logTrace("%s\n",ms);
            ms_len = 0;
        }
    }
    if (ms_len > 0) {
        ms[ms_len] = 0;
        logTrace("%s\n",ms);
    }
}

void print_long_buffer(char * buf, size_t buf_size) {
    size_t ms_len = 0;
    char ms[100];

    for (size_t i=0; i < buf_size; i++) {
        ms[ms_len++] = buf[i];
        if (ms_len > 99) {
            ms[ms_len] = 0;
            logTrace("%s\n",ms);
            ms_len = 0;
        }
    }
    if (ms_len > 0) {
        ms[ms_len] = 0;
        logTrace("%s\n",ms);
    }
}
//---------------------

static long long getHttpRequest(char const * const HttpMethod, char const * const Query, char const * const Region,
                                char const * const DateTime, char const * const AccessKey, char const * const SecretKey,
                                char const * const Date, char const * const amzParam, char const * const amzParamList,
                                char const * const ContentRange, char const * const Range, char const * const Body,
                                const unsigned long long BodySize, char * HttpRequest)
{
#ifdef METTLE
    if ( !(HttpMethod && Query && Region && DateTime && AccessKey && SecretKey && Date && amzParam && amzParamList) )
    {
        logError("\n getHttpRequest: necessary parameters not specified \n");
        return -1;
    }

    unsigned long long ContentLength = 0LL;
    if (Body != NULL)
    {
        ContentLength = BodySize;
    }

    size_t ContentRangeLength = 0;
    if (ContentRange)
    {
        ContentRangeLength = strlen("\nContent-Range: bytes ") + strlen(ContentRange);
    }

    size_t RangeLength = 0;
    if (Range)
    {
        RangeLength = strlen("\nRange: bytes=") + strlen(Range);
    }

    size_t ContentLengthString_Len = getDecimalDigitsQuantity(ContentLength) + 1;
    char ContentLengthString[ContentLengthString_Len];
    snprintf(ContentLengthString, ContentLengthString_Len, "%llu\0", ContentLength);

    if (HttpRequest == NULL)
    {
        return
              (
               strlen(HttpMethod) + strlen(" ") + strlen(Query) + strlen(" HTTP/1.1\nHost: glacier.") + strlen(Region) + strlen(".amazonaws.com\nDate: ") +
               strlen(DateTime) + strlen("\n") + strlen(amzParam) + strlen("\nAuthorization: AWS4-HMAC-SHA256 Credential=") + strlen(AccessKey) +
               strlen("/") + strlen(Date) + strlen("/") + strlen(Region) + strlen("/glacier/aws4_request, SignedHeaders=host;") + strlen(amzParamList) +
               strlen(", Signature=") + SHA256_HEX_LENGTH + ContentRangeLength + RangeLength + strlen("\nContent-Length: ") + strlen(ContentLengthString) + strlen("\n\n") + ContentLength
              );
    }

    ptrdiff_t CanonicalReqAllocatedSize = getCanonicalRequest(HttpMethod, Query, Region, amzParam, amzParamList, Body, BodySize, NULL);
    if (CanonicalReqAllocatedSize < 0)
    {
        logError("\n getHttpRequest: error in getCanonicalRequest() function occurred \n");
        return -1;
    }

    char* CanonicalReq = (char*) allocate(CanonicalReqAllocatedSize, "Canonical Request string");
    ptrdiff_t retValue = getCanonicalRequest(HttpMethod, Query, Region, amzParam, amzParamList, Body, BodySize, CanonicalReq);
    if (retValue != 0)
    {
        logError("\n getHttpRequest: error in getCanonicalRequest() function occurred \n");
        deallocate(CanonicalReq, CanonicalReqAllocatedSize);
        return -1;
    }

    ptrdiff_t StringToSignAllocatedSize = getStringToSign(DateTime, Date, Region, CanonicalReq, NULL);
    if (StringToSignAllocatedSize < 0)
    {
        logError("\n getHttpRequest: error in getStringToSign() function occurred \n");
        deallocate(CanonicalReq, CanonicalReqAllocatedSize);
        return -1;
    }
    char* StringToSign = (char*) allocate(StringToSignAllocatedSize, "String To Sign string");
    retValue = getStringToSign(DateTime, Date, Region, CanonicalReq, StringToSign);
    if (retValue != 0)
    {
        logError("\n getHttpRequest: error in getStringToSign() function occurred \n");
        deallocate(CanonicalReq, CanonicalReqAllocatedSize);
        deallocate(StringToSign, StringToSignAllocatedSize);
        return -1;
    }

    char Signature[SHA256_HEX_LENGTH + 1];
    retValue = getSignature(SecretKey, Date, Region, StringToSign, Signature);
    if (retValue != 0)
    {
        logError("\n getHttpRequest: error in getSignature() function occurred \n");
        deallocate(CanonicalReq, CanonicalReqAllocatedSize);
        deallocate(StringToSign, StringToSignAllocatedSize);
        return -1;
    }

    deallocate(CanonicalReq, CanonicalReqAllocatedSize);
    deallocate(StringToSign, StringToSignAllocatedSize);

    HttpRequest[0] = 0;
    strcat(HttpRequest, HttpMethod);
    strcat(HttpRequest, " ");
    strcat(HttpRequest, Query);
    strcat(HttpRequest, " HTTP/1.1\nHost: glacier.");
    strcat(HttpRequest, Region);
    strcat(HttpRequest, ".amazonaws.com\nDate: ");
    strcat(HttpRequest, DateTime);
    strcat(HttpRequest, "\n");
    strcat(HttpRequest, amzParam);
    strcat(HttpRequest, "\nAuthorization: AWS4-HMAC-SHA256 Credential=");
    strcat(HttpRequest, AccessKey);
    strcat(HttpRequest, "/");
    strcat(HttpRequest, Date);
    strcat(HttpRequest, "/");
    strcat(HttpRequest, Region);
    strcat(HttpRequest, "/glacier/aws4_request, SignedHeaders=host;");
    strcat(HttpRequest, amzParamList);
    strcat(HttpRequest, ", Signature=");
    strcat(HttpRequest, Signature);
    strcat(HttpRequest, "\nContent-Length: ");
    strcat(HttpRequest, ContentLengthString);
    if (ContentRange)
    {
        strcat(HttpRequest, "\nContent-Range: bytes ");
        strcat(HttpRequest, ContentRange);
    }
    if (Range)
    {
        strcat(HttpRequest, "\nRange: bytes=");
        strcat(HttpRequest, Range);
    }
    strcat(HttpRequest, "\n\n");

    to_iso8859_1(HttpRequest, strlen(HttpRequest));

    if (Body != NULL && BodySize > 0)
    {
        memcpy(&HttpRequest[strlen(HttpRequest)], Body, BodySize);   // TODO: not supported 4 Gb sizes in non-64 bit mode - "memcpy()" issue
    }

    return 0;
#endif
}

static void getContentLength(char const * const Header, unsigned long long * ContentLength)
{
    *ContentLength = 0;

    char * ContentLengthPtr = strstr(Header, "Content-Length: ");
    if (ContentLengthPtr)
    {
        ContentLengthPtr += strlen("Content-Length: ");
        sscanf(ContentLengthPtr, "%llu", ContentLength);
    }
    return;
}

static GlacierResponse* getResponse(Socket* sock)
{
#ifdef METTLE
    size_t const part = 1024;
    size_t const CORRECT_HEADER_MAX_SIZE = 1024 * 10;   // do not reduce the value (!)

    int returnCode = 0;
    int reasonCode = 0;
    int bytesCount = 0;
    
    char tmp[part];
    char eoh[] = "\r\n\r\n";
    to_iso8859_1(eoh, sizeof(eoh) / sizeof(eoh[0]));   // to ASCII

    char* eohPtr = NULL;
    char* Header = NULL;
    char* tmpHeader = NULL;

    size_t HeaderSize = 0;
    
    do
    {
        bytesCount = socketRead(sock, tmp, part, &returnCode, &reasonCode);
        if (bytesCount < 0)
        {
            logError("\n getResponse: error in socketRead() function occured, return code = %d, reason code = %d \n", returnCode, reasonCode);
            if (Header)
            {
                deallocate(Header, HeaderSize);
            }
            return NULL;
        }
        if (bytesCount > 0)
        {
            tmpHeader = Header;
            Header = (char*) allocate(HeaderSize + bytesCount, "Header");
            if (tmpHeader)
            {
                memcpy(Header, tmpHeader, HeaderSize);
                deallocate(tmpHeader, HeaderSize);
            }
            memcpy(Header + HeaderSize, tmp, bytesCount);
            HeaderSize += bytesCount;
            eohPtr = strstr(Header, eoh);
            if (eohPtr)
            {
                break;
            }
            if (HeaderSize > CORRECT_HEADER_MAX_SIZE)   // only approximately estimation
            {
                logError("\n getResponse: Header size is too big \n");
                if (Header)
                {
                    deallocate(Header, HeaderSize);
                }
                return NULL;
            }
        }
    } while (bytesCount > 0);

    char* tmpContent = NULL;
    unsigned long long ContentLength = 0;

    if (eohPtr)
    {
        size_t newHeaderSize = eohPtr - Header;
        tmpHeader = Header;
        Header = (char*) allocate(newHeaderSize + 1, "HTTP Header");
        memcpy(Header, tmpHeader, newHeaderSize);
        Header[newHeaderSize] = 0;
        from_iso8859_1(Header, newHeaderSize);   // to EBCDIC

        getContentLength(Header, &ContentLength);
        
        GlacierResponse* Response = (GlacierResponse*) allocate(sizeof(GlacierResponse), "HTTP Response");
        if (ContentLength == 0)
        {
            Response->Header = Header;
            Response->Content = NULL;
            Response->ContentLength = 0;
            deallocate(tmpHeader, HeaderSize);
            return Response;
        }

        long long Remainder = HeaderSize - (eohPtr + strlen(eoh) - tmpHeader);
        if (ContentLength < (size_t) Remainder)
        {
            logError("\n getResponse: error - response content length not corresponds to appropriate header value \n");
            deallocate(Header, newHeaderSize + 1);
            deallocate(tmpHeader, HeaderSize);
            deallocate(Response, sizeof(GlacierResponse));
            return NULL;
        }

        char* Content = (char*) allocate(ContentLength, "HTTP Content");
        
        tmpContent = eohPtr + strlen(eoh);
        memcpy(Content, tmpContent, Remainder);       // ContentLength >= Remainder here
        deallocate(tmpHeader, HeaderSize);
        tmpContent = Content + Remainder;
        unsigned long long Total = Remainder;
        Remainder = ContentLength - Remainder;

        size_t const MAX_SOCKET_PART_SIZE = (size_t) INT_MAX;

        do
        {
            int Size = (int) MAX_SOCKET_PART_SIZE;
            if (Remainder < Size)
            {
                Size = (int) Remainder;
            }

            bytesCount = socketRead(sock, tmpContent, Size, &returnCode, &reasonCode);
            if (bytesCount < 0)
            {
                logError("\n getResponse: error in socketRead() function occured \n");
                deallocate(Header, newHeaderSize + 1);
                deallocate(Content, ContentLength);
                deallocate(Response, sizeof(GlacierResponse));
                return NULL;
            }
            tmpContent += bytesCount;
            Total += (size_t) bytesCount;
            Remainder -= bytesCount;
        } while (bytesCount != 0 && Total < ContentLength);

        if ((Total != ContentLength) || (socketRead(sock, tmp, 1, &returnCode, &reasonCode) != 0))
        {
            logError("\n getResponse: error - content length does not match the size from header \n");
            deallocate(Header, newHeaderSize + 1);
            deallocate(Content, ContentLength);
            deallocate(Response, sizeof(GlacierResponse));
            return NULL;
        }

        Response->Header = Header;
        Response->Content = Content;
        Response->ContentLength = ContentLength;
        return Response;
    }

    logError("\n getResponse: error - incorrect header \n");
    if (Header)
    {
        deallocate(Header, HeaderSize);
    }
    return NULL;
#endif
}

static GlacierResponse* SendGlacierRequest(char const * const Region, char const * const Request, unsigned long long RequestSize)
{
#ifdef METTLE
    int returnCode = 0;
    int reasonCode = 0;

    SocketAddress addr;
    addr.family = AF_INET;
    addr.port = htons(80);

    char Glacier[strlen("glacier.") + strlen(Region) + strlen(".amazonaws.com") + 1];
    Glacier[0] = 0;
    strcat(Glacier, "glacier.");
    strcat(Glacier, Region);
    strcat(Glacier, ".amazonaws.com");

    addr.v4Address = getV4HostByName(Glacier);

    Socket *sock;

    sock = tcpClient(&addr, &returnCode, &reasonCode);
    if (!sock)
    {
        logError("\n SendGlacierRequest: error in tcpClient() function occured, return code = %d, reason code = %d \n", returnCode, reasonCode);
        return NULL;
    }

logTrace(" \n Request size = %llu \n",RequestSize);

    int sentByte = 0;
    unsigned long long Remainder = RequestSize;
    char* tmpRequest = (char*) Request;
    unsigned long long Total = 0;
    size_t const MAX_SOCKET_PART_SIZE = (size_t) INT_MAX;

    do
    {
        int Size = (int) MAX_SOCKET_PART_SIZE;
        if (Remainder < MAX_SOCKET_PART_SIZE)
        {
            Size = (int) Remainder;
        }

        sentByte = socketWrite(sock, tmpRequest, Size, &returnCode, &reasonCode);
        if (sentByte < 0)
        {
            logError("\n SendGlacierRequest: error in socketWrite() function occured, return code = %d, reason code = %d \n", returnCode, reasonCode);
            socketClose(sock, &returnCode, &reasonCode);
            safeFree((char *) sock, sizeof(Socket));
            return NULL;
        }

        tmpRequest += (size_t) sentByte;
        Total += (size_t) sentByte;
        Remainder -= (size_t) sentByte;
    } while (sentByte != 0 && Total < RequestSize);

    GlacierResponse* Response = getResponse(sock);

logTrace(" \n Answer from server: \n ");
logTrace(" \n Header = \n ");
print_long_string(Response->Header);
logTrace(" \n \n");

//Debug code only (UNCOMMENT ONLY FOR VIEWING JSON ANSWER, in another cases - comment it)
// Be careful about BIG Response->ContentLength field - from_iso doesn't work with BIG data
from_iso8859_1(Response->Content, Response->ContentLength);   // to EBCDIC
//

logTrace(" \n Content = \n ");
print_long_buffer(Response->Content, Response->ContentLength);
logTrace(" \n \n");

    socketClose(sock, &returnCode, &reasonCode);
    safeFree((char *) sock, sizeof(Socket));

    return Response;
#endif
}

static void hwtjFree(char* parserInstance, HWTJ_DIAGAREA* diagArea)
{
#ifdef METTLE
    int returnCode = 0;

    hwtjterm(&returnCode, parserInstance, HWTJ_NOFORCE, diagArea);
    if (returnCode == HWTJ_OK)
    {
        logTrace(" \n SUCCESS: Parser work area freed. \n");
    }
    else
    {
        hwtjterm(&returnCode, parserInstance, HWTJ_FORCE, diagArea);
        if (returnCode == HWTJ_OK)
        {
            logTrace(" \n SUCCESS: Parser work area freed using force option.\n");
        }
        else
        {
            logError(" \n hwtjFree: error in hwtjterm() function occured, return_code = %d, reason code = %d \n", returnCode, diagArea->reasonCode);
            logError(" \n Unable to perform cleanup with HWTJ_FORCE option enabled.\n Could not free parser work area. \n");
        }
    }
    return;
#endif
}

static char* getJsonObjectValueByKey(int* returnCode, char* parserInstance, int objectHandle, char* Key, HWTJ_DIAGAREA* diagArea)
{
#ifdef METTLE
    int resultHandle = 0;
    hwtjsrch(returnCode, parserInstance, HWTJ_SEARCHTYPE_OBJECT, Key, (int) strlen(Key), objectHandle, 0, &resultHandle, diagArea);
    if (*returnCode != HWTJ_OK)
    {
        logError(" \n getJsonObjectValueByKey: error in hwtjsrch() function occured, return code = %d, reason code = %d \n", *returnCode, diagArea->reasonCode);
        return NULL;
    }

    int valueLength = 0;
    int valueAddr = 0;
    char* value = NULL;
    hwtjgval(returnCode, parserInstance, resultHandle, &valueAddr, &valueLength, diagArea);
    if (*returnCode != HWTJ_OK)
    {
        logError(" \n getJsonObjectValueByKey: error in hwtjgval() function occured, return code = %d, reason code = %d \n", *returnCode, diagArea->reasonCode);
        return NULL;
    }

    value = (char*) allocate(valueLength + 1, "Value Addr");
    strncpy(value, (char*) valueAddr, valueLength);
    value[valueLength] = 0;

    return value;
#endif
}

static VaultList * createVaultListNode()
{
    VaultList * node = (VaultList *) allocate(sizeof(VaultList), "Vault List Node");
    node->CreationDate = NULL;
    node->LastInventoryDate = NULL;
    node->NumberOfArchives = NULL;
    node->SizeInBytes = NULL;
    node->VaultARN = NULL;
    node->VaultName = NULL;
    node->next = NULL;
    return node;
}

static ArchiveList * createArchiveListNode()
{
    ArchiveList * node = (ArchiveList *) allocate(sizeof(ArchiveList), "Archive List Node");
    node->ArchiveId = NULL;
    node->ArchiveDescription = NULL;
    node->CreationDate = NULL;
    node->Size = NULL;
    node->SHA256TreeHash = NULL;
    node->Next = NULL;
    return node;
}
/*--------------------------------------------------------------------------------------*/





/*----------------------------- Glacier external functions -----------------------------*/

void * allocate(unsigned long long size, char * description)
{
    #if defined(_LP64)             // used construction from "alloc.c" module for checking 64-bit mode
    return (void *) safeMalloc(size, description);   // !!! safeMalloc64() should be used, when it will be allowed (and finished) !!!
    #else
    if (size > (unsigned long long) INT_MAX)   // check for safety of using "safeMalloc" function from "alloc.c" module,
                                               // it's first argument has type "int" for size of allocated area, so
                                               // if call this function with (size > INT_MAX) it could be wrong after
                                               // overflowing "int" type but still positive and it will be elusive error
    {
        logError("\n allocate: could not allocate more than %d bytes not in 64 bit mode \n", INT_MAX);
        return NULL;
    }
    else
        return (void *) safeMalloc(size, description);
    #endif
}

void deallocate(void * ptr, unsigned long long size)
{
    if (ptr == NULL)
        return;

    // "deallocate" should use appropriate safeFree functions for called safeMallocs, so all checks will be the same as in "allocate" function
    #if defined(_LP64)
    safeFree((char *) ptr, size);   // !!! safeFree64() should be used, when it will be allowed (and finished) !!!
    #else
    if (size > (unsigned long long) INT_MAX)
        logError("\n deallocate: trying to deallocate more than %d bytes not in 64 bit mode \n", INT_MAX);
    else
        safeFree((char *) ptr, size);
    #endif
}

/*----------------------------------------------------------------------------
 * This function frees all of the allocated AuthData structure memory.
 ----------------------------------------------------------------------------*/
void Glacier_freeAuthData(Glacier_AuthData * AuthData)
{
    #ifdef METTLE
        logTrace("\n Called Glacier_freeAuthData() \n");

        if (AuthData == NULL)
            return;

        if (AuthData->secretAccessKey != NULL)
            deallocate(AuthData->secretAccessKey, AuthData->allocated_secretAccessKey_size);

        if (AuthData->accessKeyID != NULL)
            deallocate(AuthData->accessKeyID, AuthData->allocated_accessKeyID_size);

        if (AuthData->vault != NULL)
            deallocate(AuthData->vault, AuthData->allocated_Vault_size);

        if (AuthData->region != NULL)
            deallocate(AuthData->region, AuthData->allocated_Region_size);

        deallocate(AuthData, sizeof(Glacier_AuthData));
        return;
    #endif
}

/*---------------------------------------------------------------------------
 * This function creates a structure with all parameters necessary
 * for authentication process.
 * Returns a pointer to the created Glacier_AuthData object.
 ---------------------------------------------------------------------------*/
Glacier_AuthData * Glacier_makeAuthData(char const * const region,                    /* Null terminated region string */
                                        char const * const vault,                     /* Null terminated vault name string */
                                        char const * const accessKeyID,               /* Null terminated Access Key ID string */
                                        char const * const secretAccessKey            /* Null terminated Secret Access Key string */
                                       )
{
    #ifdef METTLE
        logTrace("\n Called Glacier_makeAuthData() \n");

        // Allocation & initialization
        Glacier_AuthData * AuthData = (Glacier_AuthData *) allocate(sizeof(Glacier_AuthData), "Glacier_AuthData struct");

        char * fill_region_from = (char *) region;
        if (fill_region_from == NULL)
            fill_region_from = (char *) DEFAULT_GLACIER_REGION;   // Use default Glacier region

        AuthData->allocated_Region_size = (strlen(fill_region_from) + 1) * sizeof(char);
        AuthData->region = allocate(AuthData->allocated_Region_size, "Glacier_AuthData region field");
        strcpy(AuthData->region, fill_region_from);   /* In case of Glacier there is no such possibility to ask common
                                                         server about region specific as it could be done for S3, so
                                                         we should provide this argument */

        AuthData->vault = NULL;
        AuthData->allocated_Vault_size = 0;
        if (vault != NULL)
        {
            AuthData->allocated_Vault_size = (strlen(vault) + 1) * sizeof(char);
            AuthData->vault = allocate(AuthData->allocated_Vault_size, "Glacier_AuthData vault field");
            strcpy(AuthData->vault, vault);
        }

        AuthData->accessKeyID = NULL;
        AuthData->allocated_accessKeyID_size = 0;
        if (accessKeyID != NULL)
        {
            AuthData->allocated_accessKeyID_size = (strlen(accessKeyID) + 1) * sizeof(char);
            AuthData->accessKeyID = allocate(AuthData->allocated_accessKeyID_size, "Glacier_AuthData accessKeyID field");
            strcpy(AuthData->accessKeyID, accessKeyID);
        }

        AuthData->secretAccessKey = NULL;
        AuthData->allocated_secretAccessKey_size = 0;
        if (secretAccessKey != NULL)
        {
            AuthData->allocated_secretAccessKey_size = (strlen(secretAccessKey) + 1) * sizeof(char);
            AuthData->secretAccessKey = allocate(AuthData->allocated_secretAccessKey_size, "Glacier_AuthData secretAccessKey field");
            strcpy(AuthData->secretAccessKey, secretAccessKey);
        }
        //------------------------------

        logTrace("\n Glacier_makeAuthData: successfully ended \n");
        return AuthData;
    #endif
}

size_t calculate_SHA256HashList_size(SHA256HashList const * sha_hl)
{
    size_t ans = 0;
    while (sha_hl)
    {
        ans++;
        sha_hl = sha_hl->next;
    }
    return ans;
}

void free_SHA256HashList(SHA256HashList ** sha_hl)
{
#ifdef METTLE
    while (*sha_hl)
    {
        SHA256HashList * tmp = *sha_hl;
        *sha_hl = tmp->next;
        deallocate(tmp, sizeof(SHA256HashList));
    }
#endif
}

SHA256HashList * create_SHA256HashList_from_buffer(char const * const Buffer, unsigned long long BufferSize)
{
#ifdef METTLE
    SHA256HashList * ans_list = NULL;
    SHA256HashList * head_listPtr = NULL;

    size_t ChunkSize = MB;   // http://docs.aws.amazon.com/amazonglacier/latest/dev/glacier-dg.pdf#checksum-calculations-upload-archive-in-single-payload
    size_t RemSize = BufferSize % ChunkSize;
    size_t PartsCount = (BufferSize / ChunkSize) + (RemSize > 0);
    
    char * BufferPtr = (char *) Buffer;
    size_t sha256Len = SHA256_HASH_BYTES;

    for (size_t i = 0; i < PartsCount; i++)
    {
        if ((i + 1 == PartsCount) && (RemSize > 0))
            ChunkSize = RemSize;

        SHA256HashList * new_node = (SHA256HashList *) allocate(sizeof(SHA256HashList), "SHA256HashList structure");
        new_node->next = NULL;

        unsigned char * sha256Ptr = new_node->hash_value;

        int retValue = rs_hash_oneshot(RS_ALG_SHA256, BufferPtr, ChunkSize, &sha256Ptr, &sha256Len);
        if (retValue != RS_SUCCESS)
        {
            logError("\n create_SHA256HashList_from_buffer: error in rs_hash_oneshot() function occurred (return value: %d) \n", retValue);
                        
            // Deallocate all memory from our list
            deallocate(new_node, sizeof(SHA256HashList));
            free_SHA256HashList(&ans_list);
            //------------------------------------

            return NULL;
        }

        if (ans_list == NULL)
            head_listPtr = ans_list = new_node;
        else
        {
            ans_list->next = new_node;
            ans_list = new_node;
        }

        BufferPtr += ChunkSize;
    }

    return head_listPtr;
#endif
}

// "returnCode" argument should be initialized with "0" before main call of "getTreeHash" recursion.
// The copy (!!!) of real "sha_hl" list begin pointer should be passed here, because argument "sha_hl" changes during "getTreeHash" calculation,
// in other case there will not be possible to deallocate memory from "SHA256HashList" list after this call.
char * getTreeHash(SHA256HashList ** sha_hl, size_t sha_hl_Elements_Count, size_t Level, int * returnCode)
{
#ifdef METTLE
    if (sha_hl_Elements_Count == 0)
    {
        logError("\n getTreeHash: error - could not process empty list (uploading of zero-length archives is not supproted) \n");   // (!) maybe this case will be supported in future
                                                                                                                                    //     for uploading/downloading zero-length archives (!)
        *returnCode = -1;
        return NULL;
    }
    
    if ((*sha_hl) == NULL)
    {
        if (Level == 0)
        {
            logError("\n getTreeHash: error - could not process empty list (NULL pointer) \n");
            *returnCode = -1;
        }
        return NULL;
    }

    if (*returnCode != 0)   // if something goes wrong return immediately
        return NULL;

    size_t CurrentLevelNodeCount = ((size_t) 1) << Level;

    if (CurrentLevelNodeCount < sha_hl_Elements_Count)
    {
        char * HashL = getTreeHash(sha_hl, sha_hl_Elements_Count, Level + 1, returnCode);
        char * HashR = getTreeHash(sha_hl, sha_hl_Elements_Count, Level + 1, returnCode);

        if (!(HashL || HashR))
            return NULL;

        char * tmpBuffer = allocate(SHA256_HASH_BYTES * 2, "Concatenate HashL & HashR");

        memcpy(tmpBuffer, HashL, SHA256_HASH_BYTES);

        if (HashR)
            memcpy(tmpBuffer + SHA256_HASH_BYTES, HashR, SHA256_HASH_BYTES);

        unsigned char * Hash = (unsigned char*) allocate(SHA256_HASH_BYTES, "SHA256 Hash");
        unsigned char * sha256Ptr = Hash;
        size_t sha256Len = SHA256_HASH_BYTES;
        
        if (HashR)
        {
            int retValue = rs_hash_oneshot(RS_ALG_SHA256, (char*) tmpBuffer, (size_t) SHA256_HASH_BYTES * 2, &sha256Ptr, &sha256Len);
            if (retValue != RS_SUCCESS)
            {
                logError("\n getTreeHash: error in rs_hash_oneshot() function occurred (return value: %d) \n", retValue);
                deallocate(Hash, SHA256_HASH_BYTES);
                deallocate(tmpBuffer, SHA256_HASH_BYTES * 2);
                *returnCode = -1;
                return NULL;
            }
            deallocate(HashL, SHA256_HASH_BYTES);
            deallocate(HashR, SHA256_HASH_BYTES);
            deallocate(tmpBuffer, SHA256_HASH_BYTES * 2);
            return (char *) Hash;
        }
        else
        {
            deallocate(Hash, SHA256_HASH_BYTES);
            deallocate(tmpBuffer, SHA256_HASH_BYTES * 2);
            return HashL;
        }
    }

    unsigned char * Hash = (unsigned char*) allocate(SHA256_HASH_BYTES, "SHA256 Hash");
    memcpy(Hash, (*sha_hl)->hash_value, SHA256_HASH_BYTES);

    (*sha_hl) = (*sha_hl)->next;
    
    return (char *) Hash;
#endif
}

int CharToHex(char const * const text,
              const size_t textLen,
              char * hexString,                     // output parameter in hexadecimal-string null-terminated form
              const size_t hexStringAllocatedSize   // don't forget byte for '\0' character!
             )
{
#ifdef METTLE
    char hex[4];

    hexString[0] = 0;
    size_t hexStringLength = 0;
    for (size_t i = 0; i < textLen; i++)
        if (hexStringLength + 2 < hexStringAllocatedSize)
        {
            snprintf(hex, 3, "%02x\0", (unsigned char) text[i]);
            hexString[hexStringLength++] = hex[0];
            hexString[hexStringLength++] = hex[1];
        }
        else
            return -1;

    hexString[hexStringLength] = 0;
    return 0;
#endif
}

int getHttpStatus(char const * const Header, unsigned int * HttpStatus)
{
    char * HttpStatusPtr = strstr(Header, "HTTP/1.0 ");
    if (!HttpStatusPtr)
        HttpStatusPtr = strstr(Header, "HTTP/1.1 ");
    if (HttpStatusPtr)
    {
        HttpStatusPtr += strlen("HTTP/1.0 ");
        if (sscanf(HttpStatusPtr, "%u", HttpStatus) == 1)
        {
            return 0;
        }
    }
    return -1;
}

char * getHeaderParamByName(char const * const Header, char const * const ParamName)   // returns pointer to null-terminated buffer with parameter value
                                                                                       // or NULL if some errors occured or parameter was not found
{
#ifdef METTLE
    char * ParamPtr = NULL;
    size_t ParamLen = 0;

    char * tmpPtr = strstr(Header, ParamName);
    if (tmpPtr != NULL)
    {
        ParamPtr = tmpPtr + strlen(ParamName);
        char eol[] = "\r\n";
        char * ParamEOL = strpbrk(ParamPtr, eol);
        if (ParamEOL)
        {
            ParamLen = (size_t) (ParamEOL - ParamPtr);
        }
        else
        {
            ParamLen = 0;
        }
    }

    if (ParamPtr != NULL && ParamLen > 0)
    {
        char * Param = (char*) allocate(ParamLen + 1, "Header string parameter");
        memcpy(Param, ParamPtr, ParamLen);
        Param[ParamLen] = 0;
        return Param;
    }

    return NULL;
#endif
}

void freeGlacierResponse(GlacierResponse* Response)
{
#ifdef METTLE
    if (Response)
    {
        if (Response->Header)
        {
            deallocate(Response->Header, strlen(Response->Header) + 1);
        }
        if (Response->Content)
        {
            deallocate(Response->Content, Response->ContentLength);
        }
        deallocate(Response, sizeof(GlacierResponse));
    }
    return;
#endif
}

GlacierResponse* CreateVault(char const * const AccessKey, char const * const SecretKey, char const * const Region, char const * const VaultName)
{
#ifdef METTLE
    if ( !(AccessKey && SecretKey && Region && VaultName) )
    {
        logError("\n CreateVault: necessary parameters not specified \n");
        return NULL;
    }

    char DateTime[17];
    char Date[9];
    getDateTime(DateTime, Date);

    char HttpMethod[] = "PUT";
    char Query[strlen(BaseQuery) + strlen("/") + strlen(VaultName) + 1];   // +1 for NULL character
    Query[0] = 0;
    strcat(Query, BaseQuery);
    strcat(Query, "/");
    strcat(Query, VaultName);

    char amz[] = "x-amz-glacier-version:2012-06-01";
    char amzLst[] = "x-amz-glacier-version";

    long long HttpReqAllocatedSize = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, NULL, NULL, 0, NULL);
    if (HttpReqAllocatedSize < 0)
        return NULL;
    char* HttpReq = (char*) allocate(HttpReqAllocatedSize, "HTTP Request string");
    long long status = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, NULL, NULL, 0, HttpReq);
    if (status < 0)
    {
        deallocate(HttpReq, HttpReqAllocatedSize);
        return NULL;
    }

    GlacierResponse* Response = SendGlacierRequest(Region, HttpReq, HttpReqAllocatedSize);
    deallocate(HttpReq, HttpReqAllocatedSize);

    return Response;
#endif
}

GlacierResponse* ListVaultJobs(char const * const AccessKey, char const * const SecretKey, char const * const Region, char const * const VaultName)
{
#ifdef METTLE
    if ( !(AccessKey && SecretKey && Region && VaultName) )
    {
        logError("\n ListVaultJobs: necessary parameters not specified \n");
        return NULL;
    }

    char DateTime[17];
    char Date[9];
    getDateTime(DateTime, Date);

    char HttpMethod[] = "GET";
    char Query[strlen(BaseQuery) + strlen("/") + strlen(VaultName) + strlen("/jobs") + 1];   // +1 for NULL character
    Query[0] = 0;
    strcat(Query, BaseQuery);
    strcat(Query, "/");
    strcat(Query, VaultName);
    strcat(Query, "/jobs");

    char amz[] = "x-amz-glacier-version:2012-06-01";
    char amzLst[] = "x-amz-glacier-version";

    long long HttpReqAllocatedSize = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, NULL, NULL, 0, NULL);
    if (HttpReqAllocatedSize < 0)
        return NULL;
    char* HttpReq = (char*) allocate(HttpReqAllocatedSize, "HTTP Request string");
    long long status = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, NULL, NULL, 0, HttpReq);
    if (status < 0)
    {
        deallocate(HttpReq, HttpReqAllocatedSize);
        return NULL;
    }

    GlacierResponse* Response = SendGlacierRequest(Region, HttpReq, HttpReqAllocatedSize);
    deallocate(HttpReq, HttpReqAllocatedSize);

    return Response;
#endif
}

GlacierResponse* GetVaultJobInfo(char const * const AccessKey, char const * const SecretKey, char const * const Region,
                                 char const * const VaultName, char const * const JobId)
{
#ifdef METTLE
    if ( !(AccessKey && SecretKey && Region && VaultName && JobId) )
    {
        logError("\n GetVaultJobInfo: necessary parameters not specified \n");
        return NULL;
    }

    char DateTime[17];
    char Date[9];
    getDateTime(DateTime, Date);

    char HttpMethod[] = "GET";
    char Query[strlen(BaseQuery) + strlen("/") + strlen(VaultName) + strlen("/jobs/") + strlen(JobId) + 1];   // +1 for NULL character
    Query[0] = 0;
    strcat(Query, BaseQuery);
    strcat(Query, "/");
    strcat(Query, VaultName);
    strcat(Query, "/jobs/");
    strcat(Query, JobId);

    char amz[] = "x-amz-glacier-version:2012-06-01";
    char amzLst[] = "x-amz-glacier-version";

    long long HttpReqAllocatedSize = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, NULL, NULL, 0, NULL);
    if (HttpReqAllocatedSize < 0)
        return NULL;
    char* HttpReq = (char*) allocate(HttpReqAllocatedSize, "HTTP Request string");
    long long status = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, NULL, NULL, 0, HttpReq);
    if (status < 0)
    {
        deallocate(HttpReq, HttpReqAllocatedSize);
        return NULL;
    }

    GlacierResponse* Response = SendGlacierRequest(Region, HttpReq, HttpReqAllocatedSize);
    deallocate(HttpReq, HttpReqAllocatedSize);

    return Response;
#endif
}

GlacierResponse* VaultJobOutput(char const * const AccessKey, char const * const SecretKey, char const * const Region,
                                char const * const VaultName, char const * const JobId, char const * const Range)
{
#ifdef METTLE
    if ( !(AccessKey && SecretKey && Region && VaultName && JobId) )
    {
        logError("\n VaultJobOutput: necessary parameters not specified \n");
        return NULL;
    }

    char DateTime[17];
    char Date[9];
    getDateTime(DateTime, Date);

    char HttpMethod[] = "GET";
    char Query[strlen(BaseQuery) + strlen("/") + strlen(VaultName) + strlen("/jobs/") + strlen(JobId) + strlen("/output") + 1];   // +1 for NULL character
    Query[0] = 0;
    strcat(Query, BaseQuery);
    strcat(Query, "/");
    strcat(Query, VaultName);
    strcat(Query, "/jobs/");
    strcat(Query, JobId);
    strcat(Query, "/output");

    char amz[] = "x-amz-glacier-version:2012-06-01";
    char amzLst[] = "x-amz-glacier-version";

    long long HttpReqAllocatedSize = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, Range, NULL, 0, NULL);
    if (HttpReqAllocatedSize < 0)
        return NULL;
    char* HttpReq = (char*)allocate(HttpReqAllocatedSize, "HTTP Request string");

    long long status = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, Range, NULL, 0, HttpReq);
    if (status < 0)
    {
        deallocate(HttpReq, HttpReqAllocatedSize);
        return NULL;
    }

    GlacierResponse* Response = SendGlacierRequest(Region, HttpReq, HttpReqAllocatedSize);
    deallocate(HttpReq, HttpReqAllocatedSize);

    return Response;
#endif
}

GlacierResponse* ListVaults(char const * const AccessKey, char const * const SecretKey, char const * const Region)
{
#ifdef METTLE
    if ( !(AccessKey && SecretKey && Region) )
    {
        logError("\n ListVaults: necessary parameters not specified \n");
        return NULL;
    }

    char DateTime[17];
    char Date[9];
    getDateTime(DateTime, Date);

    char HttpMethod[] = "GET";

    char amz[] = "x-amz-glacier-version:2012-06-01";
    char amzLst[] = "x-amz-glacier-version";

    long long HttpReqAllocatedSize = getHttpRequest(HttpMethod, BaseQuery, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, NULL, NULL, 0, NULL);
    if (HttpReqAllocatedSize < 0)
        return NULL;
    char* HttpReq = (char*) allocate(HttpReqAllocatedSize, "HTTP Request string");
    long long status = getHttpRequest(HttpMethod, BaseQuery, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, NULL, NULL, 0, HttpReq);
    if (status < 0)
    {
        deallocate(HttpReq, HttpReqAllocatedSize);
        return NULL;
    }

    GlacierResponse* Response = SendGlacierRequest(Region, HttpReq, HttpReqAllocatedSize);
    deallocate(HttpReq, HttpReqAllocatedSize);

    return Response;
#endif
}

GlacierResponse* RunInventoryJob(char const * const AccessKey, char const * const SecretKey, char const * const Region,
                                 char const * const VaultName, char const * const JobName)
{
#ifdef METTLE
    if ( !(AccessKey && SecretKey && Region && VaultName && JobName) )
    {
        logError("\n RunInventoryJob: necessary parameters not specified \n");
        return NULL;
    }

    char DateTime[17];
    char Date[9];
    getDateTime(DateTime, Date);

    char HttpMethod[] = "POST";
    char Query[strlen(BaseQuery) + strlen("/") + strlen(VaultName) + strlen("/jobs") + 1];   // +1 for NULL character
    Query[0] = 0;
    strcat(Query, BaseQuery);
    strcat(Query, "/");
    strcat(Query, VaultName);
    strcat(Query, "/jobs");

    char amz[] = "x-amz-glacier-version:2012-06-01";
    char amzLst[] = "x-amz-glacier-version";

    char Body[strlen("{\"Type\":\"inventory-retrieval\",\"Description\":\"") + strlen(JobName) + strlen("\",\"Format\":\"JSON\"}") + 1];   // +1 for NULL character
    Body[0] = 0;
    strcat(Body, "{\"Type\":\"inventory-retrieval\",\"Description\":\"");
    strcat(Body, JobName);
    strcat(Body, "\",\"Format\":\"JSON\"}");

    long long HttpReqAllocatedSize = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, NULL, Body, strlen(Body), NULL);
    if (HttpReqAllocatedSize < 0)
        return NULL;
    char* HttpReq = (char*) allocate(HttpReqAllocatedSize, "HTTP Request string");

    size_t BodySize = strlen(Body);
    to_iso8859_1(Body, BodySize);

    long long status = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, NULL, Body, BodySize, HttpReq);
    if (status < 0)
    {
        deallocate(HttpReq, HttpReqAllocatedSize);
        return NULL;
    }

    GlacierResponse* Response = SendGlacierRequest(Region, HttpReq, HttpReqAllocatedSize);
    deallocate(HttpReq, HttpReqAllocatedSize);

    return Response;
#endif
}

GlacierResponse* DeleteArchive(char const * const AccessKey, char const * const SecretKey, char const * const Region,
                               char const * const VaultName, char const * const ArchiveId)
{
#ifdef METTLE
    if ( !(AccessKey && SecretKey && Region && VaultName && ArchiveId) )
    {
        logError("\n DeleteArchive: necessary parameters not specified \n");
        return NULL;
    }

    char DateTime[17];
    char Date[9];
    getDateTime(DateTime, Date);

    char HttpMethod[] = "DELETE";
    char Query[strlen(BaseQuery) + strlen("/") + strlen(VaultName) + strlen("/archives/") + strlen(ArchiveId) + 1];   // +1 for NULL character
    Query[0] = 0;
    strcat(Query, BaseQuery);
    strcat(Query, "/");
    strcat(Query, VaultName);
    strcat(Query, "/archives/");
    strcat(Query, ArchiveId);

    char amz[] = "x-amz-glacier-version:2012-06-01";
    char amzLst[] = "x-amz-glacier-version";

    long long HttpReqAllocatedSize = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, NULL, NULL, 0, NULL);
    if (HttpReqAllocatedSize < 0)
        return NULL;
    char* HttpReq = (char*) allocate(HttpReqAllocatedSize, "HTTP Request string");
    long long status = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, NULL, NULL, 0, HttpReq);
    if (status < 0)
    {
        deallocate(HttpReq, HttpReqAllocatedSize);
        return NULL;
    }

    GlacierResponse* Response = SendGlacierRequest(Region, HttpReq, HttpReqAllocatedSize);
    deallocate(HttpReq, HttpReqAllocatedSize);

    return Response;
#endif
}

GlacierResponse* SingleUpload(char const * const AccessKey, char const * const SecretKey, char const * const Region, char const * const VaultName,
                              char const * const ArchiveDescription, char const * const Buffer, unsigned long long BufferSize)
{
#ifdef METTLE
    if ( !(AccessKey && SecretKey && Region && VaultName && ArchiveDescription && Buffer) )
    {
        logError("\n SingleUpload: necessary parameters not specified \n");
        return NULL;
    }

    if (BufferSize > 4294967296LL)
    {
        logError("\n SingleUpload: BufferSize over 4 Gb \n");
        return NULL;
    }

    char DateTime[17];
    char Date[9];
    getDateTime(DateTime, Date);

    char HttpMethod[] = "POST";
    char Query[strlen(BaseQuery) + strlen("/") + strlen(VaultName) + strlen("/archives") + 1];   // +1 for NULL character
    Query[0] = 0;
    strcat(Query, BaseQuery);
    strcat(Query, "/");
    strcat(Query, VaultName);
    strcat(Query, "/archives");

    size_t amzLength = strlen("x-amz-archive-description:") +
                       strlen(ArchiveDescription) +
                       strlen("\nx-amz-content-sha256:") +
                       SHA256_HEX_LENGTH +
                       strlen("\nx-amz-glacier-version:2012-06-01\n") +
                       strlen("x-amz-sha256-tree-hash:") +
                       SHA256_HEX_LENGTH;

    char ContentSHA256[SHA256_HEX_LENGTH + 1];
    char TreeSHA256[SHA256_HEX_LENGTH + 1];

    int retValue = SHA256(Buffer, BufferSize, ContentSHA256, SHA256_HEX_LENGTH + 1);
    if (retValue != 0)
    {
        logError("\n SingleUpload: error in SHA256() function occurred \n");
        return NULL;
    }

    SHA256HashList * sha_hl = create_SHA256HashList_from_buffer(Buffer, BufferSize);
    if (sha_hl == NULL)
    {
        logError("\n SingleUpload: error in create_SHA256HashList_from_buffer() function occurred \n");
        return NULL;
    }

    SHA256HashList * sha_hl_copy = sha_hl;

    int returnCode = 0;
    char* Hash = getTreeHash(&sha_hl_copy, calculate_SHA256HashList_size(sha_hl_copy), 0, &returnCode);
    free_SHA256HashList(&sha_hl);

    if (returnCode < 0)
    {
        logError("\n SingleUpload: error in getTreeHash() function occurred\n");
        return NULL;   // if returnCode < 0 then returned from getTreeHash() pointer is NULL, so memory should NOT be deallocated
    }

    retValue = CharToHex(Hash, SHA256_HASH_BYTES, TreeSHA256, SHA256_HEX_LENGTH + 1);
    deallocate(Hash, SHA256_HASH_BYTES);
    if (retValue != 0)
    {
        logError("\n SingleUpload: error in CharToHex() function occurred\n");
        return NULL;
    }

    char amz[amzLength + 1];
    amz[0] = 0;
    strcat(amz, "x-amz-archive-description:");
    strcat(amz, ArchiveDescription);
    strcat(amz, "\nx-amz-content-sha256:");
    strcat(amz, ContentSHA256);
    strcat(amz, "\nx-amz-glacier-version:2012-06-01\n");
    strcat(amz, "x-amz-sha256-tree-hash:");
    strcat(amz, TreeSHA256);

    char amzLst[] = "x-amz-archive-description;x-amz-content-sha256;x-amz-glacier-version;x-amz-sha256-tree-hash";

    long long HttpReqAllocatedSize = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, NULL, Buffer, BufferSize, NULL);
    if (HttpReqAllocatedSize < 0)
        return NULL;
    char* HttpReq = (char*) allocate(HttpReqAllocatedSize, "HTTP Request string");
    long long status = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, NULL, Buffer, BufferSize, HttpReq);
    if (status < 0)
    {
        deallocate(HttpReq, HttpReqAllocatedSize);
        return NULL;
    }

    GlacierResponse* Response = SendGlacierRequest(Region, HttpReq, HttpReqAllocatedSize);
    deallocate(HttpReq, HttpReqAllocatedSize);

    return Response;
#endif
}

GlacierResponse* RunRetrievalJob(char const * const AccessKey, char const * const SecretKey, char const * const Region,
                                 char const * const VaultName, char const * const JobName, char const * const ArchiveId,
                                 char const * const Range)
{
#ifdef METTLE
    if ( !(AccessKey && SecretKey && Region && VaultName && JobName && ArchiveId) )
    {
        logError(" \n RunRetrievalJob: necessary parameters not specified \n");
        return NULL;
    }

    char DateTime[17];
    char Date[9];
    getDateTime(DateTime, Date);

    char HttpMethod[] = "POST";
    char Query[strlen(BaseQuery) + strlen("/") + strlen(VaultName) + strlen("/jobs") + 1];   // +1 for NULL character
    Query[0] = 0;
    strcat(Query, BaseQuery);
    strcat(Query, "/");
    strcat(Query, VaultName);
    strcat(Query, "/jobs");

    char amz[] = "x-amz-glacier-version:2012-06-01";
    char amzLst[] = "x-amz-glacier-version";

    char Body[strlen("{\"Type\":\"archive-retrieval\",\"ArchiveId\":\"") + strlen(ArchiveId) + strlen("\",\"Description\":\"") + strlen(JobName) + strlen("\",\"RetrievalByteRange\":\"0-2097151\"") + strlen("}") + 1];   // +1 for NULL character
    Body[0] = 0;
    strcat(Body, "{\"Type\":\"archive-retrieval\",\"ArchiveId\":\"");
    strcat(Body, ArchiveId);
    strcat(Body, "\",\"Description\":\"");
    strcat(Body, JobName);
    strcat(Body, "\",\"RetrievalByteRange\":\"0-2097151\"");   // TODO: use Range parameter instead of constants (now we don't know the final interface here)
    strcat(Body, "}");
//print_long_buffer(Body, strlen(Body));

    long long HttpReqAllocatedSize = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, NULL, Body, strlen(Body), NULL);
    if (HttpReqAllocatedSize < 0)
        return NULL;
    char* HttpReq = (char*) allocate(HttpReqAllocatedSize, "HTTP Request string");

    size_t BodySize = strlen(Body);
    to_iso8859_1(Body, BodySize);

    long long status = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, NULL, Body, strlen(Body), HttpReq);
    if (status < 0)
    {
        deallocate(HttpReq, HttpReqAllocatedSize);
        return NULL;
    }

    GlacierResponse* Response = SendGlacierRequest(Region, HttpReq, HttpReqAllocatedSize);
    deallocate(HttpReq, HttpReqAllocatedSize);

    return Response;
#endif
}

GlacierResponse* GetMultiPartUploadId(char const* const AccessKey, char const* const SecretKey, char const* const Region, char const* const VaultName,
                                      char const* const ArchiveDescription, unsigned long long PartSize)
{
#ifdef METTLE
    if ( !(AccessKey && SecretKey && Region && VaultName && ArchiveDescription) )
    {
        logError(" \n GetMultiPartUploadId: necessary parameters not specified \n");
        return NULL;
    }

    char DateTime[17];
    char Date[9];
    getDateTime(DateTime, Date);

    char HttpMethod[] = "POST";
    char Query[strlen(BaseQuery) + strlen("/") + strlen(VaultName) + strlen("/multipart-uploads") + 1];   // +1 for NULL character
    Query[0] = 0;
    strcat(Query, BaseQuery);
    strcat(Query, "/");
    strcat(Query, VaultName);
    strcat(Query, "/multipart-uploads");

    char PartSizeString[getDecimalDigitsQuantity(PartSize) + 1];
    snprintf(PartSizeString, getDecimalDigitsQuantity(PartSize) + 1, "%llu\0", PartSize);

    size_t amzLength =  strlen("x-amz-archive-description:") + 
                        strlen(ArchiveDescription) + 
                        strlen("\nx-amz-glacier-version:2012-06-01\n") +
                        strlen("x-amz-part-size:") +
                        getDecimalDigitsQuantity(PartSize);

    char amz[amzLength + 1];
    amz[0] = 0;
    strcat(amz, "x-amz-archive-description:");
    strcat(amz, ArchiveDescription);
    strcat(amz, "\nx-amz-glacier-version:2012-06-01\n");
    strcat(amz, "x-amz-part-size:");
    strcat(amz, PartSizeString);

    char amzLst[] = "x-amz-archive-description;x-amz-glacier-version;x-amz-part-size";

    long long HttpReqAllocatedSize = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, NULL, NULL, 0, NULL);
    if (HttpReqAllocatedSize < 0)
        return NULL;
    char* HttpReq = (char*) allocate(HttpReqAllocatedSize, "HTTP Request string");
    long long status = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, NULL, NULL, 0, HttpReq);
    if (status < 0)
    {
        deallocate(HttpReq, HttpReqAllocatedSize);
        return NULL;
    }

    GlacierResponse* Response = SendGlacierRequest(Region, HttpReq, HttpReqAllocatedSize);
    deallocate(HttpReq, HttpReqAllocatedSize);

    return Response;
#endif
}

GlacierResponse* ListParts(char const* const AccessKey, char const* const SecretKey, char const* const Region, char const* const VaultName, char const* const UploadId)
{
#ifdef METTLE
    if ( !(AccessKey && SecretKey && Region && VaultName && UploadId) )
    {
        logError(" \n ListParts: necessary parameters not specified \n");
        return NULL;
    }

    char DateTime[17];
    char Date[9];
    getDateTime(DateTime, Date);

    char HttpMethod[] = "GET";
    char Query[strlen(BaseQuery) + strlen("/") + strlen(VaultName) + strlen("/multipart-uploads/") + strlen(UploadId) + 1];   // +1 for NULL character
    Query[0] = 0;
    strcat(Query, BaseQuery);
    strcat(Query, "/");
    strcat(Query, VaultName);
    strcat(Query, "/multipart-uploads/");
    strcat(Query, UploadId);

    char amz[] = "x-amz-glacier-version:2012-06-01";
    char amzLst[] = "x-amz-glacier-version";

    long long HttpReqAllocatedSize = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, NULL, NULL, 0, NULL);
    if (HttpReqAllocatedSize < 0)
        return NULL;
    char* HttpReq = (char*) allocate(HttpReqAllocatedSize, "HTTP Request string");
    long long status = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, NULL, NULL, 0, HttpReq);
    if (status < 0)
    {
        deallocate(HttpReq, HttpReqAllocatedSize);
        return NULL;
    }

    GlacierResponse* Response = SendGlacierRequest(Region, HttpReq, HttpReqAllocatedSize);
    deallocate(HttpReq, HttpReqAllocatedSize);

    return Response;
#endif
}

GlacierResponse* ListMultipartUploads(char const* const AccessKey, char const* const SecretKey, char const* const Region, char const* const VaultName)
{
#ifdef METTLE
    if ( !(AccessKey && SecretKey && Region && VaultName) )
    {
        logError(" \n ListMultipartUploads: necessary parameters not specified \n");
        return NULL;
    }

    char DateTime[17];
    char Date[9];
    getDateTime(DateTime, Date);

    char HttpMethod[] = "GET";
    char Query[strlen(BaseQuery) + strlen("/") + strlen(VaultName) + strlen("/multipart-uploads") + 1];   // +1 for NULL character
    Query[0] = 0;
    strcat(Query, BaseQuery);
    strcat(Query, "/");
    strcat(Query, VaultName);
    strcat(Query, "/multipart-uploads");

    char amz[] = "x-amz-glacier-version:2012-06-01";
    char amzLst[] = "x-amz-glacier-version";

    long long HttpReqAllocatedSize = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, NULL, NULL, 0, NULL);
    if (HttpReqAllocatedSize < 0)
        return NULL;
    char* HttpReq = (char*) allocate(HttpReqAllocatedSize, "HTTP Request string");
    long long status = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, NULL, NULL, 0, HttpReq);
    if (status < 0)
    {
        deallocate(HttpReq, HttpReqAllocatedSize);
        return NULL;
    }

    GlacierResponse* Response = SendGlacierRequest(Region, HttpReq, HttpReqAllocatedSize);
    deallocate(HttpReq, HttpReqAllocatedSize);

    return Response;
#endif
}

GlacierResponse* DeleteMultipartUpload(char const* const AccessKey, char const* const SecretKey, char const* const Region, char const* const VaultName, char const* const UploadId)
{
#ifdef METTLE
    if ( !(AccessKey && SecretKey && Region && VaultName && UploadId) )
    {
        logError(" \n DeleteMultipartUpload: necessary parameters not specified \n");
        return NULL;
    }

    char DateTime[17];
    char Date[9];
    getDateTime(DateTime, Date);

    char HttpMethod[] = "DELETE";
    char Query[strlen(BaseQuery) + strlen("/") + strlen(VaultName) + strlen("/multipart-uploads/") + strlen(UploadId) + 1];   // +1 for NULL character
    Query[0] = 0;
    strcat(Query, BaseQuery);
    strcat(Query, "/");
    strcat(Query, VaultName);
    strcat(Query, "/multipart-uploads/");
    strcat(Query, UploadId);

    char amz[] = "x-amz-glacier-version:2012-06-01";
    char amzLst[] = "x-amz-glacier-version";

    long long HttpReqAllocatedSize = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, NULL, NULL, 0, NULL);
    if (HttpReqAllocatedSize < 0)
        return NULL;
    char* HttpReq = (char*) allocate(HttpReqAllocatedSize, "HTTP Request string");
    long long status = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, NULL, NULL, 0, HttpReq);
    if (status < 0)
    {
        deallocate(HttpReq, HttpReqAllocatedSize);
        return NULL;
    }

    GlacierResponse* Response = SendGlacierRequest(Region, HttpReq, HttpReqAllocatedSize);
    deallocate(HttpReq, HttpReqAllocatedSize);

    return Response;
#endif
}

GlacierResponse* UploadPart(char const * const AccessKey, char const * const SecretKey, char const * const Region, char const * const VaultName,
                            char const * const MultiPartUploadId, char const * const Buffer, unsigned long long BufferSize,
                            unsigned long long LowLimitRange, unsigned long long HighLimitRange,
                            char * const TreeHash)
{
#ifdef METTLE

    if ( !(AccessKey && SecretKey && Region && VaultName && MultiPartUploadId && Buffer) )
    {
        logError("\n UploadPart: necessary parameters not specified \n");
        return NULL;
    }

    if (BufferSize > 4294967296LL)
    {
        logError("\n UploadPart: BufferSize over 4 Gb \n");
        return NULL;
    }

    char DateTime[17];
    char Date[9];
    getDateTime(DateTime, Date);

    char HttpMethod[] = "PUT";
    char Query[strlen(BaseQuery) + strlen("/") + strlen(VaultName) + strlen("/multipart-uploads/") + strlen(MultiPartUploadId) + 1];   // +1 for NULL character
    Query[0] = 0;
    strcat(Query, BaseQuery);
    strcat(Query, "/");
    strcat(Query, VaultName);
    strcat(Query, "/multipart-uploads/");
    strcat(Query, MultiPartUploadId);

    size_t amzLength = strlen("x-amz-content-sha256:") +
                       SHA256_HEX_LENGTH +
                       strlen("\nx-amz-glacier-version:2012-06-01\n") +
                       strlen("x-amz-sha256-tree-hash:") +
                       SHA256_HEX_LENGTH;

    char ContentSHA256[SHA256_HEX_LENGTH + 1];
    char TreeSHA256[SHA256_HEX_LENGTH + 1];

    int retValue = SHA256(Buffer, BufferSize, ContentSHA256, SHA256_HEX_LENGTH + 1);
    if (retValue != 0)
    {
        logError("\n UploadPart: error in SHA256() function occurred \n");
        return NULL;
    }

    SHA256HashList * sha_hl = create_SHA256HashList_from_buffer(Buffer, BufferSize);
    if (sha_hl == NULL)
    {
        logError("\n UploadPart: error in create_SHA256HashList_from_buffer() function occurred \n");
        return NULL;
    }

    SHA256HashList * sha_hl_copy = sha_hl;

    int returnCode = 0;
    
    char * hs = getTreeHash(&sha_hl_copy, calculate_SHA256HashList_size(sha_hl_copy), 0, &returnCode);
    free_SHA256HashList(&sha_hl);

    if (returnCode < 0)   // "hs" will be NULL in that case
    {
        logError("\n UploadPart: error in getTreeHash() function occurred \n");
        return NULL;   // if returnCode < 0 then returned from getTreeHash() pointer is NULL, so memory should NOT be deallocated
    }

    if (hs == NULL)
    {
        logError("\n UploadPart: error (getTreeHash() returned null pointer) \n");
        return NULL;
    }

    retValue = CharToHex(hs, SHA256_HASH_BYTES, TreeSHA256, SHA256_HEX_LENGTH + 1);
    
    if (TreeHash != NULL)
        memcpy(TreeHash, hs, SHA256_HASH_BYTES);
    deallocate(hs, SHA256_HASH_BYTES);

    if (retValue != 0)
    {
        logError("\n UploadPart: error in CharToHex() function occurred \n");
        return NULL;
    }

    char amz[amzLength + 1];
    amz[0] = 0;
    strcat(amz, "x-amz-content-sha256:");
    strcat(amz, ContentSHA256);
    strcat(amz, "\nx-amz-glacier-version:2012-06-01\n");
    strcat(amz, "x-amz-sha256-tree-hash:");
    strcat(amz, TreeSHA256);

    char amzLst[] = "x-amz-content-sha256;x-amz-glacier-version;x-amz-sha256-tree-hash";

    size_t ContentRangeStringLength = getDecimalDigitsQuantity(LowLimitRange) + getDecimalDigitsQuantity(HighLimitRange) + strlen("-/*") + 1;   // +1 for NULL character
    char ContentRangeString[ContentRangeStringLength];
    snprintf(ContentRangeString, ContentRangeStringLength, "%llu-%llu/*\0", LowLimitRange, HighLimitRange);

logTrace(" \n ContentRangeString = %s \n", ContentRangeString);

    long long HttpReqAllocatedSize = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, ContentRangeString, NULL, Buffer, BufferSize, NULL);
    if (HttpReqAllocatedSize < 0)
        return NULL;
    char* HttpReq = (char*) allocate(HttpReqAllocatedSize, "HTTP Request string");
    long status = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, ContentRangeString, NULL, Buffer, BufferSize, HttpReq);
    if (status < 0)
    {
        deallocate(HttpReq, HttpReqAllocatedSize);
        return NULL;
    }

//from_iso8859_1(HttpReq, HttpReqAllocatedSize);
//logTrace(" \n Request = \n ");
//print_long_buffer(HttpReq, HttpReqAllocatedSize);
//logTrace(" \n \n");

    GlacierResponse* Response = SendGlacierRequest(Region, HttpReq, HttpReqAllocatedSize);
    deallocate(HttpReq, HttpReqAllocatedSize);

    return Response;
#endif
}

GlacierResponse* CompleteMultipartUpload(char const * const AccessKey, char const * const SecretKey, char const * const Region,
                                         char const * const VaultName, char const * const UploadId, char const * const TreeHash,
                                         unsigned long long ArchiveSize)
{
#ifdef METTLE
    if ( !(AccessKey && SecretKey && Region && VaultName && UploadId && TreeHash) )
    {
        logError(" \n CompleteMultipartUpload: necessary parameters not specified \n");
        return NULL;
    }

    char DateTime[17];
    char Date[9];
    getDateTime(DateTime, Date);

    char HttpMethod[] = "POST";
    char Query[strlen(BaseQuery) + strlen("/") + strlen(VaultName) + strlen("/multipart-uploads/") + strlen(UploadId) + 1];   // +1 for NULL character
    Query[0] = 0;
    strcat(Query, BaseQuery);
    strcat(Query, "/");
    strcat(Query, VaultName);
    strcat(Query, "/multipart-uploads/");
    strcat(Query, UploadId);

    size_t ArchiveSizeStringLength = getDecimalDigitsQuantity(ArchiveSize) + 1;
    char ArchiveSizeString[ArchiveSizeStringLength];
    snprintf(ArchiveSizeString, ArchiveSizeStringLength, "%llu\0", ArchiveSize);

    size_t amzLength = strlen("x-amz-archive-size:") +
                       ArchiveSizeStringLength +
                       strlen("\nx-amz-glacier-version:2012-06-01\n") +
                       strlen("x-amz-sha256-tree-hash:") +
                       SHA256_HEX_LENGTH;

    char amz[amzLength + 1];
    amz[0] = 0;
    strcat(amz, "x-amz-archive-size:");
    strcat(amz, ArchiveSizeString);
    strcat(amz, "\nx-amz-glacier-version:2012-06-01\n");
    strcat(amz, "x-amz-sha256-tree-hash:");
    strcat(amz, TreeHash);

    char amzLst[] = "x-amz-archive-size;x-amz-glacier-version;x-amz-sha256-tree-hash";

    long long HttpReqAllocatedSize = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, NULL, NULL, 0, NULL);
    if (HttpReqAllocatedSize < 0)
        return NULL;
    char* HttpReq = (char*) allocate(HttpReqAllocatedSize, "HTTP Request string");
    long long status = getHttpRequest(HttpMethod, Query, Region, DateTime, AccessKey, SecretKey, Date, amz, amzLst, NULL, NULL, NULL, 0, HttpReq);
    if (status < 0)
    {
        deallocate(HttpReq, HttpReqAllocatedSize);
        return NULL;
    }

    GlacierResponse* Response = SendGlacierRequest(Region, HttpReq, HttpReqAllocatedSize);
    deallocate(HttpReq, HttpReqAllocatedSize);

    return Response;
#endif
}

void freeVaultList(VaultList ** lst)
{
#ifdef METTLE
    VaultList * t = NULL;
    while (*lst)
    {
        t = *lst;
        if (t->CreationDate)
            deallocate(t->CreationDate, strlen(t->CreationDate) + 1);
        if (t->LastInventoryDate)
            deallocate(t->LastInventoryDate, strlen(t->LastInventoryDate) + 1);
        if (t->NumberOfArchives)
            deallocate(t->NumberOfArchives, strlen(t->NumberOfArchives) + 1);
        if (t->SizeInBytes)
            deallocate(t->SizeInBytes, strlen(t->SizeInBytes) + 1);
        if (t->VaultARN)
            deallocate(t->VaultARN, strlen(t->VaultARN) + 1);
        if (t->VaultName)
            deallocate(t->VaultName, strlen(t->VaultName) + 1);

        *lst = (*lst)->next;
        deallocate(t, sizeof(VaultList));
    }
    *lst = NULL;
#endif
}

VaultList* getVaultList(char* jsonString, size_t jsonStringSize)
{
#ifdef METTLE
    int returnCode = 0;
    char parserInstance[12];
    HWTJ_DIAGAREA diagArea;

    hwtjinit(&returnCode, 0, parserInstance, &diagArea);
    if (returnCode != HWTJ_OK)
    {
        logError(" \n getVaultList: error in hwtjinit() function occured, return code = %d, reason code = %d \n", returnCode, diagArea.reasonCode);
        return NULL;
    }

    hwtjpars(&returnCode, parserInstance, jsonString, (int) jsonStringSize, &diagArea);
    if (returnCode != HWTJ_OK)
    {
        logError(" \n getVaultList: error in hwtjpars() function occured, return code = %d, reason code = %d \n", returnCode, diagArea.reasonCode);
        hwtjFree(parserInstance, &diagArea);
        return NULL;
    }
    
    char Key[] = "VaultList";
    int resultHandle = 0;
    hwtjsrch(&returnCode, parserInstance, HWTJ_SEARCHTYPE_GLOBAL, Key, (int) strlen(Key), 0, 0, &resultHandle, &diagArea);
    if (returnCode != HWTJ_OK)
    {
        logError(" \n getVaultList: error in hwtjsrch() function occured, return code = %d, reason code = %d \n", returnCode, diagArea.reasonCode);
        hwtjFree(parserInstance, &diagArea);
        return NULL;
    }

    int items = 0;
    hwtjgnue(&returnCode, parserInstance, resultHandle, &items, &diagArea);
    if (returnCode != HWTJ_OK)
    {
        logError(" \n getVaultList: error in hwtjgnue() function occured, return code = %d, reason code = %d \n", returnCode, diagArea.reasonCode);
        hwtjFree(parserInstance, &diagArea);
        return NULL;
    }

    if (items != 0)
    {
        int arrayEntryHandle = 0;
        VaultList * list = NULL;
        VaultList ** nodePtr = &list;
        for (int i = 0; i < items; i++)
        {
            hwtjgaen(&returnCode, parserInstance, resultHandle, i, &arrayEntryHandle, &diagArea);
            if (returnCode != HWTJ_OK)
            {
                logError(" \n getVaultList: error in hwtjgaen() function occured, return code = %d, reason code = %d \n", returnCode, diagArea.reasonCode);
                freeVaultList(&list);
                hwtjFree(parserInstance, &diagArea);
                return NULL;
            }

            *nodePtr = createVaultListNode();

            (*nodePtr)->CreationDate = getJsonObjectValueByKey(&returnCode, parserInstance, arrayEntryHandle, "CreationDate", &diagArea);
            if (returnCode != HWTJ_OK)
            {
                logError(" \n getVaultList: error in getJsonObjectValueByKey() function occured, return code = %d, reason code = %d \n", returnCode, diagArea.reasonCode);
                freeVaultList(&list);
                hwtjFree(parserInstance, &diagArea);
                return NULL;
            }

            (*nodePtr)->LastInventoryDate = getJsonObjectValueByKey(&returnCode, parserInstance, arrayEntryHandle, "LastInventoryDate", &diagArea);
            if (returnCode != HWTJ_OK)
            {
                logError(" \n getVaultList: error in getJsonObjectValueByKey() function occured, return code = %d, reason code = %d \n", returnCode, diagArea.reasonCode);
                freeVaultList(&list);
                hwtjFree(parserInstance, &diagArea);
                return NULL;
            }

            (*nodePtr)->NumberOfArchives = getJsonObjectValueByKey(&returnCode, parserInstance, arrayEntryHandle, "NumberOfArchives", &diagArea);
            if (returnCode != HWTJ_OK)
            {
                logError(" \n getVaultList: error in getJsonObjectValueByKey() function occured, return code = %d, reason code = %d \n", returnCode, diagArea.reasonCode);
                freeVaultList(&list);
                hwtjFree(parserInstance, &diagArea);
                return NULL;
            }

            (*nodePtr)->SizeInBytes = getJsonObjectValueByKey(&returnCode, parserInstance, arrayEntryHandle, "SizeInBytes", &diagArea);
            if (returnCode != HWTJ_OK)
            {
                logError(" \n getVaultList: error in getJsonObjectValueByKey() function occured, return code = %d, reason code = %d \n", returnCode, diagArea.reasonCode);
                freeVaultList(&list);
                hwtjFree(parserInstance, &diagArea);
                return NULL;
            }

            (*nodePtr)->VaultARN = getJsonObjectValueByKey(&returnCode, parserInstance, arrayEntryHandle, "VaultARN", &diagArea);
            if (returnCode != HWTJ_OK)
            {
                logError(" \n getVaultList: error in getJsonObjectValueByKey() function occured, return code = %d, reason code = %d \n", returnCode, diagArea.reasonCode);
                freeVaultList(&list);
                hwtjFree(parserInstance, &diagArea);
                return NULL;
            }

            (*nodePtr)->VaultName = getJsonObjectValueByKey(&returnCode, parserInstance, arrayEntryHandle, "VaultName", &diagArea);
            if (returnCode != HWTJ_OK)
            {
                logError(" \n getVaultList: error in getJsonObjectValueByKey() function occured, return code = %d, reason code = %d \n", returnCode, diagArea.reasonCode);
                freeVaultList(&list);
                hwtjFree(parserInstance, &diagArea);
                return NULL;
            }

            nodePtr = (VaultList**) &((*nodePtr)->next);
        }

        hwtjFree(parserInstance, &diagArea);
        return list;
    }

    hwtjFree(parserInstance, &diagArea);
    return NULL;
#endif
}

void freeArchiveList(ArchiveList ** list)
{
#ifdef METTLE
    ArchiveList * node = NULL;
    while (*list)
    {
        if ((*list)->ArchiveId)
            deallocate((*list)->ArchiveId, strlen((*list)->ArchiveId) + 1);
        if ((*list)->ArchiveDescription)
            deallocate((*list)->ArchiveDescription, strlen((*list)->ArchiveDescription) + 1);
        if ((*list)->CreationDate)
            deallocate((*list)->CreationDate, strlen((*list)->CreationDate) + 1);
        if ((*list)->Size)
            deallocate((*list)->Size, strlen((*list)->Size) + 1);
        if ((*list)->SHA256TreeHash)
            deallocate((*list)->SHA256TreeHash, strlen((*list)->SHA256TreeHash) + 1);

        node = (*list)->Next;
        deallocate((*list), sizeof(ArchiveList));
        (*list) = node;
    }
    (*list) = NULL;
    return;
#endif
}

ArchiveList* getArchiveList(char* jsonString, size_t jsonStringSize)
{
#ifdef METTLE
    int returnCode = 0;
    char parserInstance[12];
    HWTJ_DIAGAREA diagArea;

    hwtjinit(&returnCode, 0, parserInstance, &diagArea);
    if (returnCode != HWTJ_OK)
    {
        logError(" \n getArchiveList: error in hwtjinit() function occured, return code = %d, reason code = %d \n", returnCode, diagArea.reasonCode);
        return NULL;
    }

    hwtjpars(&returnCode, parserInstance, jsonString, (int) jsonStringSize, &diagArea);
    if (returnCode != HWTJ_OK)
    {
        logError(" \n getArchiveList: error in hwtjpars() function occured, return code = %d, reason code = %d \n", returnCode, diagArea.reasonCode);
        hwtjFree(parserInstance, &diagArea);
        return NULL;
    }
    
    char Key[] = "ArchiveList";
    int resultHandle = 0;
    hwtjsrch(&returnCode, parserInstance, HWTJ_SEARCHTYPE_GLOBAL, Key, (int) strlen(Key), 0, 0, &resultHandle, &diagArea);
    if (returnCode != HWTJ_OK)
    {
        logError(" \n getArchiveList: error in hwtjsrch() function occured, return code = %d, reason code = %d \n", returnCode, diagArea.reasonCode);
        hwtjFree(parserInstance, &diagArea);
        return NULL;
    }

    int items = 0;
    hwtjgnue(&returnCode, parserInstance, resultHandle, &items, &diagArea);
    if (returnCode != HWTJ_OK)
    {
        logError(" \n getArchiveList: error in hwtjgnue() function occured, return code = %d, reason code = %d \n", returnCode, diagArea.reasonCode);
        hwtjFree(parserInstance, &diagArea);
        return NULL;
    }

    if (items != 0)
    {
        int arrayEntryHandle = 0;
        ArchiveList* list = NULL;
        ArchiveList** nodePtr = &list;
        for (int i = 0; i < items; i++)
        {
            hwtjgaen(&returnCode, parserInstance, resultHandle, i, &arrayEntryHandle, &diagArea);
            if (returnCode != HWTJ_OK)
            {
                logError(" \n getArchiveList: error in hwtjgaen() function occured, return code = %d, reason code = %d \n", returnCode, diagArea.reasonCode);
                freeArchiveList(&list);
                hwtjFree(parserInstance, &diagArea);
                return NULL;
            }

            *nodePtr = createArchiveListNode();

            (*nodePtr)->ArchiveId = getJsonObjectValueByKey(&returnCode, parserInstance, arrayEntryHandle, "ArchiveId", &diagArea);
            if (returnCode != HWTJ_OK)
            {
                logError(" \n getArchiveList: error in getJsonObjectValueByKey() function occured, return code = %d, reason code = %d \n", returnCode, diagArea.reasonCode);
                freeArchiveList(&list);
                hwtjFree(parserInstance, &diagArea);
                return NULL;
            }

            (*nodePtr)->ArchiveDescription = getJsonObjectValueByKey(&returnCode, parserInstance, arrayEntryHandle, "ArchiveDescription", &diagArea);
            if (returnCode != HWTJ_OK)
            {
                logError(" \n getArchiveList: error in getJsonObjectValueByKey() function occured, return code = %d, reason code = %d \n", returnCode, diagArea.reasonCode);
                freeArchiveList(&list);
                hwtjFree(parserInstance, &diagArea);
                return NULL;
            }

            (*nodePtr)->CreationDate = getJsonObjectValueByKey(&returnCode, parserInstance, arrayEntryHandle, "CreationDate", &diagArea);
            if (returnCode != HWTJ_OK)
            {
                logError(" \n getArchiveList: error in getJsonObjectValueByKey() function occured, return code = %d, reason code = %d \n", returnCode, diagArea.reasonCode);
                freeArchiveList(&list);
                hwtjFree(parserInstance, &diagArea);
                return NULL;
            }

            (*nodePtr)->Size = getJsonObjectValueByKey(&returnCode, parserInstance, arrayEntryHandle, "Size", &diagArea);
            if (returnCode != HWTJ_OK)
            {
                logError(" \n getArchiveList: error in getJsonObjectValueByKey() function occured, return code = %d, reason code = %d \n", returnCode, diagArea.reasonCode);
                freeArchiveList(&list);
                hwtjFree(parserInstance, &diagArea);
                return NULL;
            }

            (*nodePtr)->SHA256TreeHash = getJsonObjectValueByKey(&returnCode, parserInstance, arrayEntryHandle, "SHA256TreeHash", &diagArea);
            if (returnCode != HWTJ_OK)
            {
                logError(" \n getArchiveList: error in getJsonObjectValueByKey() function occured, return code = %d, reason code = %d \n", returnCode, diagArea.reasonCode);
                freeArchiveList(&list);
                hwtjFree(parserInstance, &diagArea);
                return NULL;
            }

            nodePtr = (ArchiveList**) &((*nodePtr)->Next);
        }

        hwtjFree(parserInstance, &diagArea);
        return list;
    }

    hwtjFree(parserInstance, &diagArea);
    return NULL;
#endif
}

void freeBadRequestMsg(BadRequestMsg ** msg)
{
#ifdef METTLE
    if ((*msg) == NULL)
        return;

    if ((*msg)->Code)
        deallocate((*msg)->Code, strlen((*msg)->Code) + 1);
    if ((*msg)->Message)
        deallocate((*msg)->Message, strlen((*msg)->Message) + 1);
    if ((*msg)->Type)
        deallocate((*msg)->Type, strlen((*msg)->Type) + 1);

    deallocate((*msg), sizeof(BadRequestMsg));
    
    (*msg) = NULL;
#endif
}

BadRequestMsg* getBadRequestMsg(char* jsonString, size_t jsonStringSize)
{
#ifdef METTLE
    int returnCode = 0;
    char parserInstance[12];
    HWTJ_DIAGAREA diagArea;

    hwtjinit(&returnCode, 0, parserInstance, &diagArea);
    if (returnCode != HWTJ_OK)
    {
        logError(" \n getBadRequest: error in hwtjinit() function occured, return code = %d, reason code = %d \n", returnCode, diagArea.reasonCode);
        return NULL;
    }

    hwtjpars(&returnCode, parserInstance, jsonString, (int) jsonStringSize, &diagArea);
    if (returnCode != HWTJ_OK)
    {
        logError(" \n getBadRequest: error in hwtjpars() function occured, return code = %d, reason code = %d \n", returnCode, diagArea.reasonCode);
        hwtjFree(parserInstance, &diagArea);
        return NULL;
    }

    BadRequestMsg* msg = (BadRequestMsg*) allocate(sizeof(BadRequestMsg), "BadRequest Message");
    msg->Code = NULL;
    msg->Message = NULL;
    msg->Type = NULL;

    msg->Code = getJsonObjectValueByKey(&returnCode, parserInstance, 0, "code", &diagArea);
    if (returnCode != HWTJ_OK)
    {
        logError(" \n getArchiveList: error in getJsonObjectValueByKey() function occured, return code = %d, reason code = %d \n", returnCode, diagArea.reasonCode);
        freeBadRequestMsg(&msg);
        hwtjFree(parserInstance, &diagArea);
        return NULL;
    }

    msg->Message = getJsonObjectValueByKey(&returnCode, parserInstance, 0, "message", &diagArea);
    if (returnCode != HWTJ_OK)
    {
        logError(" \n getArchiveList: error in getJsonObjectValueByKey() function occured, return code = %d, reason code = %d \n", returnCode, diagArea.reasonCode);
        freeBadRequestMsg(&msg);
        hwtjFree(parserInstance, &diagArea);
        return NULL;
    }

    msg->Type = getJsonObjectValueByKey(&returnCode, parserInstance, 0, "type", &diagArea);
    if (returnCode != HWTJ_OK)
    {
        logError(" \n getArchiveList: error in getJsonObjectValueByKey() function occured, return code = %d, reason code = %d \n", returnCode, diagArea.reasonCode);
        freeBadRequestMsg(&msg);
        hwtjFree(parserInstance, &diagArea);
        return NULL;
    }

    hwtjFree(parserInstance, &diagArea);
    return msg;
#endif
}

// Debug purposes only
void printVaultList(VaultList* lst)
{
#ifdef METTLE
    if (lst == NULL)
        logTrace(" \n Vault list is empty \n");

    while (lst)
    {
        logTrace(" \n CreationDate: %s \n", lst->CreationDate);
        logTrace(" \n LastInventoryDate: %s \n", lst->LastInventoryDate);
        logTrace(" \n NumberOfArchives: %s \n", lst->NumberOfArchives);
        logTrace(" \n SizeInBytes: %s \n", lst->SizeInBytes);
        logTrace(" \n VaultARN: %s \n", lst->VaultARN);
        logTrace(" \n VaultName: %s \n", lst->VaultName);
        logTrace(" \n ********************************************** \n");
        lst = lst->next;
    }
#endif
}

void printArchiveList(ArchiveList* list)
{
#ifdef METTLE
    if (list == NULL)
        logTrace(" \n Archive list is empty \n");

    while(list)
    {
        logTrace(" \n ArchiveId: %s \n", list->ArchiveId);
        logTrace(" \n ArchiveDescription: %s \n", list->ArchiveDescription);
        logTrace(" \n CreationDate: %s \n", list->CreationDate);
        logTrace(" \n Size: %s \n", list->Size);
        logTrace(" \n SHA256TreeHash: %s \n", list->SHA256TreeHash);
        logTrace(" \n ********************************************** \n");
        list = list->Next;
    }
#endif
}
//-----------------------

void GlacierDeleteMultipartUpload(GlacierRequest* request, char const * const multipartUploadID)
{
#ifdef METTLE
    logTrace(" \n Entered to GlacierDeleteMultipartUpload() function \n ");
    logTrace(" \n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);

    GlacierResponse* Response = DeleteMultipartUpload(request->client->accessKeyID, request->client->secretAccessKey, request->client->region, request->client->vault, multipartUploadID);
    if (Response)
    {
        unsigned int HttpStatus = 0;
        if (getHttpStatus(Response->Header, &HttpStatus) == 0)
        {
            logTrace(" HTTP status: %d \n", HttpStatus);
        }
        else
        {
            logError(" \n GlacierDeleteMultipartUpload: error in getHttpStatus() function occured \n");
            freeGlacierResponse(Response);
            logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
            return;
        }
        
        if (HttpStatus == 204)
        {
            logTrace(" \n 204 No Content\n");
        }
        else if ((HttpStatus >= 400) && (HttpStatus < 500))
        {
            BadRequestMsg* msg = getBadRequestMsg(Response->Content, Response->ContentLength);
            if (msg)
            {
                logTrace(" \n code: %s \n", msg->Code);
                logTrace(" \n message: %s \n", msg->Message);
                logTrace(" \n type: %s \n", msg->Type);
                freeBadRequestMsg(&msg);
            }
        }

        freeGlacierResponse(Response);
    }
    else
        logError("\n GlacierDeleteMultipartUpload: error in DeleteMultipartUpload() function occured \n");

    logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
    return;
#endif
}

int GlacierGetFile(GlacierRequest* request)
{
#ifdef METTLE
    logTrace(" \n Entered to GlacierGetFile() function \n ");
    logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);

    int returnCode = 0;
    int reasonCode = 0;

    GlacierResponse* Response = VaultJobOutput(request->client->accessKeyID, request->client->secretAccessKey,
                                               request->client->region, request->client->vault, request->path, NULL);

    if (Response)
    {
        unsigned int HttpStatus = 0;
        if (getHttpStatus(Response->Header, &HttpStatus) == 0)
        {
            logTrace(" \n HTTP status: %d \n", HttpStatus);
        }
        else
        {
            logError(" \n GlacierGetFile: error in getHttpStatus() function occured \n");
            freeGlacierResponse(Response);
            logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
            return 8;
        }

        if (HttpStatus == 200)
        {
            IOBlock *ioblock = request->ioblock;

            returnCode = openLocalSource(ioblock, 0);   // second parameter equal zero only for metal C
            if (returnCode != 0)
            {
                logError(" \n GlacierGetFile: error in openLocalSource() function occured, returnCode = %d , reasonCode = %d \n", ioblock->returnCode, ioblock->reasonCode);
                freeGlacierResponse(Response);
                logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
                return 8;
            }

            int stored = putLocalChunk(Response->Content, ioblock, Response->ContentLength);
            logTrace(" \n Content-Length: %zu, stored: %d", Response->ContentLength, stored);

            closeLocalSource(ioblock);
        }
        else if ((HttpStatus >= 400) && (HttpStatus < 500))
        {
            BadRequestMsg* msg = getBadRequestMsg(Response->Content, Response->ContentLength);
            if (msg)
            {
                logTrace(" \n code: %s \n", msg->Code);
                logTrace(" \n message: %s \n", msg->Message);
                logTrace(" \n type: %s \n", msg->Type);
                freeBadRequestMsg(&msg);
            }
            freeGlacierResponse(Response);
            logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
            return 8;
        } else
        {
            freeGlacierResponse(Response);
            logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
            return 8;
        }
    }
    else
    {
        logError("\n GlacierGetFile: error in VaultJobOutput() function occured \n");
        logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
        return 8;
    }

    freeGlacierResponse(Response);
    logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);

    return 0;
#endif
}

int GlacierPutFile(GlacierRequest* request)
{
#ifdef METTLE
    logTrace("\nEntered GlacierPutFile.");
    logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);

    int returnCode = 0;
    int reasonCode = 0;

    IOBlock *ioblock = request->ioblock;

    returnCode = openLocalSource(ioblock, 0);   // second parameter equal to zero only for metal C
    if (returnCode != 0)
    {
        logError(" \n GlacierPutFile: error in openLocalSource() function occured, returnCode = %d , reasonCode = %d \n", ioblock->returnCode, ioblock->reasonCode);
        logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
        return 8;
    }

    //  unsigned long long PartSize = 4294967296ULL; // max PartSize for Amazon Glacier
    unsigned long long PartSize = 8388608ULL; // PartSize must be a power of two and be not less than 1 Mb and not more than 4 Gb
    //  unsigned long long PartSize = 1048576ULL; // min PartSize for Amazon Glacier
    char* UploadId = NULL;
    GlacierResponse* Response = GetMultiPartUploadId(request->client->accessKeyID, request->client->secretAccessKey, request->client->region, request->client->vault, request->path, PartSize);
    if (Response)
    {
        unsigned int HttpStatus = 0;
        if (getHttpStatus(Response->Header, &HttpStatus) == 0)
        {
            logTrace(" \n HTTP status: %d\n", HttpStatus);
        }
        else
        {
            logError(" \n GlacierPutFile: error in getHttpStatus() function occured \n");
            freeGlacierResponse(Response);
            closeLocalSource(ioblock);
            logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
            return 8;
        }

        if (HttpStatus == 201)
        {
            UploadId = getHeaderParamByName(Response->Header, "x-amz-multipart-upload-id: ");
            if (UploadId)
            {
                logTrace(" \n Multipart upload ID: %s\n", UploadId);
            }
            else
            {
                logError(" \n GlacierPutFile: error in getHeaderParamByName() function occured for x-amz-multipart-upload-id parameter \n");
                freeGlacierResponse(Response);
                closeLocalSource(ioblock);
                logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
                return 8;
            }
        }
        else if ((HttpStatus >= 400) && (HttpStatus < 500))
        {
            BadRequestMsg* msg = getBadRequestMsg(Response->Content, Response->ContentLength);
            if (msg)
            {
                logTrace(" \n code: %s\n", msg->Code);
                logTrace(" \n message: %s\n", msg->Message);
                logTrace(" \n type: %s\n", msg->Type);
                freeBadRequestMsg(&msg);
            }
            closeLocalSource(ioblock);
            freeGlacierResponse(Response);
            return 8;
        }
        else
        {
            closeLocalSource(ioblock);
            freeGlacierResponse(Response);
            return 8;
        }

        freeGlacierResponse(Response);
    }
    else
    {
        logError(" \n GlacierPutFile: error in GetMultiPartUploadId() function occured \n");
        closeLocalSource(ioblock);
        return 8;
    }

    SHA256HashList * sha_hl = NULL;
    SHA256HashList * sha_hl_copy = NULL;

    char* buffer = (char*) allocate(PartSize, "Buffer");
    int eof = 0;
    unsigned long long LowLimitRange = 0;
    unsigned long long HighLimitRange = 0;
    unsigned long long FileSize = 0;
    int const MAX_LOCAL_CHUNK_SIZE = INT_MAX;   // "getLocalChunk()" function uses "int" size argument
    unsigned long long Remainder = PartSize;
    while (!eof)
    {
        char* bufferPtr = buffer;
        unsigned long long ChunkSize = 0;
        while (!eof && Remainder)
        {
            int Size = MAX_LOCAL_CHUNK_SIZE;
            if (Remainder < (unsigned long long) MAX_LOCAL_CHUNK_SIZE)
                Size = (int) Remainder;
            eof = getLocalChunk(bufferPtr, ioblock, Size);
            bufferPtr += ioblock->bytesSent;
            FileSize += ioblock->bytesSent;
            ChunkSize += ioblock->bytesSent;
            HighLimitRange += ioblock->bytesSent;
            Remainder -= ioblock->bytesSent;
        }

        SHA256HashList * new_node = (SHA256HashList *) allocate(sizeof(SHA256HashList), "SHA256HashList structure");
        new_node->next = NULL;
        Response = UploadPart(request->client->accessKeyID, request->client->secretAccessKey, request->client->region,
                              request->client->vault, UploadId, buffer, ChunkSize, LowLimitRange, HighLimitRange - 1, new_node->hash_value);
        LowLimitRange += ChunkSize;
        Remainder = PartSize;
        if (Response)
        {
            unsigned int HttpStatus = 0;
            if (getHttpStatus(Response->Header, &HttpStatus) == 0)
            {
                logTrace(" \n HTTP status: %d\n", HttpStatus);
            }
            else
            {
                logError(" \n GlacierPutFile: error in getHttpStatus() function occured \n");

                // Deallocate all memory from our list
                deallocate(new_node, sizeof(SHA256HashList));
                free_SHA256HashList(&sha_hl_copy);
                //------------------------------------
                freeGlacierResponse(Response);
                deallocate(buffer, PartSize);

                GlacierDeleteMultipartUpload(request, UploadId);
                deallocate(UploadId, strlen(UploadId) + 1);

                closeLocalSource(ioblock);

                logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
                return 8;
            }

            if (HttpStatus == 204)
            {
                logTrace(" \n 204 No Content\n");

                // all is correct
                if (sha_hl == NULL)
                    sha_hl = sha_hl_copy = new_node;
                else
                {
                    sha_hl->next = new_node;
                    sha_hl = sha_hl->next;
                }
            } else if ((HttpStatus >= 400) && (HttpStatus < 500))
            {
                BadRequestMsg* msg = getBadRequestMsg(Response->Content, Response->ContentLength);
                if (msg)
                {
                    logTrace(" \n code: %s\n", msg->Code);
                    logTrace(" \n message: %s\n", msg->Message);
                    logTrace(" \n type: %s\n", msg->Type);
                    freeBadRequestMsg(&msg);
                }
                
                // Deallocate all memory from our list
                deallocate(new_node, sizeof(SHA256HashList));
                free_SHA256HashList(&sha_hl_copy);
                //------------------------------------
                freeGlacierResponse(Response);
                
                deallocate(buffer, PartSize);

                GlacierDeleteMultipartUpload(request, UploadId);
                deallocate(UploadId, strlen(UploadId) + 1);

                closeLocalSource(ioblock);

                logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
                return 8;
            }
            else
            {
                // Deallocate all memory from our list
                deallocate(new_node, sizeof(SHA256HashList));
                free_SHA256HashList(&sha_hl_copy);
                //------------------------------------
                freeGlacierResponse(Response);
                
                deallocate(buffer, PartSize);

                GlacierDeleteMultipartUpload(request, UploadId);
                deallocate(UploadId, strlen(UploadId) + 1);

                closeLocalSource(ioblock);

                logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
                return 8;
            }

            freeGlacierResponse(Response);
        }
        else
        {
            logError(" \n GlacierPutFile: error in UploadPart() function occured \n");
            // Deallocate all memory from our list
            deallocate(new_node, sizeof(SHA256HashList));
            free_SHA256HashList(&sha_hl_copy);
            //------------------------------------
            deallocate(buffer, PartSize);

            GlacierDeleteMultipartUpload(request, UploadId);
            deallocate(UploadId, strlen(UploadId) + 1);

            closeLocalSource(ioblock);

            logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
            return 8;
        }
    }

    deallocate(buffer, PartSize);
    logTrace("\n before Close IO GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
    closeLocalSource(ioblock);
    logTrace("\n after Close IO GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);

    sha_hl = sha_hl_copy;
    returnCode = 0;
    char* Hash = getTreeHash(&sha_hl_copy, calculate_SHA256HashList_size(sha_hl_copy), 0, &returnCode);
    free_SHA256HashList(&sha_hl);
    if (returnCode < 0)
    {
        logError("\n GlacierPutFile: error in getTreeHash() function occurred\n");

        GlacierDeleteMultipartUpload(request, UploadId);
        deallocate(UploadId, strlen(UploadId) + 1);

        logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
        return 8;
    }

    char TreeSHA256[SHA256_HEX_LENGTH + 1];
    int retValue = CharToHex(Hash, SHA256_HASH_BYTES, TreeSHA256, SHA256_HEX_LENGTH + 1);
    deallocate(Hash, SHA256_HASH_BYTES);
    if (retValue != 0)
    {
        logError("\n GlacierPutFile: error in CharToHex() function occurred\n");

        GlacierDeleteMultipartUpload(request, UploadId);
        deallocate(UploadId, strlen(UploadId) + 1);

        logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
        return 8;
    }

    Response = CompleteMultipartUpload(request->client->accessKeyID, request->client->secretAccessKey, request->client->region,
                                       request->client->vault, UploadId, TreeSHA256, FileSize);
    if (Response)
    {
        unsigned int HttpStatus = 0;
        if (getHttpStatus(Response->Header, &HttpStatus) == 0)
        {
            logTrace(" \n HTTP status: %d \n", HttpStatus);
        }
        else
        {
            logError(" \n GlacierPutFile: error in getHttpStatus() function occured \n");
            
            freeGlacierResponse(Response);
            GlacierDeleteMultipartUpload(request, UploadId);
            deallocate(UploadId, strlen(UploadId) + 1);

            logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
            return 8;
        }

        if (HttpStatus == 201)
        {
            for (size_t i = 0; i < Response->ContentLength; i++) logTrace("%c", Response->Content[i]);
            logTrace(" \n");
        } else if ((HttpStatus >= 400) && (HttpStatus < 500))
        {
            BadRequestMsg* msg = getBadRequestMsg(Response->Content, Response->ContentLength);
            if (msg)
            {
                logTrace(" \n code: %s \n", msg->Code);
                logTrace(" \n message: %s \n", msg->Message);
                logTrace(" \n type: %s \n", msg->Type);
                freeBadRequestMsg(&msg);
            }

            freeGlacierResponse(Response);
            GlacierDeleteMultipartUpload(request, UploadId);
            deallocate(UploadId, strlen(UploadId) + 1);

            logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
            return 8;
        }
        else
        {
            freeGlacierResponse(Response);
            GlacierDeleteMultipartUpload(request, UploadId);
            deallocate(UploadId, strlen(UploadId) + 1);

            logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
            return 8;
        }

        freeGlacierResponse(Response);
    }
    else
    {
      logError(" \n GlacierPutFile: error in CompleteMultipartUpload() function occured \n");

      GlacierDeleteMultipartUpload(request, UploadId);
      deallocate(UploadId, strlen(UploadId) + 1);
      
      logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
      return 8;
    }
    
    deallocate(UploadId, strlen(UploadId) + 1);
    logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
    return 0;
#endif
}

int GlacierPutBuffer(GlacierRequest* request)
{
#ifdef METTLE
    logTrace(" \n Entered to GlacierPutBuffer() function \n ");
    logTrace(" \n GlobalAllocatedMemory: %llu \n ", GlobalAllocatedMemory);

    //  unsigned long long PartSize = 4294967296ULL; // max PartSize for Amazon Glacier
    unsigned long long PartSize = 8388608ULL; // PartSize must be a power of two and be not less than 1 Mb and not more than 4 Gb
    //  unsigned long long PartSize = 1048576ULL; // min PartSize for Amazon Glacier

    GlacierResponse* Response = GetMultiPartUploadId(request->client->accessKeyID, request->client->secretAccessKey, request->client->region, request->client->vault, request->path, PartSize);
    
    char * multipartUploadID = NULL;

    if (Response)
    {
        unsigned int HttpStatus = 0;
        if (getHttpStatus(Response->Header, &HttpStatus) == 0)
        {
            logTrace(" \n HTTP status: %d \n", HttpStatus);
        }
        else
        {
            logError(" \n GlacierPutBuffer: error in getHttpStatus() function occured \n");

            freeGlacierResponse(Response);

            logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
            return 8;
        }

        if (HttpStatus == 201)
        {
            for (size_t i = 0; i < Response->ContentLength; i++) logTrace("%c", Response->Content[i]);
            logTrace(" \n");

            multipartUploadID = getHeaderParamByName(Response->Header, "x-amz-multipart-upload-id: ");
            if (multipartUploadID)
            {
                logTrace(" \n Multipart upload ID: %s\n", multipartUploadID);
            }
            else
            {
                logError("\n GlacierPutBuffer: error in getHeaderParamByName() function occured for x-amz-multipart-upload-id parameter \n");
                freeGlacierResponse(Response);
                return 8;
            }
        }
        else if ((HttpStatus >= 400) && (HttpStatus < 500))
        {
            BadRequestMsg* msg = getBadRequestMsg(Response->Content, Response->ContentLength);
            if (msg)
            {
                logTrace(" \n code: %s \n", msg->Code);
                logTrace(" \n message: %s \n", msg->Message);
                logTrace(" \n type: %s \n", msg->Type);
                freeBadRequestMsg(&msg);
            }

            freeGlacierResponse(Response);

            logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
            return 8;
        }
        else
        {
            freeGlacierResponse(Response);

            logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
            return 8;
        }

        freeGlacierResponse(Response);
    }
    else
    {
        logError("\n GlacierPutBuffer: error in GetMultiPartUploadId() function occured \n");
        return 8;
    }

    SHA256HashList * sha_hl = NULL;
    SHA256HashList * sha_hl_copy = NULL;

    unsigned long long buffer_size = request->ioblock->length;   // TODO: "ioblock->length" field has "int" type, so 4 Gb sizes not supported
    char* buffer = request->ioblock->source;

    unsigned long long bufferPartsCount = (buffer_size / PartSize) + (buffer_size % PartSize > 0);

    for (unsigned long long i = 0; i < bufferPartsCount; i++)
    {
        unsigned long long bg = i * PartSize;
        unsigned long long en = bg + PartSize - 1;
        if (i + 1 == bufferPartsCount && (buffer_size % PartSize > 0))
            en = buffer_size - 1;

        SHA256HashList * new_node = (SHA256HashList *) allocate(sizeof(SHA256HashList), "SHA256HashList structure");
        new_node->next = NULL;

        Response = UploadPart(request->client->accessKeyID, request->client->secretAccessKey, request->client->region, request->client->vault,
                              multipartUploadID, buffer + bg, en-bg+1, bg, en, new_node->hash_value);

        if (Response)
        {
            unsigned int HttpStatus = 0;
            if (getHttpStatus(Response->Header, &HttpStatus) == 0)
            {
                logTrace(" \n HTTP status: %d \n", HttpStatus);
            }
            else
            {
                logError(" \n GlacierPutBuffer: error in getHttpStatus() function occured \n ");

                // Deallocate all memory from our list
                deallocate(new_node, sizeof(SHA256HashList));
                free_SHA256HashList(&sha_hl_copy);
                //------------------------------------
                freeGlacierResponse(Response);

                GlacierDeleteMultipartUpload(request, multipartUploadID);
                deallocate(multipartUploadID, strlen(multipartUploadID) + 1);

                logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
                return 8;
            }

            if (HttpStatus == 204)
            {
                logTrace(" \n 204 No Content\n");

                // all is correct
                if (sha_hl == NULL)
                    sha_hl = sha_hl_copy = new_node;
                else
                {
                    sha_hl->next = new_node;
                    sha_hl = sha_hl->next;
                }
            }
            else if ((HttpStatus >= 400) && (HttpStatus < 500))
            {
                BadRequestMsg* msg = getBadRequestMsg(Response->Content, Response->ContentLength);
                if (msg)
                {
                    logTrace(" \n code: %s \n", msg->Code);
                    logTrace(" \n message: %s \n", msg->Message);
                    logTrace(" \n type: %s \n", msg->Type);
                    freeBadRequestMsg(&msg);
                }
                
                // Deallocate all memory from our list
                deallocate(new_node, sizeof(SHA256HashList));
                free_SHA256HashList(&sha_hl_copy);
                //------------------------------------
                freeGlacierResponse(Response);
                
                GlacierDeleteMultipartUpload(request, multipartUploadID);
                deallocate(multipartUploadID, strlen(multipartUploadID) + 1);

                logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
                return 8;
            }
            else
            {
                // Deallocate all memory from our list
                deallocate(new_node, sizeof(SHA256HashList));
                free_SHA256HashList(&sha_hl_copy);
                //------------------------------------
                freeGlacierResponse(Response);
                
                GlacierDeleteMultipartUpload(request, multipartUploadID);
                deallocate(multipartUploadID, strlen(multipartUploadID) + 1);

                logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
                return 8;
            }

            freeGlacierResponse(Response);
        }
        else
        {
            logError(" \n GlacierPutBuffer: error in UploadPart() function occured \n");

            // Deallocate all memory from our list
            deallocate(new_node, sizeof(SHA256HashList));
            free_SHA256HashList(&sha_hl_copy);
            //------------------------------------
            
            GlacierDeleteMultipartUpload(request, multipartUploadID);
            deallocate(multipartUploadID, strlen(multipartUploadID) + 1);

            logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
            return 8;
        }
    }

    sha_hl = sha_hl_copy;
    int returnCode = 0;
    char* Hash = getTreeHash(&sha_hl_copy, calculate_SHA256HashList_size(sha_hl_copy), 0, &returnCode);
    free_SHA256HashList(&sha_hl);

    if (returnCode < 0)
    {
        logError("\n GlacierPutBuffer: error in getTreeHash() function occurred\n");
        
        GlacierDeleteMultipartUpload(request, multipartUploadID);
        deallocate(multipartUploadID, strlen(multipartUploadID) + 1);

        logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
        return 8;
    }

    char TreeSHA256[SHA256_HEX_LENGTH + 1];
    int retValue = CharToHex(Hash, SHA256_HASH_BYTES, TreeSHA256, SHA256_HEX_LENGTH + 1);
    deallocate(Hash, SHA256_HASH_BYTES);

    if (retValue != 0)
    {
        logError("\n GlacierPutBuffer: error in CharToHex() function occurred\n");

        GlacierDeleteMultipartUpload(request, multipartUploadID);
        deallocate(multipartUploadID, strlen(multipartUploadID) + 1);

        logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
        return 8;
    }

    Response = CompleteMultipartUpload(request->client->accessKeyID, request->client->secretAccessKey, request->client->region, request->client->vault,
                                       multipartUploadID, TreeSHA256, buffer_size);
    if (Response)
    {
        unsigned int HttpStatus = 0;
        if (getHttpStatus(Response->Header, &HttpStatus) == 0)
        {
            logTrace(" \n HTTP status: %d \n", HttpStatus);
        }
        else
        {
            logError(" \n GlacierPutBuffer: error in getHttpStatus() function occured \n");
            
            GlacierDeleteMultipartUpload(request, multipartUploadID);
            deallocate(multipartUploadID, strlen(multipartUploadID) + 1);
            freeGlacierResponse(Response);

            logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
            return 8;
        }

        if (HttpStatus == 201)
        {
            for (size_t i = 0; i < Response->ContentLength; i++) logTrace("%c", Response->Content[i]);
            logTrace(" \n");
        }
        else if ((HttpStatus >= 400) && (HttpStatus < 500))
        {
            BadRequestMsg* msg = getBadRequestMsg(Response->Content, Response->ContentLength);
            if (msg)
            {
                logTrace(" \n code: %s \n", msg->Code);
                logTrace(" \n message: %s \n", msg->Message);
                logTrace(" \n type: %s \n", msg->Type);
                freeBadRequestMsg(&msg);
            }

            GlacierDeleteMultipartUpload(request, multipartUploadID);
            deallocate(multipartUploadID, strlen(multipartUploadID) + 1);
            freeGlacierResponse(Response);

            logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
            return 8;
        }
        else
        {
            GlacierDeleteMultipartUpload(request, multipartUploadID);
            deallocate(multipartUploadID, strlen(multipartUploadID) + 1);
            freeGlacierResponse(Response);

            logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
            return 8;
        }

        freeGlacierResponse(Response);
    }
    else
    {
        logError("\n GlacierPutBuffer: error in CompleteMultipartUpload() function occurred\n");
        
        GlacierDeleteMultipartUpload(request, multipartUploadID);
        deallocate(multipartUploadID, strlen(multipartUploadID) + 1);

        return 8;
    }

    deallocate(multipartUploadID, strlen(multipartUploadID) + 1);

    logTrace("\n GlobalAllocatedMemory: %llu \n", GlobalAllocatedMemory);
    return 0;
#endif
}

int GlacierPut(GlacierRequest* request)
{
#ifdef METTLE
  switch (request->ioblock->type)
  {
    case CLD_IO_TYPE_FILE:
      return GlacierPutFile(request);

    case CLD_IO_TYPE_BUFFER:
      return GlacierPutBuffer(request);
/*
    case CLD_IO_TYPE_STREAM:
      return GlacierPutStream(request);
*/
    default:
      request->returnCode = 8;
      request->reasonCode = CLD_ERR_TYPE_UNKNOWN;
      return 8;
  }
#endif
}

int GlacierGet(GlacierRequest* request)
{
#ifdef METTLE
  switch (request->ioblock->type)
  {
    case CLD_IO_TYPE_FILE:
      return GlacierGetFile(request);
/*
    case CLD_IO_TYPE_BUFFER:
      return GlacierGetBuffer(request);

    case CLD_IO_TYPE_STREAM:
      return GlacierPutStream(request);
*/
    default:
      request->returnCode = 8;
      request->reasonCode = CLD_ERR_TYPE_UNKNOWN;
      return 8;
  }
#endif
}

int callGlacier(GlacierRequest *request)
{
#ifdef METTLE
  switch (request->type)
  {
    case GL_TYPE_PUT:
      return GlacierPut(request);

    case GL_TYPE_GET:
      return GlacierGet(request);
/*
    case GL_TYPE_DELETE:
      return GlacierDelete(request);
*/
    default:
      request->returnCode = 8;
      request->reasonCode = 0; // !!! = CLD_ERR_GL_TYPE_UNKNOWN;
      return 8;
  }
#endif
}

/*--------------------------------------------------------------------------------------*/