#ifndef __GLACIER__
#define __GLACIER__

/* Local Dependencies */
#include "cldio.h"                    // For "IOBlock" structure definition
#include "../../rscrypto/rs_hash.h"   // For constant SHA256_HASH_BYTES definition

#define SHA256_HEX_LENGTH (SHA256_HASH_BYTES * 2)   // Length of SHA-256 in hexadecimal char form

#if defined(METTLE) || defined (AS400)
#pragma pack(packed)
#else
#pragma pack(push,1)
#endif

#define GL_TYPE_PUT            1
#define GL_TYPE_GET            2
#define GL_TYPE_ABORT          3            /* Used to abort a Multipart Upload on-demand. */
#define GL_TYPE_DELETE         4

/*--------------------------- Glacier structures definitions -----------------------------*/
typedef struct GlacierResponse_tag
{
	char* Header;
	char* Content;
	unsigned long long ContentLength;
} GlacierResponse;

typedef struct Glacier_AuthData_tag
{
    /* Required fields */
    char * region;              /* Null terminated region string
                                   (for example:   "us-east-1"   or   "eu-central-1") */
    char * vault;               /* Null terminated vault name string */
    char * accessKeyID;         /* Null terminated Access Key ID string */
    char * secretAccessKey;     /* Null terminated Secret Access Key string */
    
    /* Fields needed for deallocation only (if these fields will be rewritten during runtime
       for any purposes, the information about initial allocated size should be stored) */
    size_t allocated_Region_size;
    size_t allocated_Vault_size;
    size_t allocated_accessKeyID_size;
    size_t allocated_secretAccessKey_size;
    /*-------------------------------------*/
} Glacier_AuthData;

typedef struct SHA256HashList_tag
{
    unsigned char hash_value[SHA256_HASH_BYTES];
    struct SHA256HashList_tag * next;
} SHA256HashList;

typedef struct VaultList_tag
{
    char * CreationDate;
    char * LastInventoryDate;
    char * NumberOfArchives;
    char * SizeInBytes;
    char * VaultARN;
    char * VaultName;

    struct VaultList_tag * next;
} VaultList;

typedef struct ArchiveList_tag
{
	char* ArchiveId;
	char* ArchiveDescription;
	char* CreationDate;
	char* Size;
	char* SHA256TreeHash;
	void* Next;
} ArchiveList;

typedef struct BadRequestMsg_tag
{
	char* Code;
	char* Message;
	char* Type;
} BadRequestMsg;

typedef struct GlacierRequest_tag
{
  Glacier_AuthData* client;
  IOBlock* ioblock;
  char *path;                               /* Null terminated file/directory path */
  int type:16;                              /* Type of request.  See GL_TYPE_XXX for more info */
  int returnCode;
  int reasonCode;
} GlacierRequest;
/*----------------------------------------------------------------------------------------*/

/*----------------------- Glacier external functions declaration -------------------------*/
void * allocate(unsigned long long size, char * description);
void deallocate(void * ptr, unsigned long long size);

Glacier_AuthData * Glacier_makeAuthData(char const * const region,                    /* Null terminated region string */
                                        char const * const vault,                     /* Null terminated vault name string */
                                        char const * const accessKeyID,               /* Null terminated Access Key ID string */
                                        char const * const secretAccessKey            /* Null terminated Secret Access Key string */
                                       );
void Glacier_freeAuthData(Glacier_AuthData * AuthData);

size_t calculate_SHA256HashList_size(SHA256HashList const * sha_hl);
void free_SHA256HashList(SHA256HashList ** sha_hl);
SHA256HashList * create_SHA256HashList_from_buffer(char const * const Buffer, unsigned long long BufferSize);
char * getTreeHash(SHA256HashList ** sha_hl, size_t sha_hl_Elements_Count, size_t Level, int * returnCode);
int CharToHex(char const * const text, const size_t textLen, char * hexString, const size_t hexStringAllocatedSize);
int getHttpStatus(char const * const Header, unsigned int * HttpStatus);
char * getHeaderParamByName(char const * const Header, char const * const ParamName);
void freeGlacierResponse(GlacierResponse* Response);
GlacierResponse* CreateVault(char const * const AccessKey, char const * const SecretKey, char const * const Region, char const * const VaultName);
GlacierResponse* ListVaultJobs(char const * const AccessKey, char const * const SecretKey, char const * const Region, char const * const VaultName);
GlacierResponse* GetVaultJobInfo(char const * const AccessKey, char const * const SecretKey, char const * const Region,
                                 char const * const VaultName, char const * const JobId);
GlacierResponse* VaultJobOutput(char const * const AccessKey, char const * const SecretKey, char const * const Region,
                                char const * const VaultName, char const * const JobId, char const * const Range);
GlacierResponse* ListVaults(char const * const AccessKey, char const * const SecretKey, char const * const Region);
GlacierResponse* RunInventoryJob(char const * const AccessKey, char const * const SecretKey, char const * const Region,
                                 char const * const VaultName, char const * const JobName);
GlacierResponse* DeleteArchive(char const * const AccessKey, char const * const SecretKey, char const * const Region,
                               char const * const VaultName, char const * const ArchiveId);
GlacierResponse* SingleUpload(char const * const AccessKey, char const * const SecretKey, char const * const Region, char const * const VaultName,
                              char const * const ArchiveDescription, char const * const Buffer, unsigned long long BufferSize);
GlacierResponse* RunRetrievalJob(char const * const AccessKey, char const * const SecretKey, char const * const Region,
                                 char const * const VaultName, char const * const JobName, char const * const ArchiveId,
                                 char const * const Range);
GlacierResponse* GetMultiPartUploadId(char const * const AccessKey, char const * const SecretKey, char const * const Region,
                                      char const * const VaultName, char const * const ArchiveDescription, unsigned long long PartSize);
GlacierResponse* ListParts(char const * const AccessKey, char const * const SecretKey, char const * const Region,
                           char const * const VaultName, char const * const UploadId);
GlacierResponse* ListMultipartUploads(char const * const AccessKey, char const * const SecretKey, char const * const Region,
                                      char const * const VaultName);
GlacierResponse* DeleteMultipartUpload(char const * const AccessKey, char const * const SecretKey, char const * const Region,
                                       char const * const VaultName, char const * const UploadId);
GlacierResponse* UploadPart(char const * const AccessKey, char const * const SecretKey, char const * const Region, char const * const VaultName,
                            char const * const MultiPartUploadId, char const * const Buffer, unsigned long long BufferSize,
                            unsigned long long LowLimitRange, unsigned long long HighLimitRange,
                            char * const TreeHash);
GlacierResponse* CompleteMultipartUpload(char const * const AccessKey, char const * const SecretKey, char const * const Region,
                                         char const * const VaultName, char const * const UploadId, char const * const TreeHash,
                                         unsigned long long ArchiveSize);

VaultList* getVaultList(char* jsonString, size_t jsonStringSize);
void freeVaultList(VaultList ** lst);
ArchiveList* getArchiveList(char * jsonString, size_t jsonStringSize);
void freeArchiveList(ArchiveList ** list);
BadRequestMsg* getBadRequestMsg(char * jsonString, size_t jsonStringSize);
void freeBadRequestMsg(BadRequestMsg ** msg);

// Debug purposes only
void printVaultList(VaultList* lst);
void printArchiveList(ArchiveList* list);
//--------------------

/*----------------------------------------------------------------------------------------*/

#if defined(METTLE) || defined (AS400)
#pragma pack(reset)
#else
#pragma pack(pop)
#endif

#endif