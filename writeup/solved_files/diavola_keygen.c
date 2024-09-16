#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <windows.h>
#include <wincrypt.h>


typedef struct _PLAINTEXTKEYBLOB {
  BLOBHEADER hdr;
  DWORD      dwKeySize;
  BYTE       rgbKeyData[];
} PTKB;



BOOL GetExportedKey(
    HCRYPTKEY hKey,
    DWORD dwBlobType,
    LPBYTE *ppbKeyBlob,
    LPDWORD pdwBlobLen)
{


    DWORD dwBlobLength;
    *ppbKeyBlob = NULL;
    pdwBlobLen = 0;

    PTKB *plaintextkeyblob = NULL;

    // Export the public key. Here the public key is exported to a
    // PUBLICKEYBLOB. This BLOB can be written to a file and
    // sent to another user.

    if(CryptExportKey(
        hKey,
        NULL,
        dwBlobType,
        0,
        NULL,
        &dwBlobLength))
    {
        printf("Size of the BLOB for the public key determined. = %d (0x%x) \n", dwBlobLength, dwBlobLength);
        //return TRUE;
    }
    else
    {
        printf("Error computing BLOB length.\n");
        return FALSE;
    }

    // Allocate memory for the pbKeyBlob.
    if(*ppbKeyBlob = (LPBYTE)malloc(dwBlobLength))
    {
        printf("Memory has been allocated for the BLOB. \n");
    }
    else
    {
        printf("Out of memory. \n");
        return FALSE;
    }

    // Do the actual exporting into the key BLOB.
    if(CryptExportKey(
        hKey,
        NULL,
        dwBlobType,
        0,
        *ppbKeyBlob,
        &dwBlobLength))
    {
        printf("Contents have been written to the BLOB. \n");
        plaintextkeyblob = (PTKB*) *ppbKeyBlob;

        printf("key size should be: %u\n", plaintextkeyblob->dwKeySize);

        uint8_t* kb = (char*)*ppbKeyBlob;
        for (int i = 0; i < dwBlobLength; i++) {
            printf("%02x ", kb[i]);
        }
        printf("\nkey:\n");
        for(int i = 0; i < plaintextkeyblob->dwKeySize; i++) {
            printf("%02x", plaintextkeyblob->rgbKeyData[i]);
        }
        //*pdwBlobLen = dwBlobLength;
    }

    /*
    else
    {
        printf("Error exporting key.\n");
        free(*ppbKeyBlob);
        *ppbKeyBlob = NULL;

        return FALSE;
    }
*/
    return TRUE;
}

void the_encrypter(char* a1, char* a2)
{
    printf("a");
    HCRYPTPROV c_context;
    HCRYPTHASH phHash;
    HCRYPTKEY  phKey;
    //CryptAcquireContextW(&provider, 0, 0, 0x18, 0);
    CryptAcquireContextW(&c_context,(LPCWSTR)0x0,(LPCWSTR)0x0,PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
    CryptCreateHash(c_context,CALG_SHA_256,0,0,&phHash);
    CryptHashData(phHash,a1,0x20,0);
    // Note CRYPT_EXPORTABLE

    printf("b");
    CryptDeriveKey(c_context,CALG_AES_256,phHash,CRYPT_EXPORTABLE,&phKey);

    printf("c");
    LPBYTE keyBlob[1024];
    LPDWORD keyBlobLen;
    printf("d");
    GetExportedKey(phKey, PLAINTEXTKEYBLOB, keyBlob, keyBlobLen);
/*

    printf("e");
    for(int i = 0; i < 128; i++) {
        printf("%02x", keyBlob[i]);
    }
    */
//CryptSetKeyParam(phKey,KP_IV,init_vector,0);
//CryptEncrypt(phKey,0,1,0,pbData,param_5,dwBufLen);
}

int main(void)
{
    char array1[0x20];
    char array2[0x10];
    srand(1725110373);
    for(int i = 0; i < 0x20; i++) {
        printf(".\n");
        int n = rand() & 0xff;
        //printf("\\x%02x", n);
        array1[i] = n;
    }
    printf("IV: ");
    for(int i = 0; i < 0x10; i++) {
        int n = rand();
        array2[i] = n;
        printf(", 0x%x", n & 0xff);
    }
    printf("\n");
    the_encrypter(array1, array2);
}


// https://github.com/crappycrypto/wincrypto and others
