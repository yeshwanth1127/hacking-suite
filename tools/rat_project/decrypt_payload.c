#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>

#pragma comment(lib, "advapi32.lib")

// Hardcoded key/IV example (replace with your real key/iv from Python script)
BYTE AES_KEY[32] = { /* 32 bytes key */ };
BYTE AES_IV[16] = { /* 16 bytes IV */ };

LPVOID aes_decrypt(LPVOID encrypted, DWORD encrypted_size, DWORD *decrypted_size) {
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;
    BYTE *buffer = (BYTE*)HeapAlloc(GetProcessHeap(), 0, encrypted_size);
    if (!buffer) return NULL;
    memcpy(buffer, encrypted, encrypted_size);
    *decrypted_size = encrypted_size;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return NULL;

    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, AES_KEY, sizeof(AES_KEY), 0);
    CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey);
    CryptDestroyHash(hHash);

    DWORD out_size = encrypted_size;
    CryptDecrypt(hKey, 0, TRUE, 0, buffer, &out_size);

    *decrypted_size = out_size;

    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);

    return buffer;
}
