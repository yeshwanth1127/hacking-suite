#pragma once
#include <windows.h>

// Decrypt AES-encrypted payload
LPVOID aes_decrypt(LPVOID encrypted, DWORD encrypted_size, DWORD *decrypted_size);
