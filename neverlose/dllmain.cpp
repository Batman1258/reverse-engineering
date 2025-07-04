#include <windows.h>
#include <random>
#include <sstream>
#include <fstream>

#include "LeoSpecial.h"

#define WIN32_LEAN_AND_MEAN

LeoHook VEH;

typedef int(__cdecl* tlj_lex_cleanup)(int a1, DWORD* a2);
tlj_lex_cleanup lj_lex_cleanup;

uintptr_t FindPattern(uintptr_t start, size_t length) {
    const unsigned char pattern[] = {
        0x8B, 0x44, 0x24, 0x00, 0x56, 0x8B, 0x74, 0x24, 0x00, 0x57, 0x8B, 0x78
    };
    const char* mask = "xxx?xxxx?xxx";

    for (size_t i = 0; i < length - sizeof(pattern); i++) {
        bool found = true;
        for (size_t j = 0; j < sizeof(pattern); j++) {
            if (mask[j] == 'x' && *(unsigned char*)(start + i + j) != pattern[j]) {
                found = false;
                break;
            }
        }
        if (found) {
            return start + i;
        }
    }
    return 0;
}

uintptr_t ScanForFunction() {
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    const SIZE_T TARGET_SIZE = 0x23C000;
    const SIZE_T MIN_SIZE = static_cast<SIZE_T>(TARGET_SIZE * 0.8);

    uintptr_t start = (uintptr_t)sysInfo.lpMinimumApplicationAddress;
    uintptr_t end = (uintptr_t)sysInfo.lpMaximumApplicationAddress;
    while (start < end) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPCVOID)start, &mbi, sizeof(mbi))) {
            if (mbi.Protect == 0x40 && mbi.State == 0x1000 && mbi.RegionSize > MIN_SIZE) {
                uintptr_t address = FindPattern((uintptr_t)mbi.BaseAddress, mbi.RegionSize);
                if (address != 0) {
                    return address;
                }
            }
            start = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
        }
        else {
            start += 4096;
        }
    }
    return 0;
}

std::string GenerateRandomString(int length) {
    const std::string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> distrib(0, chars.size() - 1);

    std::string randomStr;
    for (int i = 0; i < length; ++i) {
        randomStr += chars[distrib(generator)];
    }

    return randomStr;
}

void SaveChunkToFile(const unsigned char* data, size_t size, const char* name) {
    if (!data || size == 0) {
        std::cerr << "Script data is empty or null!\n";
        return;
    }

    srand(static_cast<unsigned int>(time(0)));
    std::string randomFilename = "script_" + GenerateRandomString(8) + ".bin";

    std::ofstream outFile(randomFilename, std::ios::binary);
    if (!outFile.is_open()) {
        std::cerr << "Error creating file: " << randomFilename << "\n";
        return;
    }

    outFile.write(reinterpret_cast<const char*>(data), size);
    outFile.close();

    std::cout << "Saved script to file: " << randomFilename << "\n";
}

std::vector<const char*> hex_dumps;
int __cdecl hlj_lex_cleanup(int a1, DWORD* a2) {
    VEH.Unhook();
    int result = lj_lex_cleanup(a1, a2);
    VEH.Hook((uintptr_t)lj_lex_cleanup, (uintptr_t)hlj_lex_cleanup);

    const char* chunkarg = nullptr;
    const unsigned char* reader = nullptr;
    uintptr_t reader_address;

    if (a2 != nullptr) {
        DWORD* ud_array = a2;
        if (ud_array[20] != 0) {
            chunkarg = reinterpret_cast<const char*>(ud_array[20]);
        }
        if (ud_array[16] != 0) {
            DWORD* reader_struct = reinterpret_cast<DWORD*>(ud_array[16]);
            if (reader_struct != nullptr) {
                reader = reinterpret_cast<const unsigned char*>(reader_struct[0]);
                uintptr_t reader_address = static_cast<uintptr_t>(reader_struct[0]);
            }
        }
    }


    printf("reader address: %p\n", (void*)reader);

    std::cout << "Lua Name: " << chunkarg << std::endl;

    // WARNING: SHITCODE AHEAD :troll:

    size_t size = 0;
    size_t consecutive00 = 0;
    for (; size < 1024 * 1024; ++size) {
        unsigned char byte = reader[size];
        if (byte == 0x00) {
            consecutive00++;
            if (consecutive00 >= 50) break;
        }
        else {
            consecutive00 = 0;
        }
    }

    SaveChunkToFile(reader, size, chunkarg);

    return result;
}

void main() {
    AllocConsole();
    FILE* fDummy;
    freopen_s(&fDummy, "CONOUT$", "w", stdout);

    printf("God Bless SulferW (jesus).\n");

    uintptr_t lj_lex_cleanup_address = ScanForFunction();
    lj_lex_cleanup = reinterpret_cast<tlj_lex_cleanup>(lj_lex_cleanup_address);

    if (!VEH.Hook((uintptr_t)lj_lex_cleanup, (uintptr_t)hlj_lex_cleanup))
        printf("[-] Failed to hook...\n");
    else
        printf("[+] soufiw's mother was fucked.\n");
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        main();
    }

    return TRUE;
}