#include <windows.h>
#include <detours.h>
#include <iostream>

void PatchA(LPVOID address, const void *dwValue, SIZE_T dwBytes) {
    unsigned long oldProtect;
    VirtualProtect((void *)address, dwBytes, PAGE_EXECUTE_READWRITE, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), (void *)address, dwBytes);
    memcpy((void *)address, dwValue, dwBytes);
    VirtualProtect((void *)address, dwBytes, oldProtect, &oldProtect);
}

// Automatically add "patchme"
int (__cdecl *pPreInitEverQuest)(char * param_1, HINSTANCE * param_2) = nullptr;
int __cdecl PreInitEverQuest_Detour(char *param_1, HINSTANCE * param_2)
{
    std::string params = std::string(param_1);
    std::string patchme = std::string("patchme");

    if (params.find(patchme) == std::string::npos)
    {
        params += " " + patchme;
    }

    return pPreInitEverQuest((char*)params.c_str(), param_2);
}

void init_function_ptrs()
{
    pPreInitEverQuest = (int(__cdecl*)(char * param_1, HINSTANCE * param_2))((UINT_PTR)0x004ae229);
}

void hook_api(bool enable)
{
    LONG(WINAPI *_DetourAction)(_Inout_ PVOID *ppPointer, _In_ PVOID pDetour) = NULL;
    if (enable) {
        _DetourAction = DetourAttach;
    }
    else {
        _DetourAction = DetourDetach;
    }

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // perform the action (hooking/unhooking):
    _DetourAction(&(PVOID&)pPreInitEverQuest, PreInitEverQuest_Detour);

    DetourTransactionCommit();
}

void patch_memory()
{
    // disable packet compression
    *(DWORD *)0x005f48b0 = 0;
}

BOOL WINAPI DllMain(HANDLE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        OutputDebugStringA("Hooking the process");
        init_function_ptrs();
        hook_api(true);
        patch_memory();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        OutputDebugStringA("Unhooking the process");
        hook_api(false);
        break;
    }
    return TRUE;
}
