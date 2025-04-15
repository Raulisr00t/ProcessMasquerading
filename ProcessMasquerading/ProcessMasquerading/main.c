#define IDI_ICON1 1

#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#pragma comment(lib, "ntdll.lib")

typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(
    HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG
    );

BOOL MasqueradeProcess() {
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;

    pNtQueryInformationProcess NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

    if (!NtQueryInformationProcess) {
        printf("[!] Failed to resolve NtQueryInformationProcess\n");
        return FALSE;
    }

    if (NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &pbi, sizeof(pbi), &returnLength) != 0) {
        printf("[!] NtQueryInformationProcess failed\n");
        return FALSE;
    }

    PPEB peb = pbi.PebBaseAddress;
    PRTL_USER_PROCESS_PARAMETERS procParams = peb->ProcessParameters;

    WCHAR newCmd[] = L"C:\\Windows\\System32\\notepad.exe";
    SIZE_T len = wcslen(newCmd) * sizeof(WCHAR);

    DWORD oldProtect;
    
if (VirtualProtect(procParams->CommandLine.Buffer, len + sizeof(WCHAR), PAGE_READWRITE, &oldProtect)) {
        memcpy(procParams->CommandLine.Buffer, newCmd, len);
        procParams->CommandLine.Length = (USHORT)len;
        procParams->CommandLine.MaximumLength = (USHORT)(len + sizeof(WCHAR));
        VirtualProtect(procParams->CommandLine.Buffer, len + sizeof(WCHAR), oldProtect, &oldProtect);
    }

    else {
        printf("[!] Failed to change memory protection on CommandLine\n");
        return FALSE;
    }

    if (VirtualProtect(procParams->ImagePathName.Buffer, len + sizeof(WCHAR), PAGE_READWRITE, &oldProtect)) {
        memcpy(procParams->ImagePathName.Buffer, newCmd, len);
        procParams->ImagePathName.Length = (USHORT)len;
        procParams->ImagePathName.MaximumLength = (USHORT)(len + sizeof(WCHAR));
        VirtualProtect(procParams->ImagePathName.Buffer, len + sizeof(WCHAR), oldProtect, &oldProtect);
    }

    else {
        printf("[!] Failed to change memory protection on ImagePathName\n");
        return FALSE;
    }

    printf("[+] Successfully masqueraded process to: %ws\n", newCmd);

    return TRUE;
}

int main(void){
    SetCurrentDirectoryW(L"C:\\Windows\\System32");

    if (MasqueradeProcess()) {
        printf("[+] Masquerading successful!\n");
    }

    else {
        printf("[-] Masquerading failed.\n");
    }

    printf("[>>] Press Enter To Continue\n");

    getchar();

    return 0;
}
