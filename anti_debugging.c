#include <stdlib.h>
#include <windows.h>

/*
 * Anti-debugging
 * timing checks, hardware b, exception handling, parent process check
 * Exception-based detection, NtQueryInformationProcess check
 * Check for debugger windows, PEB check
*/
int check_debugger() 
{
	BOOL isRemoteDebuggerPresent = FALSE;
	CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemoteDebuggerPresent);

	if (IsDebuggerPresent() || isRemoteDebuggerPresent) 
	{
		MessageBox(
			NULL,
			"Debugger detected!\nApp will now terminate",
			"Security warning",
			MB_OK | MB_ICONERROR
			);
		exit(1);
	};
}


int check_debugger2()
{
	DWORD start = GetTickCount();
	int sum =0;
	DWORD elapsed;

	for (int i = 0; i < 1000; i++)
	{
		sum += i;
	}

	elapsed = GetTickCount() - start;

	if (elapsed > 100) 
	{
		return 1;
	}
}

int check_hardware_breakpoints() {
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        // Check if any debug registers are set
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) {
            return 1;  // Hardware breakpoint detected
        }
    }
    return 0;
}

int check_via_exception() {
    __try {
        // Trigger a breakpoint exception
        DebugBreak();
    }
    __except(GetExceptionCode() == EXCEPTION_BREAKPOINT ? 
             EXCEPTION_EXECUTE_HANDLER : EXCEPTION_CONTINUE_SEARCH) {
        // If we catch it, no debugger (debugger would handle it)
        return 0;
    }
    
    // If we reach here, debugger handled the exception
    return 1;
}

// 5. NtQueryInformationProcess check
typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(
    HANDLE, UINT, PVOID, ULONG, PULONG);

int check_ntquery() {
    HMODULE hNtdll = LoadLibrary("ntdll.dll");
    if (!hNtdll) return 0;
    
    pNtQueryInformationProcess NtQIP = 
        (pNtQueryInformationProcess)GetProcAddress(hNtdll, "NtQueryInformationProcess");
    
    if (NtQIP) {
        DWORD isDebuggerPresent = 0;
        NTSTATUS status = NtQIP(
            GetCurrentProcess(),
            7,  // ProcessDebugPort
            &isDebuggerPresent,
            sizeof(DWORD),
            NULL
        );
        
        FreeLibrary(hNtdll);
        if (status == 0 && isDebuggerPresent != 0) {
            return 1;
        }
    }
    
    FreeLibrary(hNtdll);
    return 0;
}

// 6. Check for debugger windows
int check_debugger_windows() {
    if (FindWindow("OLLYDBG", NULL)) return 1;
    if (FindWindow("x32dbg", NULL)) return 1;
    if (FindWindow("ID", NULL)) return 1;  // Immunity Debugger
    if (FindWindow("x64dbg", NULL)) return 1;
    if (FindWindow("Rock Debugger", NULL)) return 1;
    if (FindWindow("ObsidianGUI", NULL)) return 1;
    return 0;
}

// 7. PEB (Process Environment Block) check
int check_peb() {
    #ifdef _WIN64
        PPEB peb = (PPEB)__readgsqword(0x60);
    #else
        PPEB peb = (PPEB)__readfsdword(0x30);
    #endif
    
    // Check BeingDebugged flag
    if (peb->BeingDebugged) {
        return 1;
    }
    return 0;
}
