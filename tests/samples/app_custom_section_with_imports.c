// cc app_custom_section_with_imports.c -o app_custom_section_with_imports.exe
#include <windows.h>


__attribute__((section(".test_section")))
int test_global = 0x1337;

int main() {
    // Import USER32DLL
    MessageBoxA(NULL, "app_custom_section_with_imports", "app_custom_section_with_imports", MB_OK);

    // Import KERNEL32.DLL
    ExitProcess(test_global);
    return 0;
}
