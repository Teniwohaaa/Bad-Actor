#include <windows.h>

bool APIENTRY DllMain(HMODULE hModule, DWORD nReason, LPVOID lpReserved) {

  // a simple message box
  switch (nReason) {
  case DLL_PROCESS_ATTACH:
    MessageBoxW(NULL, L"Meow from DLL_PROCESS_ATTACH!", L"=^..^=", MB_OK);
    break;
  case DLL_PROCESS_DETACH:
    MessageBoxW(NULL, L"Meow from DLL_PROCESS_DETACH!", L"=^..^=", MB_OK);
    break;
  case DLL_THREAD_ATTACH:
    MessageBoxW(NULL, L"Meow from DLL_THREAD_ATTACH!", L"=^..^=", MB_OK);
    break;
  case DLL_THREAD_DETACH:
    MessageBoxW(NULL, L"Meow from DLL_THREAD_DETACH!", L"=^..^=", MB_OK);
    break;
  }
  return TRUE;
}