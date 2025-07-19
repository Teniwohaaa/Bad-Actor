#include <stdio.h>
#include <windows.h>

#define okay(msg, ...) printf("[+]" msg "\n", ##__VA_ARGS__)
#define warn(msg, ...) printf("[-]" msg "\n", ##__VA_ARGS__)

DWORD WINAPI TestFunction(LPVOID lpParam) {
  okay("Thread running...");
  okay(" Meowww = ^..^= !");
  return EXIT_SUCCESS;
}

int main(int argc, char **argv) {
  // load the dll
  HINSTANCE hDll = LoadLibraryA(argv[1]);
  HANDLE hThread = NULL;

  if (argc < 2) {
    // If the user didn't provide at least one argument after the program name,
    // it prints a message.
    warn("Usage: Programme.exe <Path to dll>");
    return EXIT_FAILURE;
  }

  if (hDll == NULL) {
    if (hDll == NULL) {
      warn("Failed to load the DLL. Error: %ld", GetLastError());
      return EXIT_FAILURE;
    }
    okay("DLL loaded at address: 0x%p", hDll);
    return EXIT_FAILURE;
  }

  hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)TestFunction, NULL, 0,
                         NULL);
  if (hThread == NULL) {
    warn("failed to create the handle, error:%ld", GetLastError());
    return EXIT_FAILURE;
  }
  // now we wait
  WaitForSingleObject(hThread, INFINITE);

  //   free the handle and the dll
  CloseHandle(hThread);

  FreeLibrary(hDll);
  okay("The End!");

  return EXIT_SUCCESS;
}