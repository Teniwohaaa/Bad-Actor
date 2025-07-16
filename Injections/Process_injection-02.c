#include <stdio.h>
#include <windows.h>

#define okay(msg, ...) printf("[+] " msg "\n", ##__VA_ARGS__)
#define Info(msg, ...) printf("[*] " msg "\n", ##__VA_ARGS__)
#define Warn(msg, ...) printf("[-] " msg "\n", ##__VA_ARGS__)

DWORD PID = 0;
HANDLE hProcess, hThread = NULL;
LPVOID rBuffer = NULL;
int main(int argc, char *argv[]) {
  unsigned char ShellCode[] = "";
  if (argc < 2) {
    // if the user didn't provide at least one argument after the programme name
    // we print a message.

    Warn("Usage Programme.exe <PID>");
    return EXIT_FAILURE;
  }
  // if the proggrame has been supplied with an PID then we turn the input into
  // an INT
  PID = atoi(argv[1]);
  okay("Trying to open the proggrame <%ld>", PID);
  // now we open a handle to the process
  hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
  if (hProcess == NULL) {
    Warn("Coudon't get a handle to the process <%ld>, error: %ld", PID,
         GetLastError());
    return EXIT_FAILURE;
  }

  //  now we allocate Bytes to the process memory
  rBuffer = VirtualAllocEX(hProcess, NULL, sizeof(ShellCode),
                           (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
  return EXIT_SUCCESS;
}