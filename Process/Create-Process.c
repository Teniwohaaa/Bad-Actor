#include <stdio.h>
#include <windows.h>

int main(void) {
  STARTUPINFOW SI = {0};
  PROCESS_INFORMATION PI = {0};

  // we use & for the pointers

  if (!CreateProcessW(L"C:\\WINDOWS\\System32\\notepad.exe", NULL, NULL, NULL,
                      FALSE, BELOW_NORMAL_PRIORITY_CLASS, NULL, NULL, &SI,
                      &PI)) {
    printf("Erreur l'os de la creation du processus: %ld", GetLastError());
    return EXIT_FAILURE;
    // the same as return 1, we use it whenthere is an error
  }

  printf("The PID: %ld", PI.dwProcessId);

  return EXIT_SUCCESS;
}