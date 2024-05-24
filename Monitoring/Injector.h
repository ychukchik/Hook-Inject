#pragma once
#include <winsock2.h>
#include <iostream>
#include <string>
#include <ShlObj.h>
#include <tlhelp32.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")


class Injector
{
private:
    LPCWSTR dll_path;

public:
    Injector() = delete;
    Injector(LPCWSTR path);
    ~Injector();

    bool IsAdmin();
    void Help();
    int GetPID(const char* proc_name);
    void InjectDLL(DWORD PID);
    int SendParameters(char* argv[]);
};