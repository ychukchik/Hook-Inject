// dllmain.cpp : Определяет точку входа для приложения DLL.

#include "pch.h"
#include "fileapi.h"
#include "detours.h"
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <strsafe.h>

#pragma comment (lib, "Ws2_32.lib")
#pragma comment(lib, "detours.lib")

#define WIN32_LEAN_AND_MEAN
#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"

// функция для печати отладочных сообщений со строкой формата
#define DBGPRINT(kwszDebugFormatString, ...) _DBGPRINT(__FUNCTIONW__, __LINE__, kwszDebugFormatString, __VA_ARGS__)
VOID _DBGPRINT(LPCWSTR kwszFunction, INT iLineNumber, LPCWSTR kwszDebugFormatString, ...);


HANDLE(WINAPI* pCreateFileA) (LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = CreateFileA;
HANDLE(WINAPI* pCreateFileW) (LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = CreateFileW;
HANDLE(WINAPI* pFindFirstFileW) (LPCWSTR lpFileName, LPWIN32_FIND_DATA lpFindFileData) = FindFirstFileW;
HANDLE(WINAPI* pFindFirstFileA)(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData) = FindFirstFileA;
BOOL(WINAPI* pFindNextFileW) (HANDLE hFindFile, LPWIN32_FIND_DATA lpFindFileData) = FindNextFileW;
BOOL(WINAPI* pFindNextFileA) (HANDLE hFindFile, LPWIN32_FIND_DATAA  lpFindFileData) = FindNextFileA;
HANDLE(WINAPI* pFindFirstFileExA) (LPCSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS  fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags) = FindFirstFileExA;
HANDLE(WINAPI* pFindFirstFileExW) (LPCWSTR lpFileName, FINDEX_INFO_LEVELS fInfoLevelId, LPVOID lpFindFileData, FINDEX_SEARCH_OPS  fSearchOp, LPVOID lpSearchFilter, DWORD dwAdditionalFlags) = FindFirstFileExW;

//HANDLE(WINAPI* pFindFirstFileA)(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData) = FindFirstFileA;
//HANDLE WINAPI MyFindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
//HANDLE(WINAPI* pFindFirstFileW)(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData) = FindFirstFileW;
//HANDLE WINAPI MyFindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData);
//BOOL(WINAPI* pFindNextFileA)(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData) = FindNextFileA;
//BOOL WINAPI MyFindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
//BOOL(WINAPI* pFindNextFileW)(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) = FindNextFileW;
//BOOL WINAPI MyFindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData);
//HANDLE(WINAPI* pCreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = CreateFileA;
//HANDLE WINAPI MyCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
//HANDLE(WINAPI* pCreateFileW)(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) = CreateFileW;
//HANDLE WINAPI MyCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
BOOL(WINAPI* pCloseHandle)(HANDLE hObject) = CloseHandle;
BOOL WINAPI MyCloseHandle(HANDLE hObject);

extern "C" LPVOID dynamicTarget = NULL;
extern "C"  VOID hookfunc();
bool notparallel = 1;
std::string funcObserve = "";
INT foo (int a, int b) { return a + b; }

// Преобразование строки в wchar
wchar_t* ToWideChar(char* non_wide_str);

// Установка перехвата
int DetourFunction(const char* func_name);

// Отправка информации обратно монитору
void SendInfo(const char* func_name);

// Выполнение настройки и запуск сервера TCP/IP на указанном порту
int StartServer();

// Получение параметров от монитора
int RecieveParameters();

// Закрытие соединения
void CloseConnection();


// Путь к файлу для hide
char hide_file_path[DEFAULT_BUFLEN] = { 0 };
wchar_t* hide_file_path_w;

SYSTEMTIME last_msg_time;

// Параметры
char param[DEFAULT_BUFLEN] = { 0 };

// Для клиент-серверного соединения
WSADATA wsaData;
int iResult;
SOCKET ListenSocket = INVALID_SOCKET;
SOCKET ClientSocket = INVALID_SOCKET;
struct addrinfo* result = NULL;
struct addrinfo hints;
char recvbuf[DEFAULT_BUFLEN];
int recvbuflen = DEFAULT_BUFLEN;


BOOL APIENTRY DllMain(HMODULE hDLL, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    DBGPRINT(L"HELLO\n");
    switch (ul_reason_for_call)
    {
        case DLL_PROCESS_ATTACH:
        {
            // Запуск
            if (StartServer() == 1)
                DBGPRINT(L"start_server() fail");
            // Получение параметров
            if (RecieveParameters() == 1)
                DBGPRINT(L"RecieveParameters() fail");
            
            // Парсинг параметров
            char* token = strtok(param, " ");
            if (strncmp(token, "--func", 6) == 0)
            {
                DBGPRINT(L"--func parameter");
                token = strtok(NULL, " ");

                DisableThreadLibraryCalls(hDLL); // Отключает уведомления DLL_THREAD_ATTACH and DLL_THREAD_DETACH
                funcObserve = token;
                if (DetourFunction(token) == 0)
                    DBGPRINT(L"DetourFunction() success, wait for logs");
                else 
                {
                    DBGPRINT(L"DetourFunction() fail");
                    CloseConnection();
                }
            }
            else if (strncmp(token, "--hide", 6) == 0)
            {
                DBGPRINT(L"--hide parameter");
                token = strtok(NULL, " ");
                
                // сохранение пути к файлу
                strcpy(hide_file_path, token);
                hide_file_path_w = ToWideChar(hide_file_path);
                DBGPRINT(L"Path to hidden file: %s", hide_file_path_w);

                DisableThreadLibraryCalls(hDLL);
                if (DetourFunction("hide") == 0) // "hide" as argument to DetourFunction() detours all functions
                {
                    DBGPRINT(L"DetourFunction() success, wait for logs");
                }
                else
                {
                    DBGPRINT(L"DetourFunction() fail");
                    CloseConnection();
                }
            }
            else
            {
                DBGPRINT(L"no --hide or --func parameter");
            }
            break;
        }
        case DLL_PROCESS_DETACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
    }
    return TRUE;
}

wchar_t* ToWideChar(char* non_wide_str)
{
    int nChars = MultiByteToWideChar(CP_ACP, 0, non_wide_str, -1, NULL, 0);
    wchar_t* wide_str = new wchar_t[nChars];
    MultiByteToWideChar(CP_ACP, 0, non_wide_str, -1, (LPWSTR)wide_str, nChars);
    return wide_str;
}

int StartServer()
{
    // Инициализация Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        DBGPRINT(L"WSAStartup() failed with error: %d\n", iResult);
        return 1;
    }

    // Очистка памяти для структуры hints
    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Определение адреса и порта сервера
    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        DBGPRINT(L"getaddrinfo() failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Создание сокета для прослушивания входящих подключений
    ListenSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (ListenSocket == INVALID_SOCKET) {
        DBGPRINT(L"socket() failed with error: %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // Привязка сокета к адресу и порту
    iResult = bind(ListenSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        DBGPRINT(L"bind() failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);
    // Установка сокета в режим прослушивания входящих соединений
    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        DBGPRINT(L"listen() failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    // Принятие входящего соединения и создание сокета для общения с клиентом
    ClientSocket = accept(ListenSocket, NULL, NULL);
    if (ClientSocket == INVALID_SOCKET) {
        DBGPRINT(L"accept() failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    // Закрытие сокета, предназначенного для прослушивания входящих соединений
    closesocket(ListenSocket);
    return 0;
}

int RecieveParameters()
{
    iResult = recv(ClientSocket, recvbuf, recvbuflen, 0);
    if (iResult > 0)
    {
        DBGPRINT(L"parameters recieved");
    }
    else if (iResult == 0)
    {
        DBGPRINT(L"parameters not recieved, connection closed");
        return 1;
    }
    else
    {
        DBGPRINT(L"recv() failed with error: %d\n", WSAGetLastError());
        closesocket(ClientSocket);
        WSACleanup();
        return 1;
    }

    // копирование результата
    int recv_param_len = iResult;
    strncpy_s(param, DEFAULT_BUFLEN, recvbuf, recv_param_len);
}

void CloseConnection()
{
    iResult = shutdown(ClientSocket, SD_SEND);
    if (iResult == SOCKET_ERROR) {
        DBGPRINT(L"shutdown failed with error: %d\n", WSAGetLastError());
        closesocket(ClientSocket);
        WSACleanup();
    }

    closesocket(ClientSocket);
    WSACleanup();
}



void SendInfo(const char* func_name)
{
    CHAR send_msg[DEFAULT_BUFLEN] = { 0 };
    SYSTEMTIME st;

    GetLocalTime(&st);
    sprintf_s(send_msg, "[dll] %d-%02d-%02d %02d:%02d:%02d:%03d : %s()\n\0", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, func_name);
    // если сообщения передались одновременно
    if (last_msg_time.wYear == st.wYear && last_msg_time.wMonth == st.wMonth && last_msg_time.wDay == st.wDay &&
        last_msg_time.wHour == st.wHour && last_msg_time.wMinute == st.wMinute && last_msg_time.wSecond == st.wSecond)
    {
        if ((st.wMilliseconds - last_msg_time.wMilliseconds) > 200)
        {
            int iSendResult = send(ClientSocket, send_msg, strlen(send_msg) + 1, 0);
            if (iSendResult == SOCKET_ERROR) {
                DBGPRINT(L"Error: Send() failed with error: %d\n", WSAGetLastError());
                closesocket(ClientSocket);
                WSACleanup();
            }
            // Сохранение времени последнего сообщения
            memcpy(&last_msg_time, &st, sizeof(SYSTEMTIME));
            return;
        }
        else
        {
            return;
        }
    }
    else // Последнее сообщение больше секунды назад
    {
        int iSendResult = send(ClientSocket, send_msg, strlen(send_msg) + 1, 0);
        if (iSendResult == SOCKET_ERROR) {
            DBGPRINT(L"Error: Send() failed with error: %d\n", WSAGetLastError());
            closesocket(ClientSocket);
            WSACleanup();
        }
        // Сохранение времени последнего сообщения
        memcpy(&last_msg_time, &st, sizeof(SYSTEMTIME));
        return;
    }

    //static char s[128] = { 0 };
    //if (notparallel)
    //{
    //    notparallel = 0;
    //    printf("detcall\n");
    //    const time_t timer = time(NULL);
    //    memset(s, 0, 128);
    //    int length = strftime(s, 40, "%d.%m.%Y %H:%M:%S, %A", localtime(&timer));                                                               //принтф в стринг из тайм
    //    std::string sendBuffer(s);

    //    sendBuffer += " - " + funcObserve;
    //    send(ClientSocket, sendBuffer.c_str(), sendBuffer.size() + 1, 0);
    //    notparallel = 1;
    //}
}

const char* g_func_name;

extern "C"  VOID detourCallback()
{
    SendInfo(g_func_name);
    //static char s[128] = { 0 };
    //if (notparallel)
    //{
    //    static char s[128] = { 0 };
    //    if (notparallel)
    //    {
    //        notparallel = 0;
    //        printf("detcall\n");
    //        const time_t timer = time(NULL);
    //        memset(s, 0, 128);
    //        int length = strftime(s, 40, "%d.%m.%Y %H:%M:%S, %A", localtime(&timer));                                                               //принтф в стринг из тайм
    //        std::string sendBuffer(s);

    //        sendBuffer += " - " + funcObserve;
    //        send(ClientSocket, sendBuffer.c_str(), sendBuffer.size() + 1, 0);
    //        notparallel = 1;
    //    }
    //    printf("detcall\n");
    //    const time_t timer = time(NULL);
    //    memset(s, 0, 128);
    //    int length = strftime(s, 40, "%d.%m.%Y %H:%M:%S, %A", localtime(&timer));                                                               //принтф в стринг из тайм
    //    std::string sendBuffer(s);

    //    sendBuffer += " - " + funcObserve;
    //    send(ClientSocket, sendBuffer.c_str(), sendBuffer.size() + 1, 0);
    //    notparallel = 1;
    //}
}

HANDLE WINAPI MyCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    SendInfo("CreateFileA");
    if (strcmp(lpFileName, hide_file_path) == 0) {
        return INVALID_HANDLE_VALUE;
    }
    return pCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

HANDLE WINAPI MyCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    SendInfo("CreateFileW");
    if (hide_file_path_w != NULL && wcscmp(lpFileName, hide_file_path_w) == 0) {
        return INVALID_HANDLE_VALUE;
    }
    return pCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

HANDLE WINAPI MyFindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData) {
    SendInfo("FindFirstFileA");
    if (strcmp(lpFileName, hide_file_path) == 0) {
        return INVALID_HANDLE_VALUE;
    }
    return pFindFirstFileA(lpFileName, lpFindFileData);
}

HANDLE WINAPI MyFindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATA lpFindFileData) {
    SendInfo("FindFirstFileW");
    if (hide_file_path_w != NULL && wcscmp(hide_file_path_w, lpFileName) == 0) {
        return INVALID_HANDLE_VALUE;
    }
    return pFindFirstFileW(lpFileName, lpFindFileData);
}

BOOL WINAPI MyFindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData) {
    SendInfo("FindNextFileA");
    bool ret = pFindNextFileA(hFindFile, lpFindFileData);
    if (strcmp(lpFindFileData->cFileName, hide_file_path) == 0) {
        ret = pFindNextFileA(hFindFile, lpFindFileData);
    }
    return ret;
}

BOOL WINAPI MyFindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) {
    DBGPRINT(L"In MyFindFirstFileW, %s", hide_file_path_w);
    SendInfo("FindNextFileW");
    bool ret = pFindNextFileW(hFindFile, lpFindFileData);
    if (hide_file_path_w != NULL && wcscmp(lpFindFileData->cFileName, hide_file_path_w) == 0) {
        DBGPRINT(L"skip!");
        ret = pFindNextFileW(hFindFile, lpFindFileData);
    }
    return ret;
}

//HANDLE WINAPI MyFindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)
//{
//    DBGPRINT(L"In MyFindFirstFileA");
//    SendInfo("FindFirstFileA");
//    if (strcmp(hide_file_path, lpFileName) == 0) // hide
//        return INVALID_HANDLE_VALUE;
//    return pFindFirstFileA(lpFileName, lpFindFileData);
//}
//
//HANDLE WINAPI MyFindFirstFileW(LPCWSTR lpFileName, LPWIN32_FIND_DATAW lpFindFileData)
//{
//    DBGPRINT(L"In MyFindFirstFileW");
//    SendInfo("FindFirstFileW");
//    if (hide_file_path_w != NULL && wcscmp(hide_file_path_w, lpFileName) == 0) // hide
//        return INVALID_HANDLE_VALUE;
//    return pFindFirstFileW(lpFileName, lpFindFileData);
//}
//
//BOOL WINAPI MyFindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)
//{
//    DBGPRINT(L"In MyFindNextFileA");
//    SendInfo("FindNextFileA");
//    if (strcmp(lpFindFileData->cFileName, hide_file_path) == 0) // hide
//        strcpy(lpFindFileData->cFileName, "nonexistent.nonexistent");
//    return pFindNextFileA(hFindFile, lpFindFileData);
//}
//
////BOOL WINAPI MyFindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData)
////{
////    DBGPRINT(L"In MyFindNextFileW");
////    SendInfo("FindNextFileW");
////    if (hide_file_path_w != NULL && wcscmp(lpFindFileData->cFileName, hide_file_path_w) == 0) // hide
////        wcscpy(lpFindFileData->cFileName, L"nonexistent.nonexistent");
////    return pFindNextFileW(hFindFile, lpFindFileData);
////}
//
//BOOL WINAPI MyFindNextFileW(HANDLE hFindFile, LPWIN32_FIND_DATAW lpFindFileData) {
//    DBGPRINT(L"In MyFindNextFileW");
//    SendInfo("FindNextFileW");
//    bool ret = pFindNextFileW(hFindFile, lpFindFileData);
//    if (lpFindFileData->cFileName == hide_file_path_w) {
//        ret = pFindNextFileW(hFindFile, lpFindFileData);
//    }
//    return ret;
//}
//
//HANDLE WINAPI MyCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
//{
//    DBGPRINT(L"In MyCreateFileA");
//    SendInfo("CreateFileA");
//    if (strcmp(lpFileName, hide_file_path) == 0) // hide
//        return INVALID_HANDLE_VALUE;
//    return pCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
//        dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
//}
//
//HANDLE WINAPI MyCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
//{
//    DBGPRINT(L"In MyCreateFileW");
//    SendInfo("CreateFileW");
//    if (hide_file_path_w != NULL && wcscmp(lpFileName, hide_file_path_w) == 0) // hide
//        return INVALID_HANDLE_VALUE;
//    return pCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes,
//        dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
//}
//
BOOL WINAPI MyCloseHandle(HANDLE hObject)
{
    //DBGPRINT(L"In MyCloseHandle");
    SendInfo("CloseHandle");
    return pCloseHandle(hObject);
}

HANDLE MyFindFirstFileExW(LPCWSTR a0, FINDEX_INFO_LEVELS a1, LPWIN32_FIND_DATAW a2, FINDEX_SEARCH_OPS a3, LPVOID a4, DWORD a5) {
    HANDLE ret = pFindFirstFileExW(a0, a1, a2, a3, a4, a5);
    if (a2->cFileName == hide_file_path_w) {
        ret = INVALID_HANDLE_VALUE;
    }
    return ret;
}

HANDLE MyFindFirstFileExA(LPCSTR a0, FINDEX_INFO_LEVELS a1, LPWIN32_FIND_DATAA a2, FINDEX_SEARCH_OPS a3, LPVOID a4, DWORD a5) {
    HANDLE ret = pFindFirstFileExA(a0, a1, a2, a3, a4, a5);
    if (a2->cFileName == hide_file_path) {
        ret = INVALID_HANDLE_VALUE;
    }
    return ret;
}

int DetourFunction(const char* func_name)
{
    if (strncmp(func_name, "hide", 4) != 0) //==func
    {
        g_func_name = func_name;
        // тут как-то сделать для всех функций
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        //dynamicTarget = GetProcAddress(LoadLibrary(L"kernel32.dll"), func_name);
        dynamicTarget = DetourFindFunction((char*)"kernel32.dll", func_name);
        DetourAttach(&(PVOID&)dynamicTarget, hookfunc);
        if (DetourTransactionCommit() == NO_ERROR)
        {
            DBGPRINT(L"FindFirstFileA() detour success");
            return 0;
        }
        else
        {
            DBGPRINT(L"FindFirstFileA() detour fail");
            return 1;
        }
            
    }
    else
    {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)pFindFirstFileA, MyFindFirstFileA);
        if (DetourTransactionCommit() == NO_ERROR)
            DBGPRINT(L"FindFirstFileA() detour success");
        else
            DBGPRINT(L"FindFirstFileA() detour fail");
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)pFindFirstFileW, MyFindFirstFileW);
        if (DetourTransactionCommit() == NO_ERROR)
            DBGPRINT(L"FindFirstFileW() detour success");
        else
            DBGPRINT(L"FindFirstFileW() detour fail");
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)pFindNextFileA, MyFindNextFileA);
        if (DetourTransactionCommit() == NO_ERROR)
            DBGPRINT(L"FindNextFileA() detour success");
        else
            DBGPRINT(L"FindNextFileA() detour fail");
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)pFindNextFileW, MyFindNextFileW);
        if (DetourTransactionCommit() == NO_ERROR)
            DBGPRINT(L"FindNextFileW() detour success");
        else
            DBGPRINT(L"FindNextFileW() detour fail");
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)pCreateFileA, MyCreateFileA);
        if (DetourTransactionCommit() == NO_ERROR)
            DBGPRINT(L"MyCreateFileA() detour success");
        else
            DBGPRINT(L"MyCreateFileA() detour fail");
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)pCreateFileW, MyCreateFileW);
        if (DetourTransactionCommit() == NO_ERROR)
            DBGPRINT(L"MyCreateFileW() detour success");
        else
            DBGPRINT(L"MyCreateFileW() detour fail");
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)pCloseHandle, MyCloseHandle);
        if (DetourTransactionCommit() == NO_ERROR)
            DBGPRINT(L"MyCloseHandle() detour success");
        else
            DBGPRINT(L"MyCloseHandle() detour fail");

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)pFindFirstFileExW, MyFindFirstFileExW);
        if (DetourTransactionCommit() == NO_ERROR)
            DBGPRINT(L"MyCreateFileW() detour success");
        else
            DBGPRINT(L"MyCreateFileW() detour fail");
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)pFindFirstFileExA, MyFindFirstFileExA);
        if (DetourTransactionCommit() == NO_ERROR)
            DBGPRINT(L"MyCloseHandle() detour success");
        else
            DBGPRINT(L"MyCloseHandle() detour fail");
        return 0;
    }
    

    
    //if (strncmp(func_name, "FindFirstFile", 13) == 0)
    //{
    //    // MyFindFirstFileA //

    //    // Начать транзакцию перехвата функции
    //    DetourTransactionBegin();

    //    // Обновить поток для перехвата
    //    DetourUpdateThread(GetCurrentThread());

    //    // Это функция, которая отвечает за подключение целевого API.
    //    // Первый параметр - это указатель на указатель функции, которую нужно обойти.
    //    // Второй - это указатель на функцию, которая будет выполнять функцию обхода.
    //    DetourAttach(&(PVOID&)pFindFirstFileA, MyFindFirstFileA);

    //    // Если транзакция прошла успешно, хук готов к подключению. Запуск.
    //    if (DetourTransactionCommit() == NO_ERROR)
    //        DBGPRINT(L"FindFirstFileA() detour success");
    //    else
    //        DBGPRINT(L"FindFirstFileA() detour fail");

    //    // MyFindFirstFileW //

    //    DetourTransactionBegin();
    //    DetourUpdateThread(GetCurrentThread());
    //    DetourAttach(&(PVOID&)pFindFirstFileW, MyFindFirstFileW);
    //    if (DetourTransactionCommit() == NO_ERROR)
    //        DBGPRINT(L"FindFirstFileW() detour success");
    //    else
    //        DBGPRINT(L"FindFirstFileW() detour fail");
    //    return 0;
    //}
    //else if (strncmp(func_name, "FindNextFile", 12) == 0)
    //{
    //    // MyFindNextFileA //

    //    DetourTransactionBegin();
    //    DetourUpdateThread(GetCurrentThread());
    //    DetourAttach(&(PVOID&)pFindNextFileA, MyFindNextFileA);
    //    if (DetourTransactionCommit() == NO_ERROR)
    //        DBGPRINT(L"FindNextFileA() detour success");
    //    else
    //        DBGPRINT(L"FindNextFileA() detour fail");

    //    // MyFindNextFileW //

    //    DetourTransactionBegin();
    //    DetourUpdateThread(GetCurrentThread());
    //    DetourAttach(&(PVOID&)pFindNextFileW, MyFindNextFileW);
    //    if (DetourTransactionCommit() == NO_ERROR)
    //        DBGPRINT(L"FindNextFileW() detour success");
    //    else
    //        DBGPRINT(L"FindNextFileW() detour fail");
    //    return 0;
    //}
    //else if (strncmp(func_name, "CreateFile", 10) == 0)
    //{

    //    // MyCreateFileA //

    //    DetourTransactionBegin();
    //    DetourUpdateThread(GetCurrentThread());
    //    DetourAttach(&(PVOID&)pCreateFileA, MyCreateFileA);
    //    if (DetourTransactionCommit() == NO_ERROR)
    //        DBGPRINT(L"MyCreateFileA() detour success");
    //    else
    //        DBGPRINT(L"MyCreateFileA() detour fail");

    //    // MyCreateFileW //

    //    DetourTransactionBegin();
    //    DetourUpdateThread(GetCurrentThread());
    //    DetourAttach(&(PVOID&)pCreateFileW, MyCreateFileW);
    //    if (DetourTransactionCommit() == NO_ERROR)
    //        DBGPRINT(L"MyCreateFileW() detour success");
    //    else
    //        DBGPRINT(L"MyCreateFileW() detour fail");
    //    return 0;
    //}
    //else if (strncmp(func_name, "CloseHandle", 11) == 0)
    //{
    //    // MyCloseHandle //

    //    DetourTransactionBegin();
    //    DetourUpdateThread(GetCurrentThread());
    //    DetourAttach(&(PVOID&)pCloseHandle, MyCloseHandle);
    //    if (DetourTransactionCommit() == NO_ERROR)
    //        DBGPRINT(L"MyCloseHandle() detour success");
    //    else
    //        DBGPRINT(L"MyCloseHandle() detour fail");
    //    return 0;
    //}
    //else if (strncmp(func_name, "hide", 4) == 0)
    //{
    //    DetourTransactionBegin();
    //    DetourUpdateThread(GetCurrentThread());
    //    DetourAttach(&(PVOID&)pFindFirstFileA, MyFindFirstFileA);
    //    if (DetourTransactionCommit() == NO_ERROR)
    //        DBGPRINT(L"FindFirstFileA() detour success");
    //    else
    //        DBGPRINT(L"FindFirstFileA() detour fail");
    //    DetourTransactionBegin();
    //    DetourUpdateThread(GetCurrentThread());
    //    DetourAttach(&(PVOID&)pFindFirstFileW, MyFindFirstFileW);
    //    if (DetourTransactionCommit() == NO_ERROR)
    //        DBGPRINT(L"FindFirstFileW() detour success");
    //    else
    //        DBGPRINT(L"FindFirstFileW() detour fail");
    //    DetourTransactionBegin();
    //    DetourUpdateThread(GetCurrentThread());
    //    DetourAttach(&(PVOID&)pFindNextFileA, MyFindNextFileA);
    //    if (DetourTransactionCommit() == NO_ERROR)
    //        DBGPRINT(L"FindNextFileA() detour success");
    //    else
    //        DBGPRINT(L"FindNextFileA() detour fail");
    //    DetourTransactionBegin();
    //    DetourUpdateThread(GetCurrentThread());
    //    DetourAttach(&(PVOID&)pFindNextFileW, MyFindNextFileW);
    //    if (DetourTransactionCommit() == NO_ERROR)
    //        DBGPRINT(L"FindNextFileW() detour success");
    //    else
    //        DBGPRINT(L"FindNextFileW() detour fail");
    //    DetourTransactionBegin();
    //    DetourUpdateThread(GetCurrentThread());
    //    DetourAttach(&(PVOID&)pCreateFileA, MyCreateFileA);
    //    if (DetourTransactionCommit() == NO_ERROR)
    //        DBGPRINT(L"MyCreateFileA() detour success");
    //    else
    //        DBGPRINT(L"MyCreateFileA() detour fail");
    //    DetourTransactionBegin();
    //    DetourUpdateThread(GetCurrentThread());
    //    DetourAttach(&(PVOID&)pCreateFileW, MyCreateFileW);
    //    if (DetourTransactionCommit() == NO_ERROR)
    //        DBGPRINT(L"MyCreateFileW() detour success");
    //    else
    //        DBGPRINT(L"MyCreateFileW() detour fail");
    //    DetourTransactionBegin();
    //    DetourUpdateThread(GetCurrentThread());
    //    DetourAttach(&(PVOID&)pCloseHandle, MyCloseHandle);
    //    if (DetourTransactionCommit() == NO_ERROR)
    //        DBGPRINT(L"MyCloseHandle() detour success");
    //    else
    //        DBGPRINT(L"MyCloseHandle() detour fail");
    //    return 0;
    //}
    //else
    //    return 1;
        
}


VOID _DBGPRINT(LPCWSTR kwszFunction, INT iLineNumber, LPCWSTR kwszDebugFormatString, ...)
{
    INT cbFormatString = 0;
    va_list args;
    PWCHAR wszDebugString = NULL;
    size_t st_Offset = 0;

    va_start(args, kwszDebugFormatString);
    // Вычисление размера форматной строки и выделение памяти под буфер
    cbFormatString = _scwprintf(L"[%s:%d] ", kwszFunction, iLineNumber) * sizeof(WCHAR);
    cbFormatString += _vscwprintf(kwszDebugFormatString, args) * sizeof(WCHAR) + 2;
    wszDebugString = (PWCHAR)_malloca(cbFormatString);

    // Заполнение буфера содержимым форматной строки
    StringCbPrintfW(wszDebugString, cbFormatString, L"[%s:%d] ", kwszFunction, iLineNumber);
    StringCbLengthW(wszDebugString, cbFormatString, &st_Offset);
    StringCbVPrintfW(&wszDebugString[st_Offset / sizeof(WCHAR)], cbFormatString - st_Offset, kwszDebugFormatString, args);

    // Вывод отладочной строки в окно отладки
    OutputDebugStringW(wszDebugString);

    _freea(wszDebugString);  // Освобождение выделенной памяти
    va_end(args); // Завершение работы со списком аргументов
}