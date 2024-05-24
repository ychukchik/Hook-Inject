#include "Injector.h"

#define WIN32_LEAN_AND_MEAN
#define DEFAULT_BUFLEN 512
#define DEFAULT_PORT "27015"

Injector::Injector(LPCWSTR path)
	: dll_path(path)
{
}

Injector::~Injector()
{
}

bool Injector::IsAdmin()
{
    return IsUserAnAdmin();
}

void Injector::Help()
{
    std::cout << "Usage:" << std::endl;
    std::cout << "injector_proj.exe --pid <pid> --func <func_name>" << std::endl;
    std::cout << "injector_proj.exe --pid <pid> --hide <path_to_file>" << std::endl;
    std::cout << "injector_proj.exe --name <proc_name> --func <func_name>" << std::endl;
    std::cout << "injector_proj.exe --name <proc_name> --hide <path_to_file>" << std::endl;
}

int Injector::GetPID(const char* proc_name)
{
    PROCESSENTRY32 proc_info; // структура для содержания сведений о процессе, таких как имя исполняемого файла,
                              // идентификатор процесса и идентификатор родительского процесса.
    proc_info.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); // «снимок» всех процессов в системе

    if (TRUE == Process32First(snapshot, &proc_info)) //извлечение сведений о процессе
    {
        while (TRUE == Process32Next(snapshot, &proc_info))
        {
            // преобразование строки в широкий формат
            int nChars = MultiByteToWideChar(CP_ACP, 0, proc_name, -1, NULL, 0);
            wchar_t* proc_name_wchar = new wchar_t[nChars];
            MultiByteToWideChar(CP_ACP, 0, proc_name, -1, (LPWSTR)proc_name_wchar, nChars);
            if (wcscmp(proc_info.szExeFile, proc_name_wchar) == 0) // поиск процесса
            {
                delete[] proc_name_wchar;
                return proc_info.th32ProcessID;
            }
            delete[] proc_name_wchar;
        }
    }
    return 0;
}

void Injector::InjectDLL(DWORD PID)
{
    // Получение дескриптора запущенного процесса
    HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, PID);
    if (process_handle == NULL)
    {
        printf("OpenProcess() fail\n");
    }

    // Расчет байтов, которые необходимо выделить на имя нашей библиотеки.
    int bytes_to_alloc = (1 + lstrlenW(dll_path)) * sizeof(WCHAR);

    // Резервирует состояние области памяти в виртуальном адресном пространстве указанного процесса. Функция инициализирует выделяемую память равным нулю.
    LPWSTR remoteBufferForLibraryPath = LPWSTR(VirtualAllocEx(process_handle, NULL, bytes_to_alloc, MEM_COMMIT, PAGE_READWRITE));

    // Записывает данные в область памяти в указанном процессе
    WriteProcessMemory(process_handle, remoteBufferForLibraryPath, dll_path, bytes_to_alloc, NULL);

    // Извлекает адрес экспортированной функции или переменной из указанной библиотеки динамических ссылок (DLL).
    PTHREAD_START_ROUTINE loadLibraryFunction = PTHREAD_START_ROUTINE(GetProcAddress(GetModuleHandleW(L"Kernel32"), "LoadLibraryW"));

    // Создает поток, который выполняется в виртуальном адресном пространстве другого процесса.
    HANDLE remoteThreadHandle = CreateRemoteThread(process_handle, NULL, 0, loadLibraryFunction, remoteBufferForLibraryPath, 0, NULL);

    if (remoteThreadHandle == NULL)
    {
        printf("Error: CreateRemoteThread failed. Line = %d, GetLastError = %d\n", __LINE__, GetLastError());
    }
}

int Injector::SendParameters(char* argv[])
{
    WSADATA wsaData;
    SOCKET ConnectSocket = INVALID_SOCKET;
    struct addrinfo* result = NULL, * ptr = NULL, hints;
    char recvbuf[DEFAULT_BUFLEN];
    int iResult;
    int recvbuflen = DEFAULT_BUFLEN;
    char* sendbuf = (char*)calloc(DEFAULT_BUFLEN, sizeof(char));

    // Копирование аргументов в sendbuf
    strcat_s(sendbuf, DEFAULT_BUFLEN, argv[3]);
    strcat_s(sendbuf, DEFAULT_BUFLEN, " ");
    strcat_s(sendbuf, DEFAULT_BUFLEN, argv[4]);

    // Инициализация библиотеки Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0)
    {
        printf("Error: WSAStartup failed with error: %d\n", iResult);
        return 1;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Получение адреса и порта сервера
    iResult = getaddrinfo("localhost", DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        printf("Error: Getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Подключение к адресу, пока не получится
    for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
    {
        // Создание SOCKET для соединения с сервером
        ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (ConnectSocket == INVALID_SOCKET)
        {
            printf("Error: Socket failed with error: %ld\n", WSAGetLastError());
            WSACleanup();
            return 1;
        }

        // Соединение с сервером
        iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
        if (iResult == SOCKET_ERROR) {
            closesocket(ConnectSocket);
            ConnectSocket = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        printf("Error: Unable to connect to server\n");
        WSACleanup();
        return 1;
    }

    // Отправка данных из аргументов
    iResult = send(ConnectSocket, sendbuf, (int)strlen(sendbuf), 0);
    if (iResult == SOCKET_ERROR) {
        printf("Error: Send failed with error: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    // Завершение подключения
    iResult = shutdown(ConnectSocket, SD_SEND);
    if (iResult == SOCKET_ERROR)
    {
        printf("Error: Shutdown failed with error: %d\n", WSAGetLastError());
        closesocket(ConnectSocket);
        WSACleanup();
        return 1;
    }

    // Принимать до тех пор, пока узел не закроет соединение
    std::cout << "Waiting for server messages..." << std::endl;
    do {

        iResult = recv(ConnectSocket, recvbuf, recvbuflen, 0);
        if (iResult > 0)
            printf(recvbuf);
        else if (iResult == 0)
            printf("Connection closed\n");
        else
            printf("Error: Recv failed with error: %d\n", WSAGetLastError());

    } while (iResult > 0);

    // Очистка
    closesocket(ConnectSocket);
    WSACleanup();

    return 0;
}