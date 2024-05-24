#include "Injector.h"
#include <iostream>

int main(int argc, char* argv[])
{
    // путь до DLL, которая будет инжектиться
    LPCWSTR dll_path = L"D:\\Univer_files\\6sem\\TRSPO\\LAB2\\Dll\\x64\\Release\\Dll.dll";
    Injector injector(dll_path);

    // Проверка прав администратора
    if (!(injector.IsAdmin()))
    {
        std::cout << "Error: Not administrator" << std::endl;
        return 1;
    }
    // Проверка количества аргументов
    if (argc != 5)
    {
        std::cout << "Error: Uncorrect number of arguments" << std::endl;
        injector.Help();
        return 1;
    }

    // Парсинг аргументов
    DWORD PID;
    if (strncmp(argv[1], "--pid", 5) == 0)
    {
        PID = atoi(argv[2]);
        if (strncmp(argv[3], "--func", 6) == 0 || strncmp(argv[3], "--hide", 6) == 0)
        {
            injector.InjectDLL(PID);
            std::cout << "OK: DLL injected to process with PID: " << PID << std::endl;
            injector.SendParameters(argv);
        }
        else
        {
            std::cout << "Error: Wrong arguments" << std::endl;
            injector.Help();
            return 1;
        }
    }
    else if (strncmp(argv[1], "--name", 6) == 0)
    {
        PID = injector.GetPID(argv[2]);
        if (PID == 0) {
            std::cout << "Error: No process with such name " << argv[2] << std::endl;
            return 1;
        }

        if (strncmp(argv[3], "--func", 6) == 0 || strncmp(argv[3], "--hide", 6) == 0)
        {
            injector.InjectDLL(PID);
            std::cout << "OK: DLL injected to process with PID: " << PID << std::endl;
            if (injector.SendParameters(argv) == 1)
                printf("Error: SendParameters() fail");
        }
        else
        {
            std::cout << "Error: Wrong arguments" << std::endl;
            injector.Help();
            return 1;
        }
    }
    else
    {
        std::cout << "Error: Wrong arguments" << std::endl;
        injector.Help();
        return 1;
    }

    return 0;
}