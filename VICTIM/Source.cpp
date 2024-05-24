//#include <iostream>
//#include <fstream>
//#include <string>
//
//int main()
//{
//    std::ifstream file("test.txt");
//
//    if (!file.is_open())
//    {
//        std::cerr << "ERROR" << std::endl;
//        return 1;
//    }
//
//    std::string line;
//    while (std::getline(file, line))
//    {
//        std::cout << line << std::endl;
//    }
//
//    file.close();
//
//    return 0;
//}

#include <windows.h>
#include <iostream>
#include <conio.h>

int main() {
    HANDLE hFile;
    DWORD dwBytesRead;
    char buffer[4096];
    while (1)
    {
        _getch();
        // Открываем файл для чтения
        hFile = CreateFile(TEXT("test.txt"), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    }
    
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "Error!" << std::endl;
        return 1;
    }
    //Sleep(5000);
    //_getch();
    // Вызываем функцию ReadFile для чтения из файла
    if (!ReadFile(hFile, buffer, sizeof(buffer), &dwBytesRead, NULL)) {
        std::cerr << "Error" << std::endl;
        CloseHandle(hFile);
        return 1;
    }
    
    //Sleep(500);
   /* ReadFile(hFile, buffer, sizeof(buffer), &dwBytesRead, NULL);
    Sleep(500);
    ReadFile(hFile, buffer, sizeof(buffer), &dwBytesRead, NULL);
    Sleep(500);
    ReadFile(hFile, buffer, sizeof(buffer), &dwBytesRead, NULL);
    Sleep(500);
    ReadFile(hFile, buffer, sizeof(buffer), &dwBytesRead, NULL);
    ReadFile(hFile, buffer, sizeof(buffer), &dwBytesRead, NULL);*/

    // Выводим содержимое файла
    std::cout << "Read " << dwBytesRead << " bytes" << std::endl;
    std::cout.write(buffer, dwBytesRead);
    //_getch();
    // Закрываем файл
    CloseHandle(hFile);
    //_getch();
    return 0;
}
