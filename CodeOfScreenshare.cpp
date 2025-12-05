#include <windows.h>
#include <d3d11.h>
#include <dxgi1_2.h>
#include <iostream>

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")

bool IsWindowBeingCaptured(HWND hwnd)
{
    RECT rect;
    GetClientRect(hwnd, &rect);

    HMONITOR monitor = MonitorFromWindow(hwnd, MONITOR_DEFAULTTONEAREST);

    IDXGIFactory1* factory = nullptr;
    if (FAILED(CreateDXGIFactory1(__uuidof(IDXGIFactory1), (void**)&factory)))
        return false;

    IDXGIAdapter1* adapter = nullptr;
    factory->EnumAdapters1(0, &adapter);

    ID3D11Device* device = nullptr;
    ID3D11DeviceContext* context = nullptr;

    HRESULT hr = D3D11CreateDevice(
        adapter,
        D3D_DRIVER_TYPE_UNKNOWN,
        NULL,
        0,
        NULL,
        0,
        D3D11_SDK_VERSION,
        &device,
        NULL,
        &context
    );

    if (FAILED(hr))
        return false;

    IDXGIOutput* output = nullptr;
    adapter->EnumOutputs(0, &output);

    IDXGIOutput1* output1 = nullptr;
    output->QueryInterface(__uuidof(IDXGIOutput1), (void**)&output1);

    IDXGIOutputDuplication* duplication = nullptr;

    hr = output1->DuplicateOutput(device, &duplication);

    if (hr == DXGI_ERROR_ACCESS_DENIED)
        return true;   // Screen is already being captured by OBS/Zoom/etc.

    return false;
}

int main()
{
    HWND hwnd = GetConsoleWindow();

    while (true)
    {
        system("cls");  // Clear terminal for clean UI

        bool captured = IsWindowBeingCaptured(hwnd);

        std::cout << "=====================================================\n";
        std::cout << "            SCREEN CAPTURE DETECTION LIVE\n";
        std::cout << "=====================================================\n";
        std::cout << "     (Press Q anytime to exit)\n\n";

        if (captured)
            std::cout << "  STATUS:  SCREEN IS BEING CAPTURED\n";
        else
            std::cout << "  STATUS:  NO ACTIVE SCREEN CAPTURE DETECTED\n";

        std::cout << "\nRefreshing every 1 second...\n";
        std::cout << "=====================================================\n";

        // Check for exit key (Q)
        for (int i = 0; i < 10; i++) {
            if (GetAsyncKeyState('Q') & 0x8000) {
                system("cls");
                std::cout << "Exiting...\n";
                return 0;
            }
            Sleep(100);  // 0.1 sec × 10 = 1 sec
        }
    }
}
