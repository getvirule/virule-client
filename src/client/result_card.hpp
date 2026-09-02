#pragma once
// The minimal native completion card, ported from the VIRULE Admin's QA
// verification result window (browser/native ownership rule): while a
// virule.app page is open the BROWSER owns every visible part of a flow
// and this window never exists. Only when no page is there at completion
// does native VIRULE show this small card with the final outcome. One
// headline, at most one supporting line; click / Escape / Enter dismiss;
// it dismisses itself on a timer. No brand mark, no spinner.

#include <atomic>
#include <string>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace vclient::result_card {

constexpr wchar_t kClassName[] = L"ViruleClientResultWindow";
constexpr UINT kTimerClose = 1;

// The Admin splash's two palettes (dark Graphite / light Fog), resolved
// from the OS AppsUseLightTheme value the same way (missing = dark).
struct Palette {
    COLORREF bg;
    COLORREF line;
    COLORREF word;
    COLORREF muted;
};

inline Palette resolve_palette() {
    bool light = false;
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
            0, KEY_QUERY_VALUE, &key) == ERROR_SUCCESS) {
        DWORD value = 0;
        DWORD size = sizeof(value);
        DWORD type = 0;
        if (RegQueryValueExW(key, L"AppsUseLightTheme", nullptr, &type,
                             reinterpret_cast<BYTE*>(&value), &size) == ERROR_SUCCESS &&
            type == REG_DWORD) {
            light = value != 0;
        }
        RegCloseKey(key);
    }
    if (light) {
        return Palette{ RGB(0xf4, 0xf6, 0xf8), RGB(0xc4, 0xcc, 0xd6),
                        RGB(0x20, 0x25, 0x2b), RGB(0x71, 0x7b, 0x86) };
    }
    return Palette{ RGB(0x19, 0x19, 0x18), RGB(0x2a, 0x2a, 0x28),
                    RGB(0xee, 0xee, 0xec), RGB(0xb4, 0xb2, 0xac) };
}

inline std::atomic<HWND> g_hwnd{ nullptr };
inline HANDLE g_thread = nullptr;
inline UINT g_dpi = 96;          // window thread only
inline Palette g_pal{};
inline std::wstring g_primary;   // written once before the thread starts
inline std::wstring g_secondary;

inline int qsc(int v) { return MulDiv(v, (int)g_dpi, 96); }

inline std::wstring widen_utf8(const std::string& s) {
    if (s.empty()) return L"";
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return L"";
    std::wstring out((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), out.data(), n);
    return out;
}

inline void paint(HWND hwnd) {
    PAINTSTRUCT ps;
    HDC dc = BeginPaint(hwnd, &ps);
    RECT rc;
    GetClientRect(hwnd, &rc);
    const int w = rc.right, h = rc.bottom;

    HDC mem = CreateCompatibleDC(dc);
    HBITMAP bmp = CreateCompatibleBitmap(dc, w, h);
    HGDIOBJ old_bmp = SelectObject(mem, bmp);

    {
        HBRUSH b = CreateSolidBrush(g_pal.bg);
        FillRect(mem, &rc, b);
        DeleteObject(b);
    }
    {
        HPEN pen = CreatePen(PS_SOLID, 1, g_pal.line);
        HGDIOBJ old_pen = SelectObject(mem, pen);
        HGDIOBJ old_br = SelectObject(mem, GetStockObject(HOLLOW_BRUSH));
        RoundRect(mem, 0, 0, w - 1, h - 1, qsc(14), qsc(14));
        SelectObject(mem, old_br);
        SelectObject(mem, old_pen);
        DeleteObject(pen);
    }

    SetBkMode(mem, TRANSPARENT);

    {
        HFONT f = CreateFontW(-qsc(13), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                              CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        HGDIOBJ old_f = SelectObject(mem, f);
        SetTextColor(mem, g_pal.word);
        RECT tr = g_secondary.empty()
            ? RECT{ qsc(20), 0, w - qsc(20), h - qsc(10) }
            : RECT{ qsc(20), qsc(38), w - qsc(20), qsc(60) };
        DrawTextW(mem, g_primary.c_str(), (int)g_primary.size(), &tr,
                  DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        SelectObject(mem, old_f);
        DeleteObject(f);
    }
    if (!g_secondary.empty()) {
        HFONT f = CreateFontW(-qsc(11), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                              CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        HGDIOBJ old_f = SelectObject(mem, f);
        SetTextColor(mem, g_pal.muted);
        RECT sr{ qsc(24), qsc(68), w - qsc(24), h - qsc(20) };
        DrawTextW(mem, g_secondary.c_str(), (int)g_secondary.size(), &sr,
                  DT_CENTER | DT_WORDBREAK | DT_END_ELLIPSIS);
        SelectObject(mem, old_f);
        DeleteObject(f);
    }

    BitBlt(dc, 0, 0, w, h, mem, 0, 0, SRCCOPY);
    SelectObject(mem, old_bmp);
    DeleteObject(bmp);
    DeleteDC(mem);
    EndPaint(hwnd, &ps);
}

inline LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE:
        SetTimer(hwnd, kTimerClose, 10000, nullptr);
        return 0;
    case WM_TIMER:
        if (wp == kTimerClose) DestroyWindow(hwnd);
        return 0;
    case WM_LBUTTONUP:
        DestroyWindow(hwnd);
        return 0;
    case WM_KEYDOWN:
        if (wp == VK_ESCAPE || wp == VK_RETURN) DestroyWindow(hwnd);
        return 0;
    case WM_PAINT:
        paint(hwnd);
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_DESTROY:
        KillTimer(hwnd, kTimerClose);
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

inline DWORD WINAPI thread_main(LPVOID) {
    HINSTANCE inst = GetModuleHandleW(nullptr);
    g_pal = resolve_palette();
    if (HMODULE user32 = GetModuleHandleW(L"user32.dll")) {
        using GetDpiFn = UINT(WINAPI*)();
        if (auto fn = (GetDpiFn)GetProcAddress(user32, "GetDpiForSystem")) g_dpi = fn();
    }
    WNDCLASSW wc{};
    wc.lpfnWndProc = wnd_proc;
    wc.hInstance = inst;
    wc.lpszClassName = kClassName;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hIcon = LoadIconW(inst, MAKEINTRESOURCEW(1));
    if (!RegisterClassW(&wc)) return 0;

    const int w = qsc(320), h = qsc(150);
    RECT work{ 0, 0, 0, 0 };
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    const int x = work.left + ((work.right - work.left) - w) / 2;
    const int y = work.top + ((work.bottom - work.top) - h) / 2;

    HWND hwnd = CreateWindowExW(0, kClassName, L"VIRULE", WS_POPUP,
                                x, y, w, h, nullptr, nullptr, inst, nullptr);
    if (!hwnd) return 0;
    SetWindowRgn(hwnd, CreateRoundRectRgn(0, 0, w + 1, h + 1, qsc(14), qsc(14)), TRUE);
    g_hwnd.store(hwnd);
    // This card only exists when no page is left to show the outcome, so
    // it must reach the FOREGROUND even though this process was spawned
    // from the background: attach to the foreground thread for the
    // switch, then a topmost pulse so the card surfaces without staying
    // topmost.
    ShowWindow(hwnd, SW_SHOW);
    if (HWND fg = GetForegroundWindow()) {
        const DWORD fg_tid = GetWindowThreadProcessId(fg, nullptr);
        const DWORD my_tid = GetCurrentThreadId();
        if (fg_tid != my_tid && AttachThreadInput(my_tid, fg_tid, TRUE)) {
            SetForegroundWindow(hwnd);
            BringWindowToTop(hwnd);
            AttachThreadInput(my_tid, fg_tid, FALSE);
        } else {
            SetForegroundWindow(hwnd);
        }
    } else {
        SetForegroundWindow(hwnd);
    }
    SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0,
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    g_hwnd.store(nullptr);
    return 0;
}

// Show the final outcome. Only called when no page is open to show it.
inline void show(const std::string& primary_utf8, const std::string& secondary_utf8) {
    if (g_thread) return;
    g_primary = widen_utf8(primary_utf8);
    g_secondary = widen_utf8(secondary_utf8);
    g_thread = CreateThread(nullptr, 0, thread_main, nullptr, 0, nullptr);
}

// Blocks until the window closes itself (timer, click or key).
inline void wait_closed() {
    if (!g_thread) return;
    WaitForSingleObject(g_thread, 30000);
    CloseHandle(g_thread);
    g_thread = nullptr;
}

} // namespace vclient::result_card
