#pragma once
// The ONE small native surface Virule-Setup.exe shows.
//
// Setup used to run and vanish with no window at all. Technically correct
// (the browser owns the flow) and, in practice, untrustworthy: a downloaded
// executable that flashes and disappears reads as nothing happened. So Setup
// now says exactly what it is doing, in VIRULE's own native visual language
// (the Admin splash / QA result card grammar: rounded dark card, yellow V
// mark, spaced wordmark, one muted line), and nothing more.
//
// NOT A WIZARD. No pages, no Next/Back, no destination picker, no component
// list, no license page, no technical terminology, no user choices of any
// kind. Three states, one line of copy each:
//
//   Working    "Setting up VIRULE..."   + a subtle indeterminate bar
//   Complete   "Setup is complete."     briefly, then the window closes
//   Failed     one short human sentence; the technical reason goes to the
//              log, never here
//
// The copy never says "return to your browser": by the time Setup finishes
// the browser may be closed, and recovering that is Setup's job, not the
// user's. Layout is fixed: the status line sits at the same coordinates in
// every state, so moving between them never shifts anything.

#include <atomic>
#include <mutex>
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

namespace vclient::setup_window {

constexpr wchar_t kClassName[] = L"ViruleSetupWindow";
constexpr UINT kTimerAnim = 1;      // indeterminate bar
constexpr UINT kTimerLife = 2;      // a failure surface never sits forever
constexpr UINT kMsgRefresh = WM_APP + 1;
constexpr UINT kMsgClose = WM_APP + 2;

// A failed Setup stays readable, then leaves on its own.
constexpr UINT kFailureLifeMs = 60000;

enum class Stage { Working, Complete, Failed };

// The Admin splash palettes (dark Graphite / light Fog), resolved from the
// OS AppsUseLightTheme value exactly as result_card.hpp resolves them.
struct Palette {
    COLORREF bg;
    COLORREF line;
    COLORREF accent;
    COLORREF ink;     // on the accent mark
    COLORREF word;
    COLORREF muted;
};

inline Palette resolve_palette() {
    bool light = false;
    HKEY key = nullptr;
    if (RegOpenKeyExW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize",
            0, KEY_QUERY_VALUE, &key) == ERROR_SUCCESS) {
        DWORD value = 0, type = 0, cb = sizeof(value);
        if (RegQueryValueExW(key, L"AppsUseLightTheme", nullptr, &type,
                             reinterpret_cast<BYTE*>(&value), &cb) == ERROR_SUCCESS &&
            type == REG_DWORD) {
            light = value != 0;
        }
        RegCloseKey(key);
    }
    if (light) {
        return Palette{ RGB(0xf4, 0xf6, 0xf8), RGB(0xc4, 0xcc, 0xd6),
                        RGB(0xfb, 0xbf, 0x24), RGB(0x0f, 0x0e, 0x0a),
                        RGB(0x20, 0x25, 0x2b), RGB(0x71, 0x7b, 0x86) };
    }
    return Palette{ RGB(0x19, 0x19, 0x18), RGB(0x2a, 0x2a, 0x28),
                    RGB(0xfb, 0xbf, 0x24), RGB(0x1a, 0x15, 0x03),
                    RGB(0xee, 0xee, 0xec), RGB(0xb4, 0xb2, 0xac) };
}

inline std::atomic<HWND> g_hwnd{ nullptr };
inline HANDLE g_thread = nullptr;
inline UINT g_dpi = 96;               // window thread only
inline Palette g_pal{};
inline std::atomic<int> g_stage{ (int)Stage::Working };
inline std::atomic<int> g_phase{ 0 }; // indeterminate bar position, 0..999
inline std::mutex g_line_mutex;
inline std::wstring g_line = L"Setting up VIRULE...";

inline int sc(int v) { return MulDiv(v, (int)g_dpi, 96); }

inline std::wstring current_line() {
    std::lock_guard<std::mutex> lock(g_line_mutex);
    return g_line;
}

inline void paint(HWND hwnd) {
    PAINTSTRUCT ps;
    HDC dc = BeginPaint(hwnd, &ps);
    RECT rc;
    GetClientRect(hwnd, &rc);
    const int w = rc.right, h = rc.bottom;

    // Double-buffered GDI: the whole card is drawn offscreen.
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
        RoundRect(mem, 0, 0, w - 1, h - 1, sc(14), sc(14));
        SelectObject(mem, old_br);
        SelectObject(mem, old_pen);
        DeleteObject(pen);
    }

    SetBkMode(mem, TRANSPARENT);

    // Yellow V mark (the Admin titlebar / splash mark).
    const int mark = sc(44);
    const int mark_x = (w - mark) / 2;
    const int mark_y = sc(30);
    {
        HBRUSH b = CreateSolidBrush(g_pal.accent);
        HGDIOBJ old_pen = SelectObject(mem, GetStockObject(NULL_PEN));
        HGDIOBJ old_br = SelectObject(mem, b);
        RoundRect(mem, mark_x, mark_y, mark_x + mark, mark_y + mark, sc(12), sc(12));
        SelectObject(mem, old_br);
        SelectObject(mem, old_pen);
        DeleteObject(b);
    }
    {
        HFONT f = CreateFontW(-sc(24), 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                              CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        HGDIOBJ old_f = SelectObject(mem, f);
        SetTextColor(mem, g_pal.ink);
        RECT mr{ mark_x, mark_y, mark_x + mark, mark_y + mark };
        DrawTextW(mem, L"V", 1, &mr, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        SelectObject(mem, old_f);
        DeleteObject(f);
    }

    // Wordmark. Measured TextOut, not DrawText(DT_CENTER): letter spacing is
    // invisible to DrawText's centering math (the Admin splash's finding).
    {
        HFONT f = CreateFontW(-sc(15), 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                              CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        HGDIOBJ old_f = SelectObject(mem, f);
        SetTextColor(mem, g_pal.word);
        const int extra = sc(4);
        const wchar_t word[] = L"VIRULE";
        const int word_len = (int)(sizeof(word) / sizeof(word[0])) - 1;
        SIZE sz{};
        GetTextExtentPoint32W(mem, word, word_len, &sz);
        const int total_w = sz.cx + extra * (word_len - 1);
        SetTextCharacterExtra(mem, extra);
        TextOutW(mem, (w - total_w) / 2, mark_y + mark + sc(14), word, word_len);
        SetTextCharacterExtra(mem, 0);
        SelectObject(mem, old_f);
        DeleteObject(f);
    }

    // The subtle activity treatment: one thin indeterminate bar, the same
    // language the browser's "Installing VIRULE..." view uses. It exists
    // only while work is happening; no invented percentages, ever.
    if ((Stage)g_stage.load() == Stage::Working) {
        const int bar_w = sc(168);
        const int bar_h = sc(3);
        const int bar_x = (w - bar_w) / 2;
        const int bar_y = sc(130);
        {
            HBRUSH b = CreateSolidBrush(g_pal.line);
            RECT track{ bar_x, bar_y, bar_x + bar_w, bar_y + bar_h };
            FillRect(mem, &track, b);
            DeleteObject(b);
        }
        {
            // A 40%-wide segment sliding across, clipped to the track.
            const int seg_w = bar_w * 2 / 5;
            const int span = bar_w + seg_w;
            const int pos = bar_x - seg_w + (int)((long long)span * g_phase.load() / 1000);
            int left = pos, right = pos + seg_w;
            if (left < bar_x) left = bar_x;
            if (right > bar_x + bar_w) right = bar_x + bar_w;
            if (right > left) {
                HBRUSH b = CreateSolidBrush(g_pal.accent);
                RECT seg{ left, bar_y, right, bar_y + bar_h };
                FillRect(mem, &seg, b);
                DeleteObject(b);
            }
        }
    }

    // The status line. Fixed top edge in EVERY state, so the states never
    // shift each other; up to two lines for a failure sentence.
    {
        const std::wstring line = current_line();
        HFONT f = CreateFontW(-sc(11), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                              CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        HGDIOBJ old_f = SelectObject(mem, f);
        SetTextColor(mem, g_pal.muted);
        RECT tr{ sc(26), sc(152), w - sc(26), h - sc(14) };
        DrawTextW(mem, line.c_str(), (int)line.size(), &tr,
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
        SetTimer(hwnd, kTimerAnim, 33, nullptr);
        return 0;
    case WM_TIMER:
        if (wp == kTimerAnim) {
            if ((Stage)g_stage.load() == Stage::Working) {
                g_phase.store((g_phase.load() + 14) % 1000);
                InvalidateRect(hwnd, nullptr, FALSE);
            }
        } else if (wp == kTimerLife) {
            DestroyWindow(hwnd);
        }
        return 0;
    case kMsgRefresh:
        if ((Stage)g_stage.load() == Stage::Failed) {
            // Readable, then gone on its own. Setup never sits open forever.
            SetTimer(hwnd, kTimerLife, kFailureLifeMs, nullptr);
        }
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    case kMsgClose:
        DestroyWindow(hwnd);
        return 0;
    case WM_LBUTTONUP:
    case WM_KEYDOWN:
        // Only a finished (failed) surface is dismissible: a click must
        // never cancel an install in progress.
        if ((Stage)g_stage.load() == Stage::Failed) {
            if (msg == WM_LBUTTONUP || wp == VK_ESCAPE || wp == VK_RETURN) {
                DestroyWindow(hwnd);
            }
        }
        return 0;
    case WM_PAINT:
        paint(hwnd);
        return 0;
    case WM_ERASEBKGND:
        return 1; // fully painted in WM_PAINT (no flicker)
    case WM_DESTROY:
        KillTimer(hwnd, kTimerAnim);
        KillTimer(hwnd, kTimerLife);
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
    if (!RegisterClassW(&wc)) return 0;

    const int w = sc(340), h = sc(200);
    RECT work{ 0, 0, 0, 0 };
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    const int x = work.left + ((work.right - work.left) - w) / 2;
    const int y = work.top + ((work.bottom - work.top) - h) / 2;

    HWND hwnd = CreateWindowExW(0, kClassName, L"VIRULE Setup", WS_POPUP,
                                x, y, w, h, nullptr, nullptr, inst, nullptr);
    if (!hwnd) return 0;
    SetWindowRgn(hwnd, CreateRoundRectRgn(0, 0, w + 1, h + 1, sc(14), sc(14)), TRUE);
    g_hwnd.store(hwnd);
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    g_hwnd.store(nullptr);
    return 0;
}

// Show the working surface. Safe to call once; later calls are ignored.
inline void show() {
    if (g_thread) return;
    g_thread = CreateThread(nullptr, 0, thread_main, nullptr, 0, nullptr);
}

inline void set_state(Stage stage, const std::wstring& line) {
    {
        std::lock_guard<std::mutex> lock(g_line_mutex);
        g_line = line;
    }
    g_stage.store((int)stage);
    if (HWND hwnd = g_hwnd.load()) PostMessageW(hwnd, kMsgRefresh, 0, 0);
}

inline void set_complete() { set_state(Stage::Complete, L"Setup is complete."); }

// One short, human, non-technical sentence. The reason belongs in the log.
inline void set_failed(const std::wstring& human_line) {
    set_state(Stage::Failed, human_line);
}

inline void close() {
    if (HWND hwnd = g_hwnd.load()) PostMessageW(hwnd, kMsgClose, 0, 0);
    if (g_thread) {
        WaitForSingleObject(g_thread, 3000);
        CloseHandle(g_thread);
        g_thread = nullptr;
    }
}

// Wait for the user (or the life timer) to dismiss a failure surface.
inline void wait_closed(DWORD timeout_ms) {
    if (!g_thread) return;
    WaitForSingleObject(g_thread, timeout_ms);
    CloseHandle(g_thread);
    g_thread = nullptr;
}

} // namespace vclient::setup_window
