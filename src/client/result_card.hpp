#pragma once
// The minimal native card, ported from the VIRULE Admin's QA verification
// result window (browser/native ownership rule): while a virule.app page is
// open the BROWSER owns every visible part of a flow and this window never
// exists. Only when no page is there does native VIRULE show this small
// card. One headline, at most one supporting line. No brand mark.
//
// Three modes (the bootstrap/handoff pass, 2026-09-03):
//
//   Result   the final outcome. Click / Escape / Enter dismiss; it
//            dismisses itself on a timer. (The original card.)
//   Working  a continuation surface shown WHILE the client completes an
//            operation the browser can no longer watch ("Finishing setup
//            for [Game]", "Installing VIRULE..."): the Setup card's subtle
//            indeterminate bar, not dismissible, no auto-close; it becomes
//            a Result via update().
//   Ready    the standalone completion surface for a Setup run with no
//            recoverable browser intent: "VIRULE is ready" over "Continue
//            at virule.app to get started." and ONE explicit
//            [ Open virule.app ] action. Nothing opens a browser except
//            that click.
//
// The card is the "next visible feedback surface" the ownership invariant
// requires before Virule-Setup is allowed to close, so takeover code waits
// on is_visible() before releasing Setup.

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
#include <windowsx.h>
#include <shellapi.h>
#pragma comment(lib, "shell32.lib")
#endif

namespace vclient::result_card {

constexpr wchar_t kClassName[] = L"ViruleClientResultWindow";
constexpr UINT kTimerClose = 1;
constexpr UINT kTimerAnim = 2;
constexpr UINT kMsgRefresh = WM_APP + 1;
constexpr UINT kMsgClose = WM_APP + 2;

// The one URL the Ready card's explicit action opens. Compile-time
// constant; the card never opens anything else.
constexpr wchar_t kSiteUrl[] = L"https://virule.app/";

enum class Mode { Result, Working, Ready };

// The Admin splash's two palettes (dark Graphite / light Fog), resolved
// from the OS AppsUseLightTheme value the same way (missing = dark).
struct Palette {
    COLORREF bg;
    COLORREF line;
    COLORREF word;
    COLORREF muted;
    COLORREF accent;
    COLORREF accent_ink;
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
                        RGB(0x20, 0x25, 0x2b), RGB(0x71, 0x7b, 0x86),
                        RGB(0xfb, 0xbf, 0x24), RGB(0x0f, 0x0e, 0x0a) };
    }
    return Palette{ RGB(0x19, 0x19, 0x18), RGB(0x2a, 0x2a, 0x28),
                    RGB(0xee, 0xee, 0xec), RGB(0xb4, 0xb2, 0xac),
                    RGB(0xfb, 0xbf, 0x24), RGB(0x1a, 0x15, 0x03) };
}

inline std::atomic<HWND> g_hwnd{ nullptr };
inline HANDLE g_thread = nullptr;
inline UINT g_dpi = 96;          // window thread only
inline Palette g_pal{};
inline std::atomic<int> g_mode{ (int)Mode::Result };
inline std::atomic<int> g_phase{ 0 }; // indeterminate bar position, 0..999
inline std::mutex g_text_mutex;
inline std::wstring g_primary;
inline std::wstring g_secondary;
inline RECT g_button{};          // Ready mode; window thread only

inline int qsc(int v) { return MulDiv(v, (int)g_dpi, 96); }

inline std::wstring widen_utf8(const std::string& s) {
    if (s.empty()) return L"";
    const int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    if (n <= 0) return L"";
    std::wstring out((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), out.data(), n);
    return out;
}

inline void open_site() {
    ShellExecuteW(nullptr, L"open", kSiteUrl, nullptr, nullptr, SW_SHOWNORMAL);
}

inline void paint(HWND hwnd) {
    PAINTSTRUCT ps;
    HDC dc = BeginPaint(hwnd, &ps);
    RECT rc;
    GetClientRect(hwnd, &rc);
    const int w = rc.right, h = rc.bottom;
    const Mode mode = (Mode)g_mode.load();
    std::wstring primary, secondary;
    {
        std::lock_guard<std::mutex> lock(g_text_mutex);
        primary = g_primary;
        secondary = g_secondary;
    }

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

    // Layout: Result keeps the original geometry; Working and Ready anchor
    // the headline higher to make room for the bar / the action button.
    const bool tall = mode != Mode::Result || !secondary.empty();
    {
        HFONT f = CreateFontW(-qsc(13), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                              CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        HGDIOBJ old_f = SelectObject(mem, f);
        SetTextColor(mem, g_pal.word);
        RECT tr = tall
            ? RECT{ qsc(20), qsc(34), w - qsc(20), qsc(56) }
            : RECT{ qsc(20), 0, w - qsc(20), h - qsc(10) };
        DrawTextW(mem, primary.c_str(), (int)primary.size(), &tr,
                  DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        SelectObject(mem, old_f);
        DeleteObject(f);
    }
    if (!secondary.empty()) {
        HFONT f = CreateFontW(-qsc(11), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                              CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        HGDIOBJ old_f = SelectObject(mem, f);
        SetTextColor(mem, g_pal.muted);
        RECT sr{ qsc(24), qsc(62), w - qsc(24),
                 mode == Mode::Ready ? qsc(90) : h - qsc(20) };
        DrawTextW(mem, secondary.c_str(), (int)secondary.size(), &sr,
                  DT_CENTER | DT_WORDBREAK | DT_END_ELLIPSIS);
        SelectObject(mem, old_f);
        DeleteObject(f);
    }

    if (mode == Mode::Working) {
        // The Setup card's subtle indeterminate bar: work is happening; no
        // invented percentages, ever.
        const int bar_w = qsc(168);
        const int bar_h = qsc(3);
        const int bar_x = (w - bar_w) / 2;
        const int bar_y = h - qsc(34);
        {
            HBRUSH b = CreateSolidBrush(g_pal.line);
            RECT track{ bar_x, bar_y, bar_x + bar_w, bar_y + bar_h };
            FillRect(mem, &track, b);
            DeleteObject(b);
        }
        {
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

    if (mode == Mode::Ready) {
        // The ONE explicit action. Accent button, VIRULE's native grammar.
        HFONT f = CreateFontW(-qsc(12), 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                              CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
        HGDIOBJ old_f = SelectObject(mem, f);
        const wchar_t label[] = L"Open virule.app";
        const int label_len = (int)(sizeof(label) / sizeof(label[0])) - 1;
        SIZE sz{};
        GetTextExtentPoint32W(mem, label, label_len, &sz);
        const int bw = sz.cx + qsc(44);
        const int bh = qsc(32);
        const int bx = (w - bw) / 2;
        const int by = h - qsc(24) - bh;
        g_button = RECT{ bx, by, bx + bw, by + bh };
        {
            HBRUSH b = CreateSolidBrush(g_pal.accent);
            HGDIOBJ old_pen = SelectObject(mem, GetStockObject(NULL_PEN));
            HGDIOBJ old_br = SelectObject(mem, b);
            RoundRect(mem, bx, by, bx + bw, by + bh, qsc(8), qsc(8));
            SelectObject(mem, old_br);
            SelectObject(mem, old_pen);
            DeleteObject(b);
        }
        SetTextColor(mem, g_pal.accent_ink);
        RECT br{ bx, by, bx + bw, by + bh };
        DrawTextW(mem, label, label_len, &br,
                  DT_CENTER | DT_VCENTER | DT_SINGLELINE);
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
        // Result auto-closes quickly. Ready stays long enough to actually
        // use (still bounded: this window never sits open forever).
        // Working never auto-closes; update() arms the timer when the
        // outcome lands.
        if ((Mode)g_mode.load() == Mode::Result) {
            SetTimer(hwnd, kTimerClose, 10000, nullptr);
        } else if ((Mode)g_mode.load() == Mode::Ready) {
            SetTimer(hwnd, kTimerClose, 120000, nullptr);
        }
        return 0;
    case WM_TIMER:
        if (wp == kTimerClose) {
            DestroyWindow(hwnd);
        } else if (wp == kTimerAnim) {
            if ((Mode)g_mode.load() == Mode::Working) {
                g_phase.store((g_phase.load() + 14) % 1000);
                InvalidateRect(hwnd, nullptr, FALSE);
            }
        }
        return 0;
    case kMsgRefresh:
        if ((Mode)g_mode.load() == Mode::Result) {
            // A Working card just received its outcome: dismissible now,
            // and it dismisses itself like any result.
            SetTimer(hwnd, kTimerClose, 10000, nullptr);
        }
        InvalidateRect(hwnd, nullptr, FALSE);
        return 0;
    case kMsgClose:
        DestroyWindow(hwnd);
        return 0;
    case WM_LBUTTONUP: {
        const Mode mode = (Mode)g_mode.load();
        if (mode == Mode::Ready) {
            POINT pt{ GET_X_LPARAM(lp), GET_Y_LPARAM(lp) };
            if (PtInRect(&g_button, pt)) {
                open_site();
                DestroyWindow(hwnd);
            }
        } else if (mode == Mode::Result) {
            DestroyWindow(hwnd);
        }
        return 0;
    }
    case WM_KEYDOWN: {
        const Mode mode = (Mode)g_mode.load();
        if (mode == Mode::Ready) {
            if (wp == VK_RETURN) {
                open_site();
                DestroyWindow(hwnd);
            } else if (wp == VK_ESCAPE) {
                DestroyWindow(hwnd);
            }
        } else if (mode == Mode::Result &&
                   (wp == VK_ESCAPE || wp == VK_RETURN)) {
            DestroyWindow(hwnd);
        }
        return 0;
    }
    case WM_PAINT:
        paint(hwnd);
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_DESTROY:
        KillTimer(hwnd, kTimerClose);
        KillTimer(hwnd, kTimerAnim);
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

    const Mode mode = (Mode)g_mode.load();
    const int w = qsc(320);
    const int h = mode == Mode::Ready ? qsc(176)
                : mode == Mode::Working ? qsc(150)
                : qsc(150);
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

inline void start_thread(Mode mode, const std::string& primary_utf8,
                         const std::string& secondary_utf8) {
    if (g_thread) return;
    {
        std::lock_guard<std::mutex> lock(g_text_mutex);
        g_primary = widen_utf8(primary_utf8);
        g_secondary = widen_utf8(secondary_utf8);
    }
    g_mode.store((int)mode);
    g_thread = CreateThread(nullptr, 0, thread_main, nullptr, 0, nullptr);
}

// Show the final outcome. Only called when no page is open to show it.
inline void show(const std::string& primary_utf8, const std::string& secondary_utf8) {
    start_thread(Mode::Result, primary_utf8, secondary_utf8);
}

// Show a continuation surface while the client completes an operation the
// browser can no longer watch. Becomes a Result via update().
inline void show_working(const std::string& primary_utf8,
                         const std::string& secondary_utf8) {
    start_thread(Mode::Working, primary_utf8, secondary_utf8);
}

// The standalone Setup completion surface: no recoverable intent, one
// explicit way onward.
inline void show_ready() {
    start_thread(Mode::Ready, "VIRULE is ready",
                 "Continue at virule.app to get started.");
}

// Turn the visible card into a Result with new copy (a Working card's
// outcome landing). Safe from any thread.
inline void update(const std::string& primary_utf8,
                   const std::string& secondary_utf8) {
    {
        std::lock_guard<std::mutex> lock(g_text_mutex);
        g_primary = widen_utf8(primary_utf8);
        g_secondary = widen_utf8(secondary_utf8);
    }
    g_mode.store((int)Mode::Result);
    if (HWND hwnd = g_hwnd.load()) PostMessageW(hwnd, kMsgRefresh, 0, 0);
}

// True once the window actually exists on screen (the ownership invariant
// waits on this before releasing Setup).
inline bool is_visible() { return g_hwnd.load() != nullptr; }

// Dismiss the card programmatically (an operation's feedback moved to a
// better surface, or a standalone card was superseded by a real intent).
inline void close() {
    if (HWND hwnd = g_hwnd.load()) PostMessageW(hwnd, kMsgClose, 0, 0);
}

// Blocks until the window closes itself (timer, click or key).
inline void wait_closed(DWORD timeout_ms = 30000) {
    if (!g_thread) return;
    WaitForSingleObject(g_thread, timeout_ms);
    CloseHandle(g_thread);
    g_thread = nullptr;
}

} // namespace vclient::result_card
