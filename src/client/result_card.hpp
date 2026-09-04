#pragma once
// The client's ONE small native surface, in two visual voices:
//
// BARE RESULT (the original card, unchanged): ported from the VIRULE
// Admin's QA verification result window (browser/native ownership rule):
// while a virule.app page is open the BROWSER owns every visible part of a
// flow and this window never exists. Only when no page is there does native
// VIRULE show this small card. One headline, at most one supporting line.
// No brand mark. Used ONLY for the QA verification outcome (qa_flow).
//
// LIFECYCLE SURFACE (the lifecycle continuity pass, 2026-09-03): the
// client is now the persistent machine manager and needs one consistent
// branded surface for its transitional states - "Updating…",
// "Finishing up…", "You're all set.", "VIRULE is ready" [Continue]. These
// wear the Virule-Setup card grammar (yellow V mark, spaced wordmark, the
// subtle indeterminate bar), so the ownership handoff Setup -> Client ->
// Admin reads as one continuous VIRULE, never as unrelated windows.
//
// Three modes:
//
//   Result   the final outcome. Click / Escape / Enter dismiss; it
//            dismisses itself on a timer. Bare when shown directly
//            (show()); branded when a lifecycle card resolved into it
//            (update()).
//   Working  a branded continuation surface shown WHILE the client
//            completes an operation ("Updating…", "Finishing up…"): the
//            Setup card's indeterminate bar, not dismissible, no
//            auto-close; it becomes a Result via update().
//   Ready    the branded standalone completion surface for a Setup run
//            with no recoverable browser intent: "VIRULE is ready" and ONE
//            explicit [ Continue ] action (opens virule.app in the default
//            browser). Nothing opens a browser except that click.
//
// The card is the "next visible feedback surface" the ownership invariant
// requires before Virule-Setup (or a closing Admin) is allowed to
// disappear, so takeover/update code waits on is_visible() before
// releasing the previous surface.
//
// REUSABLE: the client is a persistent process and shows lifecycle cards
// repeatedly (an Admin update today, another next month). One card exists
// at a time; a finished card's thread is reaped so the next can show.

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
inline std::mutex g_thread_mutex;
inline HANDLE g_thread = nullptr;    // guarded by g_thread_mutex
inline UINT g_dpi = 96;          // window thread only
inline Palette g_pal{};
inline std::atomic<int> g_mode{ (int)Mode::Result };
inline std::atomic<bool> g_branded{ false };
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

inline HFONT make_font(int size, int weight) {
    return CreateFontW(-qsc(size), 0, 0, 0, weight, FALSE, FALSE, FALSE,
                       DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                       CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
}

// The branded lifecycle layout: V mark + spaced wordmark (the Virule-Setup
// card grammar, measured TextOut because letter spacing is invisible to
// DrawText's centering), headline, then the mode's own element (bar /
// secondary line / action button).
inline void paint_branded(HDC mem, int w, int h, Mode mode,
                          const std::wstring& primary,
                          const std::wstring& secondary) {
    // Yellow V mark.
    const int mark = qsc(44);
    const int mark_x = (w - mark) / 2;
    const int mark_y = qsc(30);
    {
        HBRUSH b = CreateSolidBrush(g_pal.accent);
        HGDIOBJ old_pen = SelectObject(mem, GetStockObject(NULL_PEN));
        HGDIOBJ old_br = SelectObject(mem, b);
        RoundRect(mem, mark_x, mark_y, mark_x + mark, mark_y + mark, qsc(12), qsc(12));
        SelectObject(mem, old_br);
        SelectObject(mem, old_pen);
        DeleteObject(b);
    }
    {
        HFONT f = make_font(24, FW_BOLD);
        HGDIOBJ old_f = SelectObject(mem, f);
        SetTextColor(mem, g_pal.accent_ink);
        RECT mr{ mark_x, mark_y, mark_x + mark, mark_y + mark };
        DrawTextW(mem, L"V", 1, &mr, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
        SelectObject(mem, old_f);
        DeleteObject(f);
    }
    // Wordmark.
    {
        HFONT f = make_font(15, FW_BOLD);
        HGDIOBJ old_f = SelectObject(mem, f);
        SetTextColor(mem, g_pal.word);
        const int extra = qsc(4);
        const wchar_t word[] = L"VIRULE";
        const int word_len = (int)(sizeof(word) / sizeof(word[0])) - 1;
        SIZE sz{};
        GetTextExtentPoint32W(mem, word, word_len, &sz);
        const int total_w = sz.cx + extra * (word_len - 1);
        SetTextCharacterExtra(mem, extra);
        TextOutW(mem, (w - total_w) / 2, mark_y + mark + qsc(14), word, word_len);
        SetTextCharacterExtra(mem, 0);
        SelectObject(mem, old_f);
        DeleteObject(f);
    }
    // Headline: one line, word color, fixed band so every state aligns.
    {
        HFONT f = make_font(13, FW_SEMIBOLD);
        HGDIOBJ old_f = SelectObject(mem, f);
        SetTextColor(mem, g_pal.word);
        RECT tr{ qsc(26), qsc(118), w - qsc(26), qsc(142) };
        DrawTextW(mem, primary.c_str(), (int)primary.size(), &tr,
                  DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS);
        SelectObject(mem, old_f);
        DeleteObject(f);
    }
    if (mode == Mode::Working) {
        // The Setup card's subtle indeterminate bar: work is happening; no
        // invented percentages, ever.
        const int bar_w = qsc(168);
        const int bar_h = qsc(3);
        const int bar_x = (w - bar_w) / 2;
        const int bar_y = qsc(160);
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
    } else if (mode == Mode::Result && !secondary.empty()) {
        HFONT f = make_font(11, FW_NORMAL);
        HGDIOBJ old_f = SelectObject(mem, f);
        SetTextColor(mem, g_pal.muted);
        RECT sr{ qsc(26), qsc(146), w - qsc(26), h - qsc(10) };
        DrawTextW(mem, secondary.c_str(), (int)secondary.size(), &sr,
                  DT_CENTER | DT_WORDBREAK | DT_END_ELLIPSIS);
        SelectObject(mem, old_f);
        DeleteObject(f);
    } else if (mode == Mode::Ready) {
        // The ONE explicit action. Accent button, VIRULE's native grammar.
        HFONT f = make_font(12, FW_SEMIBOLD);
        HGDIOBJ old_f = SelectObject(mem, f);
        const wchar_t label[] = L"Continue";
        const int label_len = (int)(sizeof(label) / sizeof(label[0])) - 1;
        SIZE sz{};
        GetTextExtentPoint32W(mem, label, label_len, &sz);
        const int bw = sz.cx + qsc(56);
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
}

// The original bare-result layout (the QA doctrine card): headline, at
// most one supporting line, NO brand mark.
inline void paint_bare(HDC mem, int w, int h,
                       const std::wstring& primary,
                       const std::wstring& secondary) {
    const bool tall = !secondary.empty();
    {
        HFONT f = make_font(13, FW_SEMIBOLD);
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
        HFONT f = make_font(11, FW_NORMAL);
        HGDIOBJ old_f = SelectObject(mem, f);
        SetTextColor(mem, g_pal.muted);
        RECT sr{ qsc(24), qsc(62), w - qsc(24), h - qsc(20) };
        DrawTextW(mem, secondary.c_str(), (int)secondary.size(), &sr,
                  DT_CENTER | DT_WORDBREAK | DT_END_ELLIPSIS);
        SelectObject(mem, old_f);
        DeleteObject(f);
    }
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

    if (g_branded.load()) {
        paint_branded(mem, w, h, mode, primary, secondary);
    } else {
        paint_bare(mem, w, h, primary, secondary);
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
    // The persistent client shows lifecycle cards repeatedly; a class
    // registered by an earlier card is fine.
    if (!RegisterClassW(&wc) && GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
        return 0;
    }

    const Mode mode = (Mode)g_mode.load();
    const bool branded = g_branded.load();
    const int w = branded ? qsc(340) : qsc(320);
    const int h = branded ? (mode == Mode::Ready ? qsc(216) : qsc(200))
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
    // This card is the handoff's next feedback surface, so it must reach
    // the FOREGROUND even though this process was spawned from the
    // background: attach to the foreground thread for the switch, then a
    // topmost pulse so the card surfaces without staying topmost.
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

// ONE card at a time; a finished card's thread is reaped so the next
// lifecycle state (possibly much later in this persistent process) can
// show. A card still on screen keeps ownership: later show calls no-op and
// the state moves through update()/close() instead.
inline void start_thread(Mode mode, bool branded,
                         const std::string& primary_utf8,
                         const std::string& secondary_utf8) {
    std::lock_guard<std::mutex> lock(g_thread_mutex);
    if (g_thread) {
        if (WaitForSingleObject(g_thread, 0) == WAIT_OBJECT_0) {
            CloseHandle(g_thread);
            g_thread = nullptr;
        } else {
            return; // a live card owns the surface
        }
    }
    {
        std::lock_guard<std::mutex> text_lock(g_text_mutex);
        g_primary = widen_utf8(primary_utf8);
        g_secondary = widen_utf8(secondary_utf8);
    }
    g_mode.store((int)mode);
    g_branded.store(branded);
    g_phase.store(0);
    g_thread = CreateThread(nullptr, 0, thread_main, nullptr, 0, nullptr);
}

// Show the final outcome (the bare QA doctrine card). Only called when no
// page is open to show it.
inline void show(const std::string& primary_utf8, const std::string& secondary_utf8) {
    start_thread(Mode::Result, /*branded=*/false, primary_utf8, secondary_utf8);
}

// Show a branded lifecycle continuation surface while the client completes
// an operation ("Updating…", "Finishing up…"). Becomes a Result via
// update().
inline void show_working(const std::string& primary_utf8,
                         const std::string& secondary_utf8) {
    start_thread(Mode::Working, /*branded=*/true, primary_utf8, secondary_utf8);
}

// The standalone Setup completion surface: no recoverable intent, one
// explicit way onward (owner copy 2026-09-03: the branded window already
// says VIRULE; the single action is Continue).
inline void show_ready() {
    start_thread(Mode::Ready, /*branded=*/true, "VIRULE is ready", "");
}

// Turn the visible card into a Result with new copy (a Working card's
// outcome landing). Keeps the card's visual voice (a branded lifecycle
// card resolves branded). Safe from any thread.
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
// waits on this before releasing the previous surface).
inline bool is_visible() { return g_hwnd.load() != nullptr; }

// A lifecycle Working card is on screen and still unresolved (its outcome
// should land on it rather than on a second surface).
inline bool is_working_visible() {
    return g_hwnd.load() != nullptr && (Mode)g_mode.load() == Mode::Working;
}

// Dismiss the card programmatically (an operation's feedback moved to a
// better surface, or a standalone card was superseded by a real intent).
inline void close() {
    if (HWND hwnd = g_hwnd.load()) PostMessageW(hwnd, kMsgClose, 0, 0);
}

// Blocks until the window closes itself (timer, click or key).
inline void wait_closed(DWORD timeout_ms = 30000) {
    HANDLE h = nullptr;
    {
        std::lock_guard<std::mutex> lock(g_thread_mutex);
        h = g_thread;
    }
    if (!h) return;
    WaitForSingleObject(h, timeout_ms);
    std::lock_guard<std::mutex> lock(g_thread_mutex);
    if (g_thread == h && WaitForSingleObject(h, 0) == WAIT_OBJECT_0) {
        CloseHandle(h);
        g_thread = nullptr;
    }
}

} // namespace vclient::result_card
