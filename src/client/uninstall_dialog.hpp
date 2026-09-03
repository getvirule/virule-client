#pragma once
// The native Uninstall VIRULE confirmation (the Windows Apps & Features
// entry point; the browser owns this confirmation whenever the flow starts
// on virule.app). One small card in the established VIRULE native grammar
// (the result card / Setup card: rounded dark-or-light surface, thin
// border, Segoe UI), mirroring the site's uninstall modal exactly:
//
//   Uninstall VIRULE?
//   This removes VIRULE Admin and VIRULE Client from this PC.
//   Your local data will be kept.               (default copy)
//   [ ] Delete local data                        (OFF by default)
//   This cannot be undone. You will permanently  (only while checked)
//   lose all VIRULE data stored on this PC.
//   [ Cancel ]                    Uninstall      (right action turns into
//                                                 Uninstall & Delete Data)
//
// The dismissal (Cancel, yellow outline) sits LEFT; the destructive action
// (red text) sits RIGHT, the shared VIRULE delete-confirmation voice. The
// card has a DEFINITE height sized for its tallest state (warning shown),
// so toggling the option never moves the actions. Escape cancels; Enter
// deliberately activates nothing (a destructive default is never one
// keypress away).

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

namespace vclient::uninstall_dialog {

constexpr wchar_t kClassName[] = L"ViruleUninstallConfirmWindow";

struct Palette {
    COLORREF bg;
    COLORREF line;
    COLORREF word;
    COLORREF muted;
    COLORREF accent;
    COLORREF danger;
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
                        RGB(0x20, 0x25, 0x2b), RGB(0x71, 0x7b, 0x86),
                        RGB(0xb4, 0x86, 0x0f), RGB(0xdc, 0x26, 0x26) };
    }
    return Palette{ RGB(0x19, 0x19, 0x18), RGB(0x2a, 0x2a, 0x28),
                    RGB(0xee, 0xee, 0xec), RGB(0xb4, 0xb2, 0xac),
                    RGB(0xfb, 0xbf, 0x24), RGB(0xef, 0x44, 0x44) };
}

// Window-thread-only state (run() is modal on the calling thread).
inline UINT g_dpi = 96;
inline Palette g_pal{};
inline bool g_delete_data = false;
inline int g_result = 0; // 0 = pending/cancel, 1 = uninstall

// Hit rectangles, recomputed every paint (fixed layout, so stable).
inline RECT g_rc_check{};
inline RECT g_rc_cancel{};
inline RECT g_rc_action{};

inline int usc(int v) { return MulDiv(v, (int)g_dpi, 96); }

inline HFONT make_font(int size, int weight) {
    return CreateFontW(-usc(size), 0, 0, 0, weight, FALSE, FALSE, FALSE,
                       DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
                       CLEARTYPE_QUALITY, DEFAULT_PITCH, L"Segoe UI");
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
        RoundRect(mem, 0, 0, w - 1, h - 1, usc(14), usc(14));
        SelectObject(mem, old_br);
        SelectObject(mem, old_pen);
        DeleteObject(pen);
    }

    SetBkMode(mem, TRANSPARENT);
    const int pad = usc(26);

    // Title.
    {
        HFONT f = make_font(15, FW_SEMIBOLD);
        HGDIOBJ old_f = SelectObject(mem, f);
        SetTextColor(mem, g_pal.word);
        RECT tr{ pad, usc(22), w - pad, usc(46) };
        DrawTextW(mem, L"Uninstall VIRULE?", -1, &tr,
                  DT_LEFT | DT_SINGLELINE | DT_END_ELLIPSIS);
        SelectObject(mem, old_f);
        DeleteObject(f);
    }

    // Body. The second sentence is the preserve-data promise and only
    // holds while the destructive option is OFF.
    {
        HFONT f = make_font(11, FW_NORMAL);
        HGDIOBJ old_f = SelectObject(mem, f);
        SetTextColor(mem, g_pal.muted);
        const wchar_t* body = g_delete_data
            ? L"This removes VIRULE Admin and VIRULE Client from this PC."
            : L"This removes VIRULE Admin and VIRULE Client from this PC.\n"
              L"Your local data will be kept.";
        RECT br{ pad, usc(52), w - pad, usc(96) };
        DrawTextW(mem, body, -1, &br, DT_LEFT | DT_WORDBREAK);
        SelectObject(mem, old_f);
        DeleteObject(f);
    }

    // The one preference: the small square check the VIRULE surfaces use.
    {
        const int box = usc(15);
        const int cy = usc(104);
        RECT box_rc{ pad, cy, pad + box, cy + box };
        if (g_delete_data) {
            HBRUSH b = CreateSolidBrush(g_pal.accent);
            HGDIOBJ old_pen = SelectObject(mem, GetStockObject(NULL_PEN));
            HGDIOBJ old_br = SelectObject(mem, b);
            RoundRect(mem, box_rc.left, box_rc.top, box_rc.right + 1,
                      box_rc.bottom + 1, usc(4), usc(4));
            SelectObject(mem, old_br);
            SelectObject(mem, old_pen);
            DeleteObject(b);
            // The check mark.
            HPEN pen = CreatePen(PS_SOLID, usc(2), g_pal.bg);
            HGDIOBJ old_pen2 = SelectObject(mem, pen);
            MoveToEx(mem, box_rc.left + usc(3), cy + usc(7), nullptr);
            LineTo(mem, box_rc.left + usc(6), cy + usc(10));
            LineTo(mem, box_rc.left + usc(12), cy + usc(4));
            SelectObject(mem, old_pen2);
            DeleteObject(pen);
        } else {
            HPEN pen = CreatePen(PS_SOLID, 1, g_pal.line);
            HGDIOBJ old_pen = SelectObject(mem, pen);
            HGDIOBJ old_br = SelectObject(mem, GetStockObject(HOLLOW_BRUSH));
            RoundRect(mem, box_rc.left, box_rc.top, box_rc.right,
                      box_rc.bottom, usc(4), usc(4));
            SelectObject(mem, old_br);
            SelectObject(mem, old_pen);
            DeleteObject(pen);
        }
        HFONT f = make_font(11, FW_NORMAL);
        HGDIOBJ old_f = SelectObject(mem, f);
        SetTextColor(mem, g_pal.muted);
        RECT lr{ pad + box + usc(10), cy - usc(2), w - pad, cy + box + usc(4) };
        DrawTextW(mem, L"Delete local data", -1, &lr,
                  DT_LEFT | DT_SINGLELINE | DT_VCENTER);
        SelectObject(mem, old_f);
        DeleteObject(f);
        // The whole row is the click target.
        g_rc_check = RECT{ pad, cy - usc(4), w - pad, cy + box + usc(6) };
    }

    // The strong warning, only while the destructive option is ON. Its
    // space is part of the card's definite height either way, so toggling
    // never moves the actions.
    if (g_delete_data) {
        HFONT f = make_font(11, FW_NORMAL);
        HGDIOBJ old_f = SelectObject(mem, f);
        SetTextColor(mem, g_pal.danger);
        RECT wr{ pad, usc(132), w - pad, usc(176) };
        DrawTextW(mem,
                  L"This cannot be undone.\n"
                  L"You will permanently lose all VIRULE data stored on this PC.",
                  -1, &wr, DT_LEFT | DT_WORDBREAK);
        SelectObject(mem, old_f);
        DeleteObject(f);
    }

    // Actions: Cancel (yellow outline) LEFT, the destructive action (red
    // text) RIGHT. Fixed baseline in both states.
    {
        const int by = h - usc(52);
        const int bh = usc(30);

        // Cancel.
        {
            HFONT f = make_font(11, FW_SEMIBOLD);
            HGDIOBJ old_f = SelectObject(mem, f);
            const wchar_t* label = L"Cancel";
            SIZE sz{};
            GetTextExtentPoint32W(mem, label, (int)wcslen(label), &sz);
            const int bw = sz.cx + usc(36);
            RECT r{ pad, by, pad + bw, by + bh };
            HPEN pen = CreatePen(PS_SOLID, 1, g_pal.accent);
            HGDIOBJ old_pen = SelectObject(mem, pen);
            HGDIOBJ old_br = SelectObject(mem, GetStockObject(HOLLOW_BRUSH));
            RoundRect(mem, r.left, r.top, r.right, r.bottom, usc(8), usc(8));
            SelectObject(mem, old_br);
            SelectObject(mem, old_pen);
            DeleteObject(pen);
            SetTextColor(mem, g_pal.accent);
            DrawTextW(mem, label, -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            SelectObject(mem, old_f);
            DeleteObject(f);
            g_rc_cancel = r;
        }

        // Uninstall / Uninstall & Delete Data.
        {
            HFONT f = make_font(11, FW_SEMIBOLD);
            HGDIOBJ old_f = SelectObject(mem, f);
            const wchar_t* label = g_delete_data
                ? L"Uninstall & Delete Data" : L"Uninstall";
            SIZE sz{};
            GetTextExtentPoint32W(mem, label, (int)wcslen(label), &sz);
            const int bw = sz.cx + usc(24);
            RECT r{ w - pad - bw, by, w - pad, by + bh };
            SetTextColor(mem, g_pal.danger);
            DrawTextW(mem, label, -1, &r, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            SelectObject(mem, old_f);
            DeleteObject(f);
            g_rc_action = r;
        }
    }

    BitBlt(dc, 0, 0, w, h, mem, 0, 0, SRCCOPY);
    SelectObject(mem, old_bmp);
    DeleteObject(bmp);
    DeleteDC(mem);
    EndPaint(hwnd, &ps);
}

inline bool hit(const RECT& r, LPARAM lp) {
    const POINT p{ (SHORT)LOWORD(lp), (SHORT)HIWORD(lp) };
    return PtInRect(&r, p) != FALSE;
}

inline LRESULT CALLBACK wnd_proc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_LBUTTONUP:
        if (hit(g_rc_check, lp)) {
            g_delete_data = !g_delete_data;
            InvalidateRect(hwnd, nullptr, FALSE);
        } else if (hit(g_rc_cancel, lp)) {
            g_result = 0;
            DestroyWindow(hwnd);
        } else if (hit(g_rc_action, lp)) {
            g_result = 1;
            DestroyWindow(hwnd);
        }
        return 0;
    case WM_KEYDOWN:
        // Escape cancels. Enter deliberately does nothing: a destructive
        // confirmation is never one keypress away.
        if (wp == VK_ESCAPE) {
            g_result = 0;
            DestroyWindow(hwnd);
        }
        return 0;
    case WM_PAINT:
        paint(hwnd);
        return 0;
    case WM_ERASEBKGND:
        return 1;
    case WM_CLOSE:
        g_result = 0;
        DestroyWindow(hwnd);
        return 0;
    case WM_DESTROY:
        PostQuitMessage(0);
        return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

// Show the confirmation modally on the calling thread. Returns true to
// proceed; `delete_data_out` carries the explicit destructive choice
// (always false unless the user turned the option on).
inline bool run(bool& delete_data_out) {
    delete_data_out = false;
    HINSTANCE inst = GetModuleHandleW(nullptr);
    g_pal = resolve_palette();
    g_delete_data = false;
    g_result = 0;
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
    if (!RegisterClassW(&wc)) return false;

    // Definite height sized for the TALLEST state (warning visible), so
    // toggling the option never reflows the card.
    const int w = usc(392), h = usc(238);
    RECT work{ 0, 0, 0, 0 };
    SystemParametersInfoW(SPI_GETWORKAREA, 0, &work, 0);
    const int x = work.left + ((work.right - work.left) - w) / 2;
    const int y = work.top + ((work.bottom - work.top) - h) / 2;

    HWND hwnd = CreateWindowExW(0, kClassName, L"VIRULE", WS_POPUP,
                                x, y, w, h, nullptr, nullptr, inst, nullptr);
    if (!hwnd) {
        UnregisterClassW(kClassName, inst);
        return false;
    }
    SetWindowRgn(hwnd, CreateRoundRectRgn(0, 0, w + 1, h + 1, usc(14), usc(14)), TRUE);
    ShowWindow(hwnd, SW_SHOW);
    SetForegroundWindow(hwnd);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    UnregisterClassW(kClassName, inst);
    delete_data_out = g_delete_data;
    return g_result == 1;
}

} // namespace vclient::uninstall_dialog
