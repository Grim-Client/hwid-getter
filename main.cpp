#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
#include <memory>
#include <array>
#include "SHA256.h"

using namespace std;

void printMessage(ostream& os, const string& en, const string& pl) {
    os << en << endl
        << pl << endl;
}

string sha256(const string& text) {
    SHA256 sha;
    sha.update(text);
    return SHA256::toString(sha.digest());
}

string getHWID_Windows() {
    SECURITY_ATTRIBUTES sa{ sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
    HANDLE hRead = nullptr, hWrite = nullptr;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0))
        return "";

    STARTUPINFOA si{ sizeof(STARTUPINFOA) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;

    PROCESS_INFORMATION pi;
    BOOL ok = CreateProcessA(
        nullptr,
        const_cast<LPSTR>(
            "powershell.exe -NoProfile -Command "
            "\"Get-WmiObject -Class Win32_ComputerSystemProduct | "
            "Select-Object -ExpandProperty UUID\""
            ),
        nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW,
        nullptr, nullptr,
        &si, &pi
    );
    CloseHandle(hWrite);
    if (!ok) {
        CloseHandle(hRead);
        return "";
    }

    string raw;
    array<char, 128> buf;
    DWORD bytesRead;
    while (ReadFile(hRead, buf.data(), buf.size() - 1, &bytesRead, nullptr) && bytesRead) {
        buf[bytesRead] = '\0';
        raw += buf.data();
    }

    CloseHandle(hRead);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    raw.erase(remove_if(raw.begin(), raw.end(), ::isspace), raw.end());
    return "UUID" + raw;
}

int main() {
    string raw = getHWID_Windows();
    if (raw.empty()) {
        printMessage(cerr,
            "Failed to retrieve HWID from the system.",
            "Nie udało się pobrać HWID z systemu.");
        return 1;
    }

    vector<string> unsupportedHashes = {
        "445e8dda7991f57432a755001e06fa457cc5cc64be045d995df75b7513726e2f"
    };

    string hashed = sha256(raw);

    if (find(unsupportedHashes.begin(), unsupportedHashes.end(), hashed)
        != unsupportedHashes.end()) {
        printMessage(cout,
            "Your HWID is not supported. Please contact our support team on Discord: discord.gg/grimclient",
            "Twój HWID nie jest obsługiwany. Skontaktuj się z naszym wsparciem na Discordzie: discord.gg/grimclient");
    }
    else {
        cout << hashed << endl;
        if (OpenClipboard(nullptr)) {
            EmptyClipboard();
            HGLOBAL hGlob = GlobalAlloc(GMEM_MOVEABLE, hashed.size() + 1);
            if (hGlob) {
                memcpy(GlobalLock(hGlob), hashed.c_str(), hashed.size() + 1);
                GlobalUnlock(hGlob);
                SetClipboardData(CF_TEXT, hGlob);
            }
            CloseClipboard();
        }
    }

    system("pause");
    return 0;
}