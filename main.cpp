#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>
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

void copy_to_clipboard(const string& text) {
    if (!OpenClipboard(nullptr)) return;
    EmptyClipboard();
    HGLOBAL hGlob = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
    memcpy(GlobalLock(hGlob), text.c_str(), text.size() + 1);
    GlobalUnlock(hGlob);
    SetClipboardData(CF_TEXT, hGlob);
    CloseClipboard();
}

int main() {
    SECURITY_ATTRIBUTES sa{ sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE };
    HANDLE hRead, hWrite;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        printMessage(cerr,
            "Pipe creation failed.",
            "Nie udalo sie utworzyc potoku.");
        return 1;
    }

    STARTUPINFOA si{ sizeof(STARTUPINFOA) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;

    PROCESS_INFORMATION pi;
    BOOL ok = CreateProcessA(
        nullptr,
        const_cast<LPSTR>("wmic csproduct get uuid"),
        nullptr, nullptr, TRUE,
        CREATE_NO_WINDOW,
        nullptr, nullptr,
        &si, &pi
    );

    CloseHandle(hWrite);
    if (!ok) {
        printMessage(cerr,
            "Failed to launch WMIC.",
            "Nie udalo siê uruchomiæ WMIC.");
        return 1;
    }

    string raw;
    CHAR buffer[128];
    DWORD bytesRead;
    while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr)
        && bytesRead) {
        buffer[bytesRead] = '\0';
        raw += buffer;
    }

    CloseHandle(hRead);
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (raw.find("not recognized") != string::npos) {
        printMessage(cout,
            "WMI not found. Install WMIC feature-on-demand:\n"
            "https://techcommunity.microsoft.com/blog/windows-itpro-blog/"
            "how-to-install-wmic-feature-on-demand-on-windows-11/4189530",
            "Nie znaleziono WMI. Zainstaluj funkcje WMIC:\n"
            "https://techcommunity.microsoft.com/blog/windows-itpro-blog/"
            "how-to-install-wmic-feature-on-demand-on-windows-11/4189530");
        system("pause");
        return 1;
    }

    raw.erase(remove_if(raw.begin(), raw.end(), ::isspace), raw.end());

    vector<string> unsupportedHashes = {
        "445e8dda7991f57432a755001e06fa457cc5cc64be045d995df75b7513726e2f"
    };

    string hashed = sha256(raw);

    if (find(unsupportedHashes.begin(), unsupportedHashes.end(), hashed)
        != unsupportedHashes.end()) {
        printMessage(cout,
            "Your HWID is not supported. Please contact our support team on Discord: discord.gg/grimclient",
            "Twoj HWID nie jest obslugiwany. Skontaktuj sie z naszym wsparciem na Discordzie: discord.gg/grimclient");
    }
    else {
        cout << hashed << endl;
        copy_to_clipboard(hashed);
    }

    system("pause");
    return 0;
}