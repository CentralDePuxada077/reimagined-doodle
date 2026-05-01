// ══════════════════════════════════════════════════════════════════════════════
//  Nz Store — Implementação de Autenticação para C++
//  Arquivo: nzstore.cpp
//
//  Dependências:
//    - Windows: WinHTTP (link: winhttp.lib)
//    - Wbem para HWID (link: wbemuuid.lib, ole32.lib, oleaut32.lib)
//    - Compilador: MSVC ou MinGW com suporte a C++17
//
//  No seu .vcxproj ou CMakeLists.txt adicione:
//    target_link_libraries(SeuProjeto winhttp wbemuuid ole32 oleaut32)
// ══════════════════════════════════════════════════════════════════════════════

#include "nzstore.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winhttp.h>
#include <wbemidl.h>
#include <comdef.h>
#include <wincrypt.h>

#include <string>
#include <sstream>
#include <iomanip>
#include <stdexcept>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")

namespace NzStore
{
    // !! ALTERE PARA A URL DO SEU SERVIDOR !!
    // Exemplo Vercel:  L"seu-projeto.vercel.app"
    // Exemplo local:   L"localhost"
    static const wchar_t* API_HOST = L"SEU-PROJETO.vercel.app";
    static const wchar_t* API_PATH = L"/api/auth";
    static const INTERNET_PORT API_PORT = INTERNET_DEFAULT_HTTPS_PORT; // 443

    // ── Helpers internos ──────────────────────────────────────────────────────

    // Converte wstring para string UTF-8
    static std::string WstrToStr(const std::wstring& wstr)
    {
        if (wstr.empty()) return {};
        int sz = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string result(sz - 1, '\0');
        WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &result[0], sz, nullptr, nullptr);
        return result;
    }

    // Converte string para wstring
    static std::wstring StrToWstr(const std::string& str)
    {
        if (str.empty()) return {};
        int sz = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
        std::wstring result(sz - 1, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &result[0], sz);
        return result;
    }

    // SHA256 de uma string → hex string
    static std::string Sha256Hex(const std::string& input)
    {
        HCRYPTPROV hProv = 0;
        HCRYPTHASH hHash = 0;
        std::string result;

        if (!CryptAcquireContextA(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
            return "unknown";

        if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash))
        {
            CryptReleaseContext(hProv, 0);
            return "unknown";
        }

        CryptHashData(hHash, reinterpret_cast<const BYTE*>(input.c_str()),
                      static_cast<DWORD>(input.size()), 0);

        DWORD hashLen = 32;
        BYTE  hashBuf[32] = {};
        CryptGetHashParam(hHash, HP_HASHVAL, hashBuf, &hashLen, 0);

        std::ostringstream oss;
        for (int i = 0; i < 32; ++i)
            oss << std::hex << std::setw(2) << std::setfill('0') << (int)hashBuf[i];

        result = oss.str();
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return result;
    }

    // Consulta WMI para obter um valor de hardware
    static std::string GetWmiValue(const wchar_t* wmiClass, const wchar_t* property)
    {
        std::string result;

        CoInitializeEx(nullptr, COINIT_MULTITHREADED);

        IWbemLocator*  pLoc  = nullptr;
        IWbemServices* pSvc  = nullptr;

        HRESULT hr = CoCreateInstance(CLSID_WbemLocator, nullptr,
                                      CLSCTX_INPROC_SERVER, IID_IWbemLocator,
                                      reinterpret_cast<LPVOID*>(&pLoc));
        if (FAILED(hr)) { CoUninitialize(); return "unknown"; }

        hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr,
                                 nullptr, 0, nullptr, nullptr, &pSvc);
        if (FAILED(hr)) { pLoc->Release(); CoUninitialize(); return "unknown"; }

        CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                          RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE,
                          nullptr, EOAC_NONE);

        std::wstring query = std::wstring(L"SELECT ") + property +
                             L" FROM " + wmiClass;

        IEnumWbemClassObject* pEnum = nullptr;
        hr = pSvc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(query.c_str()),
                             WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                             nullptr, &pEnum);

        if (SUCCEEDED(hr) && pEnum)
        {
            IWbemClassObject* pObj = nullptr;
            ULONG returned = 0;
            if (pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned) == S_OK && pObj)
            {
                VARIANT vtProp;
                VariantInit(&vtProp);
                if (SUCCEEDED(pObj->Get(property, 0, &vtProp, nullptr, nullptr)))
                {
                    if (vtProp.vt == VT_BSTR && vtProp.bstrVal)
                        result = WstrToStr(vtProp.bstrVal);
                    VariantClear(&vtProp);
                }
                pObj->Release();
            }
            pEnum->Release();
        }

        pSvc->Release();
        pLoc->Release();
        CoUninitialize();

        if (result.empty()) return "unknown";
        // Remove espaços extras
        while (!result.empty() && result.back() == ' ') result.pop_back();
        return result;
    }

    // ── GetHwid ───────────────────────────────────────────────────────────────
    std::string GetHwid()
    {
        std::string cpu  = GetWmiValue(L"Win32_Processor",  L"ProcessorId");
        std::string disk = GetWmiValue(L"Win32_DiskDrive",  L"SerialNumber");
        std::string mb   = GetWmiValue(L"Win32_BaseBoard",  L"SerialNumber");

        std::string raw = cpu + "-" + disk + "-" + mb;
        return Sha256Hex(raw);
    }

    // ── HTTP POST via WinHTTP ─────────────────────────────────────────────────
    static std::string HttpPost(const std::string& jsonBody)
    {
        std::string response;

        HINTERNET hSession = WinHttpOpen(L"NzStore/1.0",
                                         WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                         WINHTTP_NO_PROXY_NAME,
                                         WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return "";

        HINTERNET hConnect = WinHttpConnect(hSession, API_HOST, API_PORT, 0);
        if (!hConnect) { WinHttpCloseHandle(hSession); return ""; }

        DWORD flags = WINHTTP_FLAG_SECURE;
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST",
                                                API_PATH, nullptr,
                                                WINHTTP_NO_REFERER,
                                                WINHTTP_DEFAULT_ACCEPT_TYPES,
                                                flags);
        if (!hRequest)
        {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return "";
        }

        // Ignora erros de certificado em dev (remova em produção se quiser)
        DWORD secFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                         SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                         SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &secFlags, sizeof(secFlags));

        std::wstring headers = L"Content-Type: application/json\r\n";
        BOOL sent = WinHttpSendRequest(hRequest,
                                       headers.c_str(), (DWORD)headers.size(),
                                       (LPVOID)jsonBody.c_str(),
                                       (DWORD)jsonBody.size(),
                                       (DWORD)jsonBody.size(), 0);

        if (sent && WinHttpReceiveResponse(hRequest, nullptr))
        {
            DWORD bytesAvail = 0;
            while (WinHttpQueryDataAvailable(hRequest, &bytesAvail) && bytesAvail > 0)
            {
                std::string chunk(bytesAvail, '\0');
                DWORD bytesRead = 0;
                WinHttpReadData(hRequest, &chunk[0], bytesAvail, &bytesRead);
                chunk.resize(bytesRead);
                response += chunk;
            }
        }

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return response;
    }

    // ── Parser JSON mínimo (sem dependências externas) ────────────────────────
    static std::string JsonGetString(const std::string& json, const std::string& key)
    {
        std::string search = "\"" + key + "\"";
        size_t pos = json.find(search);
        if (pos == std::string::npos) return "";

        pos = json.find(':', pos + search.size());
        if (pos == std::string::npos) return "";

        // Pula espaços
        pos++;
        while (pos < json.size() && json[pos] == ' ') pos++;

        if (pos >= json.size()) return "";

        if (json[pos] == '"')
        {
            // Valor string
            pos++;
            std::string val;
            while (pos < json.size() && json[pos] != '"')
            {
                if (json[pos] == '\\' && pos + 1 < json.size())
                {
                    pos++;
                    if      (json[pos] == 'n')  val += '\n';
                    else if (json[pos] == 't')  val += '\t';
                    else if (json[pos] == '"')  val += '"';
                    else if (json[pos] == '\\') val += '\\';
                    else                        val += json[pos];
                }
                else val += json[pos];
                pos++;
            }
            return val;
        }
        else
        {
            // Valor booleano / número
            size_t end = json.find_first_of(",}", pos);
            if (end == std::string::npos) end = json.size();
            std::string val = json.substr(pos, end - pos);
            // Remove espaços
            while (!val.empty() && val.back() == ' ') val.pop_back();
            return val;
        }
    }

    // ── Login ─────────────────────────────────────────────────────────────────
    AuthResult Login(const std::string& discord_id)
    {
        AuthResult result;

        if (discord_id.empty())
        {
            result.message = "Discord ID nao pode ser vazio.";
            return result;
        }

        std::string hwid = GetHwid();

        // Monta JSON manualmente (sem dependência de nlohmann/json)
        std::string body = "{\"discord_id\":\"" + discord_id + "\","
                           "\"hwid\":\"" + hwid + "\"}";

        std::string response = HttpPost(body);

        if (response.empty())
        {
            result.message = "Sem conexao com o servidor. Verifique sua internet.";
            return result;
        }

        // Parse da resposta
        std::string successVal = JsonGetString(response, "success");
        result.success   = (successVal == "true");
        result.message   = JsonGetString(response, "message");
        result.username  = JsonGetString(response, "username");
        result.avatar_url = JsonGetString(response, "avatar_url");
        result.expires_at = JsonGetString(response, "expires_at");

        return result;
    }

} // namespace NzStore
