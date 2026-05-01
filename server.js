require('dotenv').config();
const express  = require('express');
const cors     = require('cors');
const https    = require('https');
const { createClient } = require('@supabase/supabase-js');
const path     = require('path');

const app = express();
app.use(express.json());
app.use(cors());

// Serve o painel admin
app.use(express.static(path.join(__dirname, 'admin')));
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'admin', 'index.html'));
});

// ── Validação de variáveis obrigatórias ───────────────────────────────────────
if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_KEY) {
  console.error('[NzStore] ERRO: SUPABASE_URL e SUPABASE_SERVICE_KEY são obrigatórios no .env');
  process.exit(1);
}

const supabase          = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const ADMIN_PASSWORD    = process.env.ADMIN_PASSWORD    || 'admin123';
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN || '';

// ── Busca usuário no Discord ──────────────────────────────────────────────────
function fetchDiscordUser(discord_id) {
  return new Promise((resolve) => {
    const options = {
      hostname: 'discord.com',
      path: `/api/v10/users/${discord_id}`,
      method: 'GET',
      headers: {
        'Authorization': `Bot ${DISCORD_BOT_TOKEN}`,
        'User-Agent': 'NzStore/1.0'
      }
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { const j = JSON.parse(data); resolve(j.id ? j : null); }
        catch { resolve(null); }
      });
    });
    req.on('error', () => resolve(null));
    req.end();
  });
}

// ── Formata data de expiração ─────────────────────────────────────────────────
function formatExpiry(expires_at) {
  if (!expires_at) return 'Vitalicio';
  const d = new Date(expires_at);
  return d.toLocaleDateString('pt-BR', { day: '2-digit', month: '2-digit', year: 'numeric' });
}

// ── Salva log de autenticação ─────────────────────────────────────────────────
async function saveAuthLog(discord_id, success, message, hwid, ip) {
  try {
    await supabase.from('auth_logs').insert({
      discord_id,
      success,
      message,
      hwid: hwid || null,
      ip_address: ip || null
    });
  } catch (_) { /* log não crítico */ }
}

// ── POST /api/auth ────────────────────────────────────────────────────────────
app.post('/api/auth', async (req, res) => {
  const { discord_id, hwid } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';

  if (!discord_id || typeof discord_id !== 'string') {
    return res.status(400).json({ success: false, message: 'discord_id invalido.' });
  }

  const cleanId   = discord_id.trim();
  const cleanHwid = (hwid || '').trim();

  const { data, error } = await supabase
    .from('users')
    .select('discord_id, discord_username, discord_avatar_hash, ativo, expires_at, hwid, hwid_locked')
    .eq('discord_id', cleanId)
    .single();

  if (error || !data) {
    await saveAuthLog(cleanId, false, 'ID nao autorizado.', cleanHwid, ip);
    return res.status(200).json({ success: false, message: 'ID nao autorizado.' });
  }

  if (!data.ativo) {
    await saveAuthLog(cleanId, false, 'Acesso desativado.', cleanHwid, ip);
    return res.status(200).json({ success: false, message: 'Acesso desativado.' });
  }

  if (data.expires_at && new Date(data.expires_at) < new Date()) {
    await saveAuthLog(cleanId, false, 'Acesso expirado.', cleanHwid, ip);
    return res.status(200).json({ success: false, message: 'Acesso expirado.' });
  }

  // ── HWID check ────────────────────────────────────────────────────────────
  if (data.hwid_locked) {
    await saveAuthLog(cleanId, false, 'Conta bloqueada por HWID invalido.', cleanHwid, ip);
    return res.status(200).json({ success: false, message: 'Conta bloqueada por HWID invalido. Contate o suporte.' });
  }

  if (!data.hwid) {
    // Primeiro login — registra o HWID
    if (cleanHwid) {
      await supabase.from('users').update({ hwid: cleanHwid }).eq('discord_id', cleanId);
    }
  } else {
    // HWID já registrado — valida
    if (cleanHwid && cleanHwid !== data.hwid) {
      await supabase.from('users').update({ hwid_locked: true }).eq('discord_id', cleanId);
      await saveAuthLog(cleanId, false, 'HWID invalido. Conta bloqueada.', cleanHwid, ip);
      return res.status(200).json({ success: false, message: 'HWID invalido. Conta bloqueada.' });
    }
  }

  // ── Atualiza dados do Discord em tempo real ───────────────────────────────
  let username   = data.discord_username;
  let avatarHash = data.discord_avatar_hash;

  if (DISCORD_BOT_TOKEN) {
    const du = await fetchDiscordUser(cleanId);
    if (du) {
      const newName   = du.global_name || du.username || username;
      const newAvatar = du.avatar || avatarHash;
      if (newName !== username || newAvatar !== avatarHash) {
        await supabase.from('users').update({
          discord_username:    newName,
          discord_avatar_hash: newAvatar
        }).eq('discord_id', cleanId);
      }
      username   = newName;
      avatarHash = newAvatar;
    }
  }

  // ── Monta avatar URL ──────────────────────────────────────────────────────
  let avatar_url = '';
  if (avatarHash) {
    const ext = avatarHash.startsWith('a_') ? 'gif' : 'png';
    avatar_url = `https://cdn.discordapp.com/avatars/${data.discord_id}/${avatarHash}.${ext}?size=128`;
  } else {
    const idx = (BigInt(data.discord_id) >> 22n) % 6n;
    avatar_url = `https://cdn.discordapp.com/embed/avatars/${idx}.png`;
  }

  await saveAuthLog(cleanId, true, 'Autorizado.', cleanHwid, ip);

  return res.status(200).json({
    success:    true,
    username,
    avatar_url,
    expires_at: formatExpiry(data.expires_at),
    message:    'Autorizado.'
  });
});

// ── POST /api/admin/add ───────────────────────────────────────────────────────
app.post('/api/admin/add', async (req, res) => {
  const { password, discord_id, discord_username, discord_avatar_hash, expires_at } = req.body;

  if (password !== ADMIN_PASSWORD)
    return res.status(401).json({ success: false, message: 'Senha incorreta.' });
  if (!discord_id)
    return res.status(400).json({ success: false, message: 'discord_id obrigatorio.' });

  let username   = discord_username   ? discord_username.trim()   : '';
  let avatarHash = discord_avatar_hash ? discord_avatar_hash.trim() : null;

  if (DISCORD_BOT_TOKEN) {
    const du = await fetchDiscordUser(discord_id.trim());
    if (du) {
      username   = du.global_name || du.username || username;
      avatarHash = du.avatar || avatarHash;
    }
  }

  if (!username)
    return res.status(400).json({ success: false, message: 'Nao foi possivel obter o username. Informe manualmente.' });

  const expiresValue = (expires_at && expires_at.trim()) ? new Date(expires_at).toISOString() : null;

  const { error } = await supabase.from('users').upsert({
    discord_id:          discord_id.trim(),
    discord_username:    username,
    discord_avatar_hash: avatarHash,
    ativo:               true,
    expires_at:          expiresValue
  }, { onConflict: 'discord_id' });

  if (error) return res.status(500).json({ success: false, message: error.message });
  return res.status(200).json({ success: true, message: 'Usuario adicionado/atualizado com sucesso.' });
});

// ── POST /api/admin/toggle ────────────────────────────────────────────────────
app.post('/api/admin/toggle', async (req, res) => {
  const { password, discord_id, ativo } = req.body;
  if (password !== ADMIN_PASSWORD)
    return res.status(401).json({ success: false, message: 'Senha incorreta.' });

  const { error } = await supabase.from('users').update({ ativo: Boolean(ativo) }).eq('discord_id', discord_id);
  if (error) return res.status(500).json({ success: false, message: error.message });
  return res.status(200).json({ success: true, message: `Usuario ${ativo ? 'ativado' : 'desativado'}.` });
});

// ── POST /api/admin/remove ────────────────────────────────────────────────────
app.post('/api/admin/remove', async (req, res) => {
  const { password, discord_id } = req.body;
  if (password !== ADMIN_PASSWORD)
    return res.status(401).json({ success: false, message: 'Senha incorreta.' });

  const { error } = await supabase.from('users').delete().eq('discord_id', discord_id);
  if (error) return res.status(500).json({ success: false, message: error.message });
  return res.status(200).json({ success: true, message: 'Usuario removido.' });
});

// ── GET /api/admin/users ──────────────────────────────────────────────────────
app.get('/api/admin/users', async (req, res) => {
  const { password } = req.query;
  if (password !== ADMIN_PASSWORD)
    return res.status(401).json({ success: false, message: 'Senha incorreta.' });

  const { data, error } = await supabase
    .from('users')
    .select('discord_id, discord_username, discord_avatar_hash, ativo, expires_at, hwid, hwid_locked, created_at')
    .order('discord_username');

  if (error) return res.status(500).json({ success: false, message: error.message });
  return res.status(200).json({ success: true, users: data });
});

// ── POST /api/admin/reset-hwid ────────────────────────────────────────────────
app.post('/api/admin/reset-hwid', async (req, res) => {
  const { password, discord_id } = req.body;
  if (password !== ADMIN_PASSWORD)
    return res.status(401).json({ success: false, message: 'Senha incorreta.' });

  const { error } = await supabase
    .from('users')
    .update({ hwid: null, hwid_locked: false })
    .eq('discord_id', discord_id);

  if (error) return res.status(500).json({ success: false, message: error.message });
  return res.status(200).json({ success: true, message: 'HWID resetado com sucesso.' });
});

// ── GET /api/admin/logs ───────────────────────────────────────────────────────
app.get('/api/admin/logs', async (req, res) => {
  const { password, discord_id, limit = 50 } = req.query;
  if (password !== ADMIN_PASSWORD)
    return res.status(401).json({ success: false, message: 'Senha incorreta.' });

  let query = supabase
    .from('auth_logs')
    .select('discord_id, success, message, hwid, ip_address, created_at')
    .order('created_at', { ascending: false })
    .limit(Number(limit));

  if (discord_id) query = query.eq('discord_id', discord_id);

  const { data, error } = await query;
  if (error) return res.status(500).json({ success: false, message: error.message });
  return res.status(200).json({ success: true, logs: data });
});

// ── POST /api/integrar ────────────────────────────────────────────────────────
// Recebe o código original do usuário, injeta a integração Nz Store e devolve
// Body: { password, lang: 'csharp' | 'cpp', code: string, api_url: string }
app.post('/api/integrar', (req, res) => {
  const { password, lang, code, api_url } = req.body;

  if (password !== ADMIN_PASSWORD)
    return res.status(401).json({ success: false, message: 'Senha incorreta.' });
  if (!lang || !code)
    return res.status(400).json({ success: false, message: 'lang e code sao obrigatorios.' });

  const url = (api_url || '').trim() || 'https://SEU-PROJETO.vercel.app';

  // ── C# ────────────────────────────────────────────────────────────────────
  if (lang === 'csharp') {
    // Detecta namespace do projeto no Form1.cs enviado
    const nsMatch = code.match(/^namespace\s+([\w.]+)/m);
    const ns = nsMatch ? nsMatch[1] : 'SeuProjeto';

    // Bloco de integração que será injetado
    const integrationBlock = `
// ══════════════════════════════════════════════════════
// NZ STORE — INTEGRAÇÃO GERADA AUTOMATICAMENTE
// Adicione NzStore.cs ao seu projeto antes de compilar
// ══════════════════════════════════════════════════════
using System.Net.Http;
using System.Drawing;`;

    const loginMethod = `
        // ── NZ STORE: chame este método no clique do seu botão de login ──────
        private async void NzLogin(string discordId)
        {
            // Desabilita UI durante verificação
            // btnSeuBotao.Enabled = false;

            var result = await NzStore.Auth.LoginAsync(discordId);

            if (result.Success)
            {
                // ✅ AUTORIZADO — preencha com os nomes dos seus controles:
                // lblNome.Text     = result.Username;
                // lblValidade.Text = result.ExpiresAt;
                // picAvatar.Load(result.AvatarUrl);   // PictureBox com SizeMode=Zoom
                //
                // Ou carregue o avatar manualmente (sem Load):
                // using var http = new HttpClient();
                // var bytes = await http.GetByteArrayAsync(result.AvatarUrl);
                // picAvatar.Image = Image.FromStream(new System.IO.MemoryStream(bytes));
                //
                // Mostre seu painel principal:
                // pnlLogin.Visible = false;
                // pnlMain.Visible  = true;
            }
            else
            {
                // ❌ NEGADO — mostre o erro no seu label de status:
                // lblErro.Text      = result.Message;
                // lblErro.ForeColor = Color.FromArgb(229, 115, 115);
            }

            // btnSeuBotao.Enabled = true;
        }`;

    // Injeta o using no topo e o método antes do último }
    let output = code;

    // Adiciona usings se não existirem
    if (!output.includes('using System.Net.Http'))
      output = output.replace(/^(using System;)/m, 'using System;\nusing System.Net.Http;\nusing System.Drawing;');

    // Injeta o método NzLogin antes do último fechamento de classe
    const lastBrace = output.lastIndexOf('}');
    output = output.slice(0, lastBrace) + loginMethod + '\n    }\n}';

    // Adiciona comentário de instrução no topo
    const header = `// NZ STORE — Integração gerada em ${new Date().toLocaleDateString('pt-BR')}
// API URL configurada: ${url}
// Passos:
//   1. Adicione NzStore.cs ao seu projeto (baixe abaixo)
//   2. Chame NzLogin(txtDiscordId.Text) no clique do seu botão
//   3. Preencha os comentários com os nomes dos seus controles
\n`;
    output = header + output;

    // Gera o NzStore.cs com a URL correta
    const nzstoreCs = generateNzStoreCs(url);

    return res.json({
      success: true,
      files: [
        { name: 'Form1.cs',   content: output },
        { name: 'NzStore.cs', content: nzstoreCs }
      ]
    });
  }

  // ── C++ ───────────────────────────────────────────────────────────────────
  if (lang === 'cpp') {
    const loginBlock = `
// ══════════════════════════════════════════════════════════════════════════
// NZ STORE — INTEGRAÇÃO GERADA AUTOMATICAMENTE
// Adicione nzstore.h e nzstore.cpp ao seu projeto antes de compilar
// Link: winhttp.lib, wbemuuid.lib, ole32.lib, oleaut32.lib, advapi32.lib
// API URL configurada: ${url}
// ══════════════════════════════════════════════════════════════════════════
#include "nzstore.h"

// Chame esta função no início do seu main() ou onde quiser autenticar:
//
//   NzStore::AuthResult auth = NzStore::Login(discordId);
//   if (auth.success) {
//       // auth.username   → nome do usuário
//       // auth.expires_at → validade
//       // auth.avatar_url → URL da foto do Discord
//       // Seu código aqui...
//   } else {
//       // auth.message → motivo da negação
//   }
//
// Exemplo completo de uso no main():
//
//   std::string id;
//   std::cout << "Discord ID: ";
//   std::getline(std::cin, id);
//
//   auto auth = NzStore::Login(id);
//   if (!auth.success) {
//       std::cout << "[NEGADO] " << auth.message << std::endl;
//       return 1;
//   }
//   std::cout << "Bem-vindo, " << auth.username << "!" << std::endl;
//   std::cout << "Validade: "  << auth.expires_at << std::endl;
//   // ... seu código continua aqui ...
`;

    // Injeta o bloco logo após os #includes existentes ou no topo
    let output = code;
    const includeEnd = output.lastIndexOf('#include');
    if (includeEnd !== -1) {
      const lineEnd = output.indexOf('\n', includeEnd);
      output = output.slice(0, lineEnd + 1) + loginBlock + output.slice(lineEnd + 1);
    } else {
      output = loginBlock + '\n' + output;
    }

    const nzstoreCpp = generateNzStoreCpp(url);
    const nzstoreH   = generateNzStoreH();

    return res.json({
      success: true,
      files: [
        { name: 'main.cpp',    content: output },
        { name: 'nzstore.cpp', content: nzstoreCpp },
        { name: 'nzstore.h',   content: nzstoreH }
      ]
    });
  }

  return res.status(400).json({ success: false, message: 'lang deve ser "csharp" ou "cpp".' });
});

// ── Geradores de código ───────────────────────────────────────────────────────
function generateNzStoreCs(apiUrl) {
  return `// NzStore.cs — gerado automaticamente pela Nz Store
// Adicione este arquivo ao seu projeto C# (não edite)
using System;
using System.Management;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace NzStore
{
    public class AuthResponse
    {
        [JsonPropertyName("success")]   public bool   Success   { get; set; }
        [JsonPropertyName("message")]   public string Message   { get; set; } = "";
        [JsonPropertyName("username")]  public string Username  { get; set; } = "";
        [JsonPropertyName("avatar_url")]public string AvatarUrl { get; set; } = "";
        [JsonPropertyName("expires_at")]public string ExpiresAt { get; set; } = "";
    }

    public class LoginResult
    {
        public bool   Success   { get; set; }
        public string Message   { get; set; } = "";
        public string Username  { get; set; } = "";
        public string AvatarUrl { get; set; } = "";
        public string ExpiresAt { get; set; } = "";
    }

    public static class Auth
    {
        private const string API_URL = "${apiUrl}/api/auth";
        private static readonly HttpClient _http = new HttpClient { Timeout = TimeSpan.FromSeconds(10) };

        public static string GetHwid()
        {
            try
            {
                string cpu  = Wmi("Win32_Processor",  "ProcessorId");
                string disk = Wmi("Win32_DiskDrive",  "SerialNumber");
                string mb   = Wmi("Win32_BaseBoard",  "SerialNumber");
                var bytes   = SHA256.HashData(Encoding.UTF8.GetBytes($"{cpu}-{disk}-{mb}"));
                return BitConverter.ToString(bytes).Replace("-","").ToLower();
            }
            catch
            {
                var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(
                    Environment.MachineName + Environment.UserName));
                return BitConverter.ToString(bytes).Replace("-","").ToLower();
            }
        }

        private static string Wmi(string cls, string prop)
        {
            using var s = new System.Management.ManagementObjectSearcher($"SELECT {prop} FROM {cls}");
            foreach (System.Management.ManagementObject o in s.Get())
            {
                var v = o[prop]?.ToString()?.Trim();
                if (!string.IsNullOrEmpty(v)) return v;
            }
            return "unknown";
        }

        public static async Task<LoginResult> LoginAsync(string discordId)
        {
            if (string.IsNullOrWhiteSpace(discordId))
                return Fail("Discord ID nao pode ser vazio.");
            try
            {
                var body    = JsonSerializer.Serialize(new { discord_id = discordId.Trim(), hwid = GetHwid() });
                var content = new StringContent(body, Encoding.UTF8, "application/json");
                var resp    = await _http.PostAsync(API_URL, content);
                var json    = await resp.Content.ReadAsStringAsync();
                var r       = JsonSerializer.Deserialize<AuthResponse>(json);
                if (r == null) return Fail("Resposta invalida do servidor.");
                return new LoginResult { Success=r.Success, Message=r.Message, Username=r.Username, AvatarUrl=r.AvatarUrl, ExpiresAt=r.ExpiresAt };
            }
            catch (TaskCanceledException) { return Fail("Tempo esgotado. Verifique sua internet."); }
            catch (HttpRequestException)  { return Fail("Sem conexao com o servidor."); }
            catch (Exception ex)          { return Fail("Erro: " + ex.Message); }
        }

        public static LoginResult Login(string discordId) => LoginAsync(discordId).GetAwaiter().GetResult();
        private static LoginResult Fail(string m) => new LoginResult { Success = false, Message = m };
    }
}
`;
}

function generateNzStoreH() {
  return `#pragma once
// nzstore.h — gerado automaticamente pela Nz Store
#ifndef NZSTORE_H
#define NZSTORE_H
#include <string>
namespace NzStore {
    struct AuthResult {
        bool        success   = false;
        std::string message;
        std::string username;
        std::string avatar_url;
        std::string expires_at;
    };
    std::string GetHwid();
    AuthResult  Login(const std::string& discord_id);
}
#endif
`;
}

function generateNzStoreCpp(apiUrl) {
  const host = apiUrl.replace(/^https?:\/\//, '').split('/')[0];
  return `// nzstore.cpp — gerado automaticamente pela Nz Store
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
#pragma comment(lib,"winhttp.lib")
#pragma comment(lib,"wbemuuid.lib")
#pragma comment(lib,"ole32.lib")
#pragma comment(lib,"oleaut32.lib")
#pragma comment(lib,"advapi32.lib")

namespace NzStore {
static const wchar_t* API_HOST = L"${host}";
static const wchar_t* API_PATH = L"/api/auth";

static std::string WstrToStr(const std::wstring& w){
    if(w.empty())return{};
    int n=WideCharToMultiByte(CP_UTF8,0,w.c_str(),-1,nullptr,0,nullptr,nullptr);
    std::string r(n-1,'\\0');
    WideCharToMultiByte(CP_UTF8,0,w.c_str(),-1,&r[0],n,nullptr,nullptr);
    return r;
}
static std::string Sha256Hex(const std::string& s){
    HCRYPTPROV p=0;HCRYPTHASH h=0;std::string r;
    if(!CryptAcquireContextA(&p,nullptr,nullptr,PROV_RSA_AES,CRYPT_VERIFYCONTEXT))return"unknown";
    CryptCreateHash(p,CALG_SHA_256,0,0,&h);
    CryptHashData(h,(const BYTE*)s.c_str(),(DWORD)s.size(),0);
    DWORD l=32;BYTE b[32]={};CryptGetHashParam(h,HP_HASHVAL,b,&l,0);
    std::ostringstream o;for(int i=0;i<32;i++)o<<std::hex<<std::setw(2)<<std::setfill('0')<<(int)b[i];
    r=o.str();CryptDestroyHash(h);CryptReleaseContext(p,0);return r;
}
static std::string WmiVal(const wchar_t* cls,const wchar_t* prop){
    std::string r;CoInitializeEx(nullptr,COINIT_MULTITHREADED);
    IWbemLocator*pL=nullptr;IWbemServices*pS=nullptr;
    if(FAILED(CoCreateInstance(CLSID_WbemLocator,nullptr,CLSCTX_INPROC_SERVER,IID_IWbemLocator,(LPVOID*)&pL))){CoUninitialize();return"unknown";}
    if(FAILED(pL->ConnectServer(_bstr_t(L"ROOT\\\\CIMV2"),nullptr,nullptr,nullptr,0,nullptr,nullptr,&pS))){pL->Release();CoUninitialize();return"unknown";}
    CoSetProxyBlanket(pS,RPC_C_AUTHN_WINNT,RPC_C_AUTHZ_NONE,nullptr,RPC_C_AUTHN_LEVEL_CALL,RPC_C_IMP_LEVEL_IMPERSONATE,nullptr,EOAC_NONE);
    std::wstring q=std::wstring(L"SELECT ")+prop+L" FROM "+cls;
    IEnumWbemClassObject*pE=nullptr;
    if(SUCCEEDED(pS->ExecQuery(_bstr_t(L"WQL"),_bstr_t(q.c_str()),WBEM_FLAG_FORWARD_ONLY|WBEM_FLAG_RETURN_IMMEDIATELY,nullptr,&pE))&&pE){
        IWbemClassObject*pO=nullptr;ULONG ret=0;
        if(pE->Next(WBEM_INFINITE,1,&pO,&ret)==S_OK&&pO){
            VARIANT v;VariantInit(&v);
            if(SUCCEEDED(pO->Get(prop,0,&v,nullptr,nullptr))&&v.vt==VT_BSTR&&v.bstrVal)r=WstrToStr(v.bstrVal);
            VariantClear(&v);pO->Release();
        }pE->Release();
    }pS->Release();pL->Release();CoUninitialize();
    while(!r.empty()&&r.back()==' ')r.pop_back();
    return r.empty()?"unknown":r;
}
std::string GetHwid(){
    return Sha256Hex(WmiVal(L"Win32_Processor",L"ProcessorId")+"-"+
                     WmiVal(L"Win32_DiskDrive",L"SerialNumber")+"-"+
                     WmiVal(L"Win32_BaseBoard",L"SerialNumber"));
}
static std::string HttpPost(const std::string& body){
    std::string resp;
    HINTERNET hS=WinHttpOpen(L"NzStore/1.0",WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0);
    if(!hS)return"";
    HINTERNET hC=WinHttpConnect(hS,API_HOST,INTERNET_DEFAULT_HTTPS_PORT,0);
    if(!hC){WinHttpCloseHandle(hS);return"";}
    HINTERNET hR=WinHttpOpenRequest(hC,L"POST",API_PATH,nullptr,WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,WINHTTP_FLAG_SECURE);
    if(!hR){WinHttpCloseHandle(hC);WinHttpCloseHandle(hS);return"";}
    DWORD sf=SECURITY_FLAG_IGNORE_UNKNOWN_CA|SECURITY_FLAG_IGNORE_CERT_DATE_INVALID|SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
    WinHttpSetOption(hR,WINHTTP_OPTION_SECURITY_FLAGS,&sf,sizeof(sf));
    std::wstring hdr=L"Content-Type: application/json\\r\\n";
    if(WinHttpSendRequest(hR,hdr.c_str(),(DWORD)hdr.size(),(LPVOID)body.c_str(),(DWORD)body.size(),(DWORD)body.size(),0)&&WinHttpReceiveResponse(hR,nullptr)){
        DWORD av=0;
        while(WinHttpQueryDataAvailable(hR,&av)&&av>0){
            std::string c(av,'\\0');DWORD rd=0;
            WinHttpReadData(hR,&c[0],av,&rd);c.resize(rd);resp+=c;
        }
    }
    WinHttpCloseHandle(hR);WinHttpCloseHandle(hC);WinHttpCloseHandle(hS);return resp;
}
static std::string JStr(const std::string& j,const std::string& k){
    std::string s="\\""+k+"\\"";size_t p=j.find(s);if(p==std::string::npos)return"";
    p=j.find(':',p+s.size());if(p==std::string::npos)return"";
    p++;while(p<j.size()&&j[p]==' ')p++;
    if(p>=j.size())return"";
    if(j[p]=='"'){p++;std::string v;while(p<j.size()&&j[p]!='"'){if(j[p]=='\\\\'&&p+1<j.size()){p++;v+=j[p];}else v+=j[p];p++;}return v;}
    size_t e=j.find_first_of(",}",p);if(e==std::string::npos)e=j.size();
    std::string v=j.substr(p,e-p);while(!v.empty()&&v.back()==' ')v.pop_back();return v;
}
AuthResult Login(const std::string& discord_id){
    AuthResult r;
    if(discord_id.empty()){r.message="Discord ID nao pode ser vazio.";return r;}
    std::string body="{\\"discord_id\\":\\""+discord_id+"\\",\\"hwid\\":\\""+GetHwid()+"\\"}";
    std::string resp=HttpPost(body);
    if(resp.empty()){r.message="Sem conexao com o servidor.";return r;}
    r.success   =(JStr(resp,"success")=="true");
    r.message   =JStr(resp,"message");
    r.username  =JStr(resp,"username");
    r.avatar_url=JStr(resp,"avatar_url");
    r.expires_at=JStr(resp,"expires_at");
    return r;
}
}
`;
}

// ── GET /api/ping ─────────────────────────────────────────────────────────────
app.get('/api/ping', (req, res) => res.status(200).json({ status: 'ok', service: 'NzStore' }));

// Exporta para Vercel (serverless) e roda local normalmente
if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => console.log(`[NzStore] Server running on port ${PORT}`));
}

module.exports = app;
