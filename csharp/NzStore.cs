// ══════════════════════════════════════════════════════════════════════════════
//  Nz Store — Biblioteca de Autenticação para C#
//  Arquivo: NzStore.cs
//  Uso: Adicione este arquivo ao seu projeto e chame NzStore.Auth.Login(...)
// ══════════════════════════════════════════════════════════════════════════════

using System;
using System.Management;          // Para HWID — adicione referência System.Management
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace NzStore
{
    // ── Resposta da API ───────────────────────────────────────────────────────
    public class AuthResponse
    {
        [JsonPropertyName("success")]
        public bool Success { get; set; }

        [JsonPropertyName("message")]
        public string Message { get; set; } = string.Empty;

        [JsonPropertyName("username")]
        public string Username { get; set; } = string.Empty;

        [JsonPropertyName("avatar_url")]
        public string AvatarUrl { get; set; } = string.Empty;

        [JsonPropertyName("expires_at")]
        public string ExpiresAt { get; set; } = string.Empty;
    }

    // ── Resultado retornado ao Form ───────────────────────────────────────────
    public class LoginResult
    {
        public bool    Success    { get; set; }
        public string  Message    { get; set; } = string.Empty;
        public string  Username   { get; set; } = string.Empty;
        public string  AvatarUrl  { get; set; } = string.Empty;
        public string  ExpiresAt  { get; set; } = string.Empty;
    }

    // ── Classe principal ──────────────────────────────────────────────────────
    public static class Auth
    {
        // !! ALTERE PARA A URL DO SEU SERVIDOR (Vercel ou local) !!
        private const string API_URL = "https://SEU-PROJETO.vercel.app/api/auth";

        private static readonly HttpClient _http = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(10)
        };

        // ── Gera HWID único da máquina ────────────────────────────────────────
        public static string GetHwid()
        {
            try
            {
                string cpu  = GetWmiValue("Win32_Processor",  "ProcessorId");
                string disk = GetWmiValue("Win32_DiskDrive",  "SerialNumber");
                string mb   = GetWmiValue("Win32_BaseBoard",  "SerialNumber");

                string raw  = $"{cpu}-{disk}-{mb}";
                // Hash SHA256 para não expor dados brutos
                using var sha = System.Security.Cryptography.SHA256.Create();
                byte[] bytes  = sha.ComputeHash(Encoding.UTF8.GetBytes(raw));
                return BitConverter.ToString(bytes).Replace("-", "").ToLower();
            }
            catch
            {
                // Fallback: usa nome da máquina + usuário
                string fallback = $"{Environment.MachineName}-{Environment.UserName}";
                using var sha   = System.Security.Cryptography.SHA256.Create();
                byte[] bytes    = sha.ComputeHash(Encoding.UTF8.GetBytes(fallback));
                return BitConverter.ToString(bytes).Replace("-", "").ToLower();
            }
        }

        private static string GetWmiValue(string wmiClass, string property)
        {
            try
            {
                using var searcher = new ManagementObjectSearcher($"SELECT {property} FROM {wmiClass}");
                foreach (ManagementObject obj in searcher.Get())
                {
                    var val = obj[property]?.ToString()?.Trim();
                    if (!string.IsNullOrEmpty(val)) return val;
                }
            }
            catch { }
            return "unknown";
        }

        // ── Login principal ───────────────────────────────────────────────────
        public static async Task<LoginResult> LoginAsync(string discordId)
        {
            if (string.IsNullOrWhiteSpace(discordId))
                return Fail("Discord ID não pode ser vazio.");

            string hwid = GetHwid();

            var payload = new
            {
                discord_id = discordId.Trim(),
                hwid       = hwid
            };

            string json = JsonSerializer.Serialize(payload);

            try
            {
                var content  = new StringContent(json, Encoding.UTF8, "application/json");
                var response = await _http.PostAsync(API_URL, content);
                string body  = await response.Content.ReadAsStringAsync();

                var result = JsonSerializer.Deserialize<AuthResponse>(body);

                if (result == null)
                    return Fail("Resposta inválida do servidor.");

                return new LoginResult
                {
                    Success   = result.Success,
                    Message   = result.Message,
                    Username  = result.Username,
                    AvatarUrl = result.AvatarUrl,
                    ExpiresAt = result.ExpiresAt
                };
            }
            catch (TaskCanceledException)
            {
                return Fail("Tempo de conexão esgotado. Verifique sua internet.");
            }
            catch (HttpRequestException)
            {
                return Fail("Sem conexão com o servidor. Verifique sua internet.");
            }
            catch (Exception ex)
            {
                return Fail($"Erro inesperado: {ex.Message}");
            }
        }

        // ── Versão síncrona (para uso sem async/await) ────────────────────────
        public static LoginResult Login(string discordId)
            => LoginAsync(discordId).GetAwaiter().GetResult();

        private static LoginResult Fail(string msg)
            => new LoginResult { Success = false, Message = msg };
    }
}
