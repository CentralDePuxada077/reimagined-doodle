#pragma once
// ══════════════════════════════════════════════════════════════════════════════
//  Nz Store — Header de Autenticação para C++
//  Arquivo: nzstore.h
//  Inclua este header e adicione nzstore.cpp ao seu projeto
// ══════════════════════════════════════════════════════════════════════════════

#ifndef NZSTORE_H
#define NZSTORE_H

#include <string>

namespace NzStore
{
    // ── Resultado do login ────────────────────────────────────────────────────
    struct AuthResult
    {
        bool        success   = false;
        std::string message;
        std::string username;
        std::string avatar_url;
        std::string expires_at;
    };

    // ── Funções públicas ──────────────────────────────────────────────────────

    // Gera o HWID único da máquina (hash SHA256 de CPU + Disco + Placa-mãe)
    std::string GetHwid();

    // Autentica o usuário com o servidor Nz Store
    // discord_id: ID numérico do Discord (string)
    // Retorna AuthResult com success=true e dados do usuário se autorizado
    AuthResult Login(const std::string& discord_id);

} // namespace NzStore

#endif // NZSTORE_H
