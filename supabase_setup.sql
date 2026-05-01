-- ══════════════════════════════════════════════════════════════════════════════
-- Nz Store — Setup do Banco de Dados Supabase
-- Execute este script no SQL Editor do seu projeto Supabase
-- ══════════════════════════════════════════════════════════════════════════════

-- ── Tabela principal de usuários ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS public.users (
  id                   BIGSERIAL PRIMARY KEY,
  discord_id           TEXT        NOT NULL UNIQUE,
  discord_username     TEXT        NOT NULL DEFAULT '',
  discord_avatar_hash  TEXT,
  ativo                BOOLEAN     NOT NULL DEFAULT TRUE,
  expires_at           TIMESTAMPTZ,                        -- NULL = vitalício
  hwid                 TEXT,                               -- Hardware ID registrado
  hwid_locked          BOOLEAN     NOT NULL DEFAULT FALSE, -- Bloqueado por HWID inválido
  created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ── Índices para performance ──────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_users_discord_id  ON public.users (discord_id);
CREATE INDEX IF NOT EXISTS idx_users_ativo       ON public.users (ativo);
CREATE INDEX IF NOT EXISTS idx_users_expires_at  ON public.users (expires_at);

-- ── Trigger: atualiza updated_at automaticamente ──────────────────────────────
CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_users_updated_at ON public.users;
CREATE TRIGGER trg_users_updated_at
  BEFORE UPDATE ON public.users
  FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

-- ── Tabela de logs de autenticação (opcional, mas recomendado) ────────────────
CREATE TABLE IF NOT EXISTS public.auth_logs (
  id           BIGSERIAL PRIMARY KEY,
  discord_id   TEXT        NOT NULL,
  success      BOOLEAN     NOT NULL,
  message      TEXT,
  hwid         TEXT,
  ip_address   TEXT,
  created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_logs_discord_id ON public.auth_logs (discord_id);
CREATE INDEX IF NOT EXISTS idx_auth_logs_created_at ON public.auth_logs (created_at DESC);

-- ── Row Level Security (RLS) ──────────────────────────────────────────────────
-- O backend usa a SERVICE_KEY que bypassa RLS, mas é boa prática habilitar
ALTER TABLE public.users    ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.auth_logs ENABLE ROW LEVEL SECURITY;

-- Bloqueia acesso público direto (só o service role acessa)
CREATE POLICY "Deny public access to users"
  ON public.users FOR ALL
  USING (FALSE);

CREATE POLICY "Deny public access to auth_logs"
  ON public.auth_logs FOR ALL
  USING (FALSE);

-- ══════════════════════════════════════════════════════════════════════════════
-- COMO USAR:
-- 1. Acesse https://supabase.com → seu projeto → SQL Editor
-- 2. Cole todo este conteúdo e clique em "Run"
-- 3. Copie a SUPABASE_URL e SUPABASE_SERVICE_KEY em Project Settings → API
-- ══════════════════════════════════════════════════════════════════════════════
