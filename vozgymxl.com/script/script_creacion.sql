-- script_creacion.sql
-- Modelo de datos del registro de usuarios de VozGymXL para PostgreSQL 13 o
-- superior (local o Amazon RDS).
--
-- Es el ÚNICO script del modelo y siempre refleja el esquema vigente: si algo
-- cambia, se edita aquí. No hay migraciones ni ALTER TABLE; aplicarlo sobre una
-- base que ya tiene el modelo no la modifica, así que para llevar un cambio a
-- una base con datos hay que recrear el esquema (con respaldo previo).
--
--     psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f db/script_creacion.sql
--
-- Reglas que hace cumplir:
--   * Una aplicación puede compartir la base con otras: appid identifica la
--     aplicación que captó el registro.
--   * applanguage guarda el idioma efectivo del registro y solo admite los 20
--     códigos publicados por la aplicación.
--   * Un usuario por aplicación y correo vigente: el correo se guarda
--     normalizado en minúsculas (el API ya lo hace) y el índice único es
--     parcial, para que un correo suprimido pueda volver a registrarse.
--   * El mismo POST con el mismo appid y correo no duplica: el API resuelve el
--     upsert con ON CONFLICT.
--   * email_verified / email_verified_at dicen si el correo ya se confirmó:
--     cada POST lo deja en falso y solo el PUT lo activa.
--   * Un solo código vigente por usuario; los códigos vencen, se agotan por
--     intentos y nunca se guardan en claro (solo su HMAC-SHA256).
--   * Toda la persistencia la ejecuta el API: no hay funciones,
--     procedimientos ni triggers.

BEGIN;

-- ---------------------------------------------------------------------------
-- Usuarios registrados desde POST /api/app
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS app_users (
    id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),

    -- Identificador estable de la aplicación que captó el registro. Varias
    -- apps pueden compartir esta base y un mismo correo puede registrarse en
    -- cada una; appid + email es la clave de negocio.
    appid              text        NOT NULL,

    -- Idioma efectivo del registro. Se llama applanguage para distinguirlo de
    -- otros identificadores y usa los códigos de los 20 idiomas soportados.
    applanguage        text        NOT NULL DEFAULT 'en',

    -- Identidad y contacto. El correo completa la clave de negocio junto con
    -- appid: siempre va en minúsculas y sin espacios, porque así lo normaliza
    -- el API.
    email              text        NOT NULL,
    name               text        NOT NULL,

    -- Perfil declarado en el formulario.
    sex                text        NOT NULL,
    age                smallint    NOT NULL,
    experience         text        NOT NULL,

    -- Dispositivo desde el que se registró (lo envía el cliente).
    device_country     text,
    device_os          text        NOT NULL,
    device_os_version  text,

    -- Consentimiento de términos: la fecha permite acreditar cuándo se aceptó.
    terms_accepted     boolean     NOT NULL DEFAULT false,
    terms_accepted_at  timestamptz,

    -- Estado de verificación del correo: es el "si ya verificó o no".
    email_verified     boolean     NOT NULL DEFAULT false,
    email_verified_at  timestamptz,

    -- Fecha del último POST recibido (la escribe el API).
    last_registered_at timestamptz NOT NULL DEFAULT now(),

    -- Traza técnica de la llamada. Dato personal: ver retención en el README.
    origin_ip          inet,
    user_agent         text,

    -- Ciclo de vida. El API actualiza updated_at en cada escritura.
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    deleted_at         timestamptz,

    CONSTRAINT app_users_appid_valid CHECK (
        appid = lower(btrim(appid))
        AND appid ~ '^[a-z0-9][a-z0-9._-]{1,99}$'
    ),
    CONSTRAINT app_users_applanguage_valid CHECK (applanguage IN (
        'en', 'es', 'pt', 'it', 'ru', 'zh', 'ko', 'ja', 'fr', 'de',
        'tr', 'hi', 'ar', 'bn', 'id', 'ur', 'vi', 'nl', 'pl', 'uk'
    )),
    CONSTRAINT app_users_email_normalized CHECK (
        email = lower(btrim(email))
        AND position('@' IN email) > 1
        AND length(email) <= 254
    ),
    CONSTRAINT app_users_name_length CHECK (char_length(name) BETWEEN 2 AND 60),
    CONSTRAINT app_users_sex_valid CHECK (sex IN ('male', 'female', 'other')),
    -- Rango técnico de cordura: el rango de negocio lo define AGE_MIN/AGE_MAX
    -- del API, que puede cambiar sin tocar la base.
    CONSTRAINT app_users_age_sane CHECK (age BETWEEN 1 AND 120),
    CONSTRAINT app_users_experience_valid CHECK (experience IN ('beginner', 'intermediate', 'advanced')),
    CONSTRAINT app_users_device_country_valid CHECK (device_country IS NULL OR device_country ~ '^[A-Z]{2}$'),
    CONSTRAINT app_users_device_os_valid CHECK (device_os IN ('android', 'ios')),
    CONSTRAINT app_users_device_os_version_length CHECK (device_os_version IS NULL OR char_length(device_os_version) <= 40),
    CONSTRAINT app_users_terms_consistency CHECK (NOT terms_accepted OR terms_accepted_at IS NOT NULL),
    CONSTRAINT app_users_verified_consistency CHECK (NOT email_verified OR email_verified_at IS NOT NULL)
);

-- Clave única de negocio: un solo usuario vigente por aplicación y correo. El
-- id UUID sigue siendo la PK interna que relaciona los códigos. Al ser parcial,
-- un correo suprimido (derecho de supresión) puede volver a registrarse.
CREATE UNIQUE INDEX IF NOT EXISTS app_users_app_email_active_key
    ON app_users (appid, email)
    WHERE deleted_at IS NULL;

-- ---------------------------------------------------------------------------
-- Códigos de verificación enviados por correo
-- ---------------------------------------------------------------------------
-- Un usuario acumula códigos a lo largo del tiempo, pero solo uno vigente: el
-- API invalida el anterior al emitir uno nuevo. El índice único parcial sobre
-- las filas activas lo garantiza aunque el API tuviera un error.
--
-- code_hash guarda HMAC-SHA256(código) con una clave secreta del servidor
-- (CODE_PEPPER, fuera de la base). Un código de 5 dígitos tiene pocas
-- combinaciones: guardarlo en claro o con un SHA-256 simple permitiría
-- recuperarlo si la base se filtra.
CREATE TABLE IF NOT EXISTS verification_codes (
    id             bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id        uuid        NOT NULL REFERENCES app_users (id) ON DELETE CASCADE,
    code_hash      text        NOT NULL,
    sent_at        timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    attempts       smallint    NOT NULL DEFAULT 0,
    max_attempts   smallint    NOT NULL DEFAULT 5,
    consumed_at    timestamptz,
    invalidated_at timestamptz,

    CONSTRAINT verification_codes_hash_format CHECK (code_hash ~ '^[0-9a-f]{64}$'),
    CONSTRAINT verification_codes_window_valid CHECK (expires_at > sent_at),
    CONSTRAINT verification_codes_max_attempts_valid CHECK (max_attempts BETWEEN 1 AND 10),
    CONSTRAINT verification_codes_attempts_valid CHECK (attempts BETWEEN 0 AND max_attempts),
    -- Un código no puede estar consumido e invalidado a la vez.
    CONSTRAINT verification_codes_terminal_exclusive CHECK (consumed_at IS NULL OR invalidated_at IS NULL)
);

-- Solo un código vigente por usuario: consumido o invalidado deja de contar.
CREATE UNIQUE INDEX IF NOT EXISTS verification_codes_active_key
    ON verification_codes (user_id)
    WHERE consumed_at IS NULL AND invalidated_at IS NULL;

-- Purga de códigos resueltos (la ejecuta el API; ver README sección 4.3).
CREATE INDEX IF NOT EXISTS verification_codes_expiry_idx
    ON verification_codes (expires_at);

COMMIT;
