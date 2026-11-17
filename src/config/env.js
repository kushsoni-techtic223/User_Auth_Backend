require('dotenv').config();

function required(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

const env = {
  nodeEnv: process.env.NODE_ENV || 'development',
  port: Number(process.env.SERVER_PORT || process.env.PORT || 3000),
  jwtAccessSecret: required('JWT_ACCESS_SECRET'),
  jwtRefreshSecret: required('JWT_REFRESH_SECRET'),
  accessTokenTtl: process.env.ACCESS_TOKEN_TTL || '15m',
  refreshTokenTtlDays: Number(process.env.REFRESH_TOKEN_TTL_DAYS || 7),
  bcryptRounds: Number(process.env.BCRYPT_ROUNDS || 12),
  maxFailedLogins: Number(process.env.MAX_FAILED_LOGINS || 5),
  lockoutMinutes: Number(process.env.LOCKOUT_MINUTES || 15),
  privacyPolicyVersion: process.env.PRIVACY_POLICY_VERSION || '1.0.0',
  termsVersion: process.env.TERMS_VERSION || '1.0.0',
  cookieSecure: process.env.COOKIE_SECURE === 'true',
  cookieSameSite: process.env.COOKIE_SAME_SITE || 'lax',
  isProd: (process.env.NODE_ENV || 'development') === 'production',
};

module.exports = { env };
