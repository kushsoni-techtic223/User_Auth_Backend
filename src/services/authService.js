const { env } = require('../config/env');
const { hashPassword, verifyPassword, nowIso } = require('../utils/crypto');
const { writeAuditLog } = require('./auditService');
const userService = require('./userService');
const tokenService = require('./tokenService');

class AuthError extends Error {
  constructor(message, statusCode = 400, code = 'AUTH_ERROR') {
    super(message);
    this.statusCode = statusCode;
    this.code = code;
  }
}

function requestMeta(req) {
  return {
    ipAddress: req.ip || req.headers['x-forwarded-for'] || null,
    userAgent: req.get('user-agent') || null,
  };
}

async function register(payload, req) {
  const existing = userService.findActiveUserByEmail(payload.email);
  if (existing) {
    throw new AuthError('An account with this email already exists', 409, 'EMAIL_EXISTS');
  }

  const passwordHash = await hashPassword(payload.password);
  const user = userService.createUser({
    email: payload.email,
    passwordHash,
    displayName: payload.displayName,
    privacyPolicyVersion: env.privacyPolicyVersion,
    termsVersion: env.termsVersion,
    consentMarketing: payload.consentMarketing,
  });

  const verify = tokenService.createEmailToken(user.id, 'verify_email', 24);
  const meta = requestMeta(req);

  writeAuditLog({
    userId: user.id,
    eventType: 'user.registered',
    ...meta,
    metadata: {
      privacyPolicyVersion: env.privacyPolicyVersion,
      termsVersion: env.termsVersion,
      consentMarketing: Boolean(payload.consentMarketing),
    },
  });

  // In production, send verify.rawToken via email only — never log it.
  // Returned here only for local development / API testing.
  return {
    user: userService.toPublicUser(user),
    emailVerificationToken: env.isProd ? undefined : verify.rawToken,
    message:
      'Account created. Verify your email before relying on full account access.',
  };
}

async function login(payload, req) {
  const meta = requestMeta(req);
  const user = userService.findActiveUserByEmail(payload.email);

  if (!user || !user.is_active) {
    writeAuditLog({ eventType: 'auth.login_failed', ...meta, metadata: { reason: 'unknown_user' } });
    throw new AuthError('Invalid email or password', 401, 'INVALID_CREDENTIALS');
  }

  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    writeAuditLog({
      userId: user.id,
      eventType: 'auth.login_blocked_lockout',
      ...meta,
    });
    throw new AuthError(
      'Account temporarily locked due to too many failed attempts. Try again later.',
      423,
      'ACCOUNT_LOCKED'
    );
  }

  const valid = await verifyPassword(payload.password, user.password_hash);
  if (!valid) {
    userService.recordFailedLogin(user, env.maxFailedLogins, env.lockoutMinutes);
    writeAuditLog({
      userId: user.id,
      eventType: 'auth.login_failed',
      ...meta,
      metadata: { reason: 'bad_password' },
    });
    throw new AuthError('Invalid email or password', 401, 'INVALID_CREDENTIALS');
  }

  userService.clearFailedLogins(user.id);

  const accessToken = tokenService.createAccessToken(user);
  const refresh = tokenService.issueRefreshToken(user.id, meta);

  writeAuditLog({ userId: user.id, eventType: 'auth.login_success', ...meta });

  return {
    user: userService.toPublicUser(user),
    accessToken,
    refreshToken: refresh.rawToken,
    refreshTokenExpiresAt: refresh.expiresAt,
  };
}

function refresh(rawRefreshToken, req) {
  const meta = requestMeta(req);
  if (!rawRefreshToken) {
    throw new AuthError('Refresh token required', 401, 'REFRESH_REQUIRED');
  }

  const stored = tokenService.findValidRefreshToken(rawRefreshToken);
  if (!stored) {
    writeAuditLog({ eventType: 'auth.refresh_rejected', ...meta });
    throw new AuthError('Invalid or expired refresh token', 401, 'INVALID_REFRESH');
  }

  const user = userService.findActiveUserById(stored.user_id);
  if (!user || !user.is_active) {
    tokenService.revokeRefreshToken(stored.id);
    throw new AuthError('User not found or inactive', 401, 'USER_INACTIVE');
  }

  const rotated = tokenService.rotateRefreshToken(stored, user.id, meta);
  const accessToken = tokenService.createAccessToken(user);

  writeAuditLog({ userId: user.id, eventType: 'auth.token_refreshed', ...meta });

  return {
    accessToken,
    refreshToken: rotated.rawToken,
    refreshTokenExpiresAt: rotated.expiresAt,
    user: userService.toPublicUser(user),
  };
}

function logout(rawRefreshToken, req) {
  const meta = requestMeta(req);
  if (rawRefreshToken) {
    const stored = tokenService.findValidRefreshToken(rawRefreshToken);
    if (stored) {
      tokenService.revokeRefreshToken(stored.id);
      writeAuditLog({ userId: stored.user_id, eventType: 'auth.logout', ...meta });
    }
  }
  return { message: 'Logged out' };
}

function logoutAll(userId, req) {
  tokenService.revokeAllRefreshTokens(userId);
  writeAuditLog({
    userId,
    eventType: 'auth.logout_all',
    ...requestMeta(req),
  });
  return { message: 'All sessions revoked' };
}

function verifyEmail(token, req) {
  const row = tokenService.consumeEmailToken(token, 'verify_email');
  if (!row) {
    throw new AuthError('Invalid or expired verification token', 400, 'INVALID_TOKEN');
  }

  userService.markEmailVerified(row.user_id);
  writeAuditLog({
    userId: row.user_id,
    eventType: 'user.email_verified',
    ...requestMeta(req),
  });

  return { message: 'Email verified successfully' };
}

function requestPasswordReset(email, req) {
  const meta = requestMeta(req);
  const user = userService.findActiveUserByEmail(email);

  // Always return the same message to avoid account enumeration
  const generic = {
    message: 'If an account exists for that email, a reset link has been issued.',
  };

  if (!user) {
    writeAuditLog({ eventType: 'auth.password_reset_requested', ...meta, metadata: { found: false } });
    return generic;
  }

  const reset = tokenService.createEmailToken(user.id, 'reset_password', 1);
  writeAuditLog({
    userId: user.id,
    eventType: 'auth.password_reset_requested',
    ...meta,
    metadata: { found: true },
  });

  return {
    ...generic,
    // Dev-only: production must deliver via email, never in API body
    resetToken: env.isProd ? undefined : reset.rawToken,
    expiresAt: env.isProd ? undefined : reset.expiresAt,
  };
}

async function resetPassword({ token, newPassword }, req) {
  const row = tokenService.consumeEmailToken(token, 'reset_password');
  if (!row) {
    throw new AuthError('Invalid or expired reset token', 400, 'INVALID_TOKEN');
  }

  const passwordHash = await hashPassword(newPassword);
  userService.updatePassword(row.user_id, passwordHash);
  tokenService.revokeAllRefreshTokens(row.user_id);

  writeAuditLog({
    userId: row.user_id,
    eventType: 'auth.password_reset_completed',
    ...requestMeta(req),
  });

  return { message: 'Password updated. Please log in again.' };
}

async function changePassword(userId, { currentPassword, newPassword }, req) {
  const user = userService.findActiveUserById(userId);
  if (!user) {
    throw new AuthError('User not found', 404, 'NOT_FOUND');
  }

  const valid = await verifyPassword(currentPassword, user.password_hash);
  if (!valid) {
    throw new AuthError('Current password is incorrect', 401, 'INVALID_PASSWORD');
  }

  const passwordHash = await hashPassword(newPassword);
  userService.updatePassword(userId, passwordHash);
  tokenService.revokeAllRefreshTokens(userId);

  writeAuditLog({
    userId,
    eventType: 'auth.password_changed',
    ...requestMeta(req),
  });

  return { message: 'Password changed. All other sessions were revoked.' };
}

function getMe(userId) {
  const user = userService.findActiveUserById(userId);
  if (!user) {
    throw new AuthError('User not found', 404, 'NOT_FOUND');
  }
  return userService.toPublicUser(user);
}

function updateConsent(userId, consentMarketing, req) {
  userService.updateMarketingConsent(userId, consentMarketing);
  writeAuditLog({
    userId,
    eventType: 'user.consent_updated',
    ...requestMeta(req),
    metadata: { consentMarketing },
  });
  return getMe(userId);
}

function exportMyData(userId, req) {
  const data = userService.exportUserData(userId);
  if (!data) {
    throw new AuthError('User not found', 404, 'NOT_FOUND');
  }
  writeAuditLog({
    userId,
    eventType: 'user.data_exported',
    ...requestMeta(req),
  });
  return data;
}

function deleteMyAccount(userId, req) {
  const user = userService.findActiveUserById(userId);
  if (!user) {
    throw new AuthError('User not found', 404, 'NOT_FOUND');
  }

  userService.eraseUser(userId);
  writeAuditLog({
    userId,
    eventType: 'user.account_erased',
    ...requestMeta(req),
    metadata: { erasedAt: nowIso() },
  });

  return { message: 'Account deleted and personal data anonymized.' };
}

module.exports = {
  AuthError,
  register,
  login,
  refresh,
  logout,
  logoutAll,
  verifyEmail,
  requestPasswordReset,
  resetPassword,
  changePassword,
  getMe,
  updateConsent,
  exportMyData,
  deleteMyAccount,
};
