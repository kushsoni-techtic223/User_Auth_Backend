const { v4: uuidv4 } = require('uuid');
const { db } = require('../db/database');
const { nowIso } = require('../utils/crypto');

function findActiveUserByEmail(email) {
  return db
    .prepare(
      `SELECT * FROM users
       WHERE email = ? AND deleted_at IS NULL
       LIMIT 1`
    )
    .get(email);
}

function findActiveUserById(id) {
  return db
    .prepare(
      `SELECT * FROM users
       WHERE id = ? AND deleted_at IS NULL
       LIMIT 1`
    )
    .get(id);
}

function createUser({
  email,
  passwordHash,
  displayName,
  privacyPolicyVersion,
  termsVersion,
  consentMarketing,
}) {
  const id = uuidv4();
  const timestamp = nowIso();

  db.prepare(
    `INSERT INTO users (
      id, email, password_hash, display_name, email_verified, is_active,
      failed_login_count, locked_until, privacy_policy_version, terms_version,
      consent_marketing, consent_at, created_at, updated_at, deleted_at
    ) VALUES (?, ?, ?, ?, 0, 1, 0, NULL, ?, ?, ?, ?, ?, ?, NULL)`
  ).run(
    id,
    email,
    passwordHash,
    displayName || null,
    privacyPolicyVersion,
    termsVersion,
    consentMarketing ? 1 : 0,
    timestamp,
    timestamp,
    timestamp
  );

  return findActiveUserById(id);
}

function markEmailVerified(userId) {
  db.prepare(
    `UPDATE users SET email_verified = 1, updated_at = ? WHERE id = ? AND deleted_at IS NULL`
  ).run(nowIso(), userId);
}

function updatePassword(userId, passwordHash) {
  db.prepare(
    `UPDATE users SET password_hash = ?, failed_login_count = 0, locked_until = NULL, updated_at = ?
     WHERE id = ? AND deleted_at IS NULL`
  ).run(passwordHash, nowIso(), userId);
}

function recordFailedLogin(user, maxFailed, lockoutMinutes) {
  const nextCount = user.failed_login_count + 1;
  let lockedUntil = null;

  if (nextCount >= maxFailed) {
    lockedUntil = new Date(Date.now() + lockoutMinutes * 60 * 1000).toISOString();
  }

  db.prepare(
    `UPDATE users SET failed_login_count = ?, locked_until = ?, updated_at = ? WHERE id = ?`
  ).run(nextCount, lockedUntil, nowIso(), user.id);

  return { failedLoginCount: nextCount, lockedUntil };
}

function clearFailedLogins(userId) {
  db.prepare(
    `UPDATE users SET failed_login_count = 0, locked_until = NULL, updated_at = ? WHERE id = ?`
  ).run(nowIso(), userId);
}

function updateMarketingConsent(userId, consentMarketing) {
  db.prepare(
    `UPDATE users SET consent_marketing = ?, consent_at = ?, updated_at = ?
     WHERE id = ? AND deleted_at IS NULL`
  ).run(consentMarketing ? 1 : 0, nowIso(), nowIso(), userId);
}

/**
 * Right to erasure: anonymize PII, soft-delete, keep audit trail integrity.
 */
function eraseUser(userId) {
  const timestamp = nowIso();
  const anonymizedEmail = `deleted_${userId}@anonymized.local`;

  const erase = db.transaction(() => {
    db.prepare(`DELETE FROM refresh_tokens WHERE user_id = ?`).run(userId);
    db.prepare(`DELETE FROM email_tokens WHERE user_id = ?`).run(userId);
    db.prepare(
      `UPDATE users SET
        email = ?,
        password_hash = 'ERASED',
        display_name = NULL,
        email_verified = 0,
        is_active = 0,
        consent_marketing = 0,
        deleted_at = ?,
        updated_at = ?
       WHERE id = ?`
    ).run(anonymizedEmail, timestamp, timestamp, userId);
  });

  erase();
}

function toPublicUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    email: user.email,
    displayName: user.display_name,
    emailVerified: Boolean(user.email_verified),
    consentMarketing: Boolean(user.consent_marketing),
    privacyPolicyVersion: user.privacy_policy_version,
    termsVersion: user.terms_version,
    createdAt: user.created_at,
    updatedAt: user.updated_at,
  };
}

function exportUserData(userId) {
  const user = findActiveUserById(userId);
  if (!user) return null;

  const sessions = db
    .prepare(
      `SELECT id, created_at, expires_at, revoked_at, user_agent, ip_address
       FROM refresh_tokens WHERE user_id = ?`
    )
    .all(userId);

  const audits = db
    .prepare(
      `SELECT event_type, ip_address, created_at, metadata
       FROM audit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 200`
    )
    .all(userId);

  return {
    exportedAt: nowIso(),
    profile: toPublicUser(user),
    sessions: sessions.map((s) => ({
      id: s.id,
      createdAt: s.created_at,
      expiresAt: s.expires_at,
      revokedAt: s.revoked_at,
      userAgent: s.user_agent,
      ipAddress: s.ip_address,
    })),
    securityEvents: audits.map((a) => ({
      eventType: a.event_type,
      ipAddress: a.ip_address,
      createdAt: a.created_at,
      metadata: a.metadata ? JSON.parse(a.metadata) : null,
    })),
  };
}

module.exports = {
  findActiveUserByEmail,
  findActiveUserById,
  createUser,
  markEmailVerified,
  updatePassword,
  recordFailedLogin,
  clearFailedLogins,
  updateMarketingConsent,
  eraseUser,
  toPublicUser,
  exportUserData,
};
