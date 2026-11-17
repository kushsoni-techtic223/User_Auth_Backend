const { v4: uuidv4 } = require('uuid');
const { db } = require('../db/database');
const { env } = require('../config/env');
const {
  sha256,
  randomToken,
  signAccessToken,
  addDays,
  addHours,
  nowIso,
} = require('../utils/crypto');

function createAccessToken(user) {
  return signAccessToken({
    sub: user.id,
    email: user.email,
    emailVerified: Boolean(user.email_verified),
  });
}

function issueRefreshToken(userId, { ipAddress, userAgent } = {}) {
  const rawToken = randomToken(48);
  const tokenHash = sha256(rawToken);
  const id = uuidv4();
  const createdAt = nowIso();
  const expiresAt = addDays(new Date(), env.refreshTokenTtlDays).toISOString();

  db.prepare(
    `INSERT INTO refresh_tokens
      (id, user_id, token_hash, expires_at, revoked_at, created_at, user_agent, ip_address)
     VALUES (?, ?, ?, ?, NULL, ?, ?, ?)`
  ).run(id, userId, tokenHash, expiresAt, createdAt, userAgent || null, ipAddress || null);

  return { rawToken, expiresAt };
}

function findValidRefreshToken(rawToken) {
  const tokenHash = sha256(rawToken);
  return db
    .prepare(
      `SELECT * FROM refresh_tokens
       WHERE token_hash = ?
         AND revoked_at IS NULL
         AND expires_at > ?
       LIMIT 1`
    )
    .get(tokenHash, nowIso());
}

function revokeRefreshToken(tokenId) {
  db.prepare(
    `UPDATE refresh_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL`
  ).run(nowIso(), tokenId);
}

function revokeAllRefreshTokens(userId) {
  db.prepare(
    `UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL`
  ).run(nowIso(), userId);
}

function rotateRefreshToken(oldTokenRow, userId, meta) {
  const rotate = db.transaction(() => {
    revokeRefreshToken(oldTokenRow.id);
    return issueRefreshToken(userId, meta);
  });
  return rotate();
}

function createEmailToken(userId, purpose, hoursValid = 24) {
  const rawToken = randomToken(32);
  const tokenHash = sha256(rawToken);
  const id = uuidv4();
  const createdAt = nowIso();
  const expiresAt = addHours(new Date(), hoursValid).toISOString();

  // Invalidate prior unused tokens of same purpose
  db.prepare(
    `UPDATE email_tokens SET used_at = ?
     WHERE user_id = ? AND purpose = ? AND used_at IS NULL`
  ).run(createdAt, userId, purpose);

  db.prepare(
    `INSERT INTO email_tokens
      (id, user_id, token_hash, purpose, expires_at, used_at, created_at)
     VALUES (?, ?, ?, ?, ?, NULL, ?)`
  ).run(id, userId, tokenHash, purpose, expiresAt, createdAt);

  return { rawToken, expiresAt };
}

function consumeEmailToken(rawToken, purpose) {
  const tokenHash = sha256(rawToken);
  const row = db
    .prepare(
      `SELECT * FROM email_tokens
       WHERE token_hash = ?
         AND purpose = ?
         AND used_at IS NULL
         AND expires_at > ?
       LIMIT 1`
    )
    .get(tokenHash, purpose, nowIso());

  if (!row) return null;

  db.prepare(`UPDATE email_tokens SET used_at = ? WHERE id = ?`).run(nowIso(), row.id);
  return row;
}

module.exports = {
  createAccessToken,
  issueRefreshToken,
  findValidRefreshToken,
  revokeRefreshToken,
  revokeAllRefreshTokens,
  rotateRefreshToken,
  createEmailToken,
  consumeEmailToken,
};
