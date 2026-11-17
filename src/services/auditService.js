const { v4: uuidv4 } = require('uuid');
const { db } = require('../db/database');
const { nowIso } = require('../utils/crypto');

function writeAuditLog({ userId = null, eventType, ipAddress = null, userAgent = null, metadata = null }) {
  db.prepare(
    `INSERT INTO audit_logs (id, user_id, event_type, ip_address, user_agent, metadata, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  ).run(
    uuidv4(),
    userId,
    eventType,
    ipAddress,
    userAgent,
    metadata ? JSON.stringify(metadata) : null,
    nowIso()
  );
}

module.exports = { writeAuditLog };
