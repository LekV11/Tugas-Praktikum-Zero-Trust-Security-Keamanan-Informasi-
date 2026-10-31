'use strict';
require('dotenv').config();
const { getDatabase } = require('./shared/database');
const db = getDatabase();
const summary = db.prepare(`
  SELECT COUNT(*) as total,
    SUM(CASE WHEN decision='allow' THEN 1 ELSE 0 END) as allow_count,
    SUM(CASE WHEN decision='deny' THEN 1 ELSE 0 END) as deny_count
  FROM audit_log
`).get();
console.log(`Audit Log: Total=${summary.total} | Allow=${summary.allow_count} | Deny=${summary.deny_count}`);

const recent = db.prepare('SELECT timestamp, subject, method, endpoint, decision, reason FROM audit_log ORDER BY id DESC LIMIT 10').all();
recent.forEach(l => {
  console.log(`  [${l.timestamp.slice(11,19)}] ${l.decision.toUpperCase().padEnd(5)} | ${l.method} ${l.endpoint} | ${l.subject} | ${l.reason}`);
});
