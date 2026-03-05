/**
 * Cognex SDK — Data Access Control for Node.js
 *
 * Wraps your existing `pg` (node-postgres) client.
 * Every query is checked against your Cognex policy before execution.
 *
 * Install:
 *   npm install @cognex/sdk pg
 *
 * Usage:
 *   const { CognexClient } = require('@cognex/sdk');
 *   const client = new CognexClient({ role: 'contractor', userId: 'john@acme.com' });
 *   await client.connect();
 *
 *   // This automatically checks policy, rewrites query, enforces limits
 *   const result = await client.query('SELECT * FROM users');
 */

'use strict';

const { Client, Pool } = require('pg');

const COGNEX_URL = process.env.COGNEX_URL || 'https://cognex.dev';
const COGNEX_API_KEY = process.env.COGNEX_API_KEY || '';
const COGNEX_CONNECTION_ID = process.env.COGNEX_CONNECTION_ID || '';

// ── SQL Parser (minimal) ─────────────────────────────────────────────────────
function parseQuery(sql) {
  const s = sql.trim().toUpperCase();
  let operation = 'SELECT';
  if (s.startsWith('INSERT'))       operation = 'INSERT';
  else if (s.startsWith('UPDATE'))  operation = 'UPDATE';
  else if (s.startsWith('DELETE'))  operation = 'DELETE';
  else if (s.startsWith('DROP'))    operation = 'DROP';
  else if (s.startsWith('TRUNCATE')) operation = 'TRUNCATE';
  else if (s.startsWith('ALTER'))   operation = 'ALTER';
  else if (s.startsWith('CREATE'))  operation = 'CREATE';

  // Extract table name (simple regex — handles most common patterns)
  let table = null;
  const fromMatch = sql.match(/FROM\s+"?(\w+)"?/i);
  const intoMatch = sql.match(/INTO\s+"?(\w+)"?/i);
  const updateMatch = sql.match(/UPDATE\s+"?(\w+)"?/i);
  if (fromMatch)   table = fromMatch[1].toLowerCase();
  if (intoMatch)   table = intoMatch[1].toLowerCase();
  if (updateMatch) table = updateMatch[1].toLowerCase();

  // Extract column names from SELECT
  let columns = null;
  if (operation === 'SELECT') {
    const selectMatch = sql.match(/SELECT\s+(.*?)\s+FROM/is);
    if (selectMatch) {
      const colStr = selectMatch[1].trim();
      if (colStr !== '*') {
        columns = colStr.split(',').map(c => c.trim().replace(/"/g, '').split('.').pop());
      }
    }
  }

  return { operation, table, columns };
}

// ── Query Rewriter ────────────────────────────────────────────────────────────
function rewriteQuery(sql, checkResult) {
  let rewritten = sql;
  const { safe_columns, blocked_columns, max_rows, conditions } = checkResult;

  // 1. Replace SELECT * with safe columns
  if (safe_columns && safe_columns.length > 0) {
    rewritten = rewritten.replace(
      /SELECT\s+\*/i,
      `SELECT ${safe_columns.map(c => `"${c}"`).join(', ')}`
    );
  }

  // 2. Remove blocked columns from SELECT list
  if (blocked_columns && blocked_columns.length > 0) {
    for (const col of blocked_columns) {
      // Remove specific column references
      const colPattern = new RegExp(`[,\\s]?"?${col}"?[,\\s]?`, 'gi');
      rewritten = rewritten.replace(colPattern, ' ');
    }
  }

  // 3. Inject LIMIT if not present or exceeds max
  if (max_rows) {
    const limitMatch = rewritten.match(/LIMIT\s+(\d+)/i);
    if (!limitMatch) {
      rewritten = rewritten.trimEnd().replace(/;?\s*$/, '') + ` LIMIT ${max_rows}`;
    } else {
      const existingLimit = parseInt(limitMatch[1]);
      if (existingLimit > max_rows) {
        rewritten = rewritten.replace(/LIMIT\s+\d+/i, `LIMIT ${max_rows}`);
      }
    }
  }

  // 4. Inject WHERE conditions
  if (conditions && Object.keys(conditions).length > 0) {
    const whereClauses = Object.entries(conditions)
      .map(([col, val]) => `"${col}" = '${val}'`)
      .join(' AND ');

    if (/WHERE/i.test(rewritten)) {
      rewritten = rewritten.replace(/WHERE/i, `WHERE ${whereClauses} AND `);
    } else {
      const limitIdx = rewritten.search(/LIMIT/i);
      if (limitIdx > -1) {
        rewritten = rewritten.slice(0, limitIdx) + `WHERE ${whereClauses} ` + rewritten.slice(limitIdx);
      } else {
        rewritten = rewritten.trimEnd() + ` WHERE ${whereClauses}`;
      }
    }
  }

  return rewritten.replace(/\s+/g, ' ').trim();
}

// ── Cognex API ────────────────────────────────────────────────────────────────
async function callCognexCheck({ apiKey, connectionId, role, userId, table, operation, columns }) {
  try {
    const res = await fetch(`${COGNEX_URL}/check`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
      },
      body: JSON.stringify({
        connection_id: connectionId,
        role,
        user_identifier: userId,
        table_name: table,
        operation,
        columns,
      }),
      signal: AbortSignal.timeout(5000),
    });
    return await res.json();
  } catch (err) {
    return { allowed: false, reason: `Cognex unreachable: ${err.message}` };
  }
}

async function logResult(apiKey, logId, rowsReturned) {
  try {
    await fetch(`${COGNEX_URL}/log-result`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey },
      body: JSON.stringify({ log_id: logId, rows_returned: rowsReturned }),
      signal: AbortSignal.timeout(3000),
    });
  } catch {}  // best effort
}

// ── CognexClient ──────────────────────────────────────────────────────────────
class CognexClient {
  /**
   * @param {object} opts
   * @param {string} opts.role         - The role making queries ('contractor', 'ai_tool', 'junior_dev')
   * @param {string} opts.userId       - Identifier of the actual user (email, id, name)
   * @param {string} [opts.apiKey]     - Cognex API key (or COGNEX_API_KEY env var)
   * @param {string} [opts.connectionId] - Cognex connection ID (or COGNEX_CONNECTION_ID env var)
   * @param {object} [opts.pgConfig]   - pg Client config (host, port, database, user, password)
   * @param {boolean} [opts.failOpen]  - If true, allow queries when Cognex is unreachable
   * @param {boolean} [opts.dryRun]    - If true, check policy but don't execute
   */
  constructor(opts = {}) {
    this.role         = opts.role || 'unknown';
    this.userId       = opts.userId || 'unknown';
    this.apiKey       = opts.apiKey || COGNEX_API_KEY;
    this.connectionId = opts.connectionId || COGNEX_CONNECTION_ID;
    this.failOpen     = opts.failOpen || false;
    this.dryRun       = opts.dryRun || false;
    this.pgConfig     = opts.pgConfig || {};
    this._client      = null;

    if (!this.apiKey)       throw new Error('Cognex API key required. Set COGNEX_API_KEY or pass apiKey.');
    if (!this.connectionId) throw new Error('Cognex connection ID required. Set COGNEX_CONNECTION_ID or pass connectionId.');
  }

  async connect() {
    this._client = new Client(this.pgConfig);
    await this._client.connect();
    return this;
  }

  async end() {
    if (this._client) await this._client.end();
  }

  /**
   * Execute a query — automatically checked and rewritten by Cognex policy.
   * Drops in as a replacement for pg client.query()
   */
  async query(sql, params = []) {
    const { operation, table, columns } = parseQuery(sql);

    if (!table) {
      // Can't parse table — pass through with warning
      console.warn('[Cognex] Could not parse table from query — passing through unguarded');
      return this._client.query(sql, params);
    }

    // ── Check with Cognex ────────────────────────────────────────────────────
    const check = await callCognexCheck({
      apiKey: this.apiKey,
      connectionId: this.connectionId,
      role: this.role,
      userId: this.userId,
      table,
      operation,
      columns,
    });

    if (!check.allowed) {
      const err = new Error(`[Cognex] BLOCKED: ${check.reason}`);
      err.code = 'COGNEX_BLOCKED';
      err.table = table;
      err.role = this.role;
      err.reason = check.reason;
      throw err;
    }

    if (this.dryRun) {
      return { rows: [], rowCount: 0, cognex: { allowed: true, rewritten: null, check } };
    }

    // ── Rewrite query with policy enforcement ─────────────────────────────────
    const safeSql = rewriteQuery(sql, check);

    // ── Execute ───────────────────────────────────────────────────────────────
    const result = await this._client.query(safeSql, params);

    // ── Report rows back to Cognex for anomaly detection ─────────────────────
    if (check.log_id) {
      logResult(this.apiKey, check.log_id, result.rowCount || result.rows?.length || 0);
    }

    return {
      ...result,
      cognex: {
        allowed: true,
        original_sql: sql,
        rewritten_sql: safeSql,
        removed_columns: check.removed_columns,
        rule_name: check.rule_name,
        duration_ms: check.duration_ms,
      }
    };
  }
}

// ── CognexPool ────────────────────────────────────────────────────────────────
class CognexPool {
  /**
   * Pool version — wraps pg Pool for high-throughput apps.
   */
  constructor(opts = {}) {
    this.role         = opts.role || 'unknown';
    this.userId       = opts.userId || 'unknown';
    this.apiKey       = opts.apiKey || COGNEX_API_KEY;
    this.connectionId = opts.connectionId || COGNEX_CONNECTION_ID;
    this.failOpen     = opts.failOpen || false;
    this._pool        = new Pool(opts.pgConfig || {});
  }

  async query(sql, params = []) {
    const { operation, table, columns } = parseQuery(sql);

    if (!table) {
      return this._pool.query(sql, params);
    }

    const check = await callCognexCheck({
      apiKey: this.apiKey,
      connectionId: this.connectionId,
      role: this.role,
      userId: this.userId,
      table,
      operation,
      columns,
    });

    if (!check.allowed) {
      if (this.failOpen) {
        console.warn(`[Cognex] failOpen — allowing blocked query: ${check.reason}`);
        return this._pool.query(sql, params);
      }
      const err = new Error(`[Cognex] BLOCKED: ${check.reason}`);
      err.code = 'COGNEX_BLOCKED';
      throw err;
    }

    const safeSql = rewriteQuery(sql, check);
    const result = await this._pool.query(safeSql, params);

    if (check.log_id) {
      logResult(this.apiKey, check.log_id, result.rowCount || result.rows?.length || 0);
    }

    return result;
  }

  async end() { await this._pool.end(); }
}

module.exports = { CognexClient, CognexPool, parseQuery, rewriteQuery };
