/**
 * AST-based SQL injection interceptor.
 *
 * Instead of fragile regex denylists, this module parses SQL strings
 * into a lightweight AST and detects structural anomalies that indicate
 * injection (e.g. extra clauses, stacked queries, tautologies).
 */

import { logger } from '../utils/logger';

/** Minimal token types for SQL structural analysis. */
type TokenType =
  | 'KEYWORD'
  | 'IDENTIFIER'
  | 'STRING'
  | 'NUMBER'
  | 'OPERATOR'
  | 'SEMICOLON'
  | 'PAREN_OPEN'
  | 'PAREN_CLOSE'
  | 'COMMENT'
  | 'UNKNOWN';

interface Token {
  type: TokenType;
  value: string;
  position: number;
}

const SQL_KEYWORDS = new Set([
  'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'ALTER', 'CREATE',
  'TRUNCATE', 'EXEC', 'EXECUTE', 'UNION', 'FROM', 'WHERE', 'AND',
  'OR', 'NOT', 'IN', 'LIKE', 'BETWEEN', 'JOIN', 'ON', 'SET',
  'INTO', 'VALUES', 'ORDER', 'BY', 'GROUP', 'HAVING', 'LIMIT',
  'OFFSET', 'TABLE', 'INDEX', 'VIEW', 'GRANT', 'REVOKE',
  'INFORMATION_SCHEMA', 'SLEEP', 'BENCHMARK', 'WAITFOR', 'DELAY',
  'SHUTDOWN', 'NULL', 'TRUE', 'FALSE', 'AS', 'IS', 'ALL',
  'DISTINCT', 'CASE', 'WHEN', 'THEN', 'ELSE', 'END',
  'EXISTS', 'ANY', 'SOME', 'CAST', 'CONVERT',
]);

/** Tokenise a raw SQL string. */
function tokenise(sql: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;

  while (i < sql.length) {
    // Skip whitespace
    if (/\s/.test(sql[i])) {
      i++;
      continue;
    }

    // Block comments
    if (sql[i] === '/' && sql[i + 1] === '*') {
      const end = sql.indexOf('*/', i + 2);
      const commentEnd = end === -1 ? sql.length : end + 2;
      tokens.push({ type: 'COMMENT', value: sql.slice(i, commentEnd), position: i });
      i = commentEnd;
      continue;
    }

    // Line comments (-- and #)
    if ((sql[i] === '-' && sql[i + 1] === '-') || sql[i] === '#') {
      const end = sql.indexOf('\n', i);
      const commentEnd = end === -1 ? sql.length : end;
      tokens.push({ type: 'COMMENT', value: sql.slice(i, commentEnd), position: i });
      i = commentEnd;
      continue;
    }

    // Strings (single-quoted)
    if (sql[i] === "'") {
      let j = i + 1;
      while (j < sql.length) {
        if (sql[j] === "'" && sql[j + 1] === "'") {
          j += 2; // escaped quote
        } else if (sql[j] === "'") {
          break;
        } else {
          j++;
        }
      }
      tokens.push({ type: 'STRING', value: sql.slice(i, j + 1), position: i });
      i = j + 1;
      continue;
    }

    // Numbers
    if (/\d/.test(sql[i])) {
      let j = i;
      while (j < sql.length && /[\d.]/.test(sql[j])) j++;
      tokens.push({ type: 'NUMBER', value: sql.slice(i, j), position: i });
      i = j;
      continue;
    }

    // Semicolon
    if (sql[i] === ';') {
      tokens.push({ type: 'SEMICOLON', value: ';', position: i });
      i++;
      continue;
    }

    // Parens
    if (sql[i] === '(') {
      tokens.push({ type: 'PAREN_OPEN', value: '(', position: i });
      i++;
      continue;
    }
    if (sql[i] === ')') {
      tokens.push({ type: 'PAREN_CLOSE', value: ')', position: i });
      i++;
      continue;
    }

    // Operators
    if (/[=<>!+\-*/%&|^~]/.test(sql[i])) {
      let op = sql[i];
      if (i + 1 < sql.length && /[=<>!]/.test(sql[i + 1])) {
        op += sql[i + 1];
        i++;
      }
      tokens.push({ type: 'OPERATOR', value: op, position: i });
      i++;
      continue;
    }

    // Identifiers and keywords
    if (/[a-zA-Z_]/.test(sql[i])) {
      let j = i;
      while (j < sql.length && /[a-zA-Z0-9_]/.test(sql[j])) j++;
      const word = sql.slice(i, j);
      const type = SQL_KEYWORDS.has(word.toUpperCase()) ? 'KEYWORD' : 'IDENTIFIER';
      tokens.push({ type, value: word, position: i });
      i = j;
      continue;
    }

    // Comma, dot, etc.
    tokens.push({ type: 'UNKNOWN', value: sql[i], position: i });
    i++;
  }

  return tokens;
}

export interface SqliDetectionResult {
  isMalicious: boolean;
  reasons: string[];
  tokens: Token[];
}

/** Analyse tokens for injection patterns. */
function analyseTokens(tokens: Token[]): SqliDetectionResult {
  const reasons: string[] = [];
  const keywords = tokens.filter((t) => t.type === 'KEYWORD');
  const keywordValues = keywords.map((k) => k.value.toUpperCase());

  // 1. Stacked queries (multiple statements)
  const semicolons = tokens.filter((t) => t.type === 'SEMICOLON');
  if (semicolons.length > 0) {
    const afterSemicolon = tokens.slice(
      tokens.indexOf(semicolons[0]) + 1
    ).filter((t) => t.type !== 'COMMENT');
    if (afterSemicolon.length > 0) {
      reasons.push('Stacked queries detected (multiple SQL statements)');
    }
  }

  // 2. UNION-based injection
  if (keywordValues.includes('UNION') && keywordValues.filter((k) => k === 'SELECT').length > 1) {
    reasons.push('UNION SELECT detected — possible data exfiltration');
  }

  // 3. Tautology (OR 1=1, OR TRUE, OR 'a'='a', etc.)
  for (let i = 0; i < tokens.length - 2; i++) {
    if (
      tokens[i].type === 'KEYWORD' &&
      tokens[i].value.toUpperCase() === 'OR'
    ) {
      // Pattern: OR <literal> = <same literal>  (e.g. OR 1=1, OR 'x'='x')
      if (
        i + 3 < tokens.length &&
        (tokens[i + 1].type === 'NUMBER' || tokens[i + 1].type === 'STRING') &&
        tokens[i + 2].type === 'OPERATOR' && tokens[i + 2].value === '=' &&
        tokens[i + 3].type === tokens[i + 1].type &&
        tokens[i + 3].value === tokens[i + 1].value
      ) {
        reasons.push('Tautology detected (OR with always-true condition)');
      }
      // Pattern: OR TRUE
      if (tokens[i + 1].type === 'KEYWORD' && tokens[i + 1].value.toUpperCase() === 'TRUE') {
        reasons.push('Tautology detected (OR TRUE)');
      }
    }
  }

  // 4. Dangerous DDL/DCL keywords in what should be DML
  const dangerousKeywords = ['DROP', 'ALTER', 'TRUNCATE', 'GRANT', 'REVOKE', 'SHUTDOWN'];
  for (const kw of dangerousKeywords) {
    if (keywordValues.includes(kw)) {
      reasons.push(`Dangerous keyword detected: ${kw}`);
    }
  }

  // 5. Comment-based truncation (trailing -- or /* after user input)
  const comments = tokens.filter((t) => t.type === 'COMMENT');
  if (comments.length > 0) {
    reasons.push('SQL comment detected — possible clause truncation');
  }

  // 6. Time-based blind injection functions
  const blindFunctions = ['SLEEP', 'BENCHMARK', 'WAITFOR'];
  for (const fn of blindFunctions) {
    if (keywordValues.includes(fn)) {
      reasons.push(`Time-based blind injection function detected: ${fn}`);
    }
  }

  // 7. Information schema access
  if (keywordValues.includes('INFORMATION_SCHEMA')) {
    reasons.push('INFORMATION_SCHEMA access detected — possible schema enumeration');
  }

  return {
    isMalicious: reasons.length > 0,
    reasons,
    tokens,
  };
}

/**
 * Inspect a SQL query for injection attempts.
 * Returns a result object indicating whether the query is malicious.
 */
export function detectSqlInjection(query: string): SqliDetectionResult {
  const tokens = tokenise(query);
  const result = analyseTokens(tokens);

  if (result.isMalicious) {
    logger.warn('SQL injection attempt detected', {
      reasons: result.reasons,
      query: query.slice(0, 200),
    });
  }

  return result;
}

/**
 * Check a user-supplied value (not a full query) for injection payloads.
 * Useful for validating individual parameters before interpolation.
 */
export function detectSqlInjectionInValue(value: string): SqliDetectionResult {
  const tokens = tokenise(value);
  const result = analyseTokens(tokens);

  if (result.isMalicious) {
    logger.warn('SQL injection payload in user value', {
      reasons: result.reasons,
      value: value.slice(0, 200),
    });
  }

  return result;
}
