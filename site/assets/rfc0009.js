// RFC-0009 evidence verifier, in JavaScript.
//
// The third independent implementation of docs/rfcs/RFC-0009-evidence-chain-format.md,
// written from the specification. It runs in the browser on the launch site,
// where a file is verified on the visitor's machine and never uploaded, and
// under Node in CI, where it is held to the same conformance corpus and the
// same differential search as the two Go verifiers.
//
// No dependencies. Hashing and signature checks use the platform's WebCrypto.

const V2 = "agw-evidence-v2";
const V1 = "agw-evidence-v1";
const GENESIS = "0".repeat(64);

const RECORD_MEMBERS = ["v", "seq", "eventName", "timestamp", "event", "prevHash", "hash"];
const CHECKPOINT_MEMBERS = ["v", "type", "seq", "hash", "count", "issuedAt", "keyId", "signature"];

// RFC-0009 §2.2, in hash order, with each member's type.
const EVENT_FIELDS = [
  ["EventID", "s"], ["TenantID", "s"], ["AgentID", "s"], ["KeyID", "s"],
  ["DecisionID", "s"], ["RequestID", "s"], ["TraceID", "s"],
  ["RouteID", "s"], ["Action", "s"], ["ResourceType", "s"], ["ResourceID", "s"],
  ["BackendID", "s"], ["Decision", "s"], ["ReasonCode", "s"],
  ["HTTPStatus", "i"], ["SourceIP", "s"], ["UserAgent", "s"],
  ["StartedAt", "t"], ["FinishedAt", "t"], ["LatencyMS", "i"],
  // v2 only:
  ["SourceTenant", "s"], ["Federated", "b"], ["TrustGrant", "s"], ["Risk", "s"], ["Producer", "s"],
];
const V1_FIELDS = 20;

const INT64_MIN = -(2n ** 63n), INT64_MAX = 2n ** 63n - 1n, UINT64_MAX = 2n ** 64n - 1n;

class Malformed extends Error {}

// ---------------------------------------------------------------- strict JSON

// A JSON parser that keeps what JSON.parse throws away. Numbers stay as the
// exact text they were written as, because JavaScript numbers lose precision
// past 2^53 and a hash over a rounded integer is a hash over a different
// record. Objects remember their member names so duplicates are refused
// (RFC-0009 §1), which JSON.parse silently resolves by keeping the last.
//
// Values: strings are JS strings; numbers are {num: "text"}; objects are
// {obj: Map}; arrays are {arr: [...]}; true, false and null are themselves.
function parseJSON(text) {
  let i = 0;
  const ws = () => { while (i < text.length && " \t\n\r".includes(text[i])) i++; };
  const fail = (why) => { throw new Malformed(`not valid JSON: ${why} at offset ${i}`); };

  function value() {
    ws();
    const c = text[i];
    if (c === "{") return object();
    if (c === "[") return array();
    if (c === '"') return string();
    if (c === "-" || (c >= "0" && c <= "9")) return number();
    for (const [lit, v] of [["true", true], ["false", false], ["null", null]]) {
      if (text.startsWith(lit, i)) { i += lit.length; return v; }
    }
    fail("unexpected character");
  }
  function object() {
    i++;
    const m = new Map();
    ws();
    if (text[i] === "}") { i++; return { obj: m }; }
    for (;;) {
      ws();
      if (text[i] !== '"') fail("expected a member name");
      const k = string();
      if (m.has(k)) throw new Malformed(`duplicate member name "${k}"`);
      ws();
      if (text[i] !== ":") fail("expected ':'");
      i++;
      m.set(k, value());
      ws();
      if (text[i] === ",") { i++; continue; }
      if (text[i] === "}") { i++; return { obj: m }; }
      fail("expected ',' or '}'");
    }
  }
  function array() {
    i++;
    const a = [];
    ws();
    if (text[i] === "]") { i++; return { arr: a }; }
    for (;;) {
      a.push(value());
      ws();
      if (text[i] === ",") { i++; continue; }
      if (text[i] === "]") { i++; return { arr: a }; }
      fail("expected ',' or ']'");
    }
  }
  function string() {
    i++;
    let out = "";
    for (;;) {
      if (i >= text.length) fail("unterminated string");
      const c = text[i];
      // A lone surrogate becomes U+FFFD, as every other decoder does, so
      // two names that differ only in broken escapes compare equal.
      if (c === '"') { i++; return out.toWellFormed ? out.toWellFormed() : out; }
      if (c < " ") fail("control character in string");
      if (c !== "\\") { out += c; i++; continue; }
      const e = text[i + 1];
      const simple = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" }[e];
      if (simple !== undefined) { out += simple; i += 2; continue; }
      if (e !== "u") fail("bad escape");
      const hex = text.slice(i + 2, i + 6);
      if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail("bad \\u escape");
      out += String.fromCharCode(parseInt(hex, 16));
      i += 6;
    }
  }
  function number() {
    const m = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(text.slice(i));
    if (!m) fail("bad number");
    i += m[0].length;
    return { num: m[0] };
  }

  const v = value();
  ws();
  if (i !== text.length) fail("trailing data");
  return v;
}

const isObj = (v) => v !== null && typeof v === "object" && v.obj instanceof Map;

// RFC-0009 §1: a member whose name equals a defined name except for case.
function exactNames(map, defined) {
  for (const k of map.keys()) {
    for (const d of defined) {
      if (k !== d && k.toLowerCase() === d.toLowerCase()) {
        throw new Malformed(`member "${k}" differs from "${d}" only by case`);
      }
    }
  }
}

// ---------------------------------------------------------------- types

const INTEGER = /^-?(0|[1-9][0-9]*)$/;
const TIMESTAMP = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(\.[0-9]{1,9})?(Z|([+-])([0-9]{2}):([0-9]{2}))$/;

function asString(v, what) {
  if (typeof v !== "string") throw new Malformed(`${what} must be a string`);
  return v;
}
function asInt(v, what, unsigned) {
  if (v === null || typeof v !== "object" || typeof v.num !== "string" || !INTEGER.test(v.num)) {
    throw new Malformed(`${what} must be an integer`);
  }
  if (unsigned && v.num.startsWith("-")) throw new Malformed(`${what} must be a non-negative integer`);
  const n = BigInt(v.num);
  if (unsigned ? n > UINT64_MAX : n < INT64_MIN || n > INT64_MAX) {
    throw new Malformed(`${what} is out of range`);
  }
  return n;
}

// TS(t), RFC-0009 §2.3. Returns the normalised UTC form.
function ts(s, what) {
  if (typeof s !== "string") throw new Malformed(`${what} must be a timestamp string`);
  const m = TIMESTAMP.exec(s);
  if (!m) throw new Malformed(`${what} "${s}" does not match the RFC-0009 timestamp grammar`);
  const [y, mo, d, h, mi, se] = m.slice(1, 7).map(Number);
  if (mo < 1 || mo > 12 || d < 1 || h > 23 || mi > 59 || se > 59) {
    throw new Malformed(`${what} "${s}" has a field out of range`);
  }
  // Date.UTC maps years 0-99 to 1900-1999; setUTCFullYear does not.
  const day = new Date(0);
  day.setUTCFullYear(y, mo - 1, d);
  if (day.getUTCDate() !== d || day.getUTCMonth() !== mo - 1) {
    throw new Malformed(`${what} "${s}" is not a calendar date`);
  }
  let offsetMin = 0;
  if (m[8] !== "Z") {
    const oh = Number(m[10]), om = Number(m[11]);
    if (oh > 23 || om > 59) throw new Malformed(`${what} "${s}" has an offset out of range`);
    offsetMin = (m[9] === "-" ? -1 : 1) * (oh * 60 + om);
  }
  const t = new Date(0);
  t.setUTCFullYear(y, mo - 1, d);
  t.setUTCHours(h, mi, se, 0);
  t.setTime(t.getTime() - offsetMin * 60000);
  const p2 = (n) => String(n).padStart(2, "0");
  let out = `${String(t.getUTCFullYear()).padStart(4, "0")}-${p2(t.getUTCMonth() + 1)}-${p2(t.getUTCDate())}` +
    `T${p2(t.getUTCHours())}:${p2(t.getUTCMinutes())}:${p2(t.getUTCSeconds())}`;
  // The fraction is carried as text: an offset is whole minutes, so it
  // never touches it, and nothing rounds it.
  const frac = (m[7] || "").slice(1).padEnd(9, "0").replace(/0+$/, "");
  if (frac) out += "." + frac;
  return out + "Z";
}

// ---------------------------------------------------------------- encoding

const enc = new TextEncoder();
const F = (s) => `${enc.encode(s).length}:${s}`;

function eventValue(v, kind, name) {
  const absent = v === undefined || v === null;
  switch (kind) {
    case "s": return absent ? "" : asString(v, `event.${name}`);
    case "i": return absent ? "0" : asInt(v, `event.${name}`, false).toString();
    case "b":
      if (absent) return "false";
      if (v !== true && v !== false) throw new Malformed(`event.${name} must be true or false`);
      return String(v);
    case "t": return absent ? "0001-01-01T00:00:00Z" : ts(v, `event.${name}`);
  }
  throw new Error("unknown kind " + kind);
}

// H(r), RFC-0009 §3.
function hashInput(r) {
  const n = r.v === V1 ? V1_FIELDS : EVENT_FIELDS.length;
  let s = r.v + "\n" + F(r.seq.toString()) + F(r.prevHash) + F(r.eventName) + F(r.ts);
  for (const [name, kind] of EVENT_FIELDS.slice(0, n)) s += F(eventValue(r.event.get(name), kind, name));
  return s;
}

// C(c), RFC-0009 §4.2.
function signingInput(c) {
  return V2 + "/checkpoint\n" + F(c.seq.toString()) + F(c.hash) + F(c.count.toString()) + F(c.issuedAtTS) + F(c.keyId);
}

async function sha256hex(s) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)));
  return Array.from(d, (b) => b.toString(16).padStart(2, "0")).join("");
}

// Standard base64 with padding. CR and LF are skipped, as the reference's
// decoder does; everything else outside the alphabet is refused.
export function base64Decode(s) {
  s = s.replace(/[\r\n]/g, "");
  if (s.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(s)) return null;
  const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const out = [];
  for (let i = 0; i < s.length; i += 4) {
    const q = s.slice(i, i + 4);
    const v = [...q].map((ch) => (ch === "=" ? 0 : alpha.indexOf(ch)));
    const n = (v[0] << 18) | (v[1] << 12) | (v[2] << 6) | v[3];
    out.push((n >> 16) & 255);
    if (q[2] !== "=") out.push((n >> 8) & 255);
    if (q[3] !== "=") out.push(n & 255);
  }
  return new Uint8Array(out);
}

// ---------------------------------------------------------------- lines

function classify(line) {
  const root = parseJSON(line);
  if (!isObj(root)) throw new Malformed("not a JSON object");
  const m = root.obj;

  if (m.get("type") === "checkpoint") {
    for (const k of CHECKPOINT_MEMBERS) if (!m.has(k)) throw new Malformed(`checkpoint is missing "${k}"`);
    exactNames(m, CHECKPOINT_MEMBERS);
    const c = {
      v: asString(m.get("v"), "v"),
      seq: asInt(m.get("seq"), "seq", true),
      hash: asString(m.get("hash"), "hash"),
      count: asInt(m.get("count"), "count", true),
      issuedAtTS: ts(m.get("issuedAt"), "issuedAt"),
      keyId: asString(m.get("keyId"), "keyId"),
      signature: asString(m.get("signature"), "signature"),
    };
    asString(m.get("type"), "type");
    return { checkpoint: c };
  }

  for (const k of RECORD_MEMBERS) if (!m.has(k)) throw new Malformed(`record is missing "${k}"`);
  // "type" too: a record carrying "TYPE" is one a case-insensitive reader
  // would take for a checkpoint.
  exactNames(m, [...RECORD_MEMBERS, "type"]);
  const event = m.get("event");
  if (!isObj(event)) throw new Malformed("event must be an object");
  exactNames(event.obj, EVENT_FIELDS.map((f) => f[0]));
  const r = {
    v: asString(m.get("v"), "v"),
    seq: asInt(m.get("seq"), "seq", true),
    eventName: asString(m.get("eventName"), "eventName"),
    ts: ts(m.get("timestamp"), "timestamp"),
    event: event.obj,
    prevHash: asString(m.get("prevHash"), "prevHash"),
    hash: asString(m.get("hash"), "hash"),
  };
  // Type-check every defined event member now, so a wrong type is
  // malformed rather than a hash mismatch that points nowhere.
  for (const [name, kind] of EVENT_FIELDS) eventValue(event.obj.get(name), kind, name);
  return { record: r };
}

// ---------------------------------------------------------------- verify

async function signatureValid(key, c) {
  const sig = base64Decode(c.signature);
  if (!sig || sig.length !== 64) return false;
  try {
    return await crypto.subtle.verify("Ed25519", key, sig, enc.encode(signingInput(c)));
  } catch {
    return false;
  }
}

// importPublicKey turns a key file's contents (base64 of 32 bytes) into a
// WebCrypto key. Throws with a readable message.
export async function importPublicKey(text) {
  const raw = base64Decode(String(text).trim());
  if (!raw || raw.length !== 32) throw new Error("not an Ed25519 public key: expected base64 of 32 bytes");
  try {
    return await crypto.subtle.importKey("raw", raw, { name: "Ed25519" }, false, ["verify"]);
  } catch {
    throw new Error("this browser cannot verify Ed25519 signatures (needs Chrome 137+, Firefox 129+ or Safari 17+)");
  }
}

// readAnchor takes the last checkpoint line in a file.
export function readAnchor(text) {
  let last = null;
  for (const raw of text.split("\n")) {
    const line = trimLine(raw);
    if (!line) continue;
    try {
      const k = classify(line);
      if (k.checkpoint) last = k.checkpoint;
    } catch { /* not a checkpoint line */ }
  }
  if (!last) throw new Error("the anchor file contains no checkpoint");
  return last;
}

// RFC-0009 §1: ASCII whitespace only.
const trimLine = (s) => s.replace(/^[ \t\r\n\v\f]+|[ \t\r\n\v\f]+$/g, "");

// verify is RFC-0009 §6. key is a CryptoKey or null; anchor a checkpoint from
// readAnchor or null. Returns the §6.4 result.
export async function verify(logText, key = null, anchor = null) {
  const res = {
    intact: true, records: 0n, checkpoints: 0n, headSeq: 0n,
    signedThrough: 0n, unanchoredRecords: 0n, keyGiven: key !== null, problems: [],
    firstAt: null, lastAt: null, producers: new Map(), decisions: new Map(), rows: [],
  };
  const fail = (kind, seq, detail) => { res.problems.push({ kind, seq, detail }); res.intact = false; };
  let expected = GENESIS, lastSeq = 0n;
  const seen = new Map();

  for (const rawLine of logText.split("\n")) {
    const line = trimLine(rawLine);
    if (!line) continue;

    let k;
    try {
      k = classify(line);
    } catch (e) {
      if (!(e instanceof Malformed)) throw e;
      fail("malformed", lastSeq + 1n, e.message);
      continue;
    }

    if (k.checkpoint) {
      const c = k.checkpoint;
      res.checkpoints++;
      seen.set(c.seq, c.hash);
      if (c.v !== V2) fail("checkpoint", c.seq, `declares version "${c.v}"`);
      else if (c.seq !== lastSeq) fail("checkpoint", c.seq, `commits to seq ${c.seq} but the chain is at ${lastSeq}`);
      else if (c.hash !== expected) fail("checkpoint", c.seq, "commits to a head that is not the chain's head");
      else if (key && !(await signatureValid(key, c))) fail("checkpoint", c.seq, "signature does not verify under the given key");
      else if (key) res.signedThrough = c.seq;
      continue;
    }

    const r = k.record;
    if (r.v === V1) {
      res.problems.push({ kind: "superseded_format", seq: r.seq,
        detail: "v1 record: SourceTenant, Federated, TrustGrant, Risk and Producer are not protected" });
    } else if (r.v !== V2) {
      fail("version", r.seq, `declares version "${r.v}"`);
      continue;
    }
    if (r.seq !== lastSeq + 1n) fail("sequence", r.seq, `expected seq ${lastSeq + 1n}`);
    if (r.prevHash !== expected) fail("chain", r.seq, "prevHash does not match the previous record's hash");
    if ((await sha256hex(hashInput(r))) !== r.hash) fail("content", r.seq, "the record's contents do not hash to its hash");

    res.records++;
    lastSeq = r.seq;
    expected = r.hash;
    res.headSeq = r.seq;

    // For the page's summary; not part of verification.
    const get = (n) => { const v = r.event.get(n); return typeof v === "string" ? v : ""; };
    res.firstAt ??= r.ts;
    res.lastAt = r.ts;
    const producer = get("Producer") || "(unstated)";
    res.producers.set(producer, (res.producers.get(producer) || 0) + 1);
    const decision = get("Decision") || "(none)";
    res.decisions.set(decision, (res.decisions.get(decision) || 0) + 1);
    if (res.rows.length < 500) {
      res.rows.push({ seq: r.seq, ts: r.ts, decision, reason: get("ReasonCode"), action: get("Action"),
        target: get("ResourceID"), agent: get("AgentID"), producer });
    }
  }

  if (anchor && key) {
    if (anchor.v !== V2 || !(await signatureValid(key, anchor))) {
      fail("anchor_invalid", anchor.seq, "the anchor is not a checkpoint signed by the given key");
      anchor = null;
    }
  }
  if (anchor) {
    const got = seen.get(anchor.seq);
    if (res.headSeq < anchor.seq) fail("rollback", res.headSeq, `the log ends at ${res.headSeq}; the anchor covers ${anchor.seq}`);
    else if (got === undefined) fail("missing_anchor", anchor.seq, "the log contains no checkpoint at the anchor's seq");
    else if (got !== anchor.hash) fail("forked", anchor.seq, "the log's checkpoint and the anchor commit to different heads");
  }
  if (key) {
    // Saturating (RFC-0009 §6.3): a reordered log can end below the last
    // verified checkpoint.
    res.unanchoredRecords = res.headSeq > res.signedThrough ? res.headSeq - res.signedThrough : 0n;
    if (res.checkpoints === 0n && res.records > 0n) {
      fail("unanchored", res.headSeq, "no checkpoint: nothing in this log is pinned by a signature");
    }
  }
  return res;
}

export { classify as _classify, hashInput as _hashInput };
