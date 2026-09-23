// The launch site's behaviour. No dependencies, no network requests except
// the page's own sample files, fetched only when asked for.
import { verify, importPublicKey, readAnchor } from "./rfc0009.js";

const $ = (s, root = document) => root.querySelector(s);
const $$ = (s, root = document) => Array.from(root.querySelectorAll(s));

// ---------------------------------------------------------------- copy buttons

for (const btn of $$("[data-copy]")) {
  btn.addEventListener("click", async () => {
    const src = $(btn.dataset.copy);
    const text = src ? src.textContent : "";
    try {
      await navigator.clipboard.writeText(text);
      btn.textContent = "Copied";
      btn.classList.add("done");
      setTimeout(() => { btn.textContent = "Copy"; btn.classList.remove("done"); }, 1600);
    } catch {
      // Clipboard refused: select the text so the visitor can copy it.
      const r = document.createRange();
      r.selectNodeContents(src);
      const sel = getSelection();
      sel.removeAllRanges();
      sel.addRange(r);
      btn.textContent = "Selected";
    }
  });
}

// ---------------------------------------------------------------- tabs

for (const tabs of $$("[data-tabs]")) {
  const buttons = $$('[role="tab"]', tabs);
  const select = (b) => {
    for (const x of buttons) {
      const on = x === b;
      x.setAttribute("aria-selected", String(on));
      x.tabIndex = on ? 0 : -1;
      $("#" + x.getAttribute("aria-controls")).hidden = !on;
    }
  };
  buttons.forEach((b, i) => {
    b.tabIndex = b.getAttribute("aria-selected") === "true" ? 0 : -1;
    b.addEventListener("click", () => select(b));
    b.addEventListener("keydown", (e) => {
      const d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
      if (!d) return;
      const next = buttons[(i + d + buttons.length) % buttons.length];
      select(next);
      next.focus();
    });
  });
}

// ---------------------------------------------------------------- the page as a hash chain
//
// Each section is a record: seq, the previous section's hash, and the SHA-256
// of the length-prefixed previous hash and the section's text. The same
// construction as an agw evidence record, applied to the page you are reading.

const enc = new TextEncoder();
const F = (s) => `${enc.encode(s).length}:${s}`;
async function sha256(s) {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(s)));
  return Array.from(d, (b) => b.toString(16).padStart(2, "0")).join("");
}
const short = (h) => `${h.slice(0, 6)}…${h.slice(-4)}`;

async function sealPage() {
  let prev = "0".repeat(64);
  const sections = $$("section.record");
  for (const [i, sec] of sections.entries()) {
    const seal = $(".seal", sec);
    // The seal itself is not part of what it seals.
    const text = Array.from(sec.childNodes)
      .filter((n) => !(n.nodeType === 1 && n.classList.contains("seal")))
      .map((n) => n.textContent)
      .join("")
      .replace(/\s+/g, " ")
      .trim();
    const hash = await sha256(F(String(i + 1)) + F(prev) + F(sec.dataset.title || "") + F(text));
    if (seal) {
      seal.innerHTML = "";
      const parts = [
        ["label", sec.dataset.title || ""],
        ["seq", String(i + 1)],
        ["prev", short(prev)],
        ["hash", short(hash)],
      ];
      for (const [k, v] of parts) {
        const span = document.createElement("span");
        if (k === "label") {
          span.className = "label";
          span.textContent = v;
        } else {
          span.append(`${k} `);
          const b = document.createElement("b");
          b.textContent = v;
          span.append(b);
        }
        seal.append(span);
      }
      seal.title = `seq ${i + 1}\nprevHash ${prev}\nhash ${hash}`;
    }
    prev = hash;
  }
}

// ---------------------------------------------------------------- the hero transcript

function playTranscript() {
  const term = $("#hero-term");
  if (!term) return;
  const lines = $$(".line", term);
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;
  if (reduce) {
    term.classList.remove("play");
    return;
  }
  // Lines are visible at rest (dimmed); this brings each to full strength in
  // turn, the way the demo prints them.
  lines.forEach((l, i) => setTimeout(() => l.classList.add("on"), 250 + i * 170));
}

// ---------------------------------------------------------------- the verifier

const state = { log: null, logName: "", key: "", anchor: null, anchorName: "" };

function readFile(file) {
  return file.text();
}

function wireDrop(zoneId, inputId, nameId, onText) {
  const zone = $("#" + zoneId);
  const input = $("#" + inputId);
  const name = $("#" + nameId);
  const take = async (file) => {
    if (!file) return;
    name.textContent = `${file.name} · ${file.size.toLocaleString()} bytes`;
    onText(await readFile(file), file.name);
  };
  input.addEventListener("change", () => take(input.files[0]));
  zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("over"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("over"));
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("over");
    take(e.dataTransfer.files[0]);
  });
}

wireDrop("drop-log", "f-log", "n-log", (t, n) => { state.log = t; state.logName = n; run(); });
wireDrop("drop-key", "f-key", "n-key", (t) => { state.key = t.trim(); $("#key-text").value = state.key; run(); });
wireDrop("drop-anchor", "f-anchor", "n-anchor", (t, n) => {
  try {
    state.anchor = readAnchor(t);
    state.anchorName = n;
  } catch (e) {
    state.anchor = null;
    $("#n-anchor").textContent = e.message;
  }
  run();
});
$("#key-text").addEventListener("input", (e) => { state.key = e.target.value.trim(); });
$("#vform").addEventListener("submit", (e) => { e.preventDefault(); run(); });

async function loadSample(tampered) {
  const [log, key] = await Promise.all([
    fetch(`samples/contained-agent${tampered ? "-tampered" : ""}.jsonl`).then((r) => r.text()),
    fetch("samples/contained-agent.pub").then((r) => r.text()),
  ]);
  state.log = log;
  state.logName = tampered ? "contained-agent-tampered.jsonl" : "contained-agent.jsonl";
  state.key = key.trim();
  state.anchor = null;
  $("#n-log").textContent = `${state.logName} (sample) · ${log.length.toLocaleString()} bytes`;
  $("#n-key").textContent = "contained-agent.pub (sample)";
  $("#n-anchor").textContent = "a checkpoint you kept earlier: detects rollback";
  $("#key-text").value = state.key;
  await run();
}
$("#load-good").addEventListener("click", () => loadSample(false));
$("#load-bad").addEventListener("click", () => loadSample(true));

const KIND_EXPLAINED = {
  content: "a record was edited after it was written",
  chain: "a record does not link to the one before it",
  sequence: "a record was removed, inserted or reordered",
  checkpoint: "a signed checkpoint does not match the log, or its signature fails",
  malformed: "a line is not a well-formed record",
  version: "a record declares a format this verifier does not implement",
  unanchored: "nothing in the log is signed",
  rollback: "the log was truncated to before the anchor you kept",
  missing_anchor: "the checkpoint you kept is not in this log",
  forked: "the checkpoint you kept belongs to a different history",
  anchor_invalid: "the anchor is not signed by this key",
  superseded_format: "an older format that protects fewer fields",
};

function el(tag, attrs = {}, ...children) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") e.className = v;
    else e.setAttribute(k, v);
  }
  for (const c of children) e.append(c);
  return e;
}

async function run() {
  const out = $("#vout");
  // null means no file yet; "" is a file with nothing in it, which is a result.
  if (state.log === null) {
    out.replaceChildren(el("div", { class: "verdict" }, el("span", { class: "word" }, "Choose an evidence log"),
      el("span", { class: "why" }, "Or load the demo log to see a verified one.")));
    return;
  }

  let key = null;
  try {
    if (state.key) key = await importPublicKey(state.key);
  } catch (e) {
    out.replaceChildren(el("div", { class: "verdict bad" }, el("span", { class: "word" }, "Key not usable"),
      el("span", { class: "why" }, e.message)));
    return;
  }

  let r;
  try {
    r = await verify(state.log, key, state.anchor);
  } catch (e) {
    out.replaceChildren(el("div", { class: "verdict bad" }, el("span", { class: "word" }, "Could not verify"),
      el("span", { class: "why" }, e.message)));
    return;
  }

  // The verdict, stated as precisely as the result allows.
  let cls, word, why;
  if (!r.intact) {
    cls = "bad";
    word = "Tampering detected";
    const first = r.problems.find((p) => p.kind !== "superseded_format");
    why = first ? `At seq ${first.seq}: ${KIND_EXPLAINED[first.kind] || first.kind}. Records before it remain trustworthy.` : "";
  } else if (r.records === 0n) {
    cls = "partial";
    word = "Empty log";
    why = "It contains no records, so there is nothing to verify. An empty log is also what deleting every record produces; only a checkpoint you kept earlier can tell the two apart.";
  } else if (!key) {
    cls = "partial";
    word = "Chain intact, signatures not checked";
    why = "No record was edited, removed or reordered. Add the public key to prove the log was not rewritten wholesale.";
  } else if (r.unanchoredRecords > 0n) {
    cls = "partial";
    word = `Verified through seq ${r.signedThrough}`;
    why = `${r.unanchoredRecords} later record(s) are chained but not yet signed; removing them would go undetected.`;
  } else {
    cls = "ok";
    word = "Verified";
    why = "No record was altered, removed or reordered, and every record is covered by a checkpoint signed with this key." +
      (state.anchor ? " The log also extends the checkpoint you kept." : "");
  }

  const stats = el("div", { class: "stats" },
    ...[["records", r.records], ["checkpoints", r.checkpoints], ["signed through", key ? r.signedThrough : "—"],
      ["refused", r.decisions.get("deny") || 0]].map(([l, n]) =>
      el("div", { class: "stat" }, el("div", { class: "num" }, String(n)), el("div", { class: "lbl" }, l))));

  const children = [el("div", { class: `verdict ${cls}` }, el("span", { class: "word" }, word), el("span", { class: "why" }, why)), stats];

  if (r.problems.length) {
    children.push(el("ul", { class: "problems" }, ...r.problems.slice(0, 12).map((p) =>
      el("li", {}, el("span", { class: `kind${p.kind === "superseded_format" ? " info" : ""}` }, `${p.kind} @ ${p.seq}`),
        el("span", {}, p.detail)))));
  }

  if (r.producers.size) {
    const who = Array.from(r.producers.entries()).map(([p, n]) => `${n} from ${p}`).join(" · ");
    children.push(el("p", { class: "privacy" }, `Written by: ${who}. `,
      "“enforced:” producers record what an enforcement point decided; “observed:” records what an agent reported about itself."));
  }

  const table = el("table", {},
    el("thead", {}, el("tr", {}, ...["seq", "time (UTC)", "decision", "action", "target", "agent"].map((h) => el("th", { scope: "col" }, h)))),
    el("tbody", {}, ...r.rows.map((row) => el("tr", {},
      el("td", {}, String(row.seq)),
      el("td", {}, row.ts.replace("T", " ").replace(/\.\d+Z$|Z$/, "")),
      el("td", { class: row.decision === "deny" ? "d-deny" : row.decision === "allow" ? "d-allow" : "" },
        row.reason && row.reason !== "allowed" ? `${row.decision}/${row.reason}` : row.decision),
      el("td", {}, row.action),
      el("td", { class: "target", title: row.target }, row.target),
      el("td", {}, row.agent)))));
  children.push(el("div", { class: "rows", tabindex: "0", "aria-label": "Records in the log" }, table));

  out.replaceChildren(...children);
}

// ---------------------------------------------------------------- start

playTranscript();
sealPage().catch(() => {});
loadSample(false).catch(() => {
  // Opened from disk, where fetch() of neighbouring files is refused.
  $("#vout").replaceChildren(el("div", { class: "verdict" }, el("span", { class: "word" }, "Choose an evidence log"),
    el("span", { class: "why" }, "Drop a .jsonl file and its public key. The samples need the page to be served over HTTP.")));
});
