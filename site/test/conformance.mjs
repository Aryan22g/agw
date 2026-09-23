// Holds the JavaScript RFC-0009 verifier to the conformance corpus.
//   node site/test/conformance.mjs
import { readFileSync } from "node:fs";
import { verify, importPublicKey, _classify, _hashInput } from "../assets/rfc0009.js";

const corpus = JSON.parse(readFileSync(new URL("../../conformance/evidence/agw-evidence-v2.json", import.meta.url)));
const key = await importPublicKey(corpus.public_key);
let failed = 0;

for (const hv of corpus.hash_vectors) {
  const got = _hashInput(_classify(hv.record).record);
  if (got !== hv.canonical_input) {
    failed++;
    console.log(`FAIL hash vector ${hv.name}\n  got  ${JSON.stringify(got)}\n  want ${JSON.stringify(hv.canonical_input)}`);
  }
}

for (const v of corpus.verify_vectors) {
  let anchor = null;
  if (v.anchor) anchor = _classify(JSON.stringify(v.anchor)).checkpoint;
  const r = await verify(v.log, v.key === "test" ? key : null, anchor);
  const got = {
    intact: r.intact, records: Number(r.records), checkpoints: Number(r.checkpoints), head_seq: Number(r.headSeq),
    signed_through: Number(r.signedThrough), unanchored_records: Number(r.unanchoredRecords),
    problems: r.problems.map((p) => ({ kind: p.kind, seq: Number(p.seq) })),
  };
  if (JSON.stringify(got) !== JSON.stringify(v.expect)) {
    failed++;
    console.log(`FAIL ${v.name}: ${v.description}\n  got  ${JSON.stringify(got)}\n  want ${JSON.stringify(v.expect)}`);
  }
}

const total = corpus.hash_vectors.length + corpus.verify_vectors.length;
console.log(failed ? `${failed} of ${total} vectors failed` : `all ${total} vectors pass`);
process.exit(failed ? 1 : 0);
