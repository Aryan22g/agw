// Verifies many logs in one process, for the Go differential test.
//   node site/test/verify-batch.mjs KEYFILE LOG...
// Prints one JSON object per log, in order.
import { readFileSync } from "node:fs";
import { verify, importPublicKey } from "../assets/rfc0009.js";

const [keyFile, ...logs] = process.argv.slice(2);
const key = await importPublicKey(readFileSync(keyFile, "utf8"));
for (const path of logs) {
  // The Go verifiers decode invalid UTF-8 as U+FFFD; so does a non-fatal decoder.
  const text = new TextDecoder("utf-8").decode(readFileSync(path));
  const r = await verify(text, key, null);
  console.log(JSON.stringify({
    intact: r.intact, records: Number(r.records), checkpoints: Number(r.checkpoints), head_seq: Number(r.headSeq),
    signed_through: Number(r.signedThrough), unanchored_records: Number(r.unanchoredRecords),
    problems: r.problems.map((p) => `${p.kind}@${p.seq}`),
  }));
}
