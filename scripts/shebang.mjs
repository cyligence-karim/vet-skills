// esbuild keeps the source shebang only when it is the first line; the createRequire banner pushes it down. Put it back on top and make the file executable.
import { readFileSync, writeFileSync, chmodSync } from "node:fs";
const f = new URL("../dist/index.js", import.meta.url);
let s = readFileSync(f, "utf8").replace(/^#!.*\n/m, "");
writeFileSync(f, "#!/usr/bin/env node\n" + s);
chmodSync(f, 0o755);
