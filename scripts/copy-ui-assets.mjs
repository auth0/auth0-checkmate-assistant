import { cp, mkdir } from "node:fs/promises";

await mkdir("dist/src/ui/public", { recursive: true });
await cp("src/ui/public", "dist/src/ui/public", { recursive: true });
