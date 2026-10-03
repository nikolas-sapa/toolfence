import os from "node:os";
import { syncBuiltinESMExports } from "node:module";
import { CHECKS } from "../../dist/checks/index.js";

// Only the fixture redirects storage. Production still uses its normal path.
os.homedir = () => process.env.TOOLFENCE_TEST_BASELINE_DIR;
syncBuiltinESMExports();
CHECKS.push({ id: "fixture-error", title: "Fixture error", run() { throw new Error("fixture check failed"); } });
