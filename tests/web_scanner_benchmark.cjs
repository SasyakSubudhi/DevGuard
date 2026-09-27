const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { performance } = require("node:perf_hooks");

const projectRoot = path.resolve(__dirname, "..");
const fixturePath = path.join(projectRoot, "demo_files", "rigged_performance_test.py");
const appPath = path.join(projectRoot, "web", "app.js");

function elementStub() {
  return {
    textContent: "",
    innerHTML: "",
    hidden: false,
    className: "",
    lastChild: { textContent: "" },
    classList: { add() {}, remove() {} },
    addEventListener() {},
    insertAdjacentHTML(_position, html) { this.innerHTML += html; },
    click() {}
  };
}

const elements = new Map();
const context = {
  console,
  performance,
  TextDecoder,
  document: {
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, elementStub());
      return elements.get(id);
    }
  },
  fetch: async () => ({ ok: false, status: 404 })
};

vm.createContext(context);
vm.runInContext(fs.readFileSync(appPath, "utf8"), context, { filename: appPath });

const source = fs.readFileSync(fixturePath, "utf8");
const started = performance.now();
const report = context.analyzeTextFile({ name: path.basename(fixturePath) }, source, started);
const repeatedSource = Array.from({ length: 120 }, (_value, index) => `eval(input_${index})`).join("\n");
const repeatedReport = context.analyzeTextFile({ name: "repeated_findings.py" }, repeatedSource, performance.now());
const guardedReport = context.analyzeTextFile(
  { name: "guarded_division.py" },
  "def average(values):\n    if not values:\n        return 0.0\n    return sum(values) / len(values)\n",
  performance.now()
);

if (report.findings.length !== 10) {
  throw new Error(`Expected all 10 seeded findings, received ${report.findings.length}.`);
}
if (report.logs.events.length !== 2) {
  throw new Error(`Expected two explicit error-related events, received ${report.logs.events.length}.`);
}
if (repeatedReport.findings.length !== 120) {
  throw new Error(`Finding collection was truncated: expected 120, received ${repeatedReport.findings.length}.`);
}
if (guardedReport.findings.length !== 0) {
  throw new Error("A guarded division was incorrectly reported as a defect.");
}

console.log(JSON.stringify({
  bytes: Buffer.byteLength(source),
  lines: source.split(/\r?\n/).length,
  findings: report.findings.length,
  repeatedFindingsCaptured: repeatedReport.findings.length,
  guardedFalsePositives: guardedReport.findings.length,
  logEvents: report.logs.events.length,
  analysisMs: report.timings_ms.total
}, null, 2));
