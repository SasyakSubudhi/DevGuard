const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { performance } = require("node:perf_hooks");

const root = path.resolve(__dirname, "..");

function elementStub() {
  return {
    textContent: "",
    innerHTML: "",
    hidden: false,
    className: "",
    lastChild: { textContent: "" },
    style: { setProperty() {} },
    classList: { add() {}, remove() {}, toggle() {} },
    addEventListener() {},
    setAttribute() {},
    getAttribute() { return null; },
    insertAdjacentHTML(_position, html) { this.innerHTML += html; },
    click() {}
  };
}

const elements = new Map();
const impact = elementStub();
const document = {
  body: elementStub(),
  documentElement: elementStub(),
  getElementById(id) {
    if (!elements.has(id)) elements.set(id, elementStub());
    return elements.get(id);
  },
  querySelector(selector) {
    return selector === ".impact-chain" ? impact : null;
  },
  querySelectorAll() { return []; }
};

const context = {
  console,
  performance,
  TextDecoder,
  document,
  fetch: async () => ({ ok: false, status: 404 })
};

vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(root, "web", "app.js"), "utf8"), context);

const fixture = fs.readFileSync(path.join(root, "demo_files", "rigged_performance_test.py"), "utf8");
const report = context.analyzeTextFile({ name: "rigged_performance_test.py" }, fixture, performance.now());
context.renderCodeInspector(report, report.summary, report.code.matches, report.findings, report.summary.likely_fault);

const tabs = (elements.get("bugTabs").innerHTML.match(/class="bug-tab/g) || []).length;
const redLines = (elements.get("codePreview").innerHTML.match(/is-bug/g) || []).length;

if (report.findings.length !== 10) throw new Error(`Expected 10 findings, received ${report.findings.length}.`);
if (tabs !== 10) throw new Error(`Expected 10 selectable error tabs, rendered ${tabs}.`);
if (redLines !== 10) throw new Error(`Expected 10 red code lines, rendered ${redLines}.`);
const bareExcept = report.findings.find(item => item.title === "Bare exception handler");
if (bareExcept?.line !== 11 || !bareExcept.evidence.trim().startsWith("except:")) {
  throw new Error(`Bare exception location is incorrect: ${JSON.stringify(bareExcept)}.`);
}

console.log(JSON.stringify({ findings: report.findings.length, selectableErrors: tabs, redCodeLines: redLines, bareExceptLine:bareExcept.line }, null, 2));
