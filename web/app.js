const byId = (id) => document.getElementById(id);
const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[char]));
const MAX_UPLOAD_BYTES = 5 * 1024 * 1024;
const FINDINGS_PER_PAGE = 50;
const SEVERITY_ORDER = ["critical", "high", "medium", "low"];
const SCAN_RULES = [
  ["correctness", "high", "high", /\/\s*len\s*\(\s*([A-Za-z_]\w*)\s*\)/, "Possible division by empty collection", "Guard a zero-length denominator and add a regression test."],
  ["security", "critical", "high", /\b(?:eval|exec)\s*\(/, "Dynamic code execution", "Remove dynamic execution or strictly validate and isolate the input."],
  ["security", "high", "high", /shell\s*=\s*True/, "Shell command injection risk", "Use an argument list with shell disabled."],
  ["security", "high", "medium", /(?:password|api[_-]?key|token|secret)\s*[:=]\s*["'][^"']+/i, "Possible embedded secret", "Move the value to a protected environment or secret store."],
  ["database", "high", "medium", /(?:execute|executemany)\s*\(\s*f["']/, "Possible SQL injection", "Use a parameterized query."],
  ["api", "medium", "medium", /requests\.(?:get|post|put|delete|patch)\s*\((?![^\r\n)]*timeout\s*=)/, "HTTP request may lack a timeout", "Set an explicit timeout and handle failures."],
  ["reliability", "medium", "high", /^[\t ]*except[\t ]*:[\t ]*(?:#.*)?$/, "Bare exception handler", "Catch a specific exception and record useful context."],
  ["performance", "low", "medium", /time\.sleep\s*\(/, "Blocking sleep", "Confirm blocking is acceptable or use event-driven waiting."],
  ["configuration", "high", "high", /\bverify(?:_ssl)?\b\s*[:=]\s*false/i, "TLS verification disabled", "Enable certificate verification."],
  ["configuration", "medium", "high", /\bdebug\b\s*[:=]\s*(?:true|1|yes)/i, "Debug mode enabled", "Disable debug mode outside local development."]
];
const ERROR_PATTERN = /(?:[A-Za-z]*Error|[A-Za-z]*Exception)\b|\b(?:traceback|fatal|panic|failed)\b/i;
const EXCEPTION_PATTERN = /(?:Error|Exception|panic|fatal)(?::|\b)/i;

let visibleFindings = [];
let renderedFindingCount = 0;
let inspectorState = {items:[], resolved:false};

function titleCase(value) {
  return String(value || "unknown").replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function findingMarkup(item) {
  return `<article class="finding-item"><span class="severity ${escapeHtml(item.severity)}">${escapeHtml(item.severity.toUpperCase())}</span><div><h3>${escapeHtml(item.title)}</h3><p>${escapeHtml(item.recommendation)}</p></div><code>${escapeHtml(item.path)}:${item.line}</code></article>`;
}

function renderMoreFindings(reset = false) {
  if (reset) {
    renderedFindingCount = 0;
    byId("findingList").innerHTML = "";
  }
  const next = visibleFindings.slice(renderedFindingCount, renderedFindingCount + FINDINGS_PER_PAGE);
  if (next.length) byId("findingList").insertAdjacentHTML("beforeend", next.map(findingMarkup).join(""));
  renderedFindingCount += next.length;
  const remaining = visibleFindings.length - renderedFindingCount;
  byId("showMoreFindings").hidden = remaining <= 0;
  byId("showMoreFindings").textContent = remaining > 0 ? `Show ${Math.min(FINDINGS_PER_PAGE, remaining)} more (${remaining} remaining)` : "All findings shown";
}

function explainInspectorItem(item) {
  const title = item.title || "Runtime failure";
  const lower = title.toLowerCase();
  if (item.historicalDivision || lower.includes("division by empty")) return {
    heading:"Division by zero interrupts normal execution", label:"Why execution stops",
    text:"When the collection is empty, its length is zero. Dividing by zero raises ZeroDivisionError immediately, so the current function cannot return and its caller never completes normally.",
    chain:["Empty collection","ZeroDivisionError","Current request stops"]};
  if (lower.includes("dynamic code")) return {
    heading:title, label:"Why execution can stop",
    text:"The program executes input as code. Invalid or hostile input can raise an exception or run unintended instructions before the function reaches its normal return path.",
    chain:["Untrusted input","Code executed","Normal flow compromised"]};
  if (lower.includes("shell command")) return {
    heading:title, label:"Why execution can stop",
    text:"Constructed text is passed through a system shell. A malformed command can return a failure and terminate this operation, while injected commands can alter program or system state.",
    chain:["Unsafe command","Shell execution","Operation fails"]};
  if (lower.includes("sql injection")) return {
    heading:title, label:"Why execution can stop",
    text:"Interpolated input changes the SQL statement. Malformed input can make the database reject the query, so the request fails before its normal result is produced.",
    chain:["Untrusted value","Query changed","Database rejects request"]};
  if (lower.includes("timeout")) return {
    heading:title, label:"Why execution can stall",
    text:"Without a timeout, the network call can wait indefinitely when the remote service does not respond. The current request remains blocked and cannot finish normally.",
    chain:["Service unavailable","Request keeps waiting","Execution stalls"]};
  if (lower.includes("bare exception")) return {
    heading:title, label:"Why normal behavior breaks",
    text:"This handler catches every exception without identifying the actual failure. The program can continue with incomplete state, hiding the point where normal execution first broke.",
    chain:["Exception raised","Cause hidden","Invalid state continues"]};
  if (lower.includes("blocking sleep")) return {
    heading:title, label:"Why execution pauses",
    text:"A blocking sleep stops this thread from doing useful work for the entire delay. In request or async code, other work waits and may exceed its response deadline.",
    chain:["Sleep begins","Thread blocked","Response delayed"]};
  if (lower.includes("embedded secret")) return {
    heading:title, label:"Why normal operation is at risk",
    text:"A credential stored in source can be leaked, revoked, or copied into the wrong environment. Once invalidated, authentication fails and dependent requests stop.",
    chain:["Secret exposed","Credential revoked","Authentication fails"]};
  if (lower.includes("tls verification")) return {
    heading:title, label:"Why normal operation is unsafe",
    text:"Disabling certificate verification allows an attacker to impersonate the remote service. The request may receive modified data even when execution appears to continue.",
    chain:["Certificate ignored","Peer untrusted","Data can be altered"]};
  if (lower.includes("debug mode")) return {
    heading:title, label:"Why normal operation is exposed",
    text:"Debug mode can reveal stack traces, source details, and internal state. It may not stop execution directly, but it turns ordinary failures into sensitive information leaks.",
    chain:["Failure occurs","Debug details exposed","System information leaks"]};
  return {heading:title, label:"Execution impact", text:item.recommendation || "This finding can prevent the code from completing its expected behavior.", chain:["Problem reached","Behavior changes","Normal result at risk"]};
}

function activateInspectorFinding(index) {
  const item = inspectorState.items[index];
  if (!item) return;
  const detail = explainInspectorItem(item);
  document.querySelectorAll("[data-finding-index]").forEach(element => {
    const selected = Number(element.dataset.findingIndex) === index;
    element.classList.toggle("selected", selected);
    if (element.getAttribute("role") === "tab") element.setAttribute("aria-selected", String(selected));
  });
  byId("codeFilename").textContent = `${item.path || "Unknown file"}:${item.line || "?"}`;
  byId("explanationLabel").textContent = detail.label;
  byId("bugTitle").textContent = detail.heading;
  byId("bugExplanation").textContent = detail.text;
  document.querySelector(".impact-chain").innerHTML = detail.chain.map((part, position) => `${position ? "<b>→</b>" : ""}<span>${escapeHtml(part)}</span>`).join("");
}

function renderCodeInspector(report, summary, matches, findings, fault) {
  const exception = String(summary.exception || "");
  const historicalDivision = report.status === "resolved" && exception.includes("ZeroDivisionError");
  let items = findings.map(item => ({...item}));
  let rows = [];
  let fixLine;

  if (historicalDivision) {
    const match = matches.find(item => item.path === fault?.path) || matches[0];
    rows = (match?.excerpt || "").split("\n").map(row => {
      const parsed = row.match(/^(\d+):\s?(.*)$/);
      return parsed ? {line:Number(parsed[1]), text:parsed[2]} : null;
    }).filter(Boolean);
    const divisionLine = rows.find(row => /\/\s*len\s*\(/.test(row.text))?.line || fault?.line;
    fixLine = rows.find(row => /if\s+(?:not\s+|len\s*\()/.test(row.text))?.line;
    items = [{path:fault?.path || "pricing.py", line:divisionLine, title:"Possible division by empty collection", historicalDivision:true}];
  } else {
    rows = items.map((item, index) => ({line:item.line, text:item.evidence || item.title, findingIndex:index}));
  }

  inspectorState = {items, resolved:report.status === "resolved"};
  byId("bugTabs").innerHTML = items.length ? items.map((item, index) =>
    `<button type="button" role="tab" aria-selected="${index === 0}" class="bug-tab${index === 0 ? " selected" : ""}" data-finding-index="${index}"><span>${index + 1}</span><strong>${escapeHtml(item.title)}</strong><code>${escapeHtml(item.path)}:${item.line}</code></button>`
  ).join("") : '<span class="no-bugs">No supported code risks were detected.</span>';

  byId("codePreview").innerHTML = rows.length ? rows.map((row, rowIndex) => {
    const findingIndex = row.findingIndex ?? (historicalDivision && row.line === items[0]?.line ? 0 : undefined);
    const isBug = findingIndex !== undefined;
    const state = isBug ? ` is-bug${findingIndex === 0 ? " selected" : ""}` : row.line === fixLine ? " is-fix" : "";
    const data = isBug ? ` data-finding-index="${findingIndex}" tabindex="0" role="button"` : "";
    const marker = isBug ? `<span class="line-flag">BUG ${findingIndex + 1}</span>` : row.line === fixLine ? '<span class="line-flag fixed">FIX</span>' : "";
    return `<span class="code-line${state}"${data}><b>${row.line ?? rowIndex + 1}</b><code>${escapeHtml(row.text)}</code>${marker}</span>`;
  }).join("") : '<span class="code-empty">No bounded source excerpt is available for this finding.</span>';

  byId("codeRiskBadge").textContent = historicalDivision ? "Historical blocker" : `${items.length} risk${items.length === 1 ? "" : "s"} detected`;
  byId("codeRiskBadge").className = `tag ${historicalDivision ? "resolved" : items.length ? "danger" : "safe"}`;
  byId("bugResolution").hidden = !historicalDivision;
  byId("bugResolution").textContent = "The guard now returns 0.0 before the division, so the historical failure cannot reach the red line with an empty list.";

  document.querySelectorAll("[data-finding-index]").forEach(element => {
    element.addEventListener("click", () => activateInspectorFinding(Number(element.dataset.findingIndex)));
    element.addEventListener("keydown", event => {
      if (event.key === "Enter" || event.key === " ") { event.preventDefault(); element.click(); }
    });
  });
  if (items.length) activateInspectorFinding(0);
  else {
    byId("codeFilename").textContent = "No source location";
    byId("explanationLabel").textContent = "Analysis complete";
    byId("bugTitle").textContent = "No supported execution blocker found";
    byId("bugExplanation").textContent = "Runtime tests and language-specific analyzers can provide additional coverage.";
  }
}

function renderReport(report) {
  const summary = report.summary || {};
  const validation = report.test_validation || {};
  const matches = report.code?.matches || [];
  const events = report.logs?.events || [];
  const path = summary.causal_path || [];
  const findings = report.findings || [];
  const fault = summary.likely_fault;

  byId("issue").textContent = summary.issue || report.issue || "Incident under investigation";
  byId("exception").textContent = summary.exception || "Failure detected";
  byId("diagnosis").textContent = summary.preliminary_diagnosis || "Review the collected evidence to determine the root cause.";
  byId("faultLocation").textContent = fault ? `${fault.path}:${fault.line}` : "Unresolved";
  byId("confidence").textContent = `${titleCase(summary.confidence)} confidence`;
  byId("nextAction").textContent = summary.next_action || "Review the evidence and add a regression test.";
  byId("totalTime").textContent = `${Math.round(report.timings_ms?.total || 0)} ms`;
  byId("filesScanned").textContent = report.code?.files_scanned ?? 0;
  byId("eventCount").textContent = events.length;
  byId("logResult").textContent = `${events.length} relevant events`;
  byId("codeResult").textContent = `${report.code?.stack_matches || 0} stack matches`;
  byId("dependencyResult").textContent = `${report.dependencies?.manifests?.length || 0} manifests inspected`;
  byId("pathCount").textContent = `${path.length} frames`;
  byId("findingCount").textContent = `${findings.length} findings`;
  for (const severity of ["critical", "high", "medium", "low"]) {
    byId(`${severity}Count`).textContent = report.finding_counts?.[severity] || 0;
  }
  byId("validationTime").textContent = `${Math.round(validation.duration_ms || 0)} ms`;
  byId("testOutput").textContent = validation.output || validation.error || "No test command was supplied for this report.";

  const validationStatus = validation.status || "not_run";
  byId("testState").textContent = validationStatus === "passed_with_expected_failures" ? "Known failure" : titleCase(validationStatus);
  byId("validationBadge").textContent = validationStatus === "passed_with_expected_failures" ? "Expected failure" : titleCase(validationStatus);
  byId("validationBadge").className = `tag ${validationStatus === "passed" ? "safe" : "warning"}`;
  byId("statusBadge").lastChild.textContent = titleCase(report.status || "unknown");

  byId("causalPath").innerHTML = path.length ? path.map((frame, index) => {
    const match = matches.find((item) => item.path === frame.path && item.line === frame.line);
    const source = match?.excerpt?.split("\n").find((line) => line.startsWith(`${frame.line}:`))?.replace(/^\d+:\s*/, "") || "Stack frame resolved from the incident log";
    return `<li><span class="timeline-dot" aria-hidden="true"></span><div><strong>${escapeHtml(frame.path)}:${frame.line}</strong><p>${escapeHtml(source)}</p>${index === path.length - 1 ? '<span class="agent-result">Leading fault candidate</span>' : ""}</div></li>`;
  }).join("") : "<li><div><strong>No resolved causal path</strong><p>Load a report containing stack frames.</p></div></li>";

  visibleFindings = findings;
  if (findings.length) renderMoreFindings(true);
  else {
    byId("findingList").innerHTML = '<div class="finding-item"><div><h3>No heuristic findings</h3><p>Runtime evidence and external analyzers may still identify defects.</p></div></div>';
    byId("showMoreFindings").hidden = true;
  }

  renderCodeInspector(report, summary, matches, findings, fault);

  byId("loadMessage").textContent = `Loaded ${events.length} log events and ${matches.length} source matches.`;
}

function makeFinding(category, severity, confidence, filename, line, title, evidence, recommendation) {
  return { category, severity, confidence, status: "possible", path: filename, line, title, evidence, recommendation };
}

function globalPattern(pattern) {
  return new RegExp(pattern.source, `${pattern.flags.replace("g", "")}gm`);
}

function lineNumberAt(newlines, offset) {
  let low = 0;
  let high = newlines.length;
  while (low < high) {
    const middle = (low + high) >> 1;
    if (newlines[middle] < offset) low = middle + 1;
    else high = middle;
  }
  return low + 1;
}

function sourceLineAt(text, offset) {
  const start = text.lastIndexOf("\n", Math.max(0, offset - 1)) + 1;
  const nextNewline = text.indexOf("\n", offset);
  return text.slice(start, nextNewline === -1 ? text.length : nextNewline).replace(/\r$/, "");
}

function hasEmptyCollectionGuard(text, offset, name) {
  let start = offset;
  for (let count = 0; count < 5 && start > 0; count += 1) start = text.lastIndexOf("\n", start - 1);
  const escapedName = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const guard = new RegExp(`if\\s+(?:not\\s+${escapedName}|len\\s*\\(\\s*${escapedName}\\s*\\)\\s*==\\s*0|${escapedName}\\s*==\\s*\\[\\])\\s*:`);
  return guard.test(text.slice(Math.max(0, start), offset));
}

function analyzeTextFile(file, text, elapsedStart) {
  const buckets = Object.fromEntries(SEVERITY_ORDER.map(level => [level, []]));
  const counts = {critical:0, high:0, medium:0, low:0};
  const newlineOffsets = [];
  for (let offset = 0; offset < text.length; offset += 1) {
    if (text.charCodeAt(offset) === 10) newlineOffsets.push(offset);
  }

  for (const [category, severity, confidence, pattern, title, recommendation] of SCAN_RULES) {
    for (const match of text.matchAll(globalPattern(pattern))) {
      const offset = match.index || 0;
      if (title === "Possible division by empty collection" && match[1] && hasEmptyCollectionGuard(text, offset, match[1])) continue;
      const row = sourceLineAt(text, offset);
      buckets[severity].push(makeFinding(category, severity, confidence, file.name, lineNumberAt(newlineOffsets, offset), title, row.trim().slice(0, 300), recommendation));
      counts[severity] += 1;
    }
  }

  const errorRows = [];
  const errorLines = new Set();
  for (const match of text.matchAll(globalPattern(ERROR_PATTERN))) {
    const offset = match.index || 0;
    const line = lineNumberAt(newlineOffsets, offset);
    if (!errorLines.has(line)) {
      errorLines.add(line);
      errorRows.push({line, text:sourceLineAt(text, offset)});
    }
  }
  const findings = SEVERITY_ORDER.flatMap(level => buckets[level]);
  let exception;
  for (let index = errorRows.length - 1; index >= 0; index -= 1) {
    if (EXCEPTION_PATTERN.test(errorRows[index].text)) { exception = errorRows[index]; break; }
  }
  const likely = findings[0];
  const elapsed = Number((performance.now() - elapsedStart).toFixed(2));
  return {
    status: "client_scan_complete", issue: `File analysis: ${file.name}`,
    summary: {issue:`File analysis: ${file.name}`, exception:exception?.text || "No explicit runtime error found",
      likely_fault:likely ? {path:file.name,line:likely.line} : null, causal_path:likely ? [{path:file.name,line:likely.line}] : [],
      confidence:likely?.confidence || "low", preliminary_diagnosis:likely ? `${likely.title}. ${likely.evidence}` : "No known high-signal pattern was detected in this file.",
      next_action:likely?.recommendation || "Combine this file with runtime logs and repository context for deeper analysis."},
    logs:{status:"ok",events:errorRows}, code:{files_scanned:1,stack_matches:0,matches:likely ? [{path:file.name,line:likely.line,excerpt:`${likely.line}: ${likely.evidence}`}] : []},
    dependencies:{manifests:[],imports:[]}, findings, finding_counts:counts,
    test_validation:{status:"not_run",duration_ms:0,output:"Browser file analysis does not execute uploaded code."},
    timings_ms:{investigation:elapsed,total:elapsed}
  };
}

function binaryReport(file, elapsedStart) {
  return {status:"metadata_only",issue:`Binary file: ${file.name}`,
    summary:{issue:`Binary file: ${file.name}`,exception:"Binary content cannot be safely inspected as source text",likely_fault:null,causal_path:[],confidence:"low",preliminary_diagnosis:`File type ${file.type || "unknown"}; size ${file.size.toLocaleString()} bytes.`,next_action:"Provide source code, text logs, or a DevGuard JSON report for semantic analysis."},
    logs:{events:[]},code:{files_scanned:1,stack_matches:0,matches:[]},dependencies:{manifests:[],imports:[]},findings:[],finding_counts:{critical:0,high:0,medium:0,low:0},
    test_validation:{status:"not_run",duration_ms:0,output:"Binary files are never executed."},timings_ms:{investigation:Number((performance.now()-elapsedStart).toFixed(2)),total:Number((performance.now()-elapsedStart).toFixed(2))}};
}

async function analyzeFile(file) {
  const started = performance.now();
  if (file.size > MAX_UPLOAD_BYTES) throw new Error("File exceeds the 5 MB browser-analysis limit.");
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  const binary = bytes.slice(0, Math.min(bytes.length, 8192)).some(byte => byte === 0);
  if (binary) return binaryReport(file, started);
  const text = new TextDecoder("utf-8", {fatal:false}).decode(buffer);
  if (file.name.toLowerCase().endsWith(".json")) {
    try {
      const parsed = JSON.parse(text);
      if (parsed.summary && parsed.code && parsed.logs) return parsed;
    } catch (_) { /* analyze malformed JSON as text */ }
  }
  return analyzeTextFile(file, text, started);
}

async function loadDefaultReport() {
  try {
    const response = await fetch("demo-report.json", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    renderReport(await response.json());
  } catch (error) {
    byId("loadMessage").textContent = "Demo report could not be loaded automatically. Select Load report and choose demo-report.md.json.";
  }
}

async function handleFile(file) {
  if (!file) return;
  try {
    renderReport(await analyzeFile(file));
    byId("loadMessage").textContent = `Analyzed ${file.name} locally. The file was not uploaded or executed.`;
  } catch (error) {
    byId("loadMessage").textContent = error.message || "The selected file could not be analyzed.";
  }
}

byId("reportInput").addEventListener("change", (event) => handleFile(event.target.files?.[0]));
byId("showMoreFindings").addEventListener("click", () => renderMoreFindings());
const dropZone = byId("dropZone");
dropZone.addEventListener("click", () => byId("reportInput").click());
dropZone.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); byId("reportInput").click(); } });
for (const name of ["dragenter","dragover"]) dropZone.addEventListener(name, (event) => { event.preventDefault(); dropZone.classList.add("dragging"); });
for (const name of ["dragleave","drop"]) dropZone.addEventListener(name, (event) => { event.preventDefault(); dropZone.classList.remove("dragging"); });
dropZone.addEventListener("drop", (event) => handleFile(event.dataTransfer?.files?.[0]));

function initializeScrollExperience() {
  if (typeof window === "undefined" || !document.querySelectorAll) return;
  const progress = byId("scrollProgress");
  const backToTop = byId("backToTop");
  const navLinks = [...document.querySelectorAll(".nav-link")];
  const dockLinks = [...document.querySelectorAll(".dock-link")];
  const sections = navLinks.map(link => document.querySelector(link.getAttribute("href"))).filter(Boolean);
  const revealItems = [...document.querySelectorAll("main > section, main > .content-grid, .agent")];
  const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  let scrollFrame;

  document.body.classList.add("reveal-ready");
  revealItems.forEach((item, index) => {
    item.classList.add("reveal");
    item.style.setProperty("--reveal-delay", `${Math.min(index % 4, 3) * 55}ms`);
  });

  if (reducedMotion || !("IntersectionObserver" in window)) {
    revealItems.forEach(item => item.classList.add("in-view"));
  } else {
    const revealObserver = new IntersectionObserver(entries => {
      for (const entry of entries) {
        if (entry.isIntersecting) {
          entry.target.classList.add("in-view");
          revealObserver.unobserve(entry.target);
        }
      }
    }, {rootMargin:"0px 0px -8% 0px", threshold:0.08});
    revealItems.forEach(item => revealObserver.observe(item));
  }

  const updateScrollUi = () => {
    scrollFrame = undefined;
    const maxScroll = Math.max(1, document.documentElement.scrollHeight - window.innerHeight);
    progress.style.transform = `scaleX(${Math.min(1, window.scrollY / maxScroll)})`;
    const parallax = Math.min(window.scrollY, 520) * 0.035;
    document.documentElement.style.setProperty("--hero-offset", `${parallax}px`);
    document.documentElement.style.setProperty("--hero-score-offset", `${parallax * 0.45}px`);
    backToTop.classList.toggle("visible", window.scrollY > 560);

    let activeId = sections[0]?.id;
    const marker = window.scrollY + Math.min(220, window.innerHeight * 0.32);
    for (const section of sections) {
      const sectionTop = section.getBoundingClientRect().top + window.scrollY;
      if (sectionTop <= marker) activeId = section.id;
    }
    navLinks.forEach(link => link.classList.toggle("active", link.getAttribute("href") === `#${activeId}`));
    dockLinks.forEach(link => link.classList.toggle("active", link.getAttribute("href") === `#${activeId}`));
  };

  window.addEventListener("scroll", () => {
    if (!scrollFrame) scrollFrame = requestAnimationFrame(updateScrollUi);
  }, {passive:true});
  window.addEventListener("resize", updateScrollUi, {passive:true});
  backToTop.addEventListener("click", () => window.scrollTo({top:0, behavior:reducedMotion ? "auto" : "smooth"}));
  updateScrollUi();
}

loadDefaultReport();
initializeScrollExperience();
