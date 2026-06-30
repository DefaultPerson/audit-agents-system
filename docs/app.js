// Autonomous Audit Agents — interactive pipeline orchestration.
(function () {
  const STAGES = window.STAGES;
  const ACCENTS = {
    green: "#3ef2a4", cyan: "#46d6ff", amber: "#ffc24d", red: "#ff5b6e",
  };
  const reduce = matchMedia("(prefers-reduced-motion: reduce)").matches;

  // ---------- build nodes ----------
  const nodesEl = document.getElementById("nodes");
  STAGES.forEach((s, i) => {
    const btn = document.createElement("button");
    btn.className = "node";
    btn.dataset.i = i;
    btn.style.setProperty("--ac", ACCENTS[s.accent]);
    btn.innerHTML = `
      <span class="node-dot"><span class="node-num">${s.num}</span>
        <svg viewBox="0 0 24 24">${s.icon}</svg></span>
      <span class="node-name">${s.name}</span>
      <span class="node-role">${s.role}</span>`;
    btn.addEventListener("click", () => { pin(i); });
    nodesEl.appendChild(btn);
  });
  const nodeEls = [...nodesEl.querySelectorAll(".node")];

  // ---------- refs ----------
  const railFill = document.getElementById("railFill");
  const packet = document.getElementById("packet");
  const track = document.getElementById("track");
  const logEl = document.getElementById("log");
  const codeEl = document.getElementById("code");
  const vflash = document.getElementById("vflash");
  const detail = {
    root: document.getElementById("detail"),
    num: document.getElementById("dNum"),
    name: document.getElementById("dName"),
    role: document.getElementById("dRole"),
    tagline: document.getElementById("dTagline"),
    mech: document.getElementById("dMech"),
    diagram: document.getElementById("dDiagram"),
    corner: document.getElementById("dCorner"),
    bar: document.getElementById("consoleBar"),
  };
  const DIAGRAMS = window.DIAGRAMS || {};

  // ---------- counters ----------
  const metricEls = {};
  document.querySelectorAll(".metric").forEach((m) => { metricEls[m.dataset.k] = m.querySelector(".val"); });
  const counts = { contracts: 1932, functions: 14102, hypotheses: 3461, pocs: 188, confirmed: 41 };
  const metricMap = { candidates: "contracts", decompiled: "functions", hypotheses: "hypotheses", survivors: "pocs", confirmed: "confirmed" };
  function paintCounts() {
    for (const k in metricEls) metricEls[k].textContent = counts[k].toLocaleString("en-US");
  }
  paintCounts();
  // ambient drift so the dashboard always feels alive
  setInterval(() => {
    if (Math.random() < 0.7) { counts.contracts += 1; }
    if (Math.random() < 0.5) { counts.functions += Math.floor(Math.random() * 6) + 1; }
    paintCounts();
  }, 1400);

  // ---------- syntax highlight ----------
  const KW = /\b(async|def|for|while|if|in|return|yield|None|True|False|and|or|not|await)\b/g;
  function esc(s) { return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); }
  function highlight(line) {
    const ci = line.indexOf("#");
    let code = line, cmt = "";
    if (ci >= 0) { code = line.slice(0, ci); cmt = line.slice(ci); }
    let out = esc(code);
    out = out.replace(/('[^']*'|"[^"]*")/g, '<span class="str">$1</span>');
    out = out.replace(KW, '<span class="kw">$1</span>');
    out = out.replace(/\b(\d[\d_,.]*)\b/g, '<span class="num">$1</span>');
    if (cmt) out += '<span class="cmt">' + esc(cmt) + "</span>";
    return out;
  }

  // ---------- log streaming ----------
  function logHTML(text) {
    let m = esc(text);
    m = m.replace(/(✓|TRUE|ok)/g, '<span class="ok">$1</span>');
    m = m.replace(/(⚠|★)/g, '<span class="warn">$1</span>');
    m = m.replace(/(CRITICAL|9\.3|\$26M)/g, '<span class="crit">$1</span>');
    return m;
  }
  let clock = 0;
  function ts() {
    clock += Math.random() * 0.4 + 0.05;
    return "+" + clock.toFixed(2).padStart(6, "0");
  }
  function pushLog(stage, text) {
    const div = document.createElement("div");
    div.className = "log-line";
    div.innerHTML = `<span class="ts">${ts()}</span> <span class="tag" style="color:${ACCENTS[stage.accent]}">[${stage.id.toUpperCase()}]</span> <span class="msg">${logHTML(text)}</span>`;
    logEl.appendChild(div);
    while (logEl.children.length > 9) logEl.removeChild(logEl.firstChild);
  }

  // ---------- code typewriter ----------
  let codeTimer = null;
  function typeCode(stage) {
    if (codeTimer) clearInterval(codeTimer);
    const lines = stage.code;
    if (reduce) {
      codeEl.innerHTML = lines.map(highlight).join("\n") + '<span class="cursor"></span>';
      return;
    }
    let li = 0, ch = 0;
    const done = [];
    codeTimer = setInterval(() => {
      if (li >= lines.length) { clearInterval(codeTimer); return; }
      ch += 2;
      const cur = lines[li];
      const shown = cur.slice(0, ch);
      const body = done.map(highlight).join("\n");
      const partial = highlight(shown);
      codeEl.innerHTML = (body ? body + "\n" : "") + partial + '<span class="cursor"></span>';
      if (ch >= cur.length) { done.push(cur); li++; ch = 0; }
    }, 16);
  }

  // ---------- packet / rail ----------
  function moveTo(i) {
    const node = nodeEls[i].querySelector(".node-dot");
    const tRect = track.getBoundingClientRect();
    const nRect = node.getBoundingClientRect();
    const x = nRect.left + nRect.width / 2 - tRect.left;
    packet.style.left = x + "px";
    railFill.style.width = x + "px";
    const ac = ACCENTS[STAGES[i].accent];
    // fill runs through every accent passed so far -> green→cyan→amber→red
    const cols = STAGES.slice(0, i + 1).map((s) => ACCENTS[s.accent]);
    railFill.style.background = cols.length > 1
      ? `linear-gradient(90deg, ${cols.join(", ")})`
      : `linear-gradient(90deg, rgba(62,242,164,0.12), ${cols[0]})`;
    railFill.style.boxShadow = `0 0 10px ${ac}aa`;
    packet.style.background = ac;
    packet.style.boxShadow = `0 0 4px #fff, 0 0 16px ${ac}, 0 0 30px ${ac}`;
  }

  // ---------- diagram rendering ----------
  function renderDiagram(s) {
    detail.diagram.innerHTML = DIAGRAMS[s.id] || "";
    // swarm diagram is rich (fan-out + cross-check) — hide the tagline to make room
    detail.root.classList.toggle("swarm-active", s.id === "swarm");
  }

  // ---------- activate stage ----------
  let active = -1;
  function activate(i) {
    const s = STAGES[i];
    active = i;
    nodeEls.forEach((n, k) => {
      n.classList.toggle("active", k === i);
      n.classList.toggle("passed", k < i);
    });
    moveTo(i);

    // detail panel
    detail.root.style.setProperty("--ac", ACCENTS[s.accent]);
    detail.num.textContent = s.num;
    detail.name.textContent = s.name;
    detail.role.textContent = s.role;
    detail.tagline.textContent = s.tagline;
    detail.corner.textContent = s.role;
    detail.bar.style.setProperty("--ac", ACCENTS[s.accent]);
    detail.mech.innerHTML = s.mechanics.map((m) =>
      `<div class="mech"><div class="key">${m[0]}</div><div class="desc">${m[1]}</div></div>`).join("");

    // local schematic for composite stages
    const hasDg = !!DIAGRAMS[s.id];
    if (hasDg) { renderDiagram(s); detail.diagram.style.display = ""; }
    else { detail.diagram.innerHTML = ""; detail.diagram.style.display = "none"; }
    detail.root.classList.toggle("has-diagram", hasDg);

    typeCode(s);

    // stream this stage's log lines staggered
    s.log.forEach((line, k) => setTimeout(() => pushLog(s, line), 140 + k * (dwell * 0.16)));

    // bump counter for this stage's metric
    const mk = metricMap[s.metric];
    setTimeout(() => {
      const inc = mk === "confirmed" ? 1 : Math.floor(Math.random() * 4) + 1;
      counts[mk] += inc; paintCounts();
      const el = metricEls[mk];
      if (el) { el.style.transition = "none"; el.style.textShadow = `0 0 14px ${ACCENTS[s.accent]}`; setTimeout(() => { el.style.transition = "text-shadow .6s"; el.style.textShadow = "none"; }, 60); }
    }, dwell * 0.5);

    // confirmed vuln => red flash on the exploit stage
    if (s.id === "exploit") {
      setTimeout(() => { vflash.classList.remove("fire"); void vflash.offsetWidth; vflash.classList.add("fire"); }, dwell * 0.55);
    }
  }

  // ---------- auto-cycle ----------
  let dwell = 3400;
  let playing = true;
  let pinned = false;
  let loop = null;
  function step() {
    let next = (active + 1) % STAGES.length;
    if (next === 0) { clock = 0; railFill.style.transition = "width .35s"; }
    activate(next);
  }
  function schedule() {
    clearTimeout(loop);
    if (playing && !pinned) loop = setTimeout(() => { step(); schedule(); }, dwell);
  }
  function pin(i) {
    pinned = true; playing = false;
    playBtn.textContent = "▶  resume";
    playBtn.classList.remove("active");
    clearTimeout(loop);
    activate(i);
  }

  // ---------- controls ----------
  const playBtn = document.getElementById("playBtn");
  const speedInput = document.getElementById("speed");
  playBtn.addEventListener("click", () => {
    if (playing && !pinned) { playing = false; clearTimeout(loop); playBtn.textContent = "▶  play"; playBtn.classList.remove("active"); }
    else { playing = true; pinned = false; playBtn.textContent = "❚❚  auto"; playBtn.classList.add("active"); schedule(); }
  });
  speedInput.addEventListener("input", () => {
    // slider 0..100 -> dwell 6000..1400
    dwell = 6000 - (speedInput.value / 100) * 4600;
    if (playing && !pinned) schedule();
  });

  window.addEventListener("resize", () => { if (active >= 0) moveTo(active); });

  // ---------- boot ----------
  // ensure layout is settled before first packet placement.
  // use setTimeout (not rAF) so it fires even when the iframe is not painting.
  function boot() { activate(0); schedule(); }
  if (document.readyState === "complete") setTimeout(boot, 60);
  else window.addEventListener("load", () => setTimeout(boot, 60));
})();
