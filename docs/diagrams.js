// Local mini-schematics for the composite stages.
// Resting state is fully visible; only looping/decorative animations play.
(function () {
  const MODELS = [
    { id: "opus",  name: "Opus",  col: "#ff9542", hits: [3, 8], leads: 2 },
    { id: "glm",   name: "GLM",   col: "#4d9bff", hits: [6],    leads: 1 },
    { id: "codex", name: "Codex", col: "#34e39b", hits: [9],    leads: 1 },
  ];

  function swRow(m, n) {
    let cells = "";
    for (let i = 0; i < n; i++) {
      const hit = m.hits.indexOf(i) >= 0 ? " hit" : "";
      const style = hit
        ? `--ac:${m.col};animation-delay:${(i * 0.11).toFixed(2)}s`
        : `animation-delay:${(i * 0.11).toFixed(2)}s`;
      cells += `<i class="${hit}" style="${style}"></i>`;
    }
    return `<div class="sw-row">
      <span class="sw-tag" style="color:${m.col}">${m.name}</span>
      <div class="sw-cells">${cells}</div>
      <span class="sw-leads">${m.leads}<b style="color:${m.col}">★</b></span>
    </div>`;
  }

  function chip(m) { return `<span class="xc-model" style="--mc:${m.col}">${m.name}</span>`; }

  // raw opcode lines for the decompile stream (looped twice for seamless scroll)
  const DEC_OPS = [
    ["60 80", "PUSH1 0x80"], ["60 40", "PUSH1 0x40"], ["52", "MSTORE"],
    ["34", "CALLVALUE"], ["80", "DUP1"], ["15", "ISZERO"], ["61 00 10", "PUSH2 0x0010"],
    ["57", "JUMPI"], ["63 a9 05 9c", "PUSH4 0xa9059c"], ["bb", "EQ"], ["80 fd", "REVERT"],
    ["36", "CALLDATASIZE"], ["10", "LT"], ["57", "JUMPI"], ["60 04", "PUSH1 0x04"],
    ["35", "CALLDATALOAD"], ["90", "SWAP1"], ["04", "DIV"], ["f3", "RETURN"],
  ].map((o) => `<code><span class="hx">${o[0]}</span> <span class="op">${o[1]}</span></code>`).join("");

  const DIAGRAMS = {
    snapshot: `
      <div class="dg">
        <div class="dg-label">local view · sourcing funnel · scanning…</div>
        <div class="dg-funnel">
          <div class="scanbeam"></div>
          <div class="fn-stage" style="--i:0"><b>18.4M</b><span>all contracts</span></div>
          <span class="fn-arrow">▸</span>
          <div class="fn-stage" style="--i:1"><b>214K</b><span>closed-source</span></div>
          <span class="fn-arrow">▸</span>
          <div class="fn-stage" style="--i:2"><b>8,640</b><span>aged &gt; 3y</span></div>
          <span class="fn-arrow">▸</span>
          <div class="fn-stage hot" style="--i:3"><b>1,932</b><span>idle TVL · locked</span></div>
        </div>
      </div>`,

    decompile: `
      <div class="dg">
        <div class="dg-label">local view · bytecode → pseudo-solidity (Dedaub)</div>
        <div class="dec">
          <div class="dec-col">
            <div class="dec-h">raw EVM bytecode</div>
            <div class="dec-stream"><div class="dec-scroll">${DEC_OPS}${DEC_OPS}</div></div>
          </div>
          <div class="dec-mid"><span class="dec-arrow">▸</span><span class="dec-eng">decompile</span></div>
          <div class="dec-col">
            <div class="dec-h">recovered source</div>
            <div class="dec-code">
              <div class="dl" style="--i:0"><span class="kw">function</span> price() <span class="kw">public</span> {</div>
              <div class="dl" style="--i:1">&nbsp;&nbsp;uint p = reserve0 / reserve1;</div>
              <div class="dl" style="--i:2">&nbsp;&nbsp;<span class="kw">return</span> p; <span class="warn">⚠ no zero-check</span></div>
              <div class="dl" style="--i:3">}</div>
            </div>
          </div>
        </div>
      </div>`,

    // fan-out cells + cross-check rows, then a clear per-function voting table
    swarm: (function () {
      function mk(on, col) {
        return on
          ? `<span class="mk" style="color:${col}">✓</span>`
          : `<span class="mk no">·</span>`;
      }
      const rows = [
        { fn: "price()",          v: [1, 1, 1], verdict: "KEEP", n: "3/3" },
        { fn: "refreshAccount()", v: [1, 1, 0], verdict: "KEEP", n: "2/3" },
        { fn: "mint()",           v: [1, 0, 0], verdict: "drop", n: "1/3" },
      ];
      const C = MODELS.map((m) => m.col);
      const body = rows.map((r) => `
        <div class="vtab-row ${r.verdict === "KEEP" ? "kept" : ""}">
          <span class="vfn">${r.fn}</span>
          ${mk(r.v[0], C[0])}${mk(r.v[1], C[1])}${mk(r.v[2], C[2])}
          <span class="vv ${r.verdict === "KEEP" ? "keep" : "drop"}">${r.verdict} ${r.n}</span>
        </div>`).join("");
      return `
      <div class="dg">
        <div class="dg-label">local view · swarm + cross-check</div>
        <div class="dg-swarm">
          <div class="sw-src">contract<small>11 functions</small></div>
          <div class="sw-edge"></div>
          <div class="sw-fan">${MODELS.map((m) => swRow(m, 11)).join("")}</div>
        </div>
        <div class="xc">
          <div class="xc-title">then the agents cross-check each other</div>
          <div class="xc-step">${chip(MODELS[0])}<span class="xc-act">proposes</span><span class="xc-find">H2 · price() → 0 overflow</span></div>
          <div class="xc-step">${chip(MODELS[1])}<span class="xc-act">independently re-derives</span><span class="xc-ok">match ✓</span></div>
          <div class="xc-step">${chip(MODELS[2])}<span class="xc-act">writes PoC &amp; attacks it</span><span class="xc-ok">holds ✓</span></div>
          <div class="xc-consensus"><b>2-of-3 agreement</b> → promoted &nbsp;·&nbsp; solo hunches dropped</div>
        </div>
      </div>
      <div class="dg dg2">
        <div class="dg-label">every function voted on by all 3 models — 2-of-3 promoted</div>
        <div class="vtab">
          <div class="vtab-row vtab-head">
            <span class="vfn">function</span>
            <span class="mk" style="color:${C[0]}">Opus</span>
            <span class="mk" style="color:${C[1]}">GLM</span>
            <span class="mk" style="color:${C[2]}">Codex</span>
            <span class="vv">verdict</span>
          </div>
          ${body}
          <div class="vtab-more">+ 8 more functions · most drop</div>
        </div>
      </div>`;
    })(),

    validate: `
      <div class="dg">
        <div class="dg-label">local view · validation triage</div>
        <div class="dg-table">
          <div class="tri-scan"></div>
          <div class="vt keep"><span class="vt-id">H2</span><span class="vt-desc">price() → 0 overflow</span><span class="vt-verd">KEEP</span><span class="vt-why">cross-model ✓✓</span></div>
          <div class="vt keep"><span class="vt-id">H1</span><span class="vt-desc">refreshAccount() ACL</span><span class="vt-verd">KEEP</span><span class="vt-why">reachable</span></div>
          <div class="vt drop"><span class="vt-id">H5</span><span class="vt-desc">reentrancy in claim()</span><span class="vt-verd">DROP</span><span class="vt-why">guarded</span></div>
          <div class="vt drop more">+ 38 more discarded as noise / unreachable</div>
        </div>
      </div>`,

    exploit: `
      <div class="dg">
        <div class="dg-label">live exploit · replayed on a mainnet fork</div>
        <div class="xpl">
          <div class="xpl-side">
            <div class="xpl-cap">victim vault</div>
            <div class="xpl-tank"><div class="xpl-liquid"></div></div>
            <div class="xpl-sub draining">draining…</div>
          </div>
          <div class="xpl-pipe">
            <span class="eth" style="animation-delay:0s">Ξ</span>
            <span class="eth" style="animation-delay:.28s">Ξ</span>
            <span class="eth" style="animation-delay:.56s">Ξ</span>
            <span class="eth" style="animation-delay:.84s">Ξ</span>
            <span class="eth" style="animation-delay:1.12s">Ξ</span>
            <span class="eth" style="animation-delay:1.4s">Ξ</span>
          </div>
          <div class="xpl-side">
            <div class="xpl-cap">attacker</div>
            <div class="xpl-delta">+1,204.6 Ξ</div>
            <div class="xpl-sub up">balance ↑</div>
          </div>
        </div>
        <div class="xpl-badge"><span class="blip"></span>EXPLOIT CONFIRMED · reproduced on testnet</div>
      </div>`,
  };

  window.DIAGRAMS = DIAGRAMS;
})();
