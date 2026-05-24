/* ============================================================
   TORNET GRANTED — App-wide UI helpers (no framework)
   ============================================================ */
(function () {
  "use strict";

  /* -------- Toast -------- */
  function ensureToastRegion() {
    let r = document.querySelector(".toast-region");
    if (!r) {
      r = document.createElement("div");
      r.className = "toast-region";
      document.body.appendChild(r);
    }
    return r;
  }

  window.toast = function (msg, kind, ms) {
    const r = ensureToastRegion();
    const t = document.createElement("div");
    t.className = "toast" + (kind ? " toast--" + kind : "");
    t.textContent = msg;
    r.appendChild(t);
    setTimeout(() => {
      t.style.transition = "opacity 240ms ease, transform 240ms ease";
      t.style.opacity = "0";
      t.style.transform = "translateY(6px)";
      setTimeout(() => t.remove(), 260);
    }, ms || 2400);
  };

  /* -------- Copy to clipboard -------- */
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise((resolve, reject) => {
      try {
        const ta = document.createElement("textarea");
        ta.value = text;
        ta.style.position = "fixed";
        ta.style.left = "-9999px";
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
        resolve();
      } catch (e) { reject(e); }
    });
  }

  document.addEventListener("click", function (e) {
    const btn = e.target.closest("[data-copy]");
    if (!btn) return;
    e.preventDefault();
    const sel = btn.getAttribute("data-copy-target");
    const val = sel ? (document.querySelector(sel)?.value ?? document.querySelector(sel)?.textContent ?? "")
                    : btn.getAttribute("data-copy");
    copyText((val || "").trim()).then(
      () => window.toast("Copied to clipboard", "ok", 1600),
      () => window.toast("Copy failed", "threat")
    );
  });

  /* -------- Reveal masked field -------- */
  document.addEventListener("click", function (e) {
    const btn = e.target.closest("[data-reveal]");
    if (!btn) return;
    const sel = btn.getAttribute("data-reveal");
    const el = document.querySelector(sel);
    if (!el) return;
    const isMasked = el.getAttribute("data-masked") === "1";
    if (isMasked) {
      el.textContent = el.getAttribute("data-real") || el.textContent;
      el.setAttribute("data-masked", "0");
      btn.textContent = "HIDE";
    } else {
      const real = el.getAttribute("data-real") || el.textContent;
      el.setAttribute("data-real", real);
      el.textContent = "•".repeat(Math.min(real.length, 32));
      el.setAttribute("data-masked", "1");
      btn.textContent = "REVEAL";
    }
  });

  /* -------- Dropzone (delegated) -------- */
  document.querySelectorAll(".dropzone").forEach(function (dz) {
    const input = dz.querySelector("input[type=file]");
    const label = dz.querySelector(".dz-filename");
    dz.addEventListener("click", () => input && input.click());
    dz.addEventListener("dragover", (e) => { e.preventDefault(); dz.classList.add("is-drag"); });
    dz.addEventListener("dragleave", () => dz.classList.remove("is-drag"));
    dz.addEventListener("drop", (e) => {
      e.preventDefault();
      dz.classList.remove("is-drag");
      if (input && e.dataTransfer.files.length) {
        input.files = e.dataTransfer.files;
        if (label) label.textContent = e.dataTransfer.files[0].name;
      }
    });
    if (input) {
      input.addEventListener("change", () => {
        if (label && input.files[0]) label.textContent = input.files[0].name;
      });
    }
  });

  /* -------- Tabs (data-tab + data-tab-panel) -------- */
  document.querySelectorAll("[data-tabs]").forEach(function (group) {
    const tabs = group.querySelectorAll(".tab");
    tabs.forEach(t => {
      t.addEventListener("click", () => {
        const tgt = t.getAttribute("data-tab");
        tabs.forEach(x => x.classList.toggle("is-active", x === t));
        document.querySelectorAll("[data-tab-panel]").forEach(p => {
          p.classList.toggle("hidden", p.getAttribute("data-tab-panel") !== tgt);
        });
      });
    });
  });

  /* -------- Module card mouse-tracking glow -------- */
  document.querySelectorAll(".mod").forEach(function (m) {
    m.addEventListener("mousemove", (e) => {
      const r = m.getBoundingClientRect();
      m.style.setProperty("--mx", ((e.clientX - r.left) / r.width * 100) + "%");
      m.style.setProperty("--my", ((e.clientY - r.top) / r.height * 100) + "%");
    });
  });

  /* -------- Onion-network constellation (landing/login hero) -------- */
  window.renderOnionNet = function (svgEl, opts) {
    if (!svgEl) return;
    const o = Object.assign({ nodes: 28, links: 38, w: 560, h: 560 }, opts || {});
    const cx = o.w / 2, cy = o.h / 2;
    const pts = [];
    pts.push({ x: cx, y: cy, r: 6, hub: true });
    for (let i = 1; i < o.nodes; i++) {
      const ring = 1 + Math.floor(i / 9);
      const a = (i * (Math.PI * 2)) / o.nodes + Math.random() * 0.3;
      const rad = 70 * ring + Math.random() * 32;
      pts.push({
        x: cx + Math.cos(a) * rad,
        y: cy + Math.sin(a) * rad,
        r: 2 + Math.random() * 2.4,
        hub: false
      });
    }
    let svg = "";
    // links
    for (let i = 0; i < o.links; i++) {
      const a = pts[Math.floor(Math.random() * pts.length)];
      const b = pts[Math.floor(Math.random() * pts.length)];
      if (a === b) continue;
      svg += `<line x1="${a.x}" y1="${a.y}" x2="${b.x}" y2="${b.y}" stroke="rgba(0,229,255,0.18)" stroke-width="1"/>`;
    }
    // central hub link from every node
    pts.forEach((p, i) => {
      if (i === 0) return;
      svg += `<line x1="${cx}" y1="${cy}" x2="${p.x}" y2="${p.y}" stroke="rgba(0,229,255,0.08)" stroke-width="1"/>`;
    });
    // nodes
    pts.forEach((p, i) => {
      if (p.hub) {
        svg += `<circle cx="${p.x}" cy="${p.y}" r="14" fill="rgba(0,229,255,0.10)"/>`;
        svg += `<circle cx="${p.x}" cy="${p.y}" r="9"  fill="rgba(0,229,255,0.25)"/>`;
        svg += `<circle cx="${p.x}" cy="${p.y}" r="5"  fill="#6cf3ff"/>`;
      } else {
        const op = 0.55 + Math.random() * 0.45;
        svg += `<circle cx="${p.x}" cy="${p.y}" r="${p.r}" fill="rgba(0,229,255,${op.toFixed(2)})"/>`;
      }
    });
    // sweeping ring
    svg += `<circle cx="${cx}" cy="${cy}" r="180" fill="none" stroke="rgba(0,229,255,0.18)" stroke-dasharray="2 6"/>`;
    svg += `<circle cx="${cx}" cy="${cy}" r="240" fill="none" stroke="rgba(0,229,255,0.10)" stroke-dasharray="2 10"/>`;
    svgEl.setAttribute("viewBox", `0 0 ${o.w} ${o.h}`);
    svgEl.innerHTML = svg;
  };

  /* -------- Counter animation -------- */
  function easeOutCubic(t) { return 1 - Math.pow(1 - t, 3); }
  function animateCount(el) {
    const target = parseFloat(el.getAttribute("data-count") || "0");
    const dur = parseInt(el.getAttribute("data-count-dur") || "1400", 10);
    const dec = parseInt(el.getAttribute("data-count-dec") || "0", 10);
    const start = performance.now();
    function tick(now) {
      const t = Math.min(1, (now - start) / dur);
      const v = target * easeOutCubic(t);
      el.textContent = v.toLocaleString(undefined, {
        minimumFractionDigits: dec, maximumFractionDigits: dec
      });
      if (t < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }
  const io = (typeof IntersectionObserver !== "undefined")
    ? new IntersectionObserver((entries) => {
        entries.forEach(en => {
          if (en.isIntersecting) {
            animateCount(en.target);
            io.unobserve(en.target);
          }
        });
      }, { threshold: 0.3 })
    : null;

  document.querySelectorAll("[data-count]").forEach(el => {
    if (io) io.observe(el); else animateCount(el);
  });

  /* -------- Sidebar active state from current path -------- */
  const here = location.pathname.replace(/\/$/, "");
  document.querySelectorAll(".nav-item[data-path]").forEach(a => {
    const p = a.getAttribute("data-path");
    if (p && (here === p || here.startsWith(p + "/"))) a.classList.add("is-active");
  });

  /* -------- Live mission clock in topbar -------- */
  const clk = document.querySelector("[data-clock]");
  if (clk) {
    function pad(n) { return String(n).padStart(2, "0"); }
    function tickClock() {
      const d = new Date();
      const utc = d.getUTCHours() + ":" + pad(d.getUTCMinutes()) + ":" + pad(d.getUTCSeconds());
      clk.textContent = utc + "z";
    }
    tickClock();
    setInterval(tickClock, 1000);
  }
})();
