// Dashboard. Log data is attacker-controlled, so every value is written with
// textContent / setAttribute: never as HTML. (tests/test_api.py enforces this.)
(() => {
  "use strict";

  const SEVERITIES = ["critical", "high", "medium", "low"];
  const SVG_NS = "http://www.w3.org/2000/svg";
  const $ = (id) => document.getElementById(id);

  function el(tag, text, className) {
    const node = document.createElement(tag);
    if (text !== undefined && text !== null) node.textContent = String(text);
    if (className) node.className = className;
    return node;
  }

  async function getJSON(url) {
    const res = await fetch(url, { headers: { Accept: "application/json" } });
    if (!res.ok) throw new Error(`${url}: HTTP ${res.status}`);
    return res.json();
  }

  function localTime(iso) {
    return new Date(iso).toLocaleString();
  }

  function renderCards(stats) {
    const box = $("cards");
    box.replaceChildren();
    const make = (label, value, cls) => {
      const card = el("div", null, `card ${cls || ""}`);
      card.append(el("div", value, "value"), el("div", label, "label"));
      box.append(card);
    };
    make("events", stats.events);
    make("alerts", stats.alerts);
    for (const sev of SEVERITIES) make(sev, stats.alerts_by_severity[sev] || 0, sev);
  }

  function renderTimeline(points) {
    const svg = $("timeline");
    svg.replaceChildren();
    if (!points.length) return;
    const width = 600, height = 120, pad = 4;
    const max = Math.max(1, ...points.map((p) => p.count));
    const slot = width / points.length;
    points.forEach((p, i) => {
      const barHeight = Math.round(((height - 2 * pad) * p.count) / max);
      const rect = document.createElementNS(SVG_NS, "rect");
      rect.setAttribute("class", "bar");
      rect.setAttribute("x", String(i * slot + 1));
      rect.setAttribute("y", String(height - pad - barHeight));
      rect.setAttribute("width", String(Math.max(1, slot - 2)));
      rect.setAttribute("height", String(p.count ? Math.max(2, barHeight) : 0));
      const title = document.createElementNS(SVG_NS, "title");
      title.textContent = `${localTime(p.hour)}: ${p.count} alert(s)`;
      rect.append(title);
      svg.append(rect);
    });
  }

  function fillTable(id, rows) {
    const body = $(id).tBodies[0];
    body.replaceChildren();
    if (!rows.length) {
      const cell = el("td", "Nothing to show yet.", "muted");
      cell.colSpan = $(id).tHead.rows[0].cells.length;
      const tr = el("tr");
      tr.append(cell);
      body.append(tr);
      return;
    }
    for (const cells of rows) {
      const tr = el("tr");
      for (const cell of cells) tr.append(cell instanceof Node ? cell : el("td", cell));
      body.append(tr);
    }
  }

  function alertRow(alert) {
    const details = el("td");
    const wrap = el("details");
    wrap.append(el("summary", "show"), el("pre", JSON.stringify(alert.details, null, 2)));
    details.append(wrap);

    const sev = el("td");
    sev.append(el("span", alert.severity, `sev ${SEVERITIES.includes(alert.severity) ? alert.severity : ""}`));

    const rule = el("td");
    rule.append(el("div", alert.title), el("div", alert.rule_id, "muted"));

    return [localTime(alert.ts), sev, rule, alert.src_ip || "-", alert.event_count, details];
  }

  async function refresh() {
    const severity = $("severity").value;
    const alertsUrl = `/api/alerts?limit=50${severity ? `&severity=${encodeURIComponent(severity)}` : ""}`;
    try {
      const [stats, alerts] = await Promise.all([getJSON("/api/stats?hours=24"), getJSON(alertsUrl)]);
      renderCards(stats);
      renderTimeline(stats.timeline);
      fillTable("sources", stats.top_sources.map((s) => [s.src_ip, s.alerts]));
      fillTable("rules", stats.top_rules.map((r) => [r.title, r.alerts]));
      fillTable("alerts", alerts.map(alertRow));
      $("status").textContent = `updated ${new Date().toLocaleTimeString()}`;
    } catch (err) {
      $("status").textContent = `error: ${err.message}`;
    }
  }

  $("severity").addEventListener("change", refresh);
  refresh();
  setInterval(refresh, 10000);
})();
