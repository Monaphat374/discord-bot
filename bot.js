// index.js (CommonJS) — Discord bot with LAN scan + device name resolution
require("dotenv").config();

const { Client, GatewayIntentBits } = require("discord.js");
const ping = require("ping");
const fetch =
  globalThis.fetch ||
  ((...args) => import("node-fetch").then(({ default: f }) => f(...args)));
const { execFile } = require("child_process");
const os = require("os");
const dns = require("dns").promises;

/* =========================
   Config & Environment
   ========================= */
const PING_EXTRA = process.platform === "win32" ? ["-n", "3"] : ["-c", "3"];
const CHANNEL_LOCK = process.env.DISCORD_CHANNEL_ID || null;

// kept for compatibility; not used to block commands
const ALLOWLIST_ONLY = String(process.env.ALLOWLIST_ONLY || "false")
  .toLowerCase()
  .trim() === "true";

// show device names in !scan (default true)
const RESOLVE_DEVICE_NAMES = String(process.env.RESOLVE_DEVICE_NAMES || "true")
  .toLowerCase()
  .trim() === "true";

// enable mDNS name discovery if bonjour-service / bonjour is available (default true)
const ENABLE_MDNS = String(process.env.ENABLE_MDNS || "true")
  .toLowerCase()
  .trim() === "true";

// Base URL (fallback) and per-guild map
const KUMA_DASHBOARD_URL =
  (process.env.KUMA_DASHBOARD_URL || "").trim() || null;

function safeParseJSON(s, fallback) {
  if (!s) return fallback;
  try {
    const obj = JSON.parse(s);
    return obj && typeof obj === "object" ? obj : fallback;
  } catch {
    return fallback;
  }
}
const DASHBOARD_MAP =
  safeParseJSON((process.env.KUMA_DASHBOARD_MAP || "").trim(), {}) || {};

const mentionChannel = (id) => `<#${id}>`;

const client = new Client({
  intents: [
    GatewayIntentBits.Guilds,
    GatewayIntentBits.GuildMessages,
    GatewayIntentBits.MessageContent,
  ],
});

// ---------- Allowlist (used only to map names if available) ----------
let allowlist = []; // [{ name, host }]

/* =========================
   Helpers: Allowlist
   ========================= */
function norm(h) {
  if (!h) return "";
  return String(h).replace(/^https?:\/\//, "").replace(/\/.*$/, "");
}

async function refreshAllowlist() {
  const url = (process.env.KUMA_STATUS_JSON_URL || "").trim();
  if (!url) return;
  try {
    const data = await (await fetch(url)).json();
    const items = [];

    if (data?.publicGroupList) {
      for (const g of data.publicGroupList) {
        for (const m of g.monitorList || []) {
          items.push({
            name: m?.name,
            host: norm(m?.hostname || m?.url || m?.ip || m?.addr),
          });
        }
      }
    }
    if (data?.monitors) {
      for (const m of data.monitors) {
        items.push({
          name: m?.name,
          host: norm(m?.hostname || m?.url || m?.ip || m?.addr),
        });
      }
    }

    const uniq = new Map();
    for (const x of items) {
      if (x?.name && x?.host) uniq.set(x.name.toLowerCase(), x);
    }
    allowlist = [...uniq.values()];
    console.log("Allowlist loaded:", allowlist.length);
  } catch (e) {
    console.error("Allowlist error:", e?.message || e);
    allowlist = [];
  }
}

function resolveTarget(q) {
  const s = (q || "").toLowerCase();
  const byName = allowlist.find((x) => x.name?.toLowerCase() === s);
  if (byName) return { hit: "name", value: byName.host, name: byName.name };
  const asHost = allowlist.find((x) => (x.host || "").toLowerCase() === s);
  if (asHost) return { hit: "host", value: asHost.host, name: asHost.name };
  return { hit: null, value: q, name: q };
}

/* =========================
   Traceroute parsing/formatting
   ========================= */
function parseTracerouteOutput(text) {
  const lines = String(text).split(/\r?\n/);
  const rows = [];
  for (const line of lines) {
    const s = line.trim();
    if (!s) continue;

    // Windows tracert
    let m = s.match(
      /^\s*(\d+)\s+(?:(<\s*)?\d+(?:\.\d+)?\s*ms|\*)\s+(?:(<\s*)?\d+(?:\.\d+)?\s*ms|\*)\s+(?:(<\s*)?\d+(?:\.\d+)?\s*ms|\*)\s+(.+?)\s*$/
    );
    if (m) {
      const hop = Number(m[1]);
      const parts = s.split(/\s+/).filter(Boolean);
      const times = [];
      let idx = 1;
      while (times.length < 3 && idx < parts.length) {
        const token = parts[idx++];
        if (/^\*$/i.test(token)) times.push("*");
        else if (/^(?:<\s*)?\d+(?:\.\d+)?\s*ms$/i.test(token))
          times.push(token.replace(/\s+/g, " "));
      }
      const ipField = s.replace(/^.*\s{2,}/, "").trim();
      const ipMatch = ipField.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
      const ip = ipMatch ? ipMatch[1] : ipField;
      rows.push({
        hop,
        ip,
        t1: times[0] || "-",
        t2: times[1] || "-",
        t3: times[2] || "-",
      });
      continue;
    }

    // Unix traceroute
    m = s.match(/^\s*(\d+)\s+(.+)$/);
    if (m) {
      const hop = Number(m[1]);
      const rest = m[2];
      if (/^\*(\s+\*){0,}/.test(rest)) {
        rows.push({ hop, ip: "-", t1: "*", t2: "*", t3: "*" });
        continue;
      }
      const ipMatch =
        rest.match(/\((\d{1,3}(?:\.\d{1,3}){3})\)/) ||
        rest.match(/(\d{1,3}(?:\.\d{1,3}){3})/);
      const ip = ipMatch ? ipMatch[1] : "-";
      const times = (rest.match(/(?:<\s*)?\d+(?:\.\d+)?\s*ms/g) || []).slice(
        0,
        3
      );
      const t = ["-", "-", "-"];
      for (let i = 0; i < times.length; i++)
        t[i] = times[i].replace(/\s+/g, " ");
      rows.push({ hop, ip, t1: t[0], t2: t[1], t3: t[2] });
    }
  }
  rows.sort((a, b) => a.hop - b.hop);
  return rows;
}

function formatTracerouteTable(rows) {
  if (!rows.length) return "No hops found.";
  const headers = ["Hop", "IP", "Time 1", "Time 2", "Time 3"];
  const colW = [
    Math.max(headers[0].length, ...rows.map((r) => String(r.hop).length)),
    Math.max(headers[1].length, ...rows.map((r) => String(r.ip).length)),
    Math.max(headers[2].length, ...rows.map((r) => String(r.t1).length)),
    Math.max(headers[3].length, ...rows.map((r) => String(r.t2).length)),
    Math.max(headers[4].length, ...rows.map((r) => String(r.t3).length)),
  ];
  const pad = (v, w, right = false) =>
    right ? String(v).padStart(w) : String(v).padEnd(w);
  const header =
    pad(headers[0], colW[0], true) +
    "  " +
    pad(headers[1], colW[1]) +
    "  " +
    pad(headers[2], colW[2], true) +
    "  " +
    pad(headers[3], colW[3], true) +
    "  " +
    pad(headers[4], colW[4], true);
  const sep = colW.map((w) => "-".repeat(w)).join("  ");
  const body = rows
    .map(
      (r) =>
        pad(r.hop, colW[0], true) +
        "  " +
        pad(r.ip, colW[1]) +
        "  " +
        pad(r.t1, colW[2], true) +
        "  " +
        pad(r.t2, colW[3], true) +
        "  " +
        pad(r.t3, colW[4], true)
    )
    .join("\n");
  return header + "\n" + sep + "\n" + body;
}

/* =========================
   LAN scan helpers
   ========================= */
function isPrivateIPv4(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((n) => isNaN(n) || n < 0 || n > 255))
    return false;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  return false;
}

function starRange(pattern) {
  const m = /^(\d{1,3}\.\d{1,3}\.\d{1,3})\.\*$/.exec(pattern);
  if (!m) return null;
  const base = m[1];
  if (!isPrivateIPv4(base + ".1")) return null;
  const list = [];
  for (let i = 1; i <= 254; i++) list.push(`${base}.${i}`);
  return list;
}

function dashRange(range) {
  const m = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{1,3})-(\d{1,3})$/.exec(range);
  if (!m) return null;
  const base = m[1];
  const s = Number(m[2]);
  const e = Number(m[3]);
  if (s < 1 || e > 254 || e < s) return null;
  if (!isPrivateIPv4(base + "1")) return null;
  const list = [];
  for (let i = s; i <= e; i++) list.push(`${base}${i}`);
  return list;
}

function ipToInt(ip) {
  return (
    ip
      .split(".")
      .map(Number)
      .reduce((acc, n) => (acc << 8) + n, 0) >>> 0
  );
}
function intToIp(n) {
  return [
    (n >>> 24) & 255,
    (n >>> 16) & 255,
    (n >>> 8) & 255,
    n & 255,
  ].join(".");
}

function cidrToRange(cidr) {
  const m = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/.exec(cidr);
  if (!m) return null;
  const ip = m[1];
  const mask = Number(m[2]);
  if (mask < 24 || mask > 32) return null; // keep ranges small
  if (!isPrivateIPv4(ip)) return null;

  const addr = ipToInt(ip);
  const hostBits = 32 - mask;
  const size = 1 << hostBits;
  if (size > 512) return null;

  const base = (addr >>> hostBits) << hostBits;
  const start = base + 1; // skip network
  const end = base + size - 2; // skip broadcast
  const list = [];
  for (let a = start; a <= end; a++) {
    const x = intToIp(a >>> 0);
    if (isPrivateIPv4(x)) list.push(x);
  }
  return list;
}

function defaultSubnetRange() {
  const ifs = os.networkInterfaces();
  for (const name of Object.keys(ifs)) {
    for (const info of ifs[name] || []) {
      if (
        info.family === "IPv4" &&
        !info.internal &&
        isPrivateIPv4(info.address)
      ) {
        const [a, b, c] = info.address.split(".");
        const base = `${a}.${b}.${c}`;
        const list = [];
        for (let i = 1; i <= 254; i++) list.push(`${base}.${i}`);
        return list;
      }
    }
  }
  return [];
}

function parseTargets(input) {
  if (!input) return defaultSubnetRange();
  const s = input.trim();
  return (
    cidrToRange(s) ||
    starRange(s) ||
    dashRange(s) ||
    (isPrivateIPv4(s) ? [s] : null) ||
    []
  );
}

async function pingMany(hosts, concurrency = 64, timeoutSec = 1) {
  const alive = [];
  let idx = 0;
  async function worker() {
    while (idx < hosts.length) {
      const host = hosts[idx++];
      try {
        const res = await ping.promise.probe(host, {
          timeout: timeoutSec,
          extra: PING_EXTRA,
        });
        if (res.alive) alive.push({ host, time: Number(res.avg) || null });
      } catch {
        /* swallow */
      }
    }
  }
  const workers = Array(Math.min(concurrency, hosts.length))
    .fill(0)
    .map(worker);
  await Promise.all(workers);
  return alive.sort((a, b) => (a.time ?? 9999) - (b.time ?? 9999));
}

/* =========================
   Name resolution helpers
   ========================= */
function execFilePromise(bin, args, opts = {}) {
  return new Promise((resolve) => {
    execFile(
      bin,
      args,
      {
        timeout: 8000,
        shell: process.platform === "win32",
        ...opts,
      },
      (err, stdout = "", stderr = "") => {
        resolve({ ok: !err, out: (stdout || stderr || "").toString() });
      }
    );
  });
}

async function hasNmap() {
  const r = await execFilePromise("nmap", ["--version"]);
  return r.ok;
}

async function resolveOneName(ip) {
  // Quick reverse via ping -a (Windows only)
  if (process.platform === "win32") {
    try {
      const r = await execFilePromise("ping", ["-a", "-n", "1", ip]);
      const m = r.out.match(/Pinging\s+([^\s\[]+)\s*\[/i);
      if (m && m[1] && !/^\d+\.\d+\.\d+\.\d+$/.test(m[1])) return m[1].trim();
    } catch {}
  }

  // NetBIOS (Windows)
  if (process.platform === "win32") {
    try {
      const r = await execFilePromise("nbtstat", ["-A", ip]);
      const m1 = r.out.match(/^\s*Host\s*Name\s*:\s*(.+)$/im);
      if (m1 && m1[1]) return m1[1].trim();
      const m2 = r.out.match(/^\s*([^ \r\n]+)\s+<00>\s+UNIQUE\s+Registered/im);
      if (m2 && m2[1]) return m2[1].trim();
    } catch {}
  }

  // Nmap reverse DNS (if available)
  try {
    if (await hasNmap()) {
      const r2 = await execFilePromise("nmap", ["-sn", "-R", ip]);
      const m =
        r2.out.match(/Nmap scan report for (.+?) \((\d+\.\d+\.\d+\.\d+)\)/m) ||
        r2.out.match(/Nmap scan report for (\d+\.\d+\.\d+\.\d+)\s*\((.+)\)/m);
      if (m) {
        const candidate =
          m[1] && !/^\d+\.\d+\.\d+\.\d+$/.test(m[1])
            ? m[1]
            : m[2] && !/^\d+\.\d+\.\d+\.\d+$/.test(m[2])
            ? m[2]
            : null;
        if (candidate) return candidate.trim();
      }
      const m2 = r2.out.match(/reverse dns name:\s*(.+)$/im);
      if (m2 && m2[1]) return m2[1].trim();
    }
  } catch {}

  // PTR via DNS
  try {
    const ptr = await dns.reverse(ip);
    if (Array.isArray(ptr) && ptr[0]) return ptr[0];
  } catch {}

  return "-";
}

/**
 * mDNS collector — single, consolidated version
 * - Prefers `bonjour-service` if installed; falls back to `bonjour`
 * - Respects ENABLE_MDNS
 * - Returns { [ip]: "host.local" }
 */
async function collectMdnsHosts(timeoutMs = 4000) {
  if (!ENABLE_MDNS) return {};

  let BonjourCtor = null;
  let isBonjourService = false;
  let bonjourInstance = null;

  // Try bonjour-service
  try {
    const mod = require("bonjour-service");
    BonjourCtor = mod && (mod.default || mod);
    isBonjourService = !!BonjourCtor;
  } catch {}

  // Fallback: bonjour (legacy)
  if (!BonjourCtor) {
    try {
      const mod2 = require("bonjour");
      bonjourInstance = mod2(); // this one returns instance directly
    } catch {
      return {}; // no mDNS lib installed
    }
  }

  return new Promise((resolve) => {
    const map = {};
    const types = [
      "_workstation._tcp",
      "_device-info._tcp",
      "_http._tcp",
      "_printer._tcp",
    ];

    let browsers = [];

    // Case 1: bonjour-service
    if (BonjourCtor && isBonjourService) {
      const bonjour = new BonjourCtor();
      browsers = types.map((t) =>
        bonjour.find({ type: t }, (svc) => {
          const host = (svc.host || svc.name || "").toString();
          const addrs = Array.isArray(svc.addresses) ? svc.addresses : [];
          for (const ip of addrs) {
            if (/^\d+\.\d+\.\d+\.\d+$/.test(ip) && host) {
              map[ip] = host.endsWith(".local") ? host : `${host}.local`;
            }
          }
        })
      );

      setTimeout(() => {
        browsers.forEach((b) => b.stop && b.stop());
        bonjour.destroy && bonjour.destroy();
        resolve(map);
      }, timeoutMs);
      return;
    }

    // Case 2: bonjour (legacy)
    if (bonjourInstance) {
      browsers = types.map((t) =>
        bonjourInstance.find({ type: t }, (svc) => {
          const host = (svc.host || svc.name || "").toString();
          const addrs = Array.isArray(svc.addresses) ? svc.addresses : [];
          for (const ip of addrs) {
            if (/^\d+\.\d+\.\d+\.\d+$/.test(ip) && host) {
              map[ip] = host.endsWith(".local") ? host : `${host}.local`;
            }
          }
        })
      );

      setTimeout(() => {
        browsers.forEach((b) => b.stop && b.stop());
        bonjourInstance.destroy && bonjourInstance.destroy();
        resolve(map);
      }, timeoutMs);
    }
  });
}

async function resolveNamesForList(ips, concurrency = 12) {
  if (!RESOLVE_DEVICE_NAMES)
    return Object.fromEntries(ips.map((ip) => [ip, "-"]));

  // Start mDNS collection in parallel (non-blocking)
  const mdnsPromise = collectMdnsHosts(4000);

  // NBNS/Nmap/DNS in parallel (bounded)
  const map = {};
  let i = 0;
  async function worker() {
    while (i < ips.length) {
      const ip = ips[i++];
      try {
        map[ip] = await resolveOneName(ip);
      } catch {
        map[ip] = "-";
      }
    }
  }
  await Promise.all(
    Array(Math.min(concurrency, ips.length))
      .fill(0)
      .map(worker)
  );

  // Merge mDNS (prefer keep existing if already resolved)
  try {
    const mdns = await mdnsPromise;
    for (const ip of ips) {
      if ((!map[ip] || map[ip] === "-") && mdns[ip]) map[ip] = mdns[ip];
    }
  } catch {}

  return map;
}

function renderScanTableWithNames(items, nameMap, maxRows = 50) {
  const rows = items.slice(0, maxRows).map((x) => ({
    name: nameMap[x.host] || "-",
    ip: x.host,
    t: Number.isFinite(x.time) ? String(Math.round(x.time)) : "-",
  }));
  const headers = ["No.", "Name", "Ip", "avg (ms)"];
  const wNo = Math.max(3, String(rows.length).length);
  const wName = Math.max(4, ...rows.map((r) => (r.name || "-").length));
  const wIp = Math.max(2, ...rows.map((r) => r.ip.length));
  const wT = Math.max(7, ...rows.map((r) => r.t.length));
  const pad = (v, w, right = false) =>
    right ? String(v).padStart(w) : String(v).padEnd(w);
  const header = `${pad(headers[0], wNo, true)}  ${pad(
    headers[1],
    wName
  )}  ${pad(headers[2], wIp)}  ${pad(headers[3], wT, true)}`;
  const sep = `${"-".repeat(wNo)}  ${"-".repeat(wName)}  ${"-".repeat(
    wIp
  )}  ${"-".repeat(wT)}`;
  const body = rows
    .map(
      (r, i) =>
        `${pad(i + 1, wNo, true)}  ${pad(r.name, wName)}  ${pad(
          r.ip,
          wIp
        )}  ${pad(r.t, wT, true)}`
    )
    .join("\n");
  return header + "\n" + sep + "\n" + body;
}

/* =========================
   Rate limiting
   ========================= */
const lastByUser = new Map();
function ratelimit(userId, ms = 2000) {
  const last = lastByUser.get(userId) || 0;
  if (Date.now() - last < ms) return false;
  lastByUser.set(userId, Date.now());
  return true;
}

/* =========================
   Dashboard URL per guild
   ========================= */
function getDashboardUrlForGuild(guildId) {
  if (guildId && DASHBOARD_MAP[guildId]) return DASHBOARD_MAP[guildId];
  return KUMA_DASHBOARD_URL || null;
}

/* =========================
   Lifecycle
   ========================= */
let booted = false;
const onReady = async (c) => {
  if (booted) return;
  booted = true;
  console.log(`✅ Logged in as ${c.user.tag}`);

  if (!KUMA_DASHBOARD_URL && Object.keys(DASHBOARD_MAP).length === 0) {
    console.warn("[WARN] No dashboard URL configured; !status will show hint.");
  } else {
    console.log(
      "[INFO] Dashboard URL mode:",
      Object.keys(DASHBOARD_MAP).length > 0
        ? `per-guild (${Object.keys(DASHBOARD_MAP).length})`
        : `single URL (${KUMA_DASHBOARD_URL})`
    );
  }

  await refreshAllowlist();
  setInterval(refreshAllowlist, 60_000);
};
client.once("ready", onReady);

/* =========================
   Command handler
   ========================= */
client.on("messageCreate", async (m) => {
  if (m.author.bot) return;

  if (CHANNEL_LOCK && m.channelId !== CHANNEL_LOCK) {
    try {
      await m.reply(`คำสั่งนี้ใช้ได้เฉพาะในห้อง ${mentionChannel(CHANNEL_LOCK)} ครับ`);
    } catch (e) {
      console.error("reply failed (channel lock):", e?.message || e);
    }
    return;
  }

  if (!ratelimit(m.author.id)) {
    try {
      await m.reply("ขอเว้นระยะสักแป๊บ (~2 วินาที) แล้วค่อยลองใหม่นะ");
    } catch {}
    return;
  }

  const [cmd, ...args] = m.content.trim().split(/\s+/);

  if (cmd === "!hi") {
    return m.reply("สวัสดี! บอทออนไลน์แล้ว 👋");
  }

  if (cmd === "!help") {
    const maybeUrl = getDashboardUrlForGuild(m.guild?.id);
    const nameLine = RESOLVE_DEVICE_NAMES
      ? "🔎 แสดงชื่ออุปกรณ์ตอน !scan (ต้องมี DNS/NetBIOS และถ้าติดตั้งได้จะใช้ Nmap/mDNS ด้วย)"
      : "🔎 แสดงชื่ออุปกรณ์ตอน !scan: ปิดอยู่ (ตั้ง RESOLVE_DEVICE_NAMES=true เพื่อเปิด)";
    const lines = [
      "[" + process.pid + "]",
      "**คำสั่งที่ใช้ได้**",
      "`!hi` — ทักบอท",
      "`!status` — เปิดแดชบอร์ด Uptime Kuma",
      "`!ping <ชื่ออุปกรณ์|host>` — ping ด้วย ICMP (ไม่จำกัด Kuma)",
      "`!traceroute <ชื่ออุปกรณ์|host>` — ดูเส้นทาง 15 hops (ไม่จำกัด Kuma)",
      "`!scan [CIDR|x.x.x.*|x.x.x.a-b]` — สแกนหาอุปกรณ์ใน LAN (ping sweep)",
      "",
      nameLine,
      maybeUrl
        ? `🔗 แดชบอร์ด Kuma: ${maybeUrl}`
        : "⚠️ ยังไม่ได้ตั้ง URL แดชบอร์ด — ตั้งค่า `KUMA_DASHBOARD_URL` หรือ `KUMA_DASHBOARD_MAP` ใน .env",
    ].filter(Boolean);
    return m.reply(lines.join("\n"));
  }

  // ---- !ping
  if (cmd === "!ping") {
    const q = args[0];
    if (!q) return m.reply("ใช้: `!ping <ชื่อ service หรือ host>`");
    const r = resolveTarget(q);
    try {
      const res = await ping.promise.probe(r.value, {
        timeout: 2,
        extra: PING_EXTRA,
      });
      return m.reply(
        res.alive
          ? `✅ ${r.name} (${r.value}) ตอบสนอง avg=${res.avg}ms`
          : `❌ ${r.name} (${r.value}) ไม่ตอบสนอง`
      );
    } catch (e) {
      return m.reply(`ผิดพลาด: ${e?.message || e}`);
    }
  }

  // ---- !status
  if (cmd === "!status") {
    const url = getDashboardUrlForGuild(m.guild?.id);
    if (!url) {
      return m.reply(
        [
          "ยังไม่ได้ตั้งค่า URL แดชบอร์ดสำหรับเซิร์ฟเวอร์นี้",
          "- ตั้ง `KUMA_DASHBOARD_URL=http://your-kuma/dashboard`",
          "หรือ",
          "- ตั้ง `KUMA_DASHBOARD_MAP={\"<guildId>\":\"http://your-kuma/dashboard\"}`",
        ].join("\n")
      );
    }
    return m.reply(`🔗 เปิดแดชบอร์ด: ${url}`);
  }

  // ---- !traceroute
  if (cmd === "!traceroute") {
    const q = args[0];
    if (!q) return m.reply("ใช้: `!traceroute <host>`");
    const r = resolveTarget(q);
    const bin = process.platform === "win32" ? "tracert" : "traceroute";
    const params =
      process.platform === "win32"
        ? ["-d", "-h", "15", r.value]
        : ["-n", "-m", "15", r.value];
    await m.reply(`กำลัง traceroute ไปยัง ${r.value} ...`);
    try {
      execFile(
        bin,
        params,
        { timeout: 45_000, shell: process.platform === "win32" },
        (err, stdout = "", stderr = "") => {
          const raw = stdout || stderr || (err && err.message) || "no output";
          const rows = parseTracerouteOutput(raw);
          const table = formatTracerouteTable(rows);
          if (!rows.length) {
            const text = raw.split(/\r?\n/).slice(0, 40).join("\n");
            return m.channel.send("```" + text + "```");
          }
          m.channel.send("```" + table + "```");
        }
      );
    } catch (e) {
      m.channel.send("```Traceroute failed: " + (e?.message || e) + "```");
    }
  }

  // ---- !scan (with name resolution)
  if (cmd === "!scan") {
    const pattern = (args[0] || "").trim();
    const targets = parseTargets(pattern);
    if (!targets.length) {
      return m.reply(
        [
          "รูปแบบช่วงไม่ถูกต้อง หรือไม่ใช่เครือข่ายส่วนตัว",
          "ตัวอย่าง: `!scan 192.168.1.*`, `!scan 192.168.1.0/24`, `!scan 192.168.1.10-50`",
          "หรือพิมพ์ `!scan` เฉย ๆ เพื่อสแกน subnet ปัจจุบัน",
        ].join("\n")
      );
    }
    if (targets.length > 512)
      return m.reply("ช่วงใหญ่เกินไป (เกิน 512 IP) — โปรดระบุช่วงให้แคบลง");

    await m.reply(
      `กำลังสแกน ${targets.length} IP ... อาจใช้เวลาประมาณ ${Math.ceil(
        targets.length / 64
      )} รอบทำงาน`
    );

    try {
      const online = await pingMany(targets, 64, 1);
      if (!online.length) return m.channel.send("ไม่พบอุปกรณ์ที่ตอบสนอง");

      const ips = online.map((x) => x.host);

      // resolve names (NBNS/Nmap/DNS) + merge mDNS if available
      const nameMap = await resolveNamesForList(ips, 12);

      const table = renderScanTableWithNames(online, nameMap, 50);
      const more =
        online.length > 50 ? `\n... และอีก ${online.length - 50} รายการ` : "";

      return m.channel.send(
        "**พบอุปกรณ์ออนไลน์:** " +
          online.length +
          "\n```" +
          table +
          "```" +
          more
      );
    } catch (e) {
      return m.channel.send("```Scan failed: " + (e?.message || e) + "```");
    }
  }
});

/* =========================
   Login & process events
   ========================= */
console.log("PID:", process.pid);
client.login(process.env.DISCORD_BOT_TOKEN);

process.on("unhandledRejection", (e) =>
  console.error("UnhandledRejection:", e?.stack || e)
);
client.on("error", (e) => console.error("Client error:", e?.stack || e));

process.once("SIGINT", () => client.destroy());
process.once("SIGTERM", () => client.destroy());
