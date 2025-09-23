// index.js (CommonJS)
require("dotenv").config();
const { Client, GatewayIntentBits } = require("discord.js");
const ping = require("ping");
const fetch = globalThis.fetch || ((...args) =>
import('node-fetch').then(({ default: f }) => f(...args)));
const PING_EXTRA = process.platform === "win32" ? [ "-n", "3" ] : [ "-c", "3" ];
const CHANNEL_LOCK = process.env.DISCORD_CHANNEL_ID || null;
const ALLOWLIST_ONLY = String(process.env.ALLOWLIST_ONLY || "false").toLowerCase() === "true";

const { execFile } = require("child_process");
const os = require("os");

const client = new Client({
    intents: [ GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent ],
});

let allowlist = []; // [{ name, host }]

/**
 * Normalize host: ตัด http/https และ path ออกให้เหลือ host/ip
 * @param {string} h - ข้อความที่อาจเป็น URL/hostname/IP
 * @returns {string} host หรือ IP ที่ถูกตัด scheme และ path ออกแล้ว
 */
// --------- ดึงลิสต์จาก Uptime Kuma Status Page JSON ----------
function norm(h) {
    if (!h) {
        return "";
    }
    return String(h).replace(/^https?:\/\//, "").replace(/\/.*$/, "");
}

/**
 * ดึงรายการ monitors จาก Uptime Kuma Status Page (JSON)
 * แล้วอัปเดตตัวแปร allowlist ให้เป็นข้อมูลล่าสุด
 * @returns {Promise<void>} เสร็จสิ้นเมื่ออัปเดตลิสต์แล้ว
 */
async function refreshAllowlist() {
    const url = process.env.KUMA_STATUS_JSON_URL;
    if (!url) {
        return;
    }
    try {
        const data = await (await fetch(url)).json();
        const items = [];
        if (data?.publicGroupList) {
            for (const g of data.publicGroupList) {
                for (const m of (g.monitorList || [])) {
                    items.push({ name: m?.name,
                        host: norm(m?.hostname || m?.url || m?.ip || m?.addr) });
                }
            }
        }
        if (data?.monitors) {
            for (const m of data.monitors) {
                items.push({ name: m?.name,
                    host: norm(m?.hostname || m?.url || m?.ip || m?.addr) });
            }
        }
        const uniq = new Map();
        for (const x of items) {
            if (x?.name && x?.host) {
                uniq.set(x.name.toLowerCase(), x);
            }
        }

        allowlist = [ ...uniq.values() ];
        console.log("Allowlist loaded:", allowlist.length);
    } catch (e) {
        console.error("Allowlist error:", e.message);
        allowlist = [];
    }
}
/**
 * แปลงคำค้นให้เป็น host/IP ที่พร้อมใช้งานกับคำสั่งเครือข่าย
 * @param {string} q - ชื่อ service หรือ host/IP ที่ผู้ใช้พิมพ์มา
 * @returns {ResolveTargetResult} ผลลัพธ์ที่บอกว่าตรงกับชื่อ/host หรือไม่พบ พร้อมค่า host ที่จะใช้จริง
 */
function resolveTarget(q) {
    const s = q.toLowerCase();
    const byName = allowlist.find((x) => x.name.toLowerCase() === s);
    if (byName) {
        return { hit: "name",
            value: byName.host,
            name: byName.name };
    }
    const asHost = allowlist.find((x) => (x.host || "").toLowerCase() === s);
    if (asHost) {
        return { hit: "host",
            value: asHost.host,
            name: asHost.name };
    }
    return { hit: null,
        value: q,
        name: q };
}

function isPrivateIPv4(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some(n => isNaN(n) || n < 0 || n > 255)) return false;
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
  const s = Number(m[2]), e = Number(m[3]);
  if (s < 1 || e > 254 || e < s) return null;
  if (!isPrivateIPv4(base + "1")) return null;
  const list = [];
  for (let i = s; i <= e; i++) list.push(`${base}${i}`);
  return list;
}

function ipToInt(ip) {
  return ip.split(".").map(Number).reduce((acc, n) => (acc << 8) + n, 0) >>> 0;
}
function intToIp(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}
function cidrToRange(cidr) {
  const m = /^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/.exec(cidr);
  if (!m) return null;
  const ip = m[1], mask = Number(m[2]);
  if (mask < 24 || mask > 32) return null; // จำกัดช่วงไม่กว้างเกินไป
  if (!isPrivateIPv4(ip)) return null;
  const addr = ipToInt(ip);
  const hostBits = 32 - mask;
  const size = 1 << hostBits;
  if (size > 512) return null; // จำกัดขนาดช่วง
  const base = (addr >>> hostBits) << hostBits;
  const start = base + 1;             // ข้าม network
  const end = base + size - 2;        // ข้าม broadcast
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
      if (info.family === "IPv4" && !info.internal && isPrivateIPv4(info.address)) {
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

/** แปลงอินพุตช่วงให้ได้รายการ IP ที่จะสแกน */
function parseTargets(input) {
  if (!input) return defaultSubnetRange();
  return (
    cidrToRange(input) ||
    starRange(input) ||
    dashRange(input) ||
    (isPrivateIPv4(input) ? [input] : null) ||
    []
  );
}

/** ping หลายเป้าหมายพร้อมกันแบบจำกัด concurrency */
async function pingMany(hosts, concurrency = 64, timeoutSec = 1) {
  const alive = [];
  let idx = 0;
  async function worker() {
    while (idx < hosts.length) {
      const host = hosts[idx++];
      try {
        const res = await ping.promise.probe(host, { timeout: timeoutSec, extra: PING_EXTRA });
        if (res.alive) alive.push({ host, time: Number(res.avg) || null });
      } catch { /* กลืน error ต่อไปเรื่อย ๆ */ }
    }
  }
  const workers = Array(Math.min(concurrency, hosts.length)).fill(0).map(worker);
  await Promise.all(workers);
  return alive.sort((a, b) => (a.time ?? 9999) - (b.time ?? 9999));
}



// --------- กันสแปมง่าย ๆ ----------
const lastByUser = new Map();
/**
 * จำกัดความถี่การใช้คำสั่ง
 * @param {string} userId - ไอดีผู้ใช้ที่จะตรวจจับการสแปม
 * @param {number} ms - ระยะห่างขั้นต่ำระหว่างคำสั่ง (มิลลิวินาที), ค่าเริ่มต้น 2000
 * @returns {boolean} true = ผ่าน, false = ต้องรอเพิ่ม
 */
function ratelimit(userId, ms = 2000) {
    const last = lastByUser.get(userId) || 0;
    if (Date.now() - last < ms) {
        return false;
    }
    lastByUser.set(userId, Date.now());
    return true;
}
let booted = false;
const onReady = async (c) => {
    if (booted) return;
    booted = true;
    console.log(`✅ Logged in as ${c.user.tag}`);
    await refreshAllowlist();
    setInterval(refreshAllowlist, 60_000);
};

//client.once("ready", () => onReady(client));      // v14
//client.once("clientReady", onReady);  // ถูกต้องสำหรับรุ่นใหม่
client.once("ready", onReady);

client.on("messageCreate", async (m) => {
    if (m.author.bot) {
        return;
    }
    if (CHANNEL_LOCK && m.channelId !== CHANNEL_LOCK) {
        return;
    }
    if (!ratelimit(m.author.id)) {
        return;
    }

    const [ cmd, ...args ] = m.content.trim().split(/\s+/);

    if (cmd === "!hi") {
        return m.reply("สวัสดี! บอทออนไลน์แล้ว 👋");
    }

    if (cmd === "!help") {
        return m.reply("[" + process.pid + "]\n" + [
            "**คำสั่งที่ใช้ได้**",
            "`!hi` — ทักบอท",
            "`!status <name>` — ดู host ที่แมปจาก Kuma",
            "`!ping <name|host>` — ping ด้วย ICMP",
            "`!traceroute <name|host>` — ดูเส้นทาง (15 hops)",
            "`!scan [CIDR|x.x.x.*|x.x.x.a-b]` — สแกนหาอุปกรณ์ใน LAN (ping sweep)",
            ALLOWLIST_ONLY ? "_จำกัดเฉพาะที่อยู่ใน Uptime Kuma_" : ""
        ].filter(Boolean).join("\n"));
    }


    if (cmd === "!ping") {
        const q = args[0];
        if (!q) {
            return m.reply("ใช้: `!ping <ชื่อ service หรือ host>`");
        }
        const r = resolveTarget(q);
        if (ALLOWLIST_ONLY && !r.hit) {
            return m.reply("ไม่พบในลิสต์ Uptime Kuma");
        }
        try {
            const res = await ping.promise.probe(r.value, { timeout: 2,
                extra: PING_EXTRA });
            return m.reply(res.alive
                ? `✅ ${r.name} (${r.value}) ตอบสนอง avg=${res.avg}ms`
                : `❌ ${r.name} (${r.value}) ไม่ตอบสนอง`);
        } catch (e) {
            return m.reply(`ผิดพลาด: ${e.message}`);
        }
    }

    if (cmd === "!status") {
        const name = (args[0] || "").toLowerCase();
        if (!name) {
            return m.reply("ใช้: `!status <service-name>`");
        }
        const found = allowlist.find((x) => x.name.toLowerCase() === name);
        return m.reply(found ? `ℹ️ ${found.name}: ${found.host}` : "ไม่พบชื่อในลิสต์");
    }

    if (cmd === "!traceroute") {
    const q = args[0];
    if (!q) return m.reply("ใช้: `!traceroute <host>`");

    const r = resolveTarget(q);
    if (ALLOWLIST_ONLY && !r.hit) return m.reply("ไม่พบในลิสต์ Uptime Kuma");

    const bin = process.platform === "win32" ? "tracert" : "traceroute";
    const params = process.platform === "win32"
        ? ["-d", "-h", "15", r.value]    // Windows
        : ["-n", "-m", "15", r.value];   // Linux/macOS

    await m.reply(`กำลัง traceroute ไปยัง ${r.value} ...`);

    try {
        execFile(
        bin,
        params,
        {
            timeout: 45000,                                  // ขยายเวลา
            shell: process.platform === "win32" ? true : false // กันกรณีหา exe ไม่เจอใน PATH บนวินโดวส์
        },
        (err, stdout = "", stderr = "") => {
            const text =
            (stdout || stderr || (err && err.message) || "no output")
                .split(/\r?\n/)
                .slice(0, 20)
                .join("\n");
            m.channel.send("```" + text + "```");
        }
        );
    } catch (e) {
        m.channel.send("```Traceroute failed: " + e.message + "```");
    }
}

if (cmd === "!scan") {
  // รูปแบบที่รองรับ:
  //   ไม่มีพารามิเตอร์  -> สแกน subnet ของเครื่องบอท (เช่น 192.168.1.0/24)
  //   192.168.1.*        -> สแกน 192.168.1.1-254
  //   192.168.1.0/24     -> สแกนตาม CIDR (จำกัด /24 ถึง /32)
  //   192.168.1.10-50    -> สแกนช่วง 10 ถึง 50
    const pattern = (args[0] || "").trim();
    const targets = parseTargets(pattern);

    if (!targets.length) {
        return m.reply([
        "รูปแบบช่วงไม่ถูกต้อง หรือไม่ใช่เครือข่ายส่วนตัว",
        "ตัวอย่าง: `!scan 192.168.1.*`, `!scan 192.168.1.0/24`, `!scan 192.168.1.10-50`",
        "หรือพิมพ์ `!scan` เฉย ๆ เพื่อสแกน subnet ปัจจุบัน"
        ].join("\n"));
    }
    if (targets.length > 512) {
        return m.reply("ช่วงใหญ่เกินไป (เกิน 512 IP) — โปรดระบุช่วงให้แคบลง");
    }

    await m.reply(`กำลังสแกน ${targets.length} IP ... อาจใช้เวลาประมาณ ${(Math.ceil(targets.length / 64))} รอบทำงาน`);

    try {
        const online = await pingMany(targets, 64, 1);
        if (!online.length) {
        return m.channel.send("ไม่พบอุปกรณ์ที่ตอบสนอง");
        }
        const lines = online.slice(0, 50).map((x, i) =>
        `${String(i + 1).padStart(2, " ")}. ${x.host}${x.time ? `  ~${x.time}ms` : ""}`
        );
        const more = online.length > 50 ? `\n... และอีก ${online.length - 50} รายการ` : "";
        m.channel.send("**พบอุปกรณ์ออนไลน์:** " + online.length + "\n```" + lines.join("\n") + "```" + more);
    } catch (e) {
        m.channel.send("```Scan failed: " + e.message + "```");
    }
}


});
console.log('PID:', process.pid);
client.login(process.env.DISCORD_BOT_TOKEN);

process.on("unhandledRejection", (e) => console.error("UnhandledRejection:", e));
client.on("error", (e) => console.error("Client error:", e));

process.once('SIGINT', () => client.destroy());
process.once('SIGTERM', () => client.destroy());
