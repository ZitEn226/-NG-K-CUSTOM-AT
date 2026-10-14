"use strict";
/* CUSTOM AT - server đăng ký đội + admin. Chỉ dùng thư viện có sẵn của Node (>= 22). Chạy: node server.js */
const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const zlib = require("zlib");

const PORT = +process.env.PORT || 3000;
const DATA = path.join(__dirname, "data");
const UPLOADS = path.join(DATA, "uploads");
const DB_FILE = path.join(DATA, "db.json");
const WEB_USER = path.join(__dirname, "web-nguoi-choi");   // web cho người chơi
const WEB_ADMIN = path.join(__dirname, "web-admin");        // web cho admin
fs.mkdirSync(UPLOADS, { recursive: true });

const SLOTS = ["13:00", "15:00", "18:00", "20:00", "22:00", "23:50"];
const CANCEL_BEFORE = 25 * 60000, CODE_BEFORE = 25 * 60000, VN = 7 * 3600000;
const MAX_P = 6, MAX_TEAMS = 15; /* mỗi bảng (khung giờ + bảng) tối đa 15 đội, đủ thì tự khóa */
const MAX_IMG = 5 * 1024 * 1024;

/* ---------- mật khẩu admin và khóa phiên ---------- */
let ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "226"; // mật khẩu admin mặc định: 226 (đổi bằng biến ADMIN_PASSWORD)
let generated = false;
if (!ADMIN_PASSWORD) { ADMIN_PASSWORD = crypto.randomBytes(9).toString("base64url"); generated = true; }
const PW_HASH = crypto.createHash("sha256").update(ADMIN_PASSWORD).digest();
const SECRET_FILE = path.join(DATA, "secret.key");
let SECRET;
try { SECRET = fs.readFileSync(SECRET_FILE); } catch (e) { SECRET = crypto.randomBytes(32); fs.writeFileSync(SECRET_FILE, SECRET, { mode: 0o600 }); }
const SESSION_MS = 12 * 3600000;

function signSession() {
  const exp = String(Date.now() + SESSION_MS);
  const sig = crypto.createHmac("sha256", SECRET).update(exp).digest("base64url");
  return exp + "." + sig;
}
function validSession(tok) {
  if (!tok) return false;
  const i = tok.indexOf("."); if (i < 1) return false;
  const exp = tok.slice(0, i), sig = tok.slice(i + 1);
  const good = crypto.createHmac("sha256", SECRET).update(exp).digest("base64url");
  const a = Buffer.from(sig), b = Buffer.from(good);
  return a.length === b.length && crypto.timingSafeEqual(a, b) && +exp > Date.now();
}
function cookie(req, name) {
  const m = (req.headers.cookie || "").split(/;\s*/).find(c => c.startsWith(name + "="));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : "";
}
const fails = new Map(); /* ip -> {n, until} */
function ipOf(req) { return req.socket.remoteAddress || "?"; }

/* ---------- cơ sở dữ liệu (file JSON, ghi an toàn) ---------- */
let db = { teams: [] };
try { db = JSON.parse(fs.readFileSync(DB_FILE, "utf8")); if (!Array.isArray(db.teams)) db.teams = []; } catch (e) {}
function persist() {
  const tmp = DB_FILE + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_FILE);
}
const newId = () => crypto.randomBytes(6).toString("hex");

/* ---------- tiện ích ---------- */
function pad(n) { return (n < 10 ? "0" : "") + n; }
function fmtVN(ms) { const d = new Date(ms + VN); return pad(d.getUTCHours()) + ":" + pad(d.getUTCMinutes()) + " " + pad(d.getUTCDate()) + "/" + pad(d.getUTCMonth() + 1) + "/" + d.getUTCFullYear(); }
const dayOf = ms => { const d = new Date(ms + VN); return d.getUTCFullYear() + "-" + pad(d.getUTCMonth() + 1) + "-" + pad(d.getUTCDate()); }; /* ngày theo giờ VN: yyyy-mm-dd */
const dayLabel = day => day.split("-").reverse().join("-"); /* dd-mm-yyyy */
function slotOn(day, slot) { const d = day.split("-").map(Number), p = slot.split(":"); return Date.UTC(d[0], d[1] - 1, d[2], +p[0], +p[1]) - VN; }
function slotTime(slot) { return slotOn(dayOf(Date.now()), slot); }
function normPhone(v) {
  v = String(v || "").replace(/[\s.\-]/g, "");
  if (/^\+84\d{9}$/.test(v)) return "0" + v.slice(3);
  if (/^84\d{9}$/.test(v)) return "0" + v.slice(2);
  return v;
}
function send(res, code, obj, headers) {
  const body = JSON.stringify(obj);
  res.writeHead(code, Object.assign({ "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" }, headers || {}));
  res.end(body);
}
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = []; let n = 0;
    req.on("data", c => { n += c.length; if (n > limit) { reject(Object.assign(new Error("Dữ liệu gửi lên quá lớn."), { status: 413 })); req.destroy(); } else chunks.push(c); });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}
async function readJSON(req) {
  const b = await readBody(req, 1024 * 1024);
  try { return JSON.parse(b.toString("utf8") || "{}"); } catch (e) { throw Object.assign(new Error("JSON không hợp lệ."), { status: 400 }); }
}
function parseMultipart(buf, ctype) {
  const m = /boundary=(?:"([^"]+)"|([^;]+))/i.exec(ctype || "");
  if (!m) throw Object.assign(new Error("Thiếu multipart boundary."), { status: 400 });
  const delim = Buffer.from("--" + (m[1] || m[2]));
  const fields = {}, files = {};
  let pos = buf.indexOf(delim);
  while (pos !== -1) {
    pos += delim.length;
    if (buf[pos] === 45 && buf[pos + 1] === 45) break;
    if (buf[pos] === 13) pos += 2;
    const hEnd = buf.indexOf("\r\n\r\n", pos); if (hEnd === -1) break;
    const head = buf.slice(pos, hEnd).toString("utf8");
    const next = buf.indexOf(delim, hEnd + 4); if (next === -1) break;
    const data = buf.slice(hEnd + 4, next - 2);
    const name = /name="([^"]*)"/i.exec(head), fn = /filename="([^"]*)"/i.exec(head), ct = /content-type:\s*([^\r\n]+)/i.exec(head);
    if (name) { if (fn) { if (fn[1] || data.length) files[name[1]] = { filename: fn[1], type: ct ? ct[1].trim() : "", data }; } else fields[name[1]] = data.toString("utf8"); }
    pos = next;
  }
  return { fields, files };
}
function imageExt(buf) {
  if (buf.length > 4 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return "jpg";
  if (buf.length > 8 && buf.slice(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return "png";
  if (buf.length > 12 && buf.slice(0, 4).toString() === "RIFF" && buf.slice(8, 12).toString() === "WEBP") return "webp";
  if (buf.length > 6 && /^GIF8[79]a$/.test(buf.slice(0, 6).toString())) return "gif";
  return null;
}
function saveImage(file, id, kind) {
  if (!file || !file.data.length) throw Object.assign(new Error("Thiếu file ảnh " + kind + "."), { status: 400 });
  if (file.data.length > MAX_IMG) throw Object.assign(new Error("Ảnh " + kind + " vượt quá 5MB."), { status: 400 });
  const ext = imageExt(file.data);
  if (!ext) throw Object.assign(new Error("Ảnh " + kind + " phải là JPG, PNG, WEBP hoặc GIF."), { status: 400 });
  const name = id + "-" + kind + "-" + crypto.randomBytes(3).toString("hex") + "." + ext;
  fs.writeFileSync(path.join(UPLOADS, name), file.data);
  return { stored: name, original: (file.filename || "").slice(0, 120) || name };
}
function rmFile(name) { if (name && /^[\w.\-]+$/.test(name)) try { fs.unlinkSync(path.join(UPLOADS, name)); } catch (e) {} }

/* ---------- kiểm tra dữ liệu ---------- */
function checkPlayers(list) {
  if (!Array.isArray(list)) return { err: "Danh sách code tên không hợp lệ." };
  if (list.length > MAX_P) return { err: "Tối đa " + MAX_P + " người chơi." };
  const out = [], seen = {};
  for (let i = 0; i < list.length; i++) {
    const p = list[i] || {}, id = String(p.id || "").replace(/\D/g, ""), name = String(p.name || "").trim().slice(0, 30), k = "Người chơi " + (i + 1) + ": ";
    if (!id && !name) continue;
    if (!/^\d{7,14}$/.test(id)) return { err: k + "ID game chỉ gồm số, ít nhất 7 chữ số." };
    if (!name) return { err: k + "hãy nhập tên game." };
    if (seen[id]) return { err: k + "ID bị trùng." };
    seen[id] = 1; out.push({ id, name });
  }
  return { list: out };
}
function checkTeamFields(f, partial) {
  const o = {};
  if (!partial || f.team != null) { const t = String(f.team || "").trim(); if (t.length < 2 || t.length > 24) return { err: "Tên đội cần 2–24 ký tự." }; o.team = t; }
  if (!partial || f.phone != null) { const ph = normPhone(f.phone); if (!/^0[35789]\d{8}$/.test(ph)) return { err: "Số điện thoại chưa đúng (10 chữ số)." }; o.phone = ph; }
  if (!partial || f.uid != null) { const u = String(f.uid || ""); if (!/^\d{7,14}$/.test(u)) return { err: "UID đội trưởng chỉ gồm số, ít nhất 7 chữ số." }; o.uid = u; }
  if (!partial || f.zalo != null) { const z = String(f.zalo || "").trim().slice(0, 40); if (!z) return { err: "Nhập tên Zalo." }; o.zalo = z; }
  if (!partial || f.slot != null) { if (SLOTS.indexOf(f.slot) < 0) return { err: "Khung giờ không hợp lệ." }; o.slot = f.slot; }
  if (!partial || f.grp != null) { const g = +f.grp; if (!(g >= 1 && g <= 8)) return { err: "Bảng đấu không hợp lệ." }; o.grp = String(g); }
  return { o };
}
const countIn = (slot, grp, day) => db.teams.filter(t => !t.cancelled && t.slot === slot && t.grp === String(grp) && dayOf(t.slotMs) === (day || dayOf(Date.now()))).length;
function publicView(t) {
  return { id: t.id, team: t.team, phone: t.phone, uid: t.uid, zalo: t.zalo, slot: t.slot, grp: t.grp, slotMs: t.slotMs, players: t.players, cancelled: t.cancelled, cancelledAt: t.cancelledAt, logoName: t.logoName, billName: t.billName };
}
function adminView(t) {
  return Object.assign(publicView(t), { day: dayOf(t.slotMs), createdAt: t.createdAt, note: t.note || "", logoFile: t.logoFile || "", billFile: t.billFile || "", source: t.source || "web" });
}
function mine(id, token) {
  const t = db.teams.find(x => x.id === id);
  if (!t || !token) return null;
  const a = Buffer.from(String(token)), b = Buffer.from(t.token);
  return a.length === b.length && crypto.timingSafeEqual(a, b) ? t : null;
}

/* ---------- ZIP + XLSX tối giản ---------- */
function zip(entries) {
  const parts = [], central = []; let off = 0;
  entries.forEach(e => {
    const name = Buffer.from(e.name, "utf8"), raw = e.data, crc = zlib.crc32(raw);
    const deflated = e.store ? null : zlib.deflateRawSync(raw);
    const useDef = deflated && deflated.length < raw.length, data = useDef ? deflated : raw, method = useDef ? 8 : 0;
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(0x0800, 6); lh.writeUInt16LE(method, 8); lh.writeUInt16LE(0x21, 12);
    lh.writeUInt32LE(crc, 14); lh.writeUInt32LE(data.length, 18); lh.writeUInt32LE(raw.length, 22); lh.writeUInt16LE(name.length, 26);
    parts.push(lh, name, data);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0); ch.writeUInt16LE(20, 4); ch.writeUInt16LE(20, 6); ch.writeUInt16LE(0x0800, 8); ch.writeUInt16LE(method, 10); ch.writeUInt16LE(0x21, 14);
    ch.writeUInt32LE(crc, 16); ch.writeUInt32LE(data.length, 20); ch.writeUInt32LE(raw.length, 24); ch.writeUInt16LE(name.length, 28); ch.writeUInt32LE(off, 42);
    central.push(ch, name);
    off += 30 + name.length + data.length;
  });
  const cd = Buffer.concat(central), end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10); end.writeUInt32LE(cd.length, 12); end.writeUInt32LE(off, 16);
  return Buffer.concat(parts.concat([cd, end]));
}
const esc = s => String(s).replace(/[<>&"]/g, c => ({ "<": "&lt;", ">": "&gt;", "&": "&amp;", '"': "&quot;" })[c]).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "");
function colName(i) { let s = ""; i++; while (i > 0) { const m = (i - 1) % 26; s = String.fromCharCode(65 + m) + s; i = Math.floor((i - 1) / 26); } return s; }
function sheetXml(rows, widths) {
  let x = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetViews><sheetView workbookViewId="0"><pane ySplit="1" topLeftCell="A2" activePane="bottomLeft" state="frozen"/></sheetView></sheetViews><cols>';
  widths.forEach((w, i) => { x += '<col min="' + (i + 1) + '" max="' + (i + 1) + '" width="' + w + '" customWidth="1"/>'; });
  x += "</cols><sheetData>";
  rows.forEach((r, ri) => {
    x += '<row r="' + (ri + 1) + '">';
    r.forEach((c, ci) => {
      const ref = colName(ci) + (ri + 1), st = ri === 0 ? ' s="1"' : "";
      if (c && typeof c === "object" && c.link) x += '<c r="' + ref + '"' + st + ' t="str"><f>HYPERLINK("' + esc(c.link) + '","' + esc(c.text) + '")</f><v>' + esc(c.text) + "</v></c>";
      else if (typeof c === "number") x += '<c r="' + ref + '"' + st + '><v>' + c + "</v></c>";
      else x += '<c r="' + ref + '"' + st + ' t="inlineStr"><is><t xml:space="preserve">' + esc(c == null ? "" : c) + "</t></is></c>";
    });
    x += "</row>";
  });
  return x + "</sheetData></worksheet>";
}
function buildXlsx(base) {
  const status = t => t.cancelled ? "Đã hủy" : "Đang giữ slot";
  const sorted = db.teams.slice().sort((a, b) => (a.slot + a.grp).localeCompare(b.slot + b.grp) || a.createdAt - b.createdAt);
  const days = [...new Set(db.teams.map(t => dayOf(t.slotMs)))].sort().reverse(); /* ngày mới nhất ở đầu, giữ mọi ngày cũ */
  if (!days.length) days.push(dayOf(Date.now()));
  const sheets = [];
  days.forEach(day => {
    const teams = sorted.filter(t => dayOf(t.slotMs) === day);
    const r1 = [["STT", "Tên đội", "Số điện thoại", "UID đội trưởng", "Tên Zalo", "Khung giờ", "Bảng", "Trạng thái", "Số người chơi", "Thời gian đăng ký", "Logo", "Bill", "Ghi chú"]];
    teams.forEach((t, i) => r1.push([i + 1, t.team, t.phone, t.uid, t.zalo, t.slot, "Bảng " + t.grp, status(t), t.players.length, fmtVN(t.createdAt),
      t.logoFile ? { link: base + "/api/admin/file/" + t.logoFile, text: "Xem logo" } : "", t.billFile ? { link: base + "/api/admin/file/" + t.billFile, text: "Xem bill" } : "", t.note || ""]));
    const r2 = [["Tên đội", "Khung giờ", "Bảng", "Trạng thái", "STT", "ID game", "Tên game"]];
    teams.forEach(t => t.players.forEach((p, k) => r2.push([t.team, t.slot, "Bảng " + t.grp, status(t), k + 1, p.id, p.name])));
    sheets.push({ name: "Đội " + dayLabel(day), rows: r1, widths: [6, 24, 15, 16, 20, 11, 9, 15, 13, 18, 12, 12, 30] });
    sheets.push({ name: "Code tên " + dayLabel(day), rows: r2, widths: [24, 11, 9, 15, 6, 16, 26] });
  });
  const X = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>';
  const ct = X + '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>' +
    sheets.map((_, i) => '<Override PartName="/xl/worksheets/sheet' + (i + 1) + '.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>').join("") +
    '<Override PartName="/xl/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml"/></Types>';
  const rels = X + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>';
  const wb = X + '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>' +
    sheets.map((sh, i) => '<sheet name="' + esc(sh.name) + '" sheetId="' + (i + 1) + '" r:id="rId' + (i + 1) + '"/>').join("") + '</sheets></workbook>';
  const wbRels = X + '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">' +
    sheets.map((_, i) => '<Relationship Id="rId' + (i + 1) + '" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet' + (i + 1) + '.xml"/>').join("") +
    '<Relationship Id="rId' + (sheets.length + 1) + '" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>';
  const styles = X + '<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts count="2"><font><sz val="11"/><name val="Calibri"/></font><font><b/><color rgb="FFFFFFFF"/><sz val="11"/><name val="Calibri"/></font></fonts><fills count="3"><fill><patternFill patternType="none"/></fill><fill><patternFill patternType="gray125"/></fill><fill><patternFill patternType="solid"><fgColor rgb="FF0C0E12"/></patternFill></fill></fills><borders count="1"><border><left/><right/><top/><bottom/><diagonal/></border></borders><cellStyleXfs count="1"><xf numFmtId="0" fontId="0" fillId="0" borderId="0"/></cellStyleXfs><cellXfs count="2"><xf numFmtId="0" fontId="0" fillId="0" borderId="0" xfId="0"/><xf numFmtId="0" fontId="1" fillId="2" borderId="0" xfId="0" applyFont="1" applyFill="1"/></cellXfs></styleSheet>';
  return zip([
    { name: "[Content_Types].xml", data: Buffer.from(ct) }, { name: "_rels/.rels", data: Buffer.from(rels) },
    { name: "xl/workbook.xml", data: Buffer.from(wb) }, { name: "xl/_rels/workbook.xml.rels", data: Buffer.from(wbRels) },
    { name: "xl/styles.xml", data: Buffer.from(styles) }
  ].concat(sheets.map((sh, i) => ({ name: "xl/worksheets/sheet" + (i + 1) + ".xml", data: Buffer.from(sheetXml(sh.rows, sh.widths)) }))));
}
function safeName(s) { return String(s).replace(/[^\p{L}\p{N}_\-]+/gu, "_").slice(0, 40) || "doi"; }
function buildImagesZip(kind) {
  const entries = [];
  db.teams.forEach(t => {
    [["logo", t.logoFile], ["bill", t.billFile]].filter(x => x[0] === kind).forEach(([k, f]) => {
      if (!f || !/^[\w.\-]+$/.test(f)) return;
      try { entries.push({ name: dayLabel(dayOf(t.slotMs)) + "/" + t.slot.replace(":", "h") + "_B" + t.grp + "_" + safeName(t.team) + "_" + k + path.extname(f), data: fs.readFileSync(path.join(UPLOADS, f)), store: true }); } catch (e) {}
    });
  });
  return zip(entries);
}

/* ---------- định tuyến ---------- */
const MIME = { ".jpg": "image/jpeg", ".png": "image/png", ".webp": "image/webp", ".gif": "image/gif" };
const STATIC = { "/": WEB_USER, "/index.html": WEB_USER, "/admin": WEB_ADMIN, "/admin.html": WEB_ADMIN };

async function handle(req, res) {
  const url = new URL(req.url, "http://x"), p = url.pathname, m = req.method;
  const isAdmin = () => validSession(cookie(req, "at_admin"));

  if (m === "GET" && STATIC[p]) {
    const body = fs.readFileSync(path.join(STATIC[p], "index.html"));
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY" });
    return res.end(body);
  }

  /* --- người chơi --- */
  if (m === "POST" && p === "/api/register") {
    const { fields: f, files } = parseMultipart(await readBody(req, 12 * 1024 * 1024), req.headers["content-type"]);
    const c = checkTeamFields(f, false); if (c.err) return send(res, 400, { error: c.err });
    if (/\d{8,}/.test(c.o.zalo.replace(/[\s.\-]/g, "")) || /https?:|www\.|zalo\.me/i.test(c.o.zalo)) return send(res, 400, { error: "Chỉ nhập tên Zalo, không nhập số điện thoại hoặc link." });
    if (Date.now() >= slotTime(c.o.slot)) return send(res, 400, { error: "Khung giờ này đã bắt đầu, hãy chọn khung giờ khác." });
    if (db.teams.some(t => !t.cancelled && t.slotMs === slotTime(c.o.slot) && t.grp === c.o.grp && t.team.toLowerCase() === c.o.team.toLowerCase())) return send(res, 409, { error: "Tên đội đã được đăng ký trong khung giờ và bảng này." });
    if (countIn(c.o.slot, c.o.grp) >= MAX_TEAMS) return send(res, 409, { error: "Bảng " + c.o.grp + " khung giờ " + c.o.slot + " đã đủ " + MAX_TEAMS + " đội và đã khóa. Hãy chọn bảng khác." });
    const id = newId();
    let logo, bill;
    try { logo = saveImage(files.logo, id, "logo"); bill = saveImage(files.bill, id, "bill"); }
    catch (e) { if (logo) rmFile(logo.stored); throw e; }
    const t = Object.assign({ id, token: crypto.randomBytes(16).toString("hex"), slotMs: slotTime(c.o.slot), logoFile: logo.stored, logoName: logo.original, billFile: bill.stored, billName: bill.original, players: [], cancelled: false, cancelledAt: 0, createdAt: Date.now(), note: "", source: "web" }, c.o);
    db.teams.push(t); persist();
    return send(res, 200, { id, token: t.token });
  }
  /* công khai: sĩ số từng bảng và danh sách đội (tên + logo) của một bảng */
  if (m === "GET" && p === "/api/availability") {
    const counts = {}, today = dayOf(Date.now()); db.teams.forEach(t => { if (!t.cancelled && dayOf(t.slotMs) === today) counts[t.slot + "|" + t.grp] = (counts[t.slot + "|" + t.grp] || 0) + 1; });
    return send(res, 200, { max: MAX_TEAMS, counts });
  }
  if (m === "GET" && p === "/api/board") {
    const slot = url.searchParams.get("slot") || "", grp = url.searchParams.get("grp") || "";
    if (SLOTS.indexOf(slot) < 0 || !/^[1-8]$/.test(grp)) return send(res, 400, { error: "Bảng không hợp lệ." });
    const day = /^\d{4}-\d{2}-\d{2}$/.test(url.searchParams.get("day") || "") ? url.searchParams.get("day") : dayOf(Date.now());
    const list = db.teams.filter(t => !t.cancelled && t.slot === slot && t.grp === grp && dayOf(t.slotMs) === day).sort((a, b) => a.createdAt - b.createdAt);
    return send(res, 200, { slot, grp, day, max: MAX_TEAMS, count: list.length, teams: list.map(t => ({ id: t.id, team: t.team, logo: t.logoFile ? "/api/logo/" + t.logoFile : "" })) });
  }
  const lg = /^\/api\/logo\/([\w.\-]+)$/.exec(p);
  if (m === "GET" && lg) {
    const owner = db.teams.find(t => t.logoFile === lg[1]), fp = path.join(UPLOADS, lg[1]);
    if (!owner || !fs.existsSync(fp)) return send(res, 404, { error: "Không có file." });
    res.writeHead(200, { "Content-Type": MIME[path.extname(fp)] || "application/octet-stream", "Cache-Control": "public, max-age=300", "X-Content-Type-Options": "nosniff" });
    return res.end(fs.readFileSync(fp));
  }
  let mm = /^\/api\/my\/([a-f0-9]+)(?:\/(cancel|players))?$/.exec(p);
  if (mm) {
    const q = m === "GET" ? url.searchParams.get("token") : null;
    const body = m === "GET" ? {} : await readJSON(req);
    const t = mine(mm[1], q || body.token);
    if (!t) return send(res, 404, { error: "Không tìm thấy đăng ký (có thể đã bị BTC xóa)." });
    if (m === "GET" && !mm[2]) return send(res, 200, publicView(t));
    if (m === "POST" && mm[2] === "cancel") {
      if (t.cancelled) return send(res, 200, publicView(t));
      if (Date.now() >= t.slotMs - CANCEL_BEFORE) return send(res, 403, { error: "Đã quá hạn hủy slot." });
      t.cancelled = true; t.cancelledAt = Date.now(); persist(); return send(res, 200, publicView(t));
    }
    if (m === "PUT" && mm[2] === "players") {
      if (t.cancelled) return send(res, 403, { error: "Slot đã hủy." });
      if (Date.now() >= t.slotMs - CODE_BEFORE) return send(res, 403, { error: "Đã quá hạn đổi code tên. Hãy liên hệ BTC." });
      const c = checkPlayers(body.players); if (c.err) return send(res, 400, { error: c.err });
      t.players = c.list; persist(); return send(res, 200, publicView(t));
    }
  }

  /* --- admin --- */
  if (m === "POST" && p === "/api/admin/login") {
    const ip = ipOf(req), f = fails.get(ip) || { n: 0, until: 0 };
    if (f.until > Date.now()) return send(res, 429, { error: "Sai quá nhiều lần. Thử lại sau " + Math.ceil((f.until - Date.now()) / 60000) + " phút." });
    const body = await readJSON(req);
    const h = crypto.createHash("sha256").update(String(body.password || "")).digest();
    if (!crypto.timingSafeEqual(h, PW_HASH)) {
      f.n++; if (f.n >= 5) { f.until = Date.now() + 15 * 60000; f.n = 0; } fails.set(ip, f);
      return send(res, 401, { error: "Sai mật khẩu." });
    }
    fails.delete(ip);
    return send(res, 200, { ok: true }, { "Set-Cookie": "at_admin=" + encodeURIComponent(signSession()) + "; HttpOnly; SameSite=Strict; Path=/; Max-Age=" + SESSION_MS / 1000 });
  }
  if (p.startsWith("/api/admin/")) {
    if (m === "POST" && p === "/api/admin/logout") return send(res, 200, { ok: true }, { "Set-Cookie": "at_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0" });
    if (!isAdmin()) return send(res, 401, { error: "Chưa đăng nhập admin." });
    /* chặn CSRF cho thao tác ghi: yêu cầu cùng origin */
    if (m !== "GET" && req.headers.origin && new URL(req.headers.origin).host !== req.headers.host) return send(res, 403, { error: "Origin không hợp lệ." });
    const base = (req.headers["x-forwarded-proto"] || "http") + "://" + req.headers.host;

    if (m === "GET" && p === "/api/admin/me") return send(res, 200, { ok: true });
    if (m === "GET" && p === "/api/admin/teams") return send(res, 200, { teams: db.teams.map(adminView).sort((a, b) => b.createdAt - a.createdAt) });
    mm = /^\/api\/admin\/file\/([\w.\-]+)$/.exec(p);
    if (m === "GET" && mm) {
      const fp = path.join(UPLOADS, mm[1]);
      if (!fs.existsSync(fp)) return send(res, 404, { error: "Không có file." });
      res.writeHead(200, { "Content-Type": MIME[path.extname(fp)] || "application/octet-stream", "Cache-Control": "private, max-age=3600", "X-Content-Type-Options": "nosniff", "Content-Disposition": url.searchParams.get("dl") ? "attachment" : "inline" });
      return res.end(fs.readFileSync(fp));
    }
    if (m === "GET" && p === "/api/admin/export.xlsx") {
      const stamp = fmtVN(Date.now()).replace(/[: \/]/g, "-");
      res.writeHead(200, { "Content-Type": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "Content-Disposition": 'attachment; filename="custom-at-' + stamp + '.xlsx"', "Cache-Control": "no-store" });
      return res.end(buildXlsx(base));
    }
    if (m === "GET" && (p === "/api/admin/logos.zip" || p === "/api/admin/bills.zip")) {
      const kind = p === "/api/admin/logos.zip" ? "logo" : "bill";
      res.writeHead(200, { "Content-Type": "application/zip", "Content-Disposition": 'attachment; filename="custom-at-' + kind + '.zip"', "Cache-Control": "no-store" });
      return res.end(buildImagesZip(kind));
    }
    if (m === "POST" && p === "/api/admin/teams") { /* thêm đội thủ công */
      const { fields: f, files } = parseMultipart(await readBody(req, 12 * 1024 * 1024), req.headers["content-type"]);
      const c = checkTeamFields(f, false); if (c.err) return send(res, 400, { error: c.err });
      const pl = checkPlayers(f.players ? JSON.parse(f.players) : []); if (pl.err) return send(res, 400, { error: pl.err });
      const day = /^\d{4}-\d{2}-\d{2}$/.test(f.date || "") ? f.date : dayOf(Date.now());
      const id = newId(), t = Object.assign({ id, token: crypto.randomBytes(16).toString("hex"), slotMs: slotOn(day, c.o.slot), logoFile: "", logoName: "", billFile: "", billName: "", players: pl.list, cancelled: false, cancelledAt: 0, createdAt: Date.now(), note: String(f.note || "").slice(0, 500), source: "admin" }, c.o);
      if (files.logo) { const s = saveImage(files.logo, id, "logo"); t.logoFile = s.stored; t.logoName = s.original; }
      if (files.bill) { const s = saveImage(files.bill, id, "bill"); t.billFile = s.stored; t.billName = s.original; }
      db.teams.push(t); persist(); return send(res, 200, adminView(t));
    }
    mm = /^\/api\/admin\/teams\/([a-f0-9]+)(?:\/(files))?$/.exec(p);
    if (mm) {
      const t = db.teams.find(x => x.id === mm[1]);
      if (!t) return send(res, 404, { error: "Không tìm thấy đội." });
      if (m === "DELETE" && !mm[2]) { rmFile(t.logoFile); rmFile(t.billFile); db.teams = db.teams.filter(x => x !== t); persist(); return send(res, 200, { ok: true }); }
      if (m === "PUT" && !mm[2]) {
        const b = await readJSON(req), c = checkTeamFields(b, true); if (c.err) return send(res, 400, { error: c.err });
        Object.assign(t, c.o);
        if (c.o.slot || /^\d{4}-\d{2}-\d{2}$/.test(b.date || "")) t.slotMs = slotOn(/^\d{4}-\d{2}-\d{2}$/.test(b.date || "") ? b.date : dayOf(t.slotMs), t.slot);
        if (b.players != null) { const pl = checkPlayers(b.players); if (pl.err) return send(res, 400, { error: pl.err }); t.players = pl.list; }
        if (b.note != null) t.note = String(b.note).slice(0, 500);
        if (b.cancelled != null) { t.cancelled = !!b.cancelled; t.cancelledAt = t.cancelled ? (t.cancelledAt || Date.now()) : 0; }
        persist(); return send(res, 200, adminView(t));
      }
      if (m === "POST" && mm[2] === "files") { /* thay/thêm logo hoặc bill */
        const { files } = parseMultipart(await readBody(req, 12 * 1024 * 1024), req.headers["content-type"]);
        if (files.logo) { const s = saveImage(files.logo, t.id, "logo"); rmFile(t.logoFile); t.logoFile = s.stored; t.logoName = s.original; }
        if (files.bill) { const s = saveImage(files.bill, t.id, "bill"); rmFile(t.billFile); t.billFile = s.stored; t.billName = s.original; }
        persist(); return send(res, 200, adminView(t));
      }
    }
    return send(res, 404, { error: "Không tìm thấy." });
  }
  send(res, 404, { error: "Không tìm thấy." });
}

http.createServer((req, res) => {
  handle(req, res).catch(e => {
    if (res.headersSent) return res.end();
    send(res, e.status || 500, { error: e.status ? e.message : "Lỗi máy chủ." });
    if (!e.status) console.error(e);
  });
}).listen(PORT, () => {
  console.log("CUSTOM AT chạy tại http://localhost:" + PORT + "  (admin: /admin)");
  if (generated) console.log("Mật khẩu admin tạm thời (đặt ADMIN_PASSWORD để dùng mật khẩu của bạn): " + ADMIN_PASSWORD);
});
