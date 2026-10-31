// PlotManager — API (Netlify Function v2 + Netlify Blobs)
// Όλα τα endpoints κάτω από /api/*
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

const TTL = 30 * 24 * 3600 * 1000; // διάρκεια σύνδεσης: 30 ημέρες

const PLOT_FIELDS = [
  // Στοιχεία
  "code", "title", "address", "municipality", "area", "price", "kaek", "description", "dropbox",
  "lat", "lng",
  // Πολεοδομικά στοιχεία και κύρωση Πράξης Εφαρμογής
  "ot", "pol_enotita", "ydom", "pe_number", "pe_decision", "pe_date", "pe_registry", "pe_notes",
  // Υπεύθυνος επικοινωνίας
  "contact_name", "contact_phone", "contact_email", "contact_type",
  // Πρώτος έλεγχος κριτηρίων
  "crit_checked", "crit_distance", "crit_dist_sea", "crit_road_width", "crit_rejected", "crit_notes",
  // Όροι δόμησης
  "zone", "sd", "coverage", "max_height", "max_floors", "frontage", "min_area", "min_frontage",
  "units", "terms_notes",
  // Φάση (Φάση Α → έγκριση → Φάση Β → ολοκλήρωση / απόρριψη)
  "phase",
  // Γ.4 Τεκμηρίωση κριτηρίων, Γ.5 Πρόσβαση
  "dist_center", "dist_sea", "road_width_plan", "road_width_site",
  "access_metro", "access_tram", "access_bus", "access_notes",
  // Δ Οικονομοτεχνική αξιολόγηση
  "market_notes", "new_sale_m2", "build_cost_m2", "other_costs",
];
const PHASES = ["A", "approval", "B", "done", "rejected"];
// Τύποι πεδίων για έλεγχο στον διακομιστή
const NUM_FIELDS = new Set(["area", "price", "lat", "lng", "crit_distance", "crit_dist_sea", "crit_road_width",
  "sd", "coverage", "max_height", "max_floors", "frontage", "min_area", "min_frontage",
  "dist_center", "dist_sea", "road_width_plan", "road_width_site", "new_sale_m2", "build_cost_m2", "other_costs"]);
const BOOL_FIELDS = new Set(["crit_checked", "crit_rejected"]);
const DATE_FIELDS = new Set(["pe_date"]);
const MARKER_COLORS = ["#f0883e", "#f85149", "#a371f7", "#3fb950", "#58a6ff", "#e3b341"];
const MAX_MARKERS = 50;
const ENUMS = {
  phase: PHASES,
  contact_type: ["owner", "broker"],
  zone: ["", "entos", "oikismos", "ektos", "other"],
};
// Προεπιλεγμένα κριτήρια σύμβασης και βάρη βαθμολογίας για νέα έργα
const DEF_CRITERIA = { center_km: 2, sea_km: 4, road_m: 8, units_min: 2, units_max: 3, house_min_m2: 170, house_max_m2: 220, net_ratio: 0.85 };
const DEF_WEIGHTS = { loc: 25, plan: 25, tech: 20, econ: 20, env: 10 };
// Είδος κτιρίου του έργου (κατοικία, συνεργείο, ξενοδοχείο…): προσαρμόζει τα κείμενα της εφαρμογής
const BUILDING_KEYS = ["katoikia", "synergeio", "xenodoxeio", "katastima", "grafeio", "apothiki", "viotexnia", "allo"];
const MAX_FAILS = 8, LOCK_MS = 15 * 60 * 1000; // κλείδωμα σύνδεσης μετά από αποτυχίες
// Κωδικοί: ελάχιστο μήκος για ΝΕΟΥΣ κωδικούς (οι υπάρχοντες συνεχίζουν να ισχύουν).
// Ανώτατο όριο: το scrypt είναι σκόπιμα αργό, ένας τεράστιος «κωδικός» θα φόρτωνε τον διακομιστή.
const PW_MIN = 8, PW_MAX = 200;
const pwProblem = (pw) => pw.length < PW_MIN ? `Ο κωδικός θέλει τουλάχιστον ${PW_MIN} χαρακτήρες`
  : pw.length > PW_MAX ? `Ο κωδικός μπορεί να έχει έως ${PW_MAX} χαρακτήρες` : null;
class HttpError extends Error { constructor(msg, status = 400) { super(msg); this.status = status; } }
const TASK_STATUS = ["", "progress", "done", "na"];
const CHECK_STATE = ["", "ok", "problem", "na"];

const store = () => getStore({ name: "plotmanager", consistency: "strong" });

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
  });
const err = (msg, status = 400) => json({ error: msg }, status);

const norm = (u) => String(u || "").trim().toLowerCase();
const validUsername = (u) => /^[a-z0-9._-]{3,32}$/.test(u);
const validId = (id) => /^[a-zA-Z0-9-]{8,64}$/.test(id || "");
const now = () => new Date().toISOString();
const validDate = (d) => d === "" || /^\d{4}-\d{2}-\d{2}$/.test(d);
const okUrl = (u) => {
  try { const x = new URL(u); return x.protocol === "https:" || x.protocol === "http:"; } catch { return false; }
};
const str = (v, max = 20000) => (typeof v === "string" ? v.slice(0, max) : "");

// ---------- token / κωδικοί ----------
function secret() {
  const s = process.env.AUTH_SECRET;
  if (!s || s.length < 16) throw new Error("Λείπει το AUTH_SECRET (τουλάχιστον 16 χαρακτήρες) στις ρυθμίσεις του Netlify");
  return s;
}
function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.createHmac("sha256", secret()).update(body).digest("base64url");
  return body + "." + sig;
}
function verify(token) {
  if (!token) return null;
  const [body, sig] = token.split(".");
  if (!body || !sig) return null;
  const expect = crypto.createHmac("sha256", secret()).update(body).digest("base64url");
  if (!safeEq(sig, expect)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString());
    return p.exp > Date.now() ? p : null;
  } catch { return null; }
}
function safeEq(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
function hashPw(pw) {
  const salt = crypto.randomBytes(16).toString("hex");
  return { salt, hash: crypto.scryptSync(pw, salt, 64).toString("hex") };
}
function checkPw(pw, salt, hash) {
  const h = crypto.scryptSync(String(pw), salt, 64), e = Buffer.from(hash, "hex");
  return h.length === e.length && crypto.timingSafeEqual(h, e);
}
const pwVersion = (rec) => rec.hash.slice(0, 12); // αλλάζει όταν αλλάζει ο κωδικός → άκυρα τα παλιά tokens
// Για τον κύριο διαχειριστή: αλλαγή του ADMIN_PASS στο Netlify ακυρώνει όλες τις παλιές συνδέσεις του
const envPwVersion = () => crypto.createHmac("sha256", secret()).update("env:" + (process.env.ADMIN_PASS || "")).digest("base64url").slice(0, 12);

async function authenticate(req, s) {
  const p = verify((req.headers.get("authorization") || "").replace(/^Bearer\s+/i, ""));
  if (!p) return null;
  if (p.env) {
    if (!process.env.ADMIN_PASS || norm(process.env.ADMIN_USER) !== p.u || p.pv !== envPwVersion()) return null;
    return { username: p.u, name: process.env.ADMIN_NAME || "Διαχειριστής", role: "admin", env: true };
  }
  const rec = await s.get("users/" + p.u, { type: "json" });
  if (!rec || !rec.active || p.pv !== pwVersion(rec)) return null;
  return { username: rec.username, name: rec.name, role: rec.role, projects: Array.isArray(rec.projects) ? rec.projects : [] };
}
// Ο διαχειριστής βλέπει όλα τα έργα· ο χρήστης μόνο όσα του έχουν ανατεθεί
const canSee = (me, pid) => me.role === "admin" || (!!pid && (me.projects || []).includes(pid));

async function login(s, body) {
  const u = norm(body.username), pw = String(body.password || "");
  if (!u || !pw) return err("Συμπληρώστε όνομα χρήστη και κωδικό");
  if (pw.length > PW_MAX) return err("Λάθος στοιχεία σύνδεσης", 401);   // χωρίς άσκοπο scrypt σε τεράστιο κείμενο
  const envU = norm(process.env.ADMIN_USER), envP = process.env.ADMIN_PASS;
  const isEnv = !!(envU && envP && u === envU);
  if (!isEnv && !validUsername(u)) return err("Λάθος στοιχεία σύνδεσης", 401);
  // προστασία από δοκιμές κωδικών
  const lockKey = "lock/" + encodeURIComponent(u);
  const lock = (await s.get(lockKey, { type: "json" })) || { fails: 0, until: 0 };
  if (lock.until > Date.now()) {
    const min = Math.ceil((lock.until - Date.now()) / 60000);
    return err(`Πολλές αποτυχημένες προσπάθειες. Δοκιμάστε ξανά σε ${min} λεπτά.`, 429);
  }
  const fail = async () => {
    lock.fails = (lock.fails || 0) + 1;
    if (lock.fails >= MAX_FAILS) { lock.until = Date.now() + LOCK_MS; lock.fails = 0; }
    await s.setJSON(lockKey, lock);
    return err("Λάθος στοιχεία σύνδεσης", 401);
  };
  const ok = async (payload, user) => {
    if (lock.fails || lock.until) await s.delete(lockKey);
    return json({ token: sign({ ...payload, exp: Date.now() + TTL }), user });
  };
  if (isEnv) {
    if (!safeEq(pw, envP)) return fail();
    return ok({ u, env: 1, pv: envPwVersion() }, { username: u, name: process.env.ADMIN_NAME || "Διαχειριστής", role: "admin", env: true });
  }
  const rec = await s.get("users/" + u, { type: "json" });
  if (!rec) {
    // ανύπαρκτος χρήστης: περίπου ίδιος χρόνος απόκρισης (ένα scrypt), χωρίς εγγραφή κλειδώματος (όχι «σκουπίδια» στο store)
    crypto.scryptSync(pw, "0".repeat(32), 64);
    return err("Λάθος στοιχεία σύνδεσης", 401);
  }
  if (!rec.active || !checkPw(pw, rec.salt, rec.hash)) return fail();
  return ok({ u, pv: pwVersion(rec) }, { username: u, name: rec.name, role: rec.role });
}
// ---------- βοηθητικά ----------
const numOrNull = (x, min, max) => {
  const n = typeof x === "number" ? x : (x === "" || x == null ? null : Number(x));
  return n === null || !Number.isFinite(n) ? null : Math.min(max, Math.max(min, n));
};
const publicUser = (r) => ({ username: r.username, name: r.name, role: r.role, active: r.active, created: r.created, projects: Array.isArray(r.projects) ? r.projects : [] });

function cleanPlot(body) {
  const o = {};
  for (const k of PLOT_FIELDS) {
    if (!(k in body)) continue;
    const v = body[k];
    if (NUM_FIELDS.has(k)) {
      const n = v === null || v === "" ? null : Number(typeof v === "string" ? v.replace(",", ".") : v);
      if (n !== null && !Number.isFinite(n)) throw new HttpError(`Μη έγκυρος αριθμός στο πεδίο ${k}`);
      if (n !== null && n < 0 && k !== "lat" && k !== "lng") throw new HttpError(`Αρνητική τιμή στο πεδίο ${k}`);
      if (k === "coverage" && n !== null && n > 100) throw new HttpError("Η κάλυψη είναι ποσοστό: έως 100%");
      o[k] = n;
    } else if (BOOL_FIELDS.has(k)) {
      o[k] = !!v;
    } else if (k === "units") {
      const u = v == null ? "" : String(v);
      const m = /^(|0|[1-9]\d?|([1-9]\d?)-([1-9]\d?))$/.exec(u);
      if (!m || (m[2] && +m[2] >= +m[3])) throw new HttpError("Μη έγκυρη τιμή στη «Δυνατότητα» (αριθμός κτιρίων)");
      o[k] = u;
    } else if (ENUMS[k]) {
      if (v == null) { if (ENUMS[k].includes("")) o[k] = ""; continue; }
      if (!ENUMS[k].includes(v)) throw new HttpError(`Μη έγκυρη τιμή στο πεδίο ${k}`);
      o[k] = v;
    } else if (DATE_FIELDS.has(k)) {
      const d = v == null ? "" : String(v);
      if (!validDate(d)) throw new HttpError("Μη έγκυρη ημερομηνία κύρωσης Πράξης Εφαρμογής");
      o[k] = d;
    } else if (v === null) {
      o[k] = "";
    } else if (typeof v === "string") {
      if (k === "dropbox" && v && !okUrl(v)) throw new HttpError("Ο σύνδεσμος Dropbox πρέπει να ξεκινά με https://");
      o[k] = v.slice(0, 20000);
    }
  }
  if (o.lat != null && (o.lat < -90 || o.lat > 90)) throw new HttpError("Μη έγκυρο γεωγραφικό πλάτος");
  if (o.lng != null && (o.lng < -180 || o.lng > 180)) throw new HttpError("Μη έγκυρο γεωγραφικό μήκος");
  if ((o.lat == null) !== (o.lng == null) && "lat" in o && "lng" in o) throw new HttpError("Συμπληρώστε και τις δύο συντεταγμένες");
  // Εργασίες σύμβασης: { A1: {status, date, hours, notes}, ... }
  if (body.tasks && typeof body.tasks === "object") {
    o.tasks = {};
    for (const [k, t] of Object.entries(body.tasks).slice(0, 60)) {         // όριο: οι εργασίες της σύμβασης είναι λίγες
      if (!/^[A-Z][0-9]{1,2}$/.test(k) || !t || typeof t !== "object") continue;
      o.tasks[k] = {
        status: TASK_STATUS.includes(t.status) ? t.status : "",
        date: validDate(str(t.date, 10)) ? str(t.date, 10) : "", notes: str(t.notes, 5000), hours: numOrNull(t.hours, 0, 1000),
      };
    }
  }
  // Λίστα ελέγχου Γ.3: { c1: {state, note}, ... }
  if (body.checks && typeof body.checks === "object") {
    o.checks = {};
    for (const [k, c] of Object.entries(body.checks)) {
      if (!/^c[0-9]{1,2}$/.test(k) || !c || typeof c !== "object") continue;
      o.checks[k] = { state: CHECK_STATE.includes(c.state) ? c.state : "", note: str(c.note, 3000) };
    }
  }
  // Σημεία με ετικέτα στον χάρτη του οικοπέδου
  if ("markers" in body) {
    if (!Array.isArray(body.markers)) throw new HttpError("Μη έγκυρη λίστα σημείων");
    if (body.markers.length > MAX_MARKERS) throw new HttpError(`Έως ${MAX_MARKERS} σημεία ανά οικόπεδο`);
    o.markers = body.markers.map((mk) => {
      const lat = Number(mk && mk.lat), lng = Number(mk && mk.lng);
      if (!Number.isFinite(lat) || !Number.isFinite(lng) || lat < -90 || lat > 90 || lng < -180 || lng > 180)
        throw new HttpError("Μη έγκυρες συντεταγμένες σημείου");
      return {
        id: /^[a-zA-Z0-9-]{4,40}$/.test(String(mk.id || "")) ? mk.id : crypto.randomUUID(),
        lat: +lat.toFixed(7), lng: +lng.toFixed(7), label: str(mk.label, 120),
        color: MARKER_COLORS.includes(mk.color) ? mk.color : MARKER_COLORS[0],
      };
    });
  }
  // Βαθμολογία 0–10 ανά κριτήριο
  if (body.scores && typeof body.scores === "object") {
    o.scores = {};
    for (const [k, v] of Object.entries(body.scores)) {
      if (k in DEF_WEIGHTS) o.scores[k] = numOrNull(v, 0, 10);              // μόνο τα γνωστά κριτήρια Ε.1
    }
  }
  return o;
}

// Οι ώρες εργασίας είναι μόνο για τον διαχειριστή
function forViewer(p, me) {
  if (me.role === "admin" || !p.tasks) return p;
  const tasks = {};
  // eslint-disable-next-line no-unused-vars -- το hours αφαιρείται σκόπιμα
  for (const [k, t] of Object.entries(p.tasks)) { const { hours, ...rest } = t; tasks[k] = rest; }
  return { ...p, tasks };
}

async function getAll(s, prefix) {
  const { blobs } = await s.list({ prefix });
  return (await Promise.all(blobs.map((b) => s.get(b.key, { type: "json" })))).filter(Boolean);
}

// ---------- έργα ----------
function cleanProject(b, base = {}) {
  const o = {};
  if ("name" in b) { o.name = str(b.name, 120).trim(); if (!o.name) throw new HttpError("Το έργο θέλει όνομα"); }
  for (const k of ["client", "description"]) if (k in b) o[k] = str(b[k], 2000);
  if ("archived" in b) o.archived = !!b.archived;
  if ("building" in b) {
    const t = b.building && typeof b.building === "object" ? b.building : {};
    if (!BUILDING_KEYS.includes(t.key)) throw new HttpError("Μη έγκυρο είδος κτιρίου");
    if (t.key === "allo") {
      const f = (v) => str(v, 40).trim();
      o.building = { key: "allo", sg: f(t.sg), pl: f(t.pl), gpl: f(t.gpl) };
      if (!o.building.sg || !o.building.pl || !o.building.gpl) throw new HttpError("Συμπληρώστε ενικό, πληθυντικό και γενική πληθυντικού για το είδος κτιρίου");
    } else o.building = { key: t.key };
  }
  if (b.criteria && typeof b.criteria === "object") {
    const c = { ...DEF_CRITERIA, ...(base.criteria || {}) };
    for (const k of Object.keys(DEF_CRITERIA)) if (k in b.criteria) {
      const count = k === "units_min" || k === "units_max";
      const [lo, hi] = k === "net_ratio" ? [0.3, 1] : count ? [1, 20] : [0, 100000];
      const v = numOrNull(b.criteria[k], -Infinity, Infinity);
      if (v === null || v < lo || v > hi || (count && !Number.isInteger(v)))
        throw new HttpError(k === "net_ratio" ? "Ο λόγος καθαρού/μικτού πρέπει να είναι από 0,3 έως 1"
          : count ? "Ο απαιτούμενος αριθμός κτιρίων είναι ακέραιος από 1 έως 20" : "Μη έγκυρη τιμή κριτηρίου έργου");
      c[k] = v;
    }
    if (c.house_max_m2 < c.house_min_m2) throw new HttpError("Το μέγιστο εμβαδόν ανά κτίριο είναι μικρότερο από το ελάχιστο");
    if (c.units_max < c.units_min) throw new HttpError("Ο απαιτούμενος αριθμός κτιρίων «έως» είναι μικρότερος από το «από»");
    o.criteria = c;
  }
  if (b.weights && typeof b.weights === "object") {
    const w = { ...DEF_WEIGHTS, ...(base.weights || {}) };
    for (const k of Object.keys(DEF_WEIGHTS)) if (k in b.weights) {
      const v = numOrNull(b.weights[k], -Infinity, Infinity);
      if (v === null || v < 0 || v > 100) throw new HttpError("Τα βάρη βαθμολογίας πρέπει να είναι από 0 έως 100");
      w[k] = v;
    }
    if (!Object.values(w).some((x) => x > 0)) throw new HttpError("Τουλάχιστον ένα βάρος πρέπει να είναι πάνω από 0");
    o.weights = w;
  }
  return o;
}
const newProject = (b, me) => ({
  id: crypto.randomUUID(), name: "Νέο έργο", client: "", description: "", archived: false,
  criteria: { ...DEF_CRITERIA }, weights: { ...DEF_WEIGHTS }, building: { key: "katoikia" },
  ...b, created: now(), created_by: me ? me.username : "system",
});
const getProject = (s, id) => (validId(id) ? s.get("projects/" + id, { type: "json" }) : null);

// Μετάπτωση από την έκδοση χωρίς έργα: όλα τα υπάρχοντα οικόπεδα και οι χρήστες πάνε σε ένα πρώτο έργο
let migrated = false;
async function ensureMigrated(s) {
  if (migrated) return;
  if (await s.get("meta/v2", { type: "json" })) { migrated = true; return; }
  const allProjects = await getAll(s, "projects/");
  let def = allProjects.sort((a, b) => String(a.created).localeCompare(String(b.created)))[0];
  if (!def) {
    // σταθερό id: αν δύο αιτήματα κάνουν ταυτόχρονα μετάπτωση, γράφουν το ίδιο έργο και όχι δύο
    def = (await s.get("projects/default-project-0001", { type: "json" })) || { ...newProject({ name: "Έργο 1" }), id: "default-project-0001" };
    await s.setJSON("projects/" + def.id, def);
  }
  for (const p of await getAll(s, "plots/")) if (!p.project) { p.project = def.id; await s.setJSON("plots/" + p.id, p); }
  for (const u of await getAll(s, "users/")) if (!Array.isArray(u.projects)) { u.projects = [def.id]; await s.setJSON("users/" + u.username, u); }
  await s.setJSON("meta/v2", { at: now(), default_project: def.id });
  migrated = true;
}

async function projects(s, me, req, parts, body) {
  const m = req.method, id = parts[1], admin = me.role === "admin";
  if (!id) {
    if (m === "GET") {
      const list = (await getAll(s, "projects/")).filter((p) => canSee(me, p.id))
        .sort((a, b) => Number(!!a.archived) - Number(!!b.archived) || String(a.created).localeCompare(String(b.created)));
      return json(list);
    }
    if (m === "POST") {
      if (!admin) return err("Μόνο για διαχειριστή", 403);
      const p = newProject(cleanProject({ name: body.name || "Νέο έργο", ...body }), me);
      await s.setJSON("projects/" + p.id, p);
      return json(p, 201);
    }
    return err("Μη επιτρεπτή μέθοδος", 405);
  }
  const proj = await getProject(s, id);
  if (!proj || !canSee(me, proj.id)) return err("Το έργο δεν βρέθηκε", 404);
  if (m === "GET") return json(proj);
  if (!admin) return err("Μόνο για διαχειριστή", 403);
  if (m === "PUT") {
    Object.assign(proj, cleanProject(body, proj), { updated: now(), updated_by: me.username });
    await s.setJSON("projects/" + proj.id, proj);
    return json(proj);
  }
  if (m === "DELETE") {
    const count = (await getAll(s, "plots/")).filter((p) => p.project === proj.id).length;
    if (count) return err(`Το έργο έχει ${count} οικόπεδα. Μεταφέρετε ή διαγράψτε τα πρώτα.`);
    for (const u of await getAll(s, "users/")) {
      if (Array.isArray(u.projects) && u.projects.includes(proj.id)) {
        u.projects = u.projects.filter((x) => x !== proj.id); await s.setJSON("users/" + u.username, u);
      }
    }
    await s.delete("projects/" + proj.id);
    return json({ ok: true });
  }
  return err("Μη επιτρεπτή μέθοδος", 405);
}
async function cleanProjectIds(s, list) {
  if (!Array.isArray(list)) throw new HttpError("Μη έγκυρη λίστα έργων");
  const ids = [...new Set(list.map(String))];
  for (const id of ids) if (!(await getProject(s, id))) throw new HttpError("Άγνωστο έργο στη λίστα πρόσβασης");
  return ids;
}

// ---------- χρήστες (admin) ----------
async function users(s, me, req, parts, body) {
  const m = req.method, target = norm(parts[1]);
  if (!target) {
    if (m === "GET") {
      const list = (await getAll(s, "users/")).map(publicUser).sort((a, b) => a.username.localeCompare(b.username));
      return json(list);
    }
    if (m === "POST") {
      const u = norm(body.username), pw = String(body.password || "");
      if (!validUsername(u)) return err("Όνομα χρήστη: 3–32 λατινικοί χαρακτήρες, αριθμοί, . _ -");
      if (u === norm(process.env.ADMIN_USER)) return err("Το όνομα χρησιμοποιείται από τον κύριο διαχειριστή");
      if (pwProblem(pw)) return err(pwProblem(pw));
      if (await s.get("users/" + u, { type: "json" })) return err("Ο χρήστης υπάρχει ήδη");
      const rec = {
        username: u, name: str(body.name, 100) || u,
        role: body.role === "admin" ? "admin" : "user",
        active: true, created: now(), created_by: me.username, ...hashPw(pw),
        projects: body.projects ? await cleanProjectIds(s, body.projects) : [],
      };
      await s.setJSON("users/" + u, rec);
      return json(publicUser(rec), 201);
    }
    return err("Μη επιτρεπτή μέθοδος", 405);
  }
  const rec = await s.get("users/" + target, { type: "json" });
  if (!rec) return err("Ο χρήστης δεν βρέθηκε", 404);
  if (m === "PATCH") {
    if (target === me.username && ((body.role && body.role !== "admin") || body.active === false))
      return err("Δεν μπορείτε να υποβιβάσετε ή να απενεργοποιήσετε τον εαυτό σας");
    if ("name" in body) rec.name = str(body.name, 100) || rec.name;
    if ("role" in body) rec.role = body.role === "admin" ? "admin" : "user";
    if ("active" in body) rec.active = !!body.active;
    if ("projects" in body) rec.projects = await cleanProjectIds(s, body.projects);
    if (body.password) {
      if (pwProblem(String(body.password))) return err(pwProblem(String(body.password)));
      Object.assign(rec, hashPw(String(body.password)));
    }
    await s.setJSON("users/" + target, rec);
    return json(publicUser(rec));
  }
  if (m === "DELETE") {
    if (target === me.username) return err("Δεν μπορείτε να διαγράψετε τον εαυτό σας");
    await s.delete("users/" + target);
    return json({ ok: true });
  }
  return err("Μη επιτρεπτή μέθοδος", 405);
}

// ---------- οικόπεδα ----------
// κάθε αλλαγή οικοπέδου ανεβάζει την έκδοση (rev): έτσι ανιχνεύεται η ταυτόχρονη επεξεργασία
async function saveBumped(s, key, plot) {
  plot.updated = now(); plot.rev = (plot.rev || 0) + 1;
  await s.setJSON(key, plot);
}
// Μια παρατήρηση ανήκει στο έργο όπου γράφτηκε. Αν το οικόπεδο μεταφερθεί, οι παλιές παρατηρήσεις
// δεν φαίνονται στους χρήστες του νέου έργου και οι αποφάσεις τους δεν μετρούν εκεί.
const sameProject = (r, plot) => !r.project || r.project === plot.project;   // !r.project: παρατηρήσεις πριν τα έργα
function reviewsFor(all, plot, me) {
  if (me.role === "admin") return all.map((r) => (sameProject(r, plot) ? r : { ...r, foreign: true }));
  return all.filter((r) => sameProject(r, plot));
}
async function listPlots(s, me, projectId) {
  if (!projectId) return err("Λείπει το έργο");
  const proj = await getProject(s, projectId);
  if (!proj || !canSee(me, proj.id)) return err("Το έργο δεν βρέθηκε", 404);
  const [all, reviews] = await Promise.all([getAll(s, "plots/"), getAll(s, "reviews/")]);
  const inProject = all.filter((p) => p.project === proj.id);
  const ids = new Set(inProject.map((p) => p.id));
  const out = inProject.map((p) => {
    const rs = reviews.filter((r) => ids.has(r.plot_id) && r.plot_id === p.id && sameProject(r, p));
    const mine = rs.find((r) => r.username === me.username);
    const { events, links, ...rest } = p;
    return {
      ...forViewer(rest, me),
      approvals: rs.filter((r) => r.approved).map((r) => r.name || r.username),
      my_approved: !!(mine && mine.approved),
      events_count: (events || []).length,
      links_count: (links || []).length,
      rejections: rs.filter((r) => r.rejected).map((r) => r.name || r.username),
      remarks_count: rs.filter((r) => r.remarks).length,
      my_rejected: !!(mine && mine.rejected),
    };
  });
  out.sort((a, b) => String(a.code || "").localeCompare(String(b.code || ""), "el", { numeric: true }));
  return json(out);
}

async function plots(s, me, req, parts, body) {
  const m = req.method, admin = me.role === "admin", id = parts[1];
  if (!id) {
    if (m === "GET") return listPlots(s, me, new URL(req.url).searchParams.get("project"));
    if (m === "POST") {
      if (!admin) return err("Μόνο για διαχειριστή", 403);
      if (!(await getProject(s, body.project))) return err("Επιλέξτε έγκυρο έργο για το οικόπεδο");
      const p = {
        id: crypto.randomUUID(), title: "Νέο οικόπεδο", contact_type: "owner", phase: "A",
        ...cleanPlot(body), project: body.project, events: [], links: [], rev: 1,
        created: now(), updated: now(), created_by: me.username,
      };
      await s.setJSON("plots/" + p.id, p);
      return json(p, 201);
    }
    return err("Μη επιτρεπτή μέθοδος", 405);
  }
  if (!validId(id)) return err("Μη έγκυρο id", 400);
  const key = "plots/" + id;
  const plot = await s.get(key, { type: "json" });
  // οικόπεδο άλλου έργου: απαντάμε «δεν βρέθηκε», ώστε να μη φαίνεται καν ότι υπάρχει
  if (!plot || !canSee(me, plot.project)) return err("Το οικόπεδο δεν βρέθηκε", 404);
  const sub = parts[2];

  if (!sub) {
    if (m === "GET") {
      const reviews = reviewsFor(await getAll(s, `reviews/${id}/`), plot, me).sort((a, b) => String(b.updated).localeCompare(String(a.updated)));
      return json({ plot: forViewer(plot, me), reviews });
    }
    if (!admin) return err("Μόνο για διαχειριστή", 403);
    if (m === "PUT") {
      // έλεγχος ταυτόχρονης επεξεργασίας με αριθμό έκδοσης (rev), όχι με χρονοσφραγίδα
      if (body.base_rev !== undefined && body.base_rev !== (plot.rev || 0) && !body.force)
        return json({ error: "Το οικόπεδο άλλαξε στο μεταξύ (από άλλη καρτέλα, συσκευή ή χρήστη).", rev: plot.rev || 0, updated: plot.updated, updated_by: plot.updated_by }, 409);
      const merged = { ...plot, ...cleanPlot(body) };
      if ("project" in body && body.project !== plot.project) {        // μεταφορά σε άλλο έργο
        if (!(await getProject(s, body.project))) return err("Άγνωστο έργο");
        merged.project = body.project;
      }
      if ((merged.lat == null) !== (merged.lng == null)) return err("Συμπληρώστε και τις δύο συντεταγμένες ή καμία");
      Object.assign(plot, merged, { updated: now(), updated_by: me.username, rev: (plot.rev || 0) + 1 });
      await s.setJSON(key, plot);
      return json(plot);
    }
    if (m === "DELETE") {
      const { blobs } = await s.list({ prefix: `reviews/${id}/` });
      await Promise.all(blobs.map((b) => s.delete(b.key)));
      await s.delete(key);
      return json({ ok: true });
    }
    return err("Μη επιτρεπτή μέθοδος", 405);
  }

  // Παρατηρήσεις και αποφάσεις ΕΓΚΡΙΣΗ / ΑΠΟΡΡΙΨΗ: κάθε χρήστης έχει τη δική του εγγραφή
  if (sub === "review" && m === "PUT") {
    // Οι αποφάσεις ΑΠΟΡΡΙΨΗ/ΕΓΚΡΙΣΗ είναι του πελάτη· ο διαχειριστής γράφει μόνο παρατηρήσεις
    const decide = !admin;
    const rec = {
      plot_id: id, project: plot.project, username: me.username, name: me.name, role: me.role,
      remarks: str(body.remarks, 10000), rejected: decide && !!body.rejected,
      approved: decide && !body.rejected && !!body.approved, updated: now(),
    };
    await s.setJSON(`reviews/${id}/${me.username}`, rec);
    return json(rec);
  }

  if (!admin) return err("Μόνο για διαχειριστή", 403);

  // Ημερολόγιο εργασιών
  if (sub === "events") {
    plot.events = plot.events || [];
    const eid = parts[3];
    const fields = (b) => ({
      date: validDate(str(b.date, 10)) ? str(b.date, 10) : "", title: str(b.title, 300), notes: str(b.notes, 10000), done: !!b.done,
    });
    if (!eid && m === "POST") {
      if (!str(body.title).trim()) return err("Η εργασία θέλει τίτλο");
      plot.events.push({ id: crypto.randomUUID(), ...fields(body), created: now(), created_by: me.username });
    } else if (eid) {
      const i = plot.events.findIndex((e) => e.id === eid);
      if (i < 0) return err("Η εγγραφή δεν βρέθηκε", 404);
      if (m === "PUT") plot.events[i] = { ...plot.events[i], ...fields({ ...plot.events[i], ...body }) };
      else if (m === "DELETE") plot.events.splice(i, 1);
      else return err("Μη επιτρεπτή μέθοδος", 405);
    } else return err("Μη επιτρεπτή μέθοδος", 405);
    await saveBumped(s, key, plot);
    return json({ events: plot.events, updated: plot.updated, rev: plot.rev });
  }

  // Σύνδεσμοι Dropbox (φωτογραφίες / έγγραφα)
  if (sub === "links") {
    plot.links = plot.links || [];
    const lid = parts[3];
    if (!lid && m === "POST") {
      const url = str(body.url, 2000).trim();
      if (!okUrl(url)) return err("Μη έγκυρος σύνδεσμος (πρέπει να ξεκινά με https://)");
      plot.links.push({
        id: crypto.randomUUID(), kind: body.kind === "photo" ? "photo" : "doc",
        title: str(body.title, 300) || "Αρχείο", url, created: now(), created_by: me.username,
      });
    } else if (lid && m === "DELETE") {
      plot.links = plot.links.filter((l) => l.id !== lid);
    } else return err("Μη επιτρεπτή μέθοδος", 405);
    await saveBumped(s, key, plot);
    return json({ links: plot.links, updated: plot.updated, rev: plot.rev });
  }

  return err("Άγνωστο endpoint", 404);
}

// ---------- router ----------
export default async (req) => {
  try {
    const s = store();
    let parts;
    try { parts = new URL(req.url).pathname.replace(/^\/api\/?/, "").split("/").filter(Boolean).map(decodeURIComponent); }
    catch { return err("Μη έγκυρη διεύθυνση", 400); }
    const m = req.method;
    // το σώμα πρέπει να είναι αντικείμενο JSON (όχι null, πίνακας ή αριθμός)
    let body = ["POST", "PUT", "PATCH"].includes(m) ? await req.json().catch(() => ({})) : {};
    if (!body || typeof body !== "object" || Array.isArray(body)) body = {};

    await ensureMigrated(s);   // πριν την ταυτοποίηση, ώστε οι χρήστες να έχουν ήδη έργα
    if (parts[0] === "login" && m === "POST") return await login(s, body);

    const me = await authenticate(req, s);
    if (!me) return err("Απαιτείται σύνδεση", 401);

    if (parts[0] === "me") return json(me);
    if (parts[0] === "projects") return await projects(s, me, req, parts, body);

    if (parts[0] === "password" && m === "POST") {
      if (me.env) return err("Ο κωδικός του κύριου διαχειριστή αλλάζει από τις ρυθμίσεις (ADMIN_PASS) του Netlify");
      const rec = await s.get("users/" + me.username, { type: "json" });
      if (!checkPw(String(body.old || ""), rec.salt, rec.hash)) return err("Λάθος τρέχων κωδικός", 401);
      if (pwProblem(String(body.new || ""))) return err(pwProblem(String(body.new || "")));
      Object.assign(rec, hashPw(String(body.new)));
      await s.setJSON("users/" + me.username, rec);
      return json({ token: sign({ u: me.username, pv: pwVersion(rec), exp: Date.now() + TTL }) });
    }

    if (parts[0] === "users") {
      if (me.role !== "admin") return err("Μόνο για διαχειριστή", 403);
      return await users(s, me, req, parts, body);
    }
    if (parts[0] === "plots") return await plots(s, me, req, parts, body);

    // Πλήρες αντίγραφο ασφαλείας σε JSON (χωρίς κωδικούς)
    if (parts[0] === "backup" && m === "GET") {
      if (me.role !== "admin") return err("Μόνο για διαχειριστή", 403);
      const [bProjects, bPlots, bReviews, bUsers] = await Promise.all(["projects/", "plots/", "reviews/", "users/"].map((p) => getAll(s, p)));
      return json({ app: "PlotManager", version: 2, exported_at: now(), exported_by: me.username,
        projects: bProjects, plots: bPlots, reviews: bReviews, users: bUsers.map(publicUser) });
    }

    return err("Άγνωστο endpoint", 404);
  } catch (e) {
    if (e instanceof HttpError) return err(e.message, e.status);
    // απρόβλεπτο σφάλμα: λεπτομέρειες μόνο στο log του Netlify (Functions → api), όχι στον browser
    console.error(e);
    if (/AUTH_SECRET/.test(e.message || "")) return err(e.message, 500);   // ρύθμιση που λείπει: χρήσιμο μήνυμα
    return err("Σφάλμα διακομιστή. Δοκιμάστε ξανά.", 500);
  }
};

export const config = { path: "/api/*" };
