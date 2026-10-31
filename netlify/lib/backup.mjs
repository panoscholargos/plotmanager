// PlotManager — αντίγραφα ασφαλείας (κοινός κώδικας για το API και την ημερήσια προγραμματισμένη λειτουργία)
//
// Μορφή 3: ΚΑΘΕ εγγραφή του store αποθηκεύεται με το ακριβές κλειδί της ({key, value}),
// ώστε η επαναφορά να βάλει τα πάντα ακριβώς εκεί που ήταν (χωρίς «μαντεψιές» για το ποια
// παρατήρηση ανήκει σε ποιο οικόπεδο/χρήστη). Περιλαμβάνει και τους κωδικούς ως scrypt hash.
import { getStore } from "@netlify/blobs";

export const BACKUP_FORMAT = 3;
export const backupStore = () => getStore({ name: "plotmanager-backups", consistency: "strong" });
// πόσα κρατούνται ανά είδος (τα παλαιότερα σβήνονται αυτόματα)
export const KEEP = { daily: 30, manual: 20, "pre-restore": 10 };

// Επιτρεπτά κλειδιά δεδομένων· ό,τι άλλο απορρίπτεται στην επαναφορά
const ID = "[A-Za-z0-9-]{8,64}", USER = "[a-z0-9._-]{3,32}";
const KINDS = [
  ["projects", new RegExp(`^projects/(${ID})$`)],
  ["plots", new RegExp(`^plots/(${ID})$`)],
  ["reviews", new RegExp(`^reviews/(${ID})/(${USER})$`)],
  ["users", new RegExp(`^users/(${USER})$`)],
  ["meta", /^meta\/([a-z0-9]{1,20})$/],
];
const kindOf = (key) => { for (const [k, re] of KINDS) { const m = re.exec(key); if (m) return [k, m]; } return [null, null]; };
const TRANSIENT = (key) => key.startsWith("lock/");      // κλειδώματα σύνδεσης: προσωρινά, δεν σώζονται

async function pool(items, n, fn) {                      // περιορισμένος παραλληλισμός (όχι εκατοντάδες αιτήματα μαζί)
  const out = new Array(items.length); let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => {
    while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); }
  }));
  return out;
}

// Έλεγχος ακεραιότητας: errors = η δομή είναι λάθος (η επαναφορά απορρίπτεται)· warnings = πληροφοριακά
export function checkIntegrity(records) {
  const errors = [], warnings = [], seen = new Set();
  const ids = { projects: new Set(), plots: new Set(), users: new Set() };
  const plotProject = new Map();
  for (const r of records) {
    if (!r || typeof r.key !== "string") { errors.push("Εγγραφή χωρίς κλειδί"); continue; }
    if (seen.has(r.key)) { errors.push(`Διπλό κλειδί: ${r.key}`); continue; }
    seen.add(r.key);
    const [kind, m] = kindOf(r.key);
    if (!kind) { errors.push(`Άγνωστο κλειδί: ${r.key}`); continue; }
    const v = r.value;
    if (!v || typeof v !== "object" || Array.isArray(v)) { errors.push(`Μη έγκυρο περιεχόμενο: ${r.key}`); continue; }
    if (kind === "projects") { if (v.id !== m[1]) errors.push(`Το έργο ${r.key} έχει διαφορετικό id`); ids.projects.add(m[1]); }
    if (kind === "plots") { if (v.id !== m[1]) errors.push(`Το οικόπεδο ${r.key} έχει διαφορετικό id`); ids.plots.add(m[1]); plotProject.set(m[1], v.project); }
    if (kind === "users") {
      if (v.username !== m[1]) errors.push(`Ο χρήστης ${r.key} έχει διαφορετικό όνομα`);
      // ενεργός λογαριασμός χωρίς κωδικό δεν θα μπορούσε να συνδεθεί (οι ανενεργοί από παλιά αντίγραφα επιτρέπονται)
      else if (v.active && (typeof v.hash !== "string" || typeof v.salt !== "string")) errors.push(`Ο ενεργός χρήστης ${m[1]} δεν έχει κωδικό`);
      ids.users.add(m[1]);
    }
    if (kind === "reviews" && (v.plot_id !== m[1] || v.username !== m[2])) errors.push(`Η παρατήρηση ${r.key} δεν ταιριάζει με οικόπεδο/χρήστη του κλειδιού`);
  }
  // αναφορές μεταξύ εγγραφών
  // προειδοποίηση, όχι σφάλμα: ένα «ορφανό» οικόπεδο (π.χ. από ταυτόχρονη διαγραφή έργου) δεν μπερδεύει δεδομένα
  // και δεν πρέπει να κάνει ΟΛΑ τα αντίγραφα μη επαναφέρσιμα· επανέρχεται ως έχει και ο διαχειριστής το βλέπει στη σύνοψη
  for (const [pid, proj] of plotProject) if (!proj || !ids.projects.has(proj)) warnings.push(`Το οικόπεδο ${pid} ανήκει σε ανύπαρκτο έργο`);
  for (const r of records) {
    const [kind, m] = kindOf(r.key || "");
    if (kind === "reviews" && !ids.plots.has(m[1])) warnings.push(`Παρατήρηση για ανύπαρκτο οικόπεδο: ${r.key}`);
    if (kind === "users" && Array.isArray(r.value.projects)) for (const p of r.value.projects)
      if (!ids.projects.has(p)) warnings.push(`Ο χρήστης ${m[1]} έχει πρόσβαση σε ανύπαρκτο έργο ${p}`);
  }
  return { errors, warnings };
}
export function countRecords(records) {
  const c = { projects: 0, plots: 0, reviews: 0, users: 0, meta: 0 };
  for (const r of records) { const [k] = kindOf(r.key || ""); if (k) c[k]++; }
  return c;
}

// Πλήρες στιγμιότυπο όλων των δεδομένων
export async function snapshot(store, by) {
  const { blobs } = await store.list();
  const keys = blobs.map((b) => b.key).filter((k) => !TRANSIENT(k)).sort();
  const values = await pool(keys, 8, (k) => store.get(k, { type: "json" }));
  const records = keys.map((key, i) => ({ key, value: values[i] })).filter((r) => r.value !== null);
  return {
    app: "PlotManager", format: BACKUP_FORMAT, created: new Date().toISOString(), created_by: by || "system",
    counts: countRecords(records), integrity: checkIntegrity(records), records,
  };
}

// Μετατροπή παλιού αντιγράφου (μορφή 2: λίστες χωρίς κλειδιά και χωρίς κωδικούς) σε μορφή 3
export async function fromV2(data, store) {
  const recs = [], notes = [];
  for (const p of data.projects || []) recs.push({ key: "projects/" + p.id, value: p });
  for (const p of data.plots || []) recs.push({ key: "plots/" + p.id, value: p });
  for (const r of data.reviews || []) recs.push({ key: `reviews/${r.plot_id}/${r.username}`, value: r });
  for (const u of data.users || []) {
    const cur = await store.get("users/" + u.username, { type: "json" });
    const v = { ...u };
    if (cur && cur.hash) { v.salt = cur.salt; v.hash = cur.hash; }      // κρατάμε τον τρέχοντα κωδικό
    else { v.active = false; notes.push(u.username); }                  // χωρίς κωδικό: ανενεργός μέχρι νέο κωδικό
    recs.push({ key: "users/" + u.username, value: v });
  }
  return { records: recs, inactive: notes };
}

// Επαναφορά: γράφει όλες τις εγγραφές και μετά σβήνει όσες δεν υπάρχουν στο αντίγραφο
// (πρώτα εγγραφή, μετά διαγραφή: δεν μένει ποτέ «άδεια» η βάση στη μέση της διαδικασίας)
export async function restoreRecords(store, records) {
  const { errors } = checkIntegrity(records);
  if (errors.length) {                                   // expose: το μήνυμα είναι για τον χρήστη (όχι εσωτερικό σφάλμα)
    const e = new Error("Το αντίγραφο δεν είναι έγκυρο: " + errors.slice(0, 3).join(" · ")); e.status = 400; e.expose = true; throw e;
  }
  const keep = new Set(records.map((r) => r.key));
  await pool(records, 8, (r) => store.setJSON(r.key, r.value));
  const { blobs } = await store.list();
  const extra = blobs.map((b) => b.key).filter((k) => !keep.has(k) && !TRANSIENT(k));
  await pool(extra, 8, (k) => store.delete(k));
  return { written: records.length, removed: extra.length, counts: countRecords(records) };
}

// Αποθήκευση στο store αντιγράφων + καθάρισμα παλιών
const stamp = (iso) => iso.replace(/[:.]/g, "-");
export async function saveBackup(bstore, kind, data) {
  // ημερήσιο: ένα ανά ημέρα· τα υπόλοιπα: χρονοσφραγίδα + τυχαίο επίθημα (ποτέ δύο με το ίδιο όνομα)
  const key = kind === "daily" ? `daily/${data.created.slice(0, 10)}.json`
    : `${kind}/${stamp(data.created)}-${Math.random().toString(36).slice(2, 6)}.json`;
  await bstore.setJSON(key, data);
  const { blobs } = await bstore.list({ prefix: kind + "/" });
  const old = blobs.map((b) => b.key).sort().reverse().slice(KEEP[kind] || 20);
  await pool(old, 8, (k) => bstore.delete(k));
  return key;
}
export async function listBackups(bstore) {
  const { blobs } = await bstore.list();
  return blobs.map((b) => b.key).filter((k) => /^(daily|manual|pre-restore)\/[\w-]+\.json$/.test(k))
    .map((key) => ({ key, kind: key.split("/")[0] })).sort((a, b) => b.key.split("/")[1].localeCompare(a.key.split("/")[1]));
}
export const validBackupKey = (k) => /^(daily|manual|pre-restore)\/[\w-]+\.json$/.test(k || "");
