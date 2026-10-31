// PlotManager — αυτόματο ημερήσιο αντίγραφο ασφαλείας (Netlify Scheduled Function)
// Τρέχει μία φορά τη μέρα, σώζει πλήρες στιγμιότυπο στο store «plotmanager-backups»
// και κρατά τα τελευταία 30 (τα παλαιότερα σβήνονται αυτόματα).
import { getStore } from "@netlify/blobs";
import { snapshot, saveBackup, backupStore } from "../lib/backup.mjs";

export default async () => {
  const data = await snapshot(getStore({ name: "plotmanager", consistency: "strong" }), "αυτόματο");
  const key = await saveBackup(backupStore(), "daily", data);
  console.log("backup", key, JSON.stringify(data.counts), data.integrity.errors.length ? "ERRORS: " + data.integrity.errors.join("; ") : "ok");
  return new Response("ok");
};

export const config = { schedule: "@daily" };
