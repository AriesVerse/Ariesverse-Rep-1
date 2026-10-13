// export-chats.js — run on your own PC, never deployed as part of the site.
// Reads chat_log and user_events from Firestore and writes:
//   exports\<uid>\chat-001_2026-10-06.txt   one file per conversation
//   exports\summary.csv                      one row per user: first/last prompt, returns
//   exports\events.csv                       every recorded action, oldest first
//
// Run from CMD (see the chat instructions for the two "set" lines):
//   node export-chats.js

const admin = require("firebase-admin");
const fs = require("fs");
const path = require("path");

admin.initializeApp({ projectId: "aries-money-blueprint-30125" });
const db = admin.firestore();

// A prompt sent this long after the previous one counts as "the user returned".
const RETURN_GAP_MINUTES = 60;

const OUT_DIR = path.join(__dirname, "..", "exports");
const iso = d => d.toISOString().replace("T", " ").slice(0, 19);
const csv = v => { let s = String(v == null ? "" : v); if (/^[=+\-@]/.test(s)) s = "'" + s; return '"' + s.replace(/"/g, '""') + '"'; };

async function emailFor(uid) {
  try { return (await admin.auth().getUser(uid)).email || ""; } catch (e) { return ""; }
}

async function main() {
  fs.mkdirSync(OUT_DIR, { recursive: true });

  // ---------- conversations ----------
  const snap = await db.collection("chat_log").orderBy("at").get();
  const byUser = {};
  snap.forEach(doc => {
    const d = doc.data();
    if (!d.at) return;
    (byUser[d.uid] = byUser[d.uid] || []).push({ ...d, at: d.at.toDate() });
  });

  const summary = [["uid", "email", "conversations", "prompts", "first_prompt_utc",
                    "last_prompt_utc", "times_returned", "returned_at_utc"].map(csv).join(",")];

  for (const uid of Object.keys(byUser)) {
    const turns = byUser[uid];
    const email = await emailFor(uid);
    const userDir = path.join(OUT_DIR, uid);
    fs.mkdirSync(userDir, { recursive: true });

    // Split into conversations: `first` is true on the opening prompt of a chat.
    const chats = [];
    for (const t of turns) {
      if (t.first || !chats.length) chats.push([]);
      chats[chats.length - 1].push(t);
    }

    chats.forEach((chat, i) => {
      const lines = [
        `User: ${email || uid}`,
        `Conversation ${i + 1} of ${chats.length}`,
        `Started: ${iso(chat[0].at)} UTC`,
        `Last prompt: ${iso(chat[chat.length - 1].at)} UTC`,
        ""
      ];
      chat.forEach(t => {
        lines.push(`[${iso(t.at)} UTC] USER:`, t.prompt, "", "ARIES:", t.reply, "", "-----", "");
      });
      const name = `chat-${String(i + 1).padStart(3, "0")}_${chat[0].at.toISOString().slice(0, 10)}.txt`;
      fs.writeFileSync(path.join(userDir, name), lines.join("\r\n"), "utf8");
    });

    // Returns: any prompt sent RETURN_GAP_MINUTES or more after the previous one.
    const returns = [];
    for (let i = 1; i < turns.length; i++) {
      if ((turns[i].at - turns[i - 1].at) / 60000 >= RETURN_GAP_MINUTES) returns.push(iso(turns[i].at));
    }

    summary.push([uid, email, chats.length, turns.length, iso(turns[0].at),
                  iso(turns[turns.length - 1].at), returns.length, returns.join(" | ")].map(csv).join(","));
  }
  fs.writeFileSync(path.join(OUT_DIR, "summary.csv"), summary.join("\r\n"), "utf8");

  // ---------- actions ----------
  const evSnap = await db.collection("user_events").orderBy("at").get();
  const events = [["time_utc", "event", "uid", "device"].map(csv).join(",")];
  evSnap.forEach(doc => {
    const d = doc.data();
    if (!d.at) return;
    events.push([iso(d.at.toDate()), d.name, d.uid || "", d.device || ""].map(csv).join(","));
  });
  fs.writeFileSync(path.join(OUT_DIR, "events.csv"), events.join("\r\n"), "utf8");

  console.log(`Done. ${Object.keys(byUser).length} users, ${snap.size} prompts, ${evSnap.size} events.`);
  console.log("Files are in: " + OUT_DIR);
}

main().catch(err => { console.error(err); process.exit(1); });
