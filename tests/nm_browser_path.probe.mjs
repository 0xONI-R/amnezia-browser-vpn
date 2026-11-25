// Проверка пути БРАУЗЕРА: расширение разбирает vpn:// само и отправляет помощнику
// готовый профиль. Поэтому проверяем именно эту связку: vpnparse.js → кадр native
// messaging → помощник → туннель → egress.
//
//   node extension/tests/nm-browser-path.probe.mjs <ссылка vpn://> <бинарь помощника>
//
// Не входит в обычный прогон: нужен живой сервер и свободный порт SOCKS.
import { spawn } from "node:child_process";
import { readFileSync } from "node:fs";
import { createContext, runInContext } from "node:vm";
import net from "node:net";

const [, , link, bin] = process.argv;
if (!link || !bin) {
  console.error("usage: node nm-browser-path.probe.mjs <vpn://link> <helper-binary>");
  process.exit(2);
}

// 1. то, что делает background.js
const SRC = readFileSync(new URL("../extension/lib/vpnparse.js", import.meta.url), "utf8");
const ctx = createContext({ DecompressionStream, Response, Blob, TextDecoder, atob, globalThis: null });
ctx.globalThis = ctx;
runInContext(SRC, ctx);
const profile = await ctx.awgbvDecodeVpn(link);

const awg3 = ["headerProtectionKey", "rekeyAfterTime", "keepaliveTimeout", "randomTrailers", "disableCookies"]
  .filter((k) => profile.awg[k]);
console.log("профиль из расширения: host=%s port=%s ip=%s mtu=%s", profile.host, profile.port, profile.clientIp, profile.mtu);
console.log("поля AWG 3 в профиле:", awg3.join(", ") || "НЕТ");
if (!profile.awg.headerProtectionKey) {
  console.error("ПРОВАЛ: расширение не передало HeaderProtectionKey — сервер AWG 3 не ответит");
  process.exit(1);
}

// 2. кадр native messaging: 4-байтная длина little-endian + JSON
const msg = {
  id: 1,
  cmd: "connect",
  listen: "127.0.0.1:1094",
  mtuAuto: true,
  portFallback: true,
  profile,
};
const body = Buffer.from(JSON.stringify(msg), "utf8");
const frame = Buffer.alloc(4 + body.length);
frame.writeUInt32LE(body.length, 0);
body.copy(frame, 4);

// помощник в режиме native messaging живёт, пока браузер держит порт: читаем один
// кадр ответа, потом просим quit — ждать выхода процесса нельзя.
const child = spawn(bin, [], { env: { ...process.env, HOME: "/tmp/nm-browser-home" }, stdio: ["pipe", "pipe", "inherit"] });
let buf = Buffer.alloc(0);
const replies = [];
child.stdout.on("data", (d) => {
  buf = Buffer.concat([buf, d]);
  while (buf.length >= 4) {
    const n = buf.readUInt32LE(0);
    if (buf.length < 4 + n) break;
    replies.push(JSON.parse(buf.subarray(4, 4 + n).toString("utf8")));
    buf = buf.subarray(4 + n);
  }
});
child.stdin.write(frame);
const reply = await new Promise((res, rej) => {
  const t = setInterval(() => {
    if (replies.length) { clearInterval(t); res(replies[0]); }
  }, 100);
  setTimeout(() => { clearInterval(t); rej(new Error("помощник не ответил за 60 с")); }, 60000);
});
const st = reply.status || {};
console.log("ответ помощника: ok=%s state=%s порт SOCKS=%s endpoint=%s", reply.ok, st.state, st.socksPort, st.endpoint);
const quit = async () => {
  const b = Buffer.from(JSON.stringify({ id: 99, cmd: "quit" }), "utf8");
  const f = Buffer.alloc(4 + b.length);
  f.writeUInt32LE(b.length, 0); b.copy(f, 4);
  child.stdin.write(f);
  await new Promise((r) => setTimeout(r, 500));
  child.kill();
};
if (!reply.ok || st.state !== "connected") {
  console.error("ПРОВАЛ:", JSON.stringify(reply).slice(0, 400));
  await quit();
  process.exit(1);
}

// 3. данные через SOCKS5: должен быть IP сервера, а не наш
const sock = net.connect(Number(st.socksPort), st.socksHost || "127.0.0.1");
const host = "api.ipify.org";
const req = Buffer.concat([
  Buffer.from([5, 1, 0]),
]);
await new Promise((res, rej) => {
  sock.once("connect", res);
  sock.once("error", rej);
});
sock.write(req);
await new Promise((res) => sock.once("data", res));
const nameBuf = Buffer.from(host, "utf8");
const conn = Buffer.concat([Buffer.from([5, 1, 0, 3, nameBuf.length]), nameBuf, Buffer.from([0, 80])]);
sock.write(conn);
await new Promise((res) => sock.once("data", res));
sock.write("GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\n\r\n");
let body2 = "";
await new Promise((res) => {
  sock.on("data", (d) => { body2 += d.toString(); });
  sock.on("end", res);
  sock.on("close", res);
  setTimeout(res, 15000);
});
sock.destroy();
const ip = (body2.split("\r\n\r\n")[1] || "").trim();
console.log("egress через туннель:", ip || "(пусто)");
if (!ip || ip.startsWith("10.") || ip.startsWith("127.")) {
  console.error("ПРОВАЛ: данные через туннель не идут");
  process.exit(1);
}
console.log("OK: путь браузера работает, egress =", ip);
await quit();
