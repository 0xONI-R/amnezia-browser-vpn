// Разбор vpn:// в расширении — это ОТДЕЛЬНЫЙ слой от разбора в помощнике.
// Браузер декодирует ссылку сам и отправляет помощнику уже готовый профиль,
// поэтому поле, забытое здесь, не доедет до демона даже при новом помощнике.
// Именно так и вышло с AmneziaWG 3: сервер нового Amnezia молча выбрасывал
// handshake, а в интерфейсе было «no handshake on port 443 mtu 1280».
import assert from "node:assert/strict";
import { test } from "node:test";
import { readFileSync } from "node:fs";
import { createContext, runInContext } from "node:vm";
import { deflateSync } from "node:zlib";

const SRC = readFileSync(new URL("../lib/vpnparse.js", import.meta.url), "utf8");

function loadParser() {
  const ctx = createContext({ DecompressionStream, Response, Blob, TextDecoder, atob, globalThis: null });
  ctx.globalThis = ctx;
  runInContext(SRC, ctx);
  return ctx.awgbvDecodeVpn;
}

// vpn:// = base64url( uint32be(len) || zlib(json) ), как у Amnezia
function makeLink(doc) {
  const raw = Buffer.from(JSON.stringify(doc), "utf8");
  const packed = deflateSync(raw);
  const out = Buffer.alloc(4 + packed.length);
  out.writeUInt32BE(raw.length, 0);
  packed.copy(out, 4);
  return "vpn://" + out.toString("base64url");
}

const HEADER_KEY = Buffer.alloc(32, 0x27).toString("base64");
const PRIV = Buffer.alloc(32, 0x11).toString("base64");
const PUB = Buffer.alloc(32, 0x22).toString("base64");
const PSK = Buffer.alloc(32, 0x33).toString("base64");

function docWith({ lastExtra = {}, awgExtra = {} } = {}) {
  const last = {
    hostName: "vpn.example.net",
    port: "31060",
    client_priv_key: PRIV,
    server_pub_key: PUB,
    psk_key: PSK,
    client_ip: "10.8.1.20",
    mtu: "1376",
    Jc: "6", Jmin: "10", Jmax: "50",
    S1: "12", S2: "12", S3: "12", S4: "12",
    H1: "1", H2: "2", H3: "3", H4: "4",
    ...lastExtra,
  };
  return {
    description: "Poland",
    hostName: "vpn.example.net",
    defaultContainer: "amnezia-awg2",
    containers: [{
      container: "amnezia-awg2",
      awg: {
        Jc: 6, Jmin: 10, Jmax: 50,
        S1: 12, S2: 12, S3: 12, S4: 12,
        H1: 1, H2: 2, H3: 3, H4: 4,
        port: 31060,
        ...awgExtra,
        last_config: JSON.stringify(last),
      },
    }],
  };
}

test("AmneziaWG 3: параметры из last_config доезжают до профиля", async () => {
  const decode = loadParser();
  const link = makeLink(docWith({
    lastExtra: {
      HeaderProtectionKey: HEADER_KEY,
      ContentPaddingAddition: "5-15",
      RekeyAfterTime: "100-120",
      RekeyTimeout: "3-7",
      RejectAfterTime: "150-180",
      KeepaliveTimeout: "5-15",
      MaxHandshakeAttempts: "15-20",
      RandomTrailers: "on",
      DisableCookies: "on",
    },
  }));
  const p = await decode(link);
  assert.equal(p.awg.headerProtectionKey, HEADER_KEY);
  assert.equal(p.awg.contentPaddingAddition, "5-15");
  assert.equal(p.awg.rekeyAfterTime, "100-120");
  assert.equal(p.awg.rekeyTimeout, "3-7");
  assert.equal(p.awg.rejectAfterTime, "150-180");
  assert.equal(p.awg.keepaliveTimeout, "5-15");
  assert.equal(p.awg.maxHandshakeAttempts, "15-20");
  assert.equal(p.awg.randomTrailers, "on");
  assert.equal(p.awg.disableCookies, "on");
});

test("AmneziaWG 3: числа в контейнере не теряются (Jc: 6, S1: 12)", async () => {
  const decode = loadParser();
  // last_config без обфускации — значения должны прийти из awg числами
  const doc = docWith();
  const last = JSON.parse(doc.containers[0].awg.last_config);
  for (const k of ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4"]) delete last[k];
  doc.containers[0].awg.last_config = JSON.stringify(last);
  doc.containers[0].awg.HeaderProtectionKey = HEADER_KEY;
  const p = await decode(makeLink(doc));
  assert.equal(p.awg.jc, "6");
  assert.equal(p.awg.s1, "12");
  assert.equal(p.awg.h4, "4");
  assert.equal(p.awg.headerProtectionKey, HEADER_KEY);
});

test("AmneziaWG 1.x: без AWG 3 поля пустые, лишнего в профиль не попадает", async () => {
  const decode = loadParser();
  const p = await decode(makeLink(docWith()));
  assert.equal(p.awg.headerProtectionKey, "");
  assert.equal(p.awg.rekeyAfterTime, "");
  assert.equal(p.awg.disableCookies, "");
  assert.equal(p.awg.jc, "6");
  assert.equal(p.port, 31060);
  assert.equal(p.clientIp, "10.8.1.20");
});

test("флаги, пришедшие булевыми, приводятся к on/off", async () => {
  const decode = loadParser();
  const p = await decode(makeLink(docWith({ lastExtra: { RandomTrailers: true, DisableCookies: false } })));
  assert.equal(p.awg.randomTrailers, "on");
  assert.equal(p.awg.disableCookies, "off");
});
