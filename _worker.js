import { connect } from 'cloudflare:sockets';

// ✅ 你的UUID，支持多个逗号分隔
const UUID = "af871764-6fe8-4460-8f7c-7620f9d2673f";

// ✅ 反代IP，支持多个逗号分隔
const 反代IP = 'sg.wogg.us.kg';

// 直连超时
const DIRECT_TIMEOUT_MS = 3000;
// 最大gRPC帧
const MAX_GRPC_FRAME_SIZE = 16 * 1024 * 1024;

// 背压参数（参考CM大佬）
const BUFFER_SIZE     = 512 * 1024;       // 512KB
const MAX_CHUNK_LEN   = 64 * 1024;        // 64KB
const START_THRESHOLD = 50 * 1024 * 1024; // 50MB后启用限速
const FLUSH_TIME      = 20;               // 20ms

// ✅ UUID预处理缓存
const UUID_BYTES_SET = new Set(
  UUID.split(',').map(u => u.trim()).map(u => {
    const hex = u.replace(/-/g, '');
    return Array.from({length: 16}, (_, i) =>
      parseInt(hex.slice(i * 2, i * 2 + 2), 16)
    ).join(',');
  })
);

function validateUUID(data, offset) {
  if (data.length < offset + 16) return false;
  return UUID_BYTES_SET.has(
    Array.from(data.slice(offset, offset + 16)).join(',')
  );
}

function 解析地址端口(proxyIP) {
  proxyIP = proxyIP.toLowerCase();
  let 地址 = proxyIP, 端口 = 443;
  if (proxyIP.includes('.tp')) {
    const m = proxyIP.match(/\.tp(\d+)/);
    if (m) 端口 = parseInt(m[1], 10);
    return [地址, 端口];
  }
  if (proxyIP.includes(']:')) {
    const parts = proxyIP.split(']:');
    地址 = parts[0] + ']';
    端口 = parseInt(parts[1], 10) || 端口;
  } else if (proxyIP.includes(':') && !proxyIP.startsWith('[')) {
    const idx = proxyIP.lastIndexOf(':');
    地址 = proxyIP.slice(0, idx);
    端口 = parseInt(proxyIP.slice(idx + 1), 10) || 端口;
  }
  return [地址, 端口];
}

async function 反代参数获取(request, 当前反代IP) {
  const url = new URL(request.url);
  const { pathname, searchParams } = url;
  const pathLower = pathname.toLowerCase();

  if (searchParams.has('proxyip')) {
    const ips = searchParams.get('proxyip').split(',');
    return ips[Math.floor(Math.random() * ips.length)].trim();
  }
  const m = pathLower.match(/\/(proxyip[.=]|pyip=|ip=)([^/]+)/);
  if (m) {
    const ips = m[2].split(',');
    return ips[Math.floor(Math.random() * ips.length)].trim();
  }
  if (当前反代IP) {
    const ips = 当前反代IP.split(',');
    return ips[Math.floor(Math.random() * ips.length)].trim();
  }
  return request.cf?.colo
    ? `${request.cf.colo}.PrOxYip.CmLiuSsSs.nEt`
    : 'proxyip.svip888.us.kg';
}

async function connectWithTimeout(hostname, port, ms) {
  const socket = connect({ hostname, port });
  await Promise.race([
    socket.opened,
    new Promise((_, r) => setTimeout(() => r(new Error('timeout')), ms))
  ]);
  return socket;
}

function extractVlessFromProtobuf(raw) {
  if (!raw || raw.length < 5) throw new Error('payload太短');
  if (raw[0] !== 0x0A) throw new Error('非protobuf格式');

  let ptr = 1, shift = 0;
  while (ptr < raw.length) {
    const b = raw[ptr++];
    if (!(b & 0x80)) break;
    if (++shift > 4) throw new Error('varint异常');
  }

  const start = ptr;
  if (raw.length < start + 18) throw new Error('header截断');

  const version = raw[start];
  if (!validateUUID(raw, start + 1)) throw new Error('UUID不匹配');

  const addonLen = raw[start + 17];
  const o1 = start + 18 + addonLen;
  if (raw.length < o1 + 4) throw new Error('地址段截断');

  const port = (raw[o1 + 1] << 8) | raw[o1 + 2];
  const addrType = raw[o1 + 3];
  let o2 = o1 + 4, host, addrLen;

  switch (addrType) {
    case 1:
      addrLen = 4;
      if (raw.length < o2 + addrLen) throw new Error('IPv4截断');
      host = Array.from(raw.slice(o2, o2 + addrLen)).join('.');
      break;
    case 2:
      addrLen = raw[o2++];
      if (raw.length < o2 + addrLen) throw new Error('域名截断');
      host = new TextDecoder().decode(raw.slice(o2, o2 + addrLen));
      break;
    case 3:
      addrLen = 16;
      if (raw.length < o2 + addrLen) throw new Error('IPv6截断');
      host = `[${Array.from({length: 8}, (_, i) =>
        ((raw[o2+i*2] << 8) | raw[o2+i*2+1]).toString(16)
      ).join(':')}]`;
      break;
    default:
      throw new Error(`未知地址类型 ${addrType}`);
  }

  return { host, port, vlessPayload: raw.slice(o2 + addrLen), version };
}

function makeGrpcFrame(data) {
  const len = data.length;
  const varint = [];
  let t = len;
  while (t > 127) { varint.push((t & 0x7F) | 0x80); t >>>= 7; }
  varint.push(t);
  const pbHeader = new Uint8Array([0x0A, ...varint]);
  const totalLen = pbHeader.length + len;
  const frame = new Uint8Array(5 + totalLen);
  frame[1] = (totalLen >>> 24) & 0xFF;
  frame[2] = (totalLen >>> 16) & 0xFF;
  frame[3] = (totalLen >>> 8) & 0xFF;
  frame[4] = totalLen & 0xFF;
  frame.set(pbHeader, 5);
  frame.set(data, 5 + pbHeader.length);
  return frame;
}

// ✅ 真背压pipe（CM大佬方案）
async function manualPipe(readable, responseWriter) {
  const _safe = BUFFER_SIZE - MAX_CHUNK_LEN;
  let mainBuf = new ArrayBuffer(BUFFER_SIZE);
  let offset = 0, time = 2, totalBytes = 0;
  let timerId = null, resume = null, isReading = false, needsFlush = false;

  const flush = () => {
    if (isReading) { needsFlush = true; return; }
    if (offset > 0) {
      responseWriter.write(makeGrpcFrame(new Uint8Array(mainBuf, 0, offset))).catch(() => {});
      offset = 0;
    }
    needsFlush = false;
    if (timerId) { clearTimeout(timerId); timerId = null; }
    if (resume) { resume(); resume = null; }
  };

  // ✅ BYOB零拷贝读取
  const reader = readable.getReader({ mode: 'byob' });
  try {
    while (true) {
      isReading = true;
      const { done, value } = await reader.read(new Uint8Array(mainBuf, offset, MAX_CHUNK_LEN));
      isReading = false;
      if (done) break;
      mainBuf = value.buffer;
      const chunkLen = value.byteLength;

      if (chunkLen < MAX_CHUNK_LEN) {
        time = 2;
        if (chunkLen < 4096) totalBytes = 0;
        if (offset > 0) {
          offset += chunkLen;
          flush();
        } else {
          responseWriter.write(makeGrpcFrame(value.slice())).catch(() => {});
        }
      } else {
        totalBytes += chunkLen;
        offset += chunkLen;
        if (!timerId) timerId = setTimeout(flush, time);
        if (needsFlush) flush();
        if (offset > _safe) {
          if (totalBytes > START_THRESHOLD) time = FLUSH_TIME;
          await new Promise(r => { resume = r; });
        }
      }
    }
  } finally {
    isReading = false;
    flush();
    reader.releaseLock();
  }
}

async function processStream(request, responseWriter, proxyIP) {
  // ✅ BYOB Reader 复用buffer
  const reader = request.body.getReader({ mode: 'byob' });
  let sessionBuffer = new ArrayBuffer(65536);
  let grpcBuf = new Uint8Array(0);
  let socket = null, remoteWriter = null;
  let isFirst = true, pipePromise = null;

  try {
    while (true) {
      const { done, value } = await reader.read(new Uint8Array(sessionBuffer, 0, 65536));
      if (done) break;
      sessionBuffer = value.buffer;

      // 合并buffer
      if (grpcBuf.byteLength > 0) {
        const combined = new Uint8Array(grpcBuf.byteLength + value.byteLength);
        combined.set(grpcBuf);
        combined.set(value, grpcBuf.byteLength);
        grpcBuf = combined;
      } else {
        grpcBuf = value.slice();
      }

      while (grpcBuf.byteLength >= 5) {
        const grpcLen = ((grpcBuf[1] << 24) >>> 0) | (grpcBuf[2] << 16) | (grpcBuf[3] << 8) | grpcBuf[4];
        if (grpcLen > MAX_GRPC_FRAME_SIZE) throw new Error(`帧过大: ${grpcLen}`);
        if (grpcBuf.byteLength < 5 + grpcLen) break;

        const grpcData = grpcBuf.subarray(5, 5 + grpcLen);
        grpcBuf = grpcBuf.subarray(5 + grpcLen); // ✅ 零拷贝推进

        // ✅ 精确varint跳过（CM大佬写法）
        let p = (grpcData[0] === 0x0A) ? 1 : 0;
        while (p && (grpcData[p++] & 0x80));
        const payload = p === 0 ? grpcData : grpcData.subarray(p);
        if (payload.length === 0) continue;

        if (isFirst) {
          isFirst = false;
          let parsed;
          try {
            parsed = extractVlessFromProtobuf(payload);
          } catch (e) {
            console.error('[拒绝]', e.message);
            return;
          }

          const { host, port, vlessPayload, version } = parsed;
          console.log(`[Target] ${host}:${port}`);

          try {
            socket = await connectWithTimeout(host, port, DIRECT_TIMEOUT_MS);
            console.log(`[直连] ${host}:${port}`);
          } catch {
            try {
              const [h, pt] = 解析地址端口(proxyIP);
              socket = connect({ hostname: h, port: pt });
              await socket.opened;
              console.log(`[反代] ${h}:${pt}`);
            } catch (e2) {
              console.error('[反代失败]', e2.message);
              return;
            }
          }

          remoteWriter = socket.writable.getWriter();
          await responseWriter.write(makeGrpcFrame(new Uint8Array([version, 0])));
          pipePromise = manualPipe(socket.readable, responseWriter);

          if (vlessPayload.length > 0) await remoteWriter.write(vlessPayload);

        } else {
          if (remoteWriter) await remoteWriter.write(payload);
        }
      }
    }
  } catch (e) {
    console.error('[错误]', e.message);
  } finally {
    if (pipePromise) {
      await Promise.race([pipePromise, new Promise(r => setTimeout(r, 2000))]);
    }
    try { reader.releaseLock(); } catch {}
    try { remoteWriter?.releaseLock(); } catch {}
    try { socket?.close(); } catch {}
    try { responseWriter.close(); } catch {}
  }
}

// ✅ _worker.js 标准入口
export default {
  async fetch(request, env, ctx) {
    // ✅ 参考大佬：Pages环境下content-type可能被修改
    // 只要是POST请求就尝试处理，兼容性更强
    if (request.method !== 'POST') {
      return new Response('Not Found', { status: 404 });
    }

    const contentType = request.headers.get('content-type') || '';
    // ✅ 放宽判断：application/grpc 或 application/octet-stream 都接受
    const isGrpc = contentType.startsWith('application/grpc') || 
                   contentType.startsWith('application/octet-stream') ||
                   contentType.length === 0;

    if (!isGrpc) {
      return new Response('Not Found', { status: 404 });
    }

    const proxyIP = await 反代参数获取(request, 反代IP);
    const { readable, writable } = new TransformStream();
    const responseWriter = writable.getWriter();

    ctx.waitUntil(
      processStream(request, responseWriter, proxyIP)
        .catch(e => console.error('[流异常]', e.message))
    );

    return new Response(readable, {
      status: 200,
      headers: {
        'Content-Type': 'application/grpc',
        'grpc-status': '0'
      }
    });
  }
};
