import { connect } from 'cloudflare:sockets';

const UUID = "af871764-6fe8-4460-8f7c-7620f9d2673f";
let 反代IP = 'sg.wogg.us.kg';
const DIRECT_TIMEOUT_MS = 3000;
const MAX_GRPC_FRAME_SIZE = 16 * 1024 * 1024;

const BUFFER_SIZE = 512 * 1024;
const MAX_CHUNK_LEN = 64 * 1024;
const START_THRESHOLD = 50 * 1024 * 1024;
const FLUSH_TIME = 20;

const UUID_BYTES_SET = new Set(
  UUID.split(',').map(u => {
    const hex = u.trim().replace(/-/g, '');
    return Array.from({length: 16}, (_, i) => parseInt(hex.slice(i*2, i*2+2), 16)).join(',');
  })
);

function validateUUID(data, offset) {
  if (data.length < offset + 16) return false;
  return UUID_BYTES_SET.has(Array.from(data.slice(offset, offset + 16)).join(','));
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

async function connectWithTimeout(hostname, port, timeoutMs) {
  const socket = connect({ hostname, port });
  await Promise.race([
    socket.opened,
    new Promise((_, r) => setTimeout(() => r(new Error('timeout')), timeoutMs))
  ]);
  return socket;
}

function extractVlessFromProtobuf(rawPayload) {
  if (!rawPayload || rawPayload.length < 5) throw new Error('[解析] payload太短');
  if (rawPayload[0] !== 0x0A) throw new Error('[解析] 非protobuf格式');
  let ptr = 1;
  while (ptr < rawPayload.length) {
    const b = rawPayload[ptr++];
    if (!(b & 0x80)) break;
  }
  const start = ptr;
  if (rawPayload.length < start + 18) throw new Error('[解析] header截断');
  const version = rawPayload[start];
  if (!validateUUID(rawPayload, start + 1)) throw new Error('[验证] UUID不匹配');
  const addonLen = rawPayload[start + 17];
  const o1 = start + 18 + addonLen;
  if (rawPayload.length < o1 + 4) throw new Error('[解析] 地址段截断');
  const port = (rawPayload[o1 + 1] << 8) | rawPayload[o1 + 2];
  const addrType = rawPayload[o1 + 3];
  let o2 = o1 + 4, host, addrLen;
  switch (addrType) {
    case 1:
      addrLen = 4;
      if (rawPayload.length < o2 + addrLen) throw new Error('[解析] IPv4截断');
      host = Array.from(rawPayload.slice(o2, o2 + addrLen)).join('.');
      break;
    case 2:
      addrLen = rawPayload[o2++];
      if (rawPayload.length < o2 + addrLen) throw new Error('[解析] 域名截断');
      host = new TextDecoder().decode(rawPayload.slice(o2, o2 + addrLen));
      break;
    case 3:
      addrLen = 16;
      if (rawPayload.length < o2 + addrLen) throw new Error('[解析] IPv6截断');
      host = `[${Array.from({length: 8}, (_, i) =>
        ((rawPayload[o2+i*2] << 8) | rawPayload[o2+i*2+1]).toString(16)
      ).join(':')}]`;
      break;
    default:
      throw new Error(`[解析] 未知地址类型 ${addrType}`);
  }
  return { host, port, vlessPayload: rawPayload.slice(o2 + addrLen), version };
}

function makeProtobufGrpcFrame(data) {
  const len = data.length;
  const varint = [];
  let tempLen = len;
  while (tempLen > 127) {
    varint.push((tempLen & 0x7F) | 0x80);
    tempLen >>>= 7;
  }
  varint.push(tempLen);
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

async function manualPipe(readable, responseWriter) {
  const _safe = BUFFER_SIZE - MAX_CHUNK_LEN;
  let mainBuf = new ArrayBuffer(BUFFER_SIZE);
  let offset = 0, time = 2, timerId = null;
  let resume = null, isReading = false, needsFlush = false, totalBytes = 0;

  const flush = () => {
    if (isReading) { needsFlush = true; return; }
    if (offset > 0) {
      const frame = makeProtobufGrpcFrame(new Uint8Array(mainBuf, 0, offset));
      responseWriter.write(frame).catch(() => {});
      offset = 0;
    }
    needsFlush = false;
    if (timerId) { clearTimeout(timerId); timerId = null; }
    if (resume) { resume(); resume = null; }
  };

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
          responseWriter.write(makeProtobufGrpcFrame(value.slice())).catch(() => {});
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

export default {
  async fetch(request) {
    const contentType = request.headers.get('content-type') || '';
    // ✅ 同时支持 grpc 和 grpc-web（Pages会把grpc转成grpc-web格式）
    const isGrpc = request.method === 'POST' && (
      contentType.startsWith('application/grpc') // 含 application/grpc-web
    );
    if (!isGrpc) {
      return new Response('Not Found', { status: 404 });
    }

    const 当前反代IP = await 反代参数获取(request, 反代IP);
    const { readable, writable } = new TransformStream();
    const responseWriter = writable.getWriter();

    processStream(request, responseWriter, 当前反代IP)
      .catch(e => console.error('[流异常]', e.message));

    // ✅ 响应头同时兼容 grpc 和 grpc-web
    const isGrpcWeb = contentType.includes('grpc-web');
    return new Response(readable, {
      status: 200,
      headers: {
        'Content-Type': isGrpcWeb ? 'application/grpc-web+proto' : 'application/grpc',
        'grpc-status': '0',
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Expose-Headers': 'grpc-status,grpc-message'
      }
    });
  }
};

async function processStream(request, responseWriter, proxyIP) {
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
        if (grpcLen > MAX_GRPC_FRAME_SIZE) throw new Error(`[防护] 帧过大: ${grpcLen}`);
        if (grpcBuf.byteLength < 5 + grpcLen) break;
        const grpcData = grpcBuf.subarray(5, 5 + grpcLen);
        grpcBuf = grpcBuf.subarray(5 + grpcLen);
        if (isFirst) {
          isFirst = false;
          let parsed;
          try {
            parsed = extractVlessFromProtobuf(grpcData);
          } catch (e) {
            console.error('[解析/验证失败]', e.message);
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
          await responseWriter.write(makeProtobufGrpcFrame(new Uint8Array([version, 0])));
          pipePromise = manualPipe(socket.readable, responseWriter);
          if (vlessPayload.length > 0) await remoteWriter.write(vlessPayload);
        } else {
          let p = (grpcData[0] === 0x0A) ? 1 : 0;
          while (p && (grpcData[p++] & 0x80));
          const payload = p === 0 ? grpcData : grpcData.subarray(p);
          if (payload.length > 0 && remoteWriter) await remoteWriter.write(payload);
        }
      }
    }
  } catch (e) {
    console.error('[致命错误]', e.message);
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
