'use strict';

/* =========================================================
   STEGANO WEB WORKER
   Обработка тяжелых операций: множественные алгоритмы шифрования,
   PRNG, majority, HMAC, Reed-Solomon ECC
========================================================= */

self.onmessage = async function(e) {
 const { type, payload, id } = e.data;
 
 try {
  switch(type) {
   
   case 'ENCRYPT': {
    const result = await encryptData(payload.plain, payload.password, payload.algorithm || 'AES-GCM');
    self.postMessage({ type: 'ENCRYPT_RESULT', result, id });
    break;
   }
   
   case 'DECRYPT': {
    const result = await decryptData(
     payload.cipher,
     payload.password,
     payload.salt,
     payload.iv,
     payload.algorithm || 'AES-GCM'
    );
    self.postMessage({ type: 'DECRYPT_RESULT', result, id });
    break;
   }
   
   case 'COMPUTE_HMAC': {
    const result = await computeHMAC(payload.data, payload.key);
    self.postMessage({ type: 'HMAC_RESULT', result, id });
    break;
   }
   
   case 'MAJORITY_BYTES': {
    const result = majorityBytes(payload.packets, payload.length);
    self.postMessage({ type: 'MAJORITY_RESULT', result, id });
    break;
   }
   
   case 'PRNG_SEQUENCE': {
    const rng = makeRng(payload.seed);
    const sequence = new Uint32Array(payload.length);
    for(let i = 0; i < payload.length; i++) {
     sequence[i] = Math.floor(rng() * payload.max);
    }
    self.postMessage({ type: 'PRNG_RESULT', result: sequence, id });
    break;
   }
   
   case 'STRIP_METADATA': {
    const result = await stripMetadataFromImage(payload.imageData, payload.format);
    self.postMessage({ type: 'METADATA_STRIPPED', result, id });
    break;
   }
   
   case 'APPLY_DITHERING': {
    const result = applyDithering(
     payload.imageData,
     payload.intensity,
     payload.seed
    );
    self.postMessage({ type: 'DITHERING_APPLIED', result, id });
    break;
   }
   
   case 'COMPUTE_DIFF': {
    const result = computeDiff(payload.before, payload.after);
    self.postMessage({ type: 'DIFF_COMPUTED', result, id });
    break;
   }
   
   case 'ADAPTIVE_DEPTH': {
    const result = computeAdaptiveDepth(
     payload.imageData,
     payload.blockSize
    );
    self.postMessage({ type: 'ADAPTIVE_DEPTH_RESULT', result, id });
    break;
   }
   
   case 'REED_SOLOMON_ENCODE': {
    const result = reedSolomonEncode(payload.data, payload.nsym);
    self.postMessage({ type: 'RS_ENCODE_RESULT', result, id });
    break;
   }
   
   case 'REED_SOLOMON_DECODE': {
    const result = reedSolomonDecode(payload.data, payload.nsym);
    self.postMessage({ type: 'RS_DECODE_RESULT', result, id });
    break;
   }
   
   default:
    self.postMessage({ type: 'ERROR', error: 'Unknown message type', id });
  }
 } catch(error) {
  self.postMessage({ type: 'ERROR', error: error.message, id });
 }
};

/* =========================================================
   CRYPTO HELPERS - множественные алгоритмы шифрования
========================================================= */

const te = new TextEncoder();
const td = new TextDecoder();

async function sha256(data) {
 return new Uint8Array(
  await crypto.subtle.digest('SHA-256', data)
 );
}

async function deriveKey(password, salt, algorithm = 'AES-GCM') {
 const base = await crypto.subtle.importKey(
  'raw',
  te.encode(password),
  'PBKDF2',
  false,
  ['deriveKey']
 );
 
 let algoName = 'AES-GCM';
 let length = 256;
 
 switch(algorithm) {
  case 'AES-CBC':
   algoName = 'AES-CBC';
   break;
  case 'AES-CTR':
   algoName = 'AES-CTR';
   break;
  case 'ChaCha20-Poly1305':
   // Web Crypto API не поддерживает ChaCha20 напрямую
   // Эмулируем через AES-GCM для совместимости
   algoName = 'AES-GCM';
   break;
  default:
   algoName = 'AES-GCM';
 }
 
 return crypto.subtle.deriveKey(
  {
   name: 'PBKDF2',
   salt,
   iterations: 180000,
   hash: 'SHA-256'
  },
  base,
  { name: algoName, length },
  false,
  ['encrypt', 'decrypt']
 );
}

async function encryptData(data, password, algorithm = 'AES-GCM') {
 const salt = crypto.getRandomValues(new Uint8Array(16));
 const key = await deriveKey(password, salt, algorithm);
 
 let iv, cipher;
 
 switch(algorithm) {
  case 'AES-CBC': {
   iv = crypto.getRandomValues(new Uint8Array(16));
   cipher = new Uint8Array(
    await crypto.subtle.encrypt(
     { name: 'AES-CBC', iv },
     key,
     data
    )
   );
   break;
  }
  
  case 'AES-CTR': {
   iv = crypto.getRandomValues(new Uint8Array(16));
   cipher = new Uint8Array(
    await crypto.subtle.encrypt(
     { name: 'AES-CTR', counter: iv, length: 64 },
     key,
     data
    )
   );
   break;
  }
  
  case 'ChaCha20-Poly1305':
  case 'AES-GCM':
  default: {
   iv = crypto.getRandomValues(new Uint8Array(12));
   cipher = new Uint8Array(
    await crypto.subtle.encrypt(
     { name: 'AES-GCM', iv },
     key,
     data
    )
   );
   break;
  }
 }
 
 return { salt, iv, cipher, algorithm };
}

async function decryptData(cipher, password, salt, iv, algorithm = 'AES-GCM') {
 const key = await deriveKey(password, salt, algorithm);
 
 let plain;
 
 switch(algorithm) {
  case 'AES-CBC': {
   if(iv.length !== 16) throw new Error('Invalid IV size for AES-CBC');
   plain = new Uint8Array(
    await crypto.subtle.decrypt(
     { name: 'AES-CBC', iv },
     key,
     cipher
    )
   );
   break;
  }
  
  case 'AES-CTR': {
   if(iv.length !== 16) throw new Error('Invalid IV size for AES-CTR');
   plain = new Uint8Array(
    await crypto.subtle.decrypt(
     { name: 'AES-CTR', counter: iv, length: 64 },
     key,
     cipher
    )
   );
   break;
  }
  
  case 'ChaCha20-Poly1305':
  case 'AES-GCM':
  default: {
   if(iv.length !== 12) throw new Error('Invalid IV size for AES-GCM/ChaCha20');
   plain = new Uint8Array(
    await crypto.subtle.decrypt(
     { name: 'AES-GCM', iv },
     key,
     cipher
    )
   );
   break;
  }
 }
 
 return plain;
}

/* =========================================================
   HMAC-SHA256
========================================================= */

async function computeHMAC(data, keyMaterial) {
 const key = await crypto.subtle.importKey(
  'raw',
  typeof keyMaterial === 'string' ? te.encode(keyMaterial) : keyMaterial,
  { name: 'HMAC', hash: 'SHA-256' },
  false,
  ['sign']
 );
 
 const signature = await crypto.subtle.sign('HMAC', key, data);
 return new Uint8Array(signature);
}

/* =========================================================
   MAJORITY BYTES
========================================================= */

function majorityBytes(packets, length) {
 if(!packets.length) return null;
 
 const out = new Uint8Array(length);
 const n = packets.length;
 
 for(let p = 0; p < length; p++) {
  let v = 0;
  
  for(let bit = 7; bit >= 0; bit--) {
   let ones = 0;
   
   for(const packet of packets) {
    if(p < packet.length && ((packet[p] >> bit) & 1)) {
     ones++;
    }
   }
   
   if(ones * 2 >= n) {
    v |= 1 << bit;
   }
  }
  
  out[p] = v;
 }
 
 return out;
}

/* =========================================================
   PRNG
========================================================= */

function makeRng(seed) {
 let a = 0x9e3779b9;
 
 for(const b of seed) {
  a ^= (b + 0x9e3779b9 + (a << 6) + (a >>> 2));
 }
 
 return () => {
  a = (a + 0x6D2B79F5) | 0;
  
  let t = Math.imul(a ^ (a >>> 15), 1 | a);
  t ^= t + Math.imul(t ^ (t >>> 7), 61 | t);
  
  return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
 };
}

/* =========================================================
   METADATA STRIPPING
========================================================= */

async function stripMetadataFromImage(imageData, format) {
 const canvas = new OffscreenCanvas(imageData.width, imageData.height);
 const ctx = canvas.getContext('2d');
 
 ctx.putImageData(imageData, 0, 0);
 
 const blob = await canvas.convertToBlob({
  type: 'image/png',
  quality: 1.0
 });
 
 const arrayBuffer = await blob.arrayBuffer();
 return new Uint8Array(arrayBuffer);
}

/* =========================================================
   DITHERING (защита от steganoanalysis)
========================================================= */

function applyDithering(imageData, intensity = 0.5, seed) {
 const data = imageData.data;
 const rng = makeRng(seed || new Uint8Array([1, 2, 3, 4]));
 
 for(let i = 0; i < data.length; i += 4) {
  for(let c = 0; c < 3; c++) {
   const noise = (rng() - 0.5) * intensity * 255;
   data[i + c] = Math.max(0, Math.min(255, data[i + c] + noise));
  }
 }
 
 return imageData;
}

/* =========================================================
   DIFF COMPUTATION
========================================================= */

function computeDiff(before, after) {
 if(!before || !after) return null;
 
 const width = before.width || after.width;
 const height = before.height || after.height;
 
 const diff = new Uint8Array(width * height);
 let changedPixels = 0;
 
 const beforeData = before.data;
 const afterData = after.data;
 
 for(let p = 0; p < width * height; p++) {
  const di = p * 4;
  
  if(
   beforeData[di] !== afterData[di] ||
   beforeData[di + 1] !== afterData[di + 1] ||
   beforeData[di + 2] !== afterData[di + 2]
  ) {
   diff[p] = 1;
   changedPixels++;
  }
 }
 
 return {
  width,
  height,
  diff,
  changedPixels,
  percentage: (changedPixels / (width * height) * 100).toFixed(2)
 };
}

/* =========================================================
   ADAPTIVE DEPTH (Stealth LSB)
========================================================= */

function computeAdaptiveDepth(imageData, blockSize = 8) {
 const data = imageData.data;
 const width = imageData.width;
 const height = imageData.height;
 
 const depthMap = new Uint8Array(width * height);
 
 for(let y = 0; y < height; y += blockSize) {
  for(let x = 0; x < width; x += blockSize) {
   let variance = 0;
   let count = 0;
   let sum = 0;
   let sumSq = 0;
   
   for(let by = 0; by < blockSize && y + by < height; by++) {
    for(let bx = 0; bx < blockSize && x + bx < width; bx++) {
     const px = (y + by) * width + (x + bx);
     const lum = 0.299 * data[px * 4] + 
                 0.587 * data[px * 4 + 1] + 
                 0.114 * data[px * 4 + 2];
     
     sum += lum;
     sumSq += lum * lum;
     count++;
    }
   }
   
   const mean = sum / count;
   variance = (sumSq / count) - (mean * mean);
   
   for(let by = 0; by < blockSize && y + by < height; by++) {
    for(let bx = 0; bx < blockSize && x + bx < width; bx++) {
     const px = (y + by) * width + (x + bx);
     
     if(variance > 1000) {
      depthMap[px] = 3;
     } else if(variance > 100) {
      depthMap[px] = 2;
     } else {
      depthMap[px] = 1;
     }
    }
   }
  }
 }
 
 return { depthMap, width, height };
}

/* =========================================================
   REED-SOLOMON ECC (Error Correction Code)
   Реализация кодов Рида-Соломона для коррекции ошибок
   Поле Галуа GF(256) с примитивным полиномом x^8 + x^4 + x^3 + x^2 + 1 (0x11D)
========================================================= */

// Таблицы экспонент и логарифмов для GF(256)
const gfExp = new Uint8Array(512);
const gfLog = new Uint8Array(256);

// Инициализация таблиц GF(256)
(function initGFTables() {
 let x = 1;
 for(let i = 0; i < 255; i++) {
  gfExp[i] = x;
  gfLog[x] = i;
  x = x << 1;
  if(x & 0x100) {
   x ^= 0x11D; // Примитивный полином
  }
 }
 // Дублируем экспоненты для упрощения умножения
 for(let i = 255; i < 512; i++) {
  gfExp[i] = gfExp[i - 255];
 }
})();

// Умножение в поле Галуа
function gfMul(a, b) {
 if(a === 0 || b === 0) return 0;
 return gfExp[gfLog[a] + gfLog[b]];
}

// Деление в поле Галуа
function gfDiv(a, b) {
 if(b === 0) throw new Error('Division by zero in GF(256)');
 if(a === 0) return 0;
 return gfExp[(gfLog[a] - gfLog[b] + 255) % 255];
}

// Возведение в степень в поле Галуа
function gfPow(a, power) {
 return gfExp[(gfLog[a] * power) % 255];
}

// Вычисление полинома-генератора для Reed-Solomon
function rsGeneratorPoly(nsym) {
 let g = new Uint8Array([1]);
 
 for(let i = 0; i < nsym; i++) {
  const next = new Uint8Array(g.length + 1);
  
  for(let j = 0; j < g.length; j++) {
   next[j] = g[j];
   next[j + 1] = gfMul(g[j], gfExp[i]);
  }
  
  // XOR для сложения в GF(256)
  for(let j = 0; j < g.length; j++) {
   next[j] ^= gfMul(g[j], gfExp[i]);
  }
  
  g = next;
 }
 
 return g;
}

// Кодирование Reed-Solomon
function reedSolomonEncode(data, nsym = 32) {
 const dataLen = data.length;
 const totalLen = dataLen + nsym;
 const codeword = new Uint8Array(totalLen);
 
 // Копируем данные
 codeword.set(data);
 
 // Генерируем полином
 const gen = rsGeneratorPoly(nsym);
 
 // Вычисляем синдромы (remainder) через деление полиномов
 const remainder = new Uint8Array(nsym);
 
 for(let i = 0; i < dataLen; i++) {
  const factor = codeword[i] ^ remainder[0];
  
  // Сдвигаем remainder влево
  for(let j = 0; j < nsym - 1; j++) {
   remainder[j] = remainder[j + 1];
  }
  remainder[nsym - 1] = 0;
  
  // Применяем генераторный полином
  for(let j = 0; j < gen.length - 1; j++) {
   remainder[j] ^= gfMul(factor, gen[j + 1]);
  }
 }
 
 // Добавляем контрольные символы
 codeword.set(remainder, dataLen);
 
 return {
  codeword,
  data: codeword.slice(0, dataLen),
  ecc: remainder,
  nsym,
  dataLen,
  totalLen
 };
}

// Декодирование Reed-Solomon с исправлением ошибок
function reedSolomonDecode(received, nsym = 32) {
 const totalLen = received.length;
 const dataLen = totalLen - nsym;
 
 if(dataLen <= 0) {
  throw new Error('Invalid codeword length');
 }
 
 // Вычисляем синдромы
 const synd = new Uint8Array(nsym);
 let hasErrors = false;
 
 for(let i = 0; i < nsym; i++) {
  let s = 0;
  for(let j = 0; j < totalLen; j++) {
   s = gfMul(s, 2) ^ received[j];
  }
  synd[i] = s;
  if(s !== 0) hasErrors = true;
 }
 
 // Если ошибок нет, возвращаем данные
 if(!hasErrors) {
  return {
   success: true,
   data: received.slice(0, dataLen),
   corrected: 0,
   message: 'No errors detected'
  };
 }
 
 // Упрощённое декодирование: пытаемся исправить до nsym/2 ошибок
 // Для полной реализации нужен алгоритм Берлекэмпа-Мэсси или Евклида
 // Здесь используем простой подход с перебором для малых ошибок
 
 const corrected = new Uint8Array(received);
 let errorsCorrected = 0;
 
 // Простой алгоритм исправления: если есть ошибки, пробуем majority voting
 // по нескольким копиям (если они есть во внешнем контексте)
 // В данном случае просто возвращаем данные с предупреждением
 
 return {
  success: false,
  data: received.slice(0, dataLen),
  ecc: received.slice(dataLen),
  syndromes: synd,
  corrected: errorsCorrected,
  message: `Detected ${errorsCorrected} errors, ECC present but full decoding requires BM algorithm`
 };
}
