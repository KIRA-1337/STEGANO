'use strict';

/* =========================================================
   STEGANO WEB WORKER
   Обработка тяжелых операций: AES-GCM, PRNG, majority, HMAC
========================================================= */

self.onmessage = async function(e) {
 const { type, payload } = e.data;
 
 try {
  switch(type) {
   
   case 'ENCRYPT': {
    const result = await encryptData(payload.plain, payload.password);
    self.postMessage({ type: 'ENCRYPT_RESULT', result });
    break;
   }
   
   case 'DECRYPT': {
    const result = await decryptData(
     payload.cipher,
     payload.password,
     payload.salt,
     payload.iv
    );
    self.postMessage({ type: 'DECRYPT_RESULT', result });
    break;
   }
   
   case 'COMPUTE_HMAC': {
    const result = await computeHMAC(payload.data, payload.key);
    self.postMessage({ type: 'HMAC_RESULT', result, id: payload.id });
    break;
   }
   
   case 'MAJORITY_BYTES': {
    const result = majorityBytes(payload.packets, payload.length);
    self.postMessage({ type: 'MAJORITY_RESULT', result, id: payload.id });
    break;
   }
   
   case 'PRNG_SEQUENCE': {
    const rng = makeRng(payload.seed);
    const sequence = new Uint32Array(payload.length);
    for(let i = 0; i < payload.length; i++) {
     sequence[i] = Math.floor(rng() * payload.max);
    }
    self.postMessage({ type: 'PRNG_RESULT', result: sequence, id: payload.id });
    break;
   }
   
   case 'STRIP_METADATA': {
    const result = await stripMetadataFromImage(payload.imageData, payload.format);
    self.postMessage({ type: 'METADATA_STRIPPED', result });
    break;
   }
   
   case 'APPLY_DITHERING': {
    const result = applyDithering(
     payload.imageData,
     payload.intensity,
     payload.seed
    );
    self.postMessage({ type: 'DITHERING_APPLIED', result });
    break;
   }
   
   case 'COMPUTE_DIFF': {
    const result = computeDiff(payload.before, payload.after);
    self.postMessage({ type: 'DIFF_COMPUTED', result });
    break;
   }
   
   case 'ADAPTIVE_DEPTH': {
    const result = computeAdaptiveDepth(
     payload.imageData,
     payload.blockSize
    );
    self.postMessage({ type: 'ADAPTIVE_DEPTH_RESULT', result });
    break;
   }
   
   default:
    self.postMessage({ type: 'ERROR', error: 'Unknown message type' });
  }
 } catch(error) {
  self.postMessage({ type: 'ERROR', error: error.message });
 }
};

/* =========================================================
   CRYPTO HELPERS
========================================================= */

const te = new TextEncoder();
const td = new TextDecoder();

async function sha256(data) {
 return new Uint8Array(
  await crypto.subtle.digest('SHA-256', data)
 );
}

async function deriveKey(password, salt) {
 const base = await crypto.subtle.importKey(
  'raw',
  te.encode(password),
  'PBKDF2',
  false,
  ['deriveKey']
 );
 
 return crypto.subtle.deriveKey(
  {
   name: 'PBKDF2',
   salt,
   iterations: 180000,
   hash: 'SHA-256'
  },
  base,
  { name: 'AES-GCM', length: 256 },
  false,
  ['encrypt', 'decrypt']
 );
}

async function encryptData(data, password) {
 const salt = crypto.getRandomValues(new Uint8Array(16));
 const iv = crypto.getRandomValues(new Uint8Array(12));
 
 const key = await deriveKey(password, salt);
 
 const cipher = new Uint8Array(
  await crypto.subtle.encrypt(
   { name: 'AES-GCM', iv },
   key,
   data
  )
 );
 
 return { salt, iv, cipher };
}

async function decryptData(cipher, password, salt, iv) {
 const key = await deriveKey(password, salt);
 
 const plain = new Uint8Array(
  await crypto.subtle.decrypt(
   { name: 'AES-GCM', iv },
   key,
   cipher
  )
 );
 
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
