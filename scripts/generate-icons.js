/**
 * Generates valid PNG icons for Chrome Extension and Chrome Web Store
 * Produces 16x16, 48x48, 128x128 icons with exact dimensions and violet shield artwork.
 */

import fs from 'fs';
import path from 'path';
import zlib from 'zlib';

function createCrcTable() {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) {
      if (c & 1) c = 0xedb88320 ^ (c >>> 1);
      else c = c >>> 1;
    }
    table[n] = c;
  }
  return table;
}

const crcTable = createCrcTable();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    c = crcTable[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function makeChunk(type, data) {
  const typeBuf = Buffer.from(type, 'ascii');
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(data.length, 0);

  const body = Buffer.concat([typeBuf, data]);
  const crc = crc32(body);
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc, 0);

  return Buffer.concat([lenBuf, body, crcBuf]);
}

function createShieldPng(size) {
  // Raw RGBA pixels with scanline filter 0
  const rowBytes = 1 + size * 4;
  const rawData = Buffer.alloc(rowBytes * size);

  const cx = size / 2;
  const cy = size / 2;
  const r = size * 0.44;

  for (let y = 0; y < size; y++) {
    const rowOffset = y * rowBytes;
    rawData[rowOffset] = 0; // Filter: None

    for (let x = 0; x < size; x++) {
      const pxOffset = rowOffset + 1 + x * 4;

      // Shield boundary check (simple shield curve)
      const dx = (x - cx) / r;
      const dy = (y - cy) / r;

      const inShieldTop = dy >= -0.8 && dy <= 0.2 && Math.abs(dx) <= 0.85;
      const inShieldBottom = dy > 0.2 && dy <= 1.0 && Math.abs(dx) <= (1.0 - (dy - 0.2) * 1.05);

      if (inShieldTop || inShieldBottom) {
        // Violet gradient: #7C4DFF to #A78BFA
        const grad = (y / size);
        const red = Math.round(124 + grad * 43);
        const green = Math.round(77 + grad * 62);
        const blue = Math.round(255 - grad * 5);

        // Subtle border check
        const isBorder = (
          (Math.abs(dx) > 0.75 && inShieldTop) ||
          (dy < -0.72) ||
          (inShieldBottom && Math.abs(dx) > (0.9 - (dy - 0.2) * 1.05))
        );

        if (isBorder) {
          rawData[pxOffset] = 200;     // R
          rawData[pxOffset + 1] = 184; // G
          rawData[pxOffset + 2] = 255; // B (#C8B8FF border)
          rawData[pxOffset + 3] = 255; // A
        } else {
          rawData[pxOffset] = red;
          rawData[pxOffset + 1] = green;
          rawData[pxOffset + 2] = blue;
          rawData[pxOffset + 3] = 255;
        }
      } else {
        // Transparent background
        rawData[pxOffset] = 0;
        rawData[pxOffset + 1] = 0;
        rawData[pxOffset + 2] = 0;
        rawData[pxOffset + 3] = 0;
      }
    }
  }

  // PNG Signature
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  // IHDR
  const ihdrData = Buffer.alloc(13);
  ihdrData.writeUInt32BE(size, 0); // width
  ihdrData.writeUInt32BE(size, 4); // height
  ihdrData[8] = 8; // Bit depth: 8
  ihdrData[9] = 6; // Color type: 6 (RGBA)
  ihdrData[10] = 0; // Compression: 0
  ihdrData[11] = 0; // Filter: 0
  ihdrData[12] = 0; // Interlace: 0

  const ihdrChunk = makeChunk('IHDR', ihdrData);

  // IDAT
  const compressed = zlib.deflateSync(rawData);
  const idatChunk = makeChunk('IDAT', compressed);

  // IEND
  const iendChunk = makeChunk('IEND', Buffer.alloc(0));

  return Buffer.concat([signature, ihdrChunk, idatChunk, iendChunk]);
}

const assetsDir = path.resolve('extension', 'assets');
const storeDir = path.resolve('store');

fs.mkdirSync(assetsDir, { recursive: true });
fs.mkdirSync(storeDir, { recursive: true });

[16, 48, 128].forEach((size) => {
  const buf = createShieldPng(size);
  fs.writeFileSync(path.join(assetsDir, `icon-${size}.png`), buf);
  fs.writeFileSync(path.join(storeDir, `icon-${size}.png`), buf);
  console.log(`Generated icon-${size}.png (${buf.length} bytes, ${size}x${size})`);
});
