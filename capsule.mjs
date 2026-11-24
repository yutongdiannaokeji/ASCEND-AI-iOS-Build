import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
const [operation, kind, input, output] = process.argv.slice(2);
const keyText = process.env.ASCEND_BUILD_KEY;
if (!keyText || !/^[a-f0-9]{64}$/.test(keyText) || !['source', 'result'].includes(kind)) throw new Error('Invalid build capsule arguments.');
const key = Buffer.from(keyText, 'hex');
const aad = Buffer.from('ascend-ios-build/v1/' + kind);
const data = readFileSync(input);
if (operation === 'seal') {
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  cipher.setAAD(aad);
  const contents = Buffer.concat([cipher.update(data), cipher.final()]);
  writeFileSync(output, Buffer.concat([nonce, cipher.getAuthTag(), contents]));
} else if (operation === 'open') {
  if (data.length < 29) throw new Error('Build capsule is incomplete.');
  const decipher = createDecipheriv('aes-256-gcm', key, data.subarray(0, 12));
  decipher.setAAD(aad);
  decipher.setAuthTag(data.subarray(12, 28));
  const contents = Buffer.concat([decipher.update(data.subarray(28)), decipher.final()]);
  writeFileSync(output, contents);
} else {
  throw new Error('Unknown build capsule operation.');
}

