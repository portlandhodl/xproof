// Build circuit inputs for the BIP32 test-vector-1 master and the given paths.
//   node tools/mkinputs.mjs 0/1 1/3 > inputs.json
const R = new URL("../../js/", import.meta.url).href;
const B = await import(R + "bip32.js"), W = await import(R + "noir-witness.js"), H = await import(R + "hash.js");
const m = await B.masterFromSeed(H.hexToBytes("000102030405060708090a0b0c0d0e0f"));
const [pa, pb] = process.argv.slice(2);
const { inputs, keyA, keyB } = await W.buildInputs({
  xpub: B.toXpubData(m), pathA: B.parsePath(pa), pathB: B.parsePath(pb),
  contextHash: await H.sha256(new TextEncoder().encode("c")), expiresAt: 9999999999999,
});
console.error(`key_a ${keyA}\nkey_b ${keyB}`);
console.log(JSON.stringify(inputs));
