const r = await fetch('https://sdk.cashfree.com/js/v3/cashfree.js');
const text = await r.text();
const urls = new Set();
for (const m of text.matchAll(/https:\/\/[^"'`\s]+/g)) {
  urls.add(m[0]);
}
console.log('URLs in Cashfree SDK:');
urls.forEach(u => console.log(u));
