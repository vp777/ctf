const puppeteer = require('puppeteer');

(async () => {
  const browser = await puppeteer.launch({args: ['--no-sandbox', '--disable-setuid-sandbox']});
  const page = await browser.newPage();

  await page.setCookie({
    'value': 'CTF{n1c3_j0b_0n70_7h3_n3x7}',
    'domain': 'localhost:5000',
    'expires': Date.now() / 1000 + 10,
    'name': 'flag'
  });
  await page.goto('http://localhost:5000/reviews', {waitUntil: 'load', timeout:5000});
  await page.waitFor(10000);
  await browser.close();
})();
