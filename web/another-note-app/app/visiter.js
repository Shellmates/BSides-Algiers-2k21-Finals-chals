const puppeteer = require('puppeteer')

const launchOptions = {
  args: ["--no-sandbox"],
  headless: true,
}

const env = {
  FLAG: process.env.FLAG,
}

async function visit(url) {
  const browser = await puppeteer.launch(launchOptions)
  const page = await browser.newPage()

  const domain = url.match(/^http:\/\/(.*?)\//)[1]

  await page.setCookie({
    name: "FLAG",
    value: env.FLAG,
    httpOnly: false,
    domain: domain,
    sameSite: 'Strict',
  })

  await page.goto(url, {waitUntil: "networkidle2", timeout: 10000})

  await new Promise(resolve => setTimeout(resolve, 500));
  await page.close()
  await browser.close()
}

module.exports = { visit }
