const puppeteer = require('puppeteer');
const assert = require("assert");
const pino = require('pino');
const logger = pino({
    level: "info",
    transport: {
        target: 'pino-pretty'
    }
});

(async () => {
    const browser = await puppeteer.launch({
        headless: true,
        ignoreHTTPSErrors: true,
        devtools: false,
        defaultViewport: null,
        slowMo: 5,
        args: ['--start-maximized', "--window-size=1920,1080"]
    });

    try {
        const page = await browser.newPage();
        await page.goto('https://localhost:8443/cas/login');

        await page.waitForSelector("#username", {visible: true});
        await page.$eval("#username", el => el.value = '');
        await page.type("#username", "casuser");

        await page.waitForSelector("#password", {visible: true});
        await page.$eval("#password", el => el.value = '');
        await page.type("#password", "Mellon");

        await page.keyboard.press('Enter');
        await page.waitForNavigation();

        const cookies = (await page.cookies()).filter(c => {
            logger.debug(`Checking cookie ${c.name}:${c.value}`);
            return c.name === "TGC";
        });
        assert(cookies.length !== 0);
        logger.info(`Cookie:\n${JSON.stringify(cookies, undefined, 2)}`);
    } finally {
        await browser.close();
    }
})();