const puppeteer = require('puppeteer')

const ADMIN_PASSWORD = process.env['ADMIN_PASSWORD'] || 'password';

async function visit(url) {
	const browser = await puppeteer.launch({ args: ['--no-sandbox'], headless:"new" })

	var page = await browser.newPage()

	try {
        console.error("Logging in");

		await page.goto("http://to.just-l33t.fibonhack.it/login");
		await new Promise(resolve => setTimeout(resolve, 1000));

		await page.type('#username', 'admin');
		await page.type('#password', ADMIN_PASSWORD);

		await page.click('#login_button');

		await new Promise(resolve => setTimeout(resolve, 1000));

        console.error("Visiting your site")
		await page.goto(url);

		await new Promise(resolve => setTimeout(resolve, 60000));
		console.error('Ending wait')

		await page.close()
		await browser.close()
	} catch (e) {
		await browser.close()
		throw (e)
	}
}

module.exports = { visit }