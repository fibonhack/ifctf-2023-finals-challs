const express = require('express')
const bot = require('./bot')

const app = express();
app.use(express.urlencoded({ extended: true }));

app.get('/', function (req, res) {
	res.sendFile(__dirname + '/index.html');
});

app.post('/visit', async function (req, res) {
	try {
		let url = req.body.url;

		if(url && typeof url == "string" && (url.startsWith(`http://`) || url.startsWith(`https://`))){
			bot.visit(url);
			res.send('Admin will visit the page soon');	
		}
		else{
			res.send('Invalid URL ://');
		}
	} catch (e) {
		console.log(e);
		res.status(400);
		res.send('bad url');
	}
})


app.listen(8080, () => {
	console.log('Server running on port 8080');
});