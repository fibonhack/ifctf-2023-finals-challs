const express = require('express')
const sessions = require('express-session');
const cookieParser = require("cookie-parser");
const sha256 = require('sha256');
const mysql = require('mysql2');

const FLAG = process.env['FLAG'] || 'ifctf{kek}';

const conn = mysql.createConnection({
    host     : process.env['DBHOST'] || 'localhost',
    user     : 'root',
    password : process.env['MYSQL_ROOT_PASSWORD'] || 'password',
    database : process.env['MYSQL_DATABASE'] || 'just_l33t_db'
});

const app = express()
app.use(express.urlencoded({extended: true}))
app.use(express.json())
app.use(sessions({
    secret: process.env['SECRET_KEY'] || 'secret',
    saveUninitialized: true,
    cookie: { maxAge: 1000 * 60 * 60 * 24 },
    resave: false,
    httpOnly: true,
    name: 'session'
}));
app.use(cookieParser());

app.engine('html', require('ejs').renderFile);
app.engine('css', require('ejs').renderFile);

app.get('/api/cookie_bridge', (req, res) => {
    let token = req.query.token;

    if(token && typeof token === 'string'){
        conn.query('SELECT `c`.`cookies`, `c`.`user_id`, `u`.`username`, `u`.`is_admin` FROM `cookie` `c`  INNER JOIN `user` `u` ON `u`.`id` = `c`.`user_id` WHERE `c`.`id` = ?;', [token], (err, result) => {
            if(err || result.length !== 1){
                return res.redirect('/orders');
            }

            if(!result[0].is_admin){
                return res.redirect('/login');
            }

            cookies = JSON.parse(result[0].cookies);

            for (const [key, value] of Object.entries(cookies)) {
                res.cookie(key, value, {
                    maxAge: 1000 * 60 * 60 * 24,
                    httpOnly: true
                });
            }

            req.session.user = {
                username: result[0].username,
                id: result[0].user_id
            };

            conn.query('DELETE FROM `cookie` WHERE id = ?;', [token], (err, result) => {
                return res.redirect('/orders');
            });
        });
    }
    else{
        return res.redirect('/orders')
    }
})

app.get('/', (req, res) => {
    return res.render('login.html')
})

app.get('/style.css', (req, res)  => {
    return res
        .setHeader('Content-Type', 'text/css')
        .render('style.css');
});

app.post('/login', (req, res) => {
    let username = req.body.username;
    let password = req.body.password;

    if(!username || !password || typeof username !== 'string' || typeof password !== 'string'){
        return res.redirect('/')
    }

    conn.query('SELECT username, password_hash, salt FROM `user` WHERE username = ? AND is_admin = true;', [username], (err, result) => {
        if(err || result.length !== 1){
            return res.redirect('/?error=no_user')
        }

        let user = result[0];

        if(sha256(password + user.salt) !== user.password_hash){
            return res.redirect('/?error=wrong_password')
        }

        req.session.user = {
            username: user.username,
            id: user.id
        };
        return res.redirect('/orders');
    });
})

// Authentication middleware
app.use((req, res, next) => {
    if (!req.session.user)
      return res.redirect('/');
  
    return next();
});

app.get('/orders', (req, res) => {   
    conn.query("SELECT `o`.`id` as id, `o`.`tip` as tip, `u`.`username` as username, SUM(`i`.`price` * `oi`.`quantity`) as total FROM `order` `o` INNER JOIN `order_item` `oi` ON `oi`.`order_id` = `o`.`id` INNER JOIN `item` `i` ON `i`.`id` = `oi`.`item_id` INNER JOIN `user` `u` ON `u`.`id` = `o`.`user_id` GROUP BY `o`.`id` LIMIT 10", [], (err, result) => {
        if(err){
            return res.send("ERRORE")
        }

        return res.render('orders.html', { orders:result });
    })
})

app.get('/order', (req, res) => {
    let order_id = req.query.order_id;

    if (order_id){
        order_id = parseInt(order_id);
        conn.query('SELECT `o`.`id` as id, `o`.`tip` as tip, `u`.`username` as username FROM `order` `o` INNER JOIN `user` `u` ON `u`.`id` = `user_id` WHERE `o`.`id` = ?;', [order_id], (err, result) => {
            if(err || result.length !== 1){
                return res.redirect('/orders');
            }
    
            let order = result[0];
    
            conn.query('SELECT `i`.`name_en` as `name`, `i`.`tag` as `tag`, `i`.`price` as `price`, `quantity` FROM `order_item` INNER JOIN `item` `i` ON `item_id` = `i`.`id` WHERE `order_id` = ?', [order_id], (err, result) => {
                if(err){
                    return res.redirect('/orders');
                }
    
                order.items = result;
                return res.render('order.html', { order , FLAG});
            });
        })
    }
    else{
        return res.send("NO VALUE KEK");
        return res.redirect('/orders');
    }
})

app.get('/tags', (req, res) => {
    let colors = {
        'kebab': 'red',
        'pizza': 'green',
        'other': 'blue'
    };

    try{
        colors = JSON.parse(atob(req.cookies.colors));
    }
    catch(e){}

    return res.render('tags.html', { colors })
})

app.post('/tags', (req, res) => {
    let new_colors = {
        'kebab': (req.body.kebab && typeof req.body.kebab === 'string') ? req.body.kebab : 'red',
        'pizza': (req.body.pizza && typeof req.body.pizza === 'string') ? req.body.pizza : 'green',
        'other': (req.body.other && typeof req.body.other === 'string') ? req.body.other : 'blue',
    };

    res.cookie('colors', btoa(JSON.stringify(new_colors)), {
        maxAge: 1000 * 60 * 60 * 24,
        httpOnly: true
    });
    return res.redirect('/orders')
})

app.get('/tags.css', (req, res) => {
    let colors = (req.cookies.colors) ? JSON.parse(atob(req.cookies.colors)) : {
        'kebab': 'red',
        'pizza': 'green',
        'other': 'blue'
    };

    return res
        .setHeader('Content-Type', 'text/css')
        .render('colors.css', {colors: colors})
})


app.listen(3000, () => {
    console.log('Server is running on port 3000')
})
