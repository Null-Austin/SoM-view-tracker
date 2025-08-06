// init
const port = process.env.trackerport || 3000

// packages
const express = require('express')
const fs = require('fs')
const path = require('node:path')
const _db = require('better-sqlite3')
const crypto = require('crypto')
const ejs = require('ejs')

// setting up db
let db = _db(path.join(__dirname,'db.db'))
db.prepare(`CREATE table IF NOT EXISTS users (uuid default 0,ips default "[]",unique_views default 0,views default 0)`).run()

function add(uuid, ip) {
    const hashedIp = crypto.createHash('sha256').update(ip).digest('hex')
    
    let user = db.prepare('SELECT * FROM users WHERE uuid = ?').get(uuid)
    
    if (!user) {
        const createUser = db.prepare('INSERT INTO users (uuid, ips, unique_views, views) VALUES (?, ?, ?, ?)')
        createUser.run(uuid, JSON.stringify([hashedIp]), 1, 1)
    } else {
        const existingIps = JSON.parse(user.ips)
        const isNewIp = !existingIps.includes(hashedIp)
        
        if (isNewIp) {
            existingIps.push(hashedIp)
            const updateUser = db.prepare('UPDATE users SET ips = ?, unique_views = unique_views + 1, views = views + 1 WHERE uuid = ?')
            updateUser.run(JSON.stringify(existingIps), uuid)
        } else {
            const updateViews = db.prepare('UPDATE users SET views = views + 1 WHERE uuid = ?')
            updateViews.run(uuid)
        }
    }
}
function get(uuid){
    const getUser = db.prepare('SELECT * FROM users WHERE uuid = ?').get(uuid)
    return getUser || { uuid: uuid, views: 0, unique_views: 0 }
}

// set up app
const app = express()

// endpoints
app.get('/',(req,res)=>{
    res.send('hi')
})

app.get('/docs',(req,res)=>{
    res.send('hii')
})

fs.readdirSync(path.join(__dirname,'svgs')).forEach(_svg=>{
    const svg = fs.readFileSync(path.join(__dirname,'svgs',_svg), 'utf8')
    app.get(`/svg/views/:uuid/${_svg}`,(req,res)=>{
        let uuid = req.params.uuid
        let ip = req.headers['x-forwarded-for']?.split(',').shift()?.trim() || req.ip || req.connection.remoteAddress || req.socket.remoteAddress
        add(uuid, ip)
        
        console.log(uuid)
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        res.setHeader('Surrogate-Control', 'no-store');
        res.type('svg').send(
            ejs.render(svg,get(uuid))
        )
    })
})
app.get('/svg/views/:x/:y',(req,res)=>{
    res.redirect('/')
})
// app.get('/svg/views/:uuid', (req, res) => {
//     let uuid = req.params.uuid
//     let ip = req.ip || req.connection.remoteAddress || req.socket.remoteAddress
    
//     // Track the view
//     add(uuid, ip)
    
//     console.log(uuid)
//     res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
//     res.setHeader('Pragma', 'no-cache');
//     res.setHeader('Expires', '0');
//     res.setHeader('Surrogate-Control', 'no-store');
//     res.type('svg').send(
//         ejs.render(svg,get(uuid))
//     )
// });

app.listen(port,err=>{
    if (err){
        return console.error(err)
    }
    return console.log("Server started! http://localhost:"+port)
})