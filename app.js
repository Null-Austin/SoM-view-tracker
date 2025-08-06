// init
const port = process.env.trackerport || 3000

// packages
const express = require('express')
const path = require('node:path')
const _db = require('better-sqlite3')

// setting up db
let db = _db(path.join(__dirname,'db.db'))
db.prepare(`CREATE table IF NOT EXISTS users (uuid,ips,unique_views,views)`).run()

// set up app
const app = express()

// endpoints
app.get('/css/views/',(req,res)=>{
    res.sendFile(path.join(__dirname,'stylesheet.css'))
})

app.listen(port,err=>{
    if (err){
        return console.error(err)
    }
    return console.log("Server started! http://localhost:"+port)
})