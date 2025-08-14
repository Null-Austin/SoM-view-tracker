// init
const port = process.env.trackerport || 3000
let test;
if (process.argv.includes('-t')){
    test = true
    console.log('testing mode')
} else{
    test = false
}

// packages
const express = require('express')
const fs = require('fs')
const path = require('node:path')
const _db = require('better-sqlite3')
const crypto = require('crypto')
const ejs = require('ejs')
const geoip = require('geoip-lite')
require('dotenv').config()

// set up api
let api = process.env.openweatherapi
if (api == 'false'){
    api = false
}

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

// Configure Express to trust proxies - essential for accurate IP detection
app.set('trust proxy', true)

// Enhanced IP detection middleware - works with all proxy configurations
app.use((req, res, next) => {
    let detectedIp = null;
    let source = 'unknown';
    
    // Priority-ordered list of IP sources
    const ipSources = [
        // Cloudflare and CDN headers (highest priority)
        { header: 'cf-connecting-ip', name: 'Cloudflare' },
        { header: 'x-real-ip', name: 'Nginx/Real-IP' },
        { header: 'x-client-ip', name: 'Client-IP' },
        
        // Standard forwarded headers
        { header: 'x-forwarded-for', name: 'X-Forwarded-For', multi: true },
        { header: 'x-forwarded', name: 'X-Forwarded', multi: true },
        { header: 'forwarded-for', name: 'Forwarded-For', multi: true },
        { header: 'forwarded', name: 'RFC7239-Forwarded', multi: true },
        
        // Load balancer headers
        { header: 'x-cluster-client-ip', name: 'Cluster-Client-IP' },
        { header: 'x-original-forwarded-for', name: 'Original-Forwarded-For', multi: true },
        
        // Other proxy headers
        { header: 'x-remote-ip', name: 'Remote-IP' },
        { header: 'x-remote-addr', name: 'Remote-Addr' },
        { header: 'x-proxy-user-ip', name: 'Proxy-User-IP' }
    ];
    
    // Try each IP source in order of priority
    for (const ipSource of ipSources) {
        const headerValue = req.headers[ipSource.header];
        if (headerValue && typeof headerValue === 'string') {
            let ip = headerValue.trim();
            
            // Handle multi-IP headers (comma-separated)
            if (ipSource.multi) {
                // Split by comma and take the leftmost IP (original client)
                const ips = ip.split(',').map(i => i.trim()).filter(i => i);
                if (ips.length > 0) {
                    // Skip private/local IPs in forwarded chains if possible
                    ip = ips.find(i => !isPrivateIP(i)) || ips[0];
                }
            }
            
            if (ip && isValidIP(ip)) {
                detectedIp = ip;
                source = ipSource.name;
                break;
            }
        }
    }
    
    // Fallback to Express's req._ip (uses trust proxy setting)
    if (!detectedIp && req._ip) {
        detectedIp = req._ip;
        source = 'Express-req._ip';
    }
    
    // Final fallbacks for direct connections
    if (!detectedIp) {
        const fallbackIps = [
            req.connection?.remoteAddress,
            req.socket?.remoteAddress,
            req.info?.remoteAddress
        ].filter(Boolean);
        
        if (fallbackIps.length > 0) {
            detectedIp = fallbackIps[0];
            source = 'Direct-Connection';
        }
    }
    
    // Ultimate fallback
    if (!detectedIp) {
        detectedIp = '127.0.0.1';
        source = 'Fallback-Localhost';
        console.warn('No valid IP detected, using localhost fallback');
    }
    
    // Clean up IPv6-mapped IPv4 addresses
    if (detectedIp.startsWith('::ffff:')) {
        detectedIp = detectedIp.substring(7);
        source += '-IPv6Mapped';
    }
    
    // Validate and clean the final IP
    if (!isValidIP(detectedIp)) {
        console.warn(`Invalid IP format detected: ${detectedIp} from ${source}, using fallback`);
        detectedIp = '127.0.0.1';
        source = 'Invalid-Fallback';
    }
    
    // Set the IP and add metadata for debugging
    req._ip = detectedIp;
    req._ipSource = source;

    if (test){
        req._ip = "6.161.236.94"
    }
    
    next();
});

// Helper function to get lat/long from IP using local database
function getLatLongFromIP(ip) {
    try {
        const geo = geoip.lookup(ip);
        if (geo && geo.ll && geo.ll.length === 2) {
            return {
                latitude: geo.ll[0],
                longitude: geo.ll[1],
                city: geo.city || 'Unknown',
                country: geo.country || 'Unknown'
            };
        }
    } catch (error) {
        console.error('Error looking up IP geolocation:', error);
    }
    
    return {
        latitude: 39.8283,
        longitude: -98.5795,
        city: 'Unknown',
        country: 'Unknown'
    };
}

// Helper function to check if IP is private/local
function isPrivateIP(ip) {
    // IPv4 private ranges
    const privateRanges = [
        /^127\./,          // Loopback
        /^10\./,           // Private Class A
        /^172\.(1[6-9]|2[0-9]|3[01])\./,  // Private Class B
        /^192\.168\./,     // Private Class C
        /^169\.254\./,     // Link-local
        /^::1$/,           // IPv6 loopback
        /^fc00:/,          // IPv6 unique local
        /^fe80:/           // IPv6 link-local
    ];
    
    return privateRanges.some(range => range.test(ip));
}

// Helper function to validate IP format
function isValidIP(ip) {
    if (!ip || typeof ip !== 'string') return false;
    
    // IPv4 validation
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (ipv4Regex.test(ip)) {
        const parts = ip.split('.');
        return parts.every(part => {
            const num = parseInt(part, 10);
            return num >= 0 && num <= 255;
        });
    }
    
    // IPv6 validation (basic)
    const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;
    if (ipv6Regex.test(ip)) {
        return true;
    }
    
    // Compressed IPv6 validation
    if (ip.includes('::') && ip.split('::').length === 2) {
        return true;
    }
    
    return false;
}

// endpoints
app.get('/',(req,res)=>{
    ejs.renderFile(path.join(__dirname,'pages','index.html'),(err,str)=>{
        if (err){
            return res.status(500).send('Error rendering index page')
        }
        res.send(str)
    })
})

app.get('/docs',(req,res)=>{
    try {
        // Dynamically get all SVG files from the svgs directory
        const svgData = fs.readdirSync(path.join(__dirname,'svgs'))
            .filter(file => file.endsWith('.svg') && !(file === "wait-is-that-my-weather.svg" && !api))
            .map(svgFile => {
                const displayName = svgFile === 'wait-is-that-my-ip.svg' ? 'wait...? is that my...?' 
                    : svgFile.replace('.svg', '').replace(/-/g, ' ').replace(/\b\w/g, l => l.toUpperCase())
                const altText = svgFile === 'wait-is-that-my-ip.svg' ? 'hehe' : `${displayName} View Counter`
                
                return {
                    fileName: svgFile,
                    displayName: displayName,
                    altText: altText
                }
            })

        ejs.renderFile(path.join(__dirname,'pages','docs.html'), { svgData }, (err,str)=>{
            if (err){
                console.error('Error rendering docs page:', err)
                return res.status(500).send('Error rendering docs page')
            }
            res.send(str)
        })
    } catch (error) {
        console.error('Error loading SVG files:', error)
        return res.status(500).send('Error loading documentation')
    }
})

app.get('/api/svg-list',(req,res)=>{
    try {
        const svgFiles = fs.readdirSync(path.join(__dirname,'svgs'))
            .filter(file => file.endsWith('.svg'))
        res.json(svgFiles)
    } catch (error) {
        console.error('Error reading SVG directory:', error)
        res.status(500).json({error: 'Unable to read SVG files'})
    }
})
app.get('/svg/views/:x/wait-is-that-my-ip.svg',(req,res)=>{
    console.log(req._ip)
    const svg = fs.readFileSync(path.join(__dirname,'svgs','wait-is-that-my-ip.svg'), 'utf8')
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');
    res.setHeader('Surrogate-Control', 'no-store');
    res.type('svg').send(
        ejs.render(svg,{ip:req._ip})
    )
})
let weather_cache = {}
app.get('/svg/views/:x/wait-is-that-my-weather.svg',async (req,res)=>{
    if (!api){
        return;
    }
    console.log(req._ip)
    
    const cacheKey = req._ip;
    const now = Date.now();
    const cacheExpiry = 60 * 60 * 1000; 
    
    if (weather_cache[cacheKey] && 
        weather_cache[cacheKey].timestamp && 
        (now - weather_cache[cacheKey].timestamp) < cacheExpiry) {

        let weather = weather_cache[cacheKey].data
        weather = JSON.parse(weather).weather[0].description;
        weather = weather
        
        console.log(`Using cached weather data for IP: ${req._ip}`);
        const svg = fs.readFileSync(path.join(__dirname,'svgs','wait-is-that-my-weather.svg'), 'utf8')
        
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        res.setHeader('Surrogate-Control', 'no-store');
        res.type('svg').send(
            ejs.render(svg, {weather: weather})
        );
        return;
    }
    
    try {
        const geoData = getLatLongFromIP(req._ip);
        const latitude = geoData.latitude;
        const longitude = geoData.longitude;
        
        console.log(`IP: ${req._ip} -> Lat: ${latitude}, Lon: ${longitude}, City: ${geoData.city}`);
        
        let weather = await fetch(`https://api.openweathermap.org/data/2.5/weather?lat=${latitude}&lon=${longitude}&appid=${api}`)
        weather = await weather.text()
        weather = String(weather)
        
        weather_cache[cacheKey] = {
            data: weather,
            timestamp: now
        };
        
        console.log(`Cached weather data for IP: ${req._ip}`);
        
        const svg = fs.readFileSync(path.join(__dirname,'svgs','wait-is-that-my-weather.svg'), 'utf8')
        console.log(weather)
        
        weather = JSON.parse(weather).weather[0].description;
        weather = weather

        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        res.setHeader('Surrogate-Control', 'no-store');
        res.type('svg').send(
            ejs.render(svg,{weather:weather})
        )
    } catch (error) {
        console.error('Error fetching weather data:', error);
        res.status(500).send('Error fetching weather data');
    }
})
fs.readdirSync(path.join(__dirname,'svgs')).forEach(_svg=>{
    app.get(`/svg/views/all/${_svg}`,(req,res)=>{
        const svg = fs.readFileSync(path.join(__dirname,'svgs',_svg), 'utf8')
        
        console.log('all')
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
        res.setHeader('Pragma', 'no-cache');
        res.setHeader('Expires', '0');
        res.setHeader('Surrogate-Control', 'no-store');
        let data = { uuid: 'all', views: 0, unique_views: 0 }
        let _views = db.prepare('SELECT * FROM users').all()
        let views = 0
        _views.forEach(x=>{
            views+=x.views
        })
        data.views = views
        data.unique_views = views
        res.type('svg').send(
            ejs.render(svg,data)
        )
    })
})

fs.readdirSync(path.join(__dirname,'svgs')).forEach(_svg=>{
    app.get(`/svg/views/:uuid/${_svg}`,(req,res)=>{
        const svg = fs.readFileSync(path.join(__dirname,'svgs',_svg), 'utf8')
        let uuid = req.params.uuid
        add(uuid, req._ip)
        
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
//     let ip = req._ip || req.connection.remoteAddress || req.socket.remoteAddress
    
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