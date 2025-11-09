#!/usr/bin/env node

const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 8000;
const HOST = 'localhost';

// MIME 类型映射
const mimeTypes = {
    '.html': 'text/html',
    '.js': 'text/javascript',
    '.css': 'text/css',
    '.json': 'application/json',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.gif': 'image/gif',
    '.svg': 'image/svg+xml',
    '.wasm': 'application/wasm',
    '.woff': 'font/woff',
    '.woff2': 'font/woff2',
    '.ttf': 'font/ttf',
    '.eot': 'application/vnd.ms-fontobject',
    '.otf': 'font/otf',
};

const server = http.createServer((req, res) => {
    let filePath = req.url === '/' || req.url === '/examples/' 
        ? '/examples/index.html' 
        : req.url;
    filePath = filePath.split('?')[0];
    const fullPath = path.join(__dirname, '..', filePath);
    const extname = String(path.extname(fullPath)).toLowerCase();
    const contentType = mimeTypes[extname] || 'application/octet-stream';
    fs.readFile(fullPath, (error, content) => {
        if (error) {
            if (error.code === 'ENOENT') {
                res.writeHead(404, { 'Content-Type': 'text/html' });
                res.end(`
                    <html>
                    <head>
                        <title>404 Not Found</title>
                        <style>
                            body {
                                background: #0a0e27;
                                color: #00ff41;
                                font-family: 'Consolas', monospace;
                                display: flex;
                                justify-content: center;
                                align-items: center;
                                height: 100vh;
                                margin: 0;
                            }
                            .error {
                                text-align: center;
                            }
                            h1 {
                                font-size: 4em;
                                margin: 0;
                                text-shadow: 0 0 10px #00ff41;
                            }
                            p {
                                font-size: 1.2em;
                                color: #00d9ff;
                            }
                        </style>
                    </head>
                    <body>
                        <div class="error">
                            <h1>404</h1>
                            <p>File Not Found: ${filePath}</p>
                            <p><a href="/examples/" style="color: #00ff41;">← Back to Home</a></p>
                        </div>
                    </body>
                    </html>
                `, 'utf-8');
            } else {
                // 500 - 服务器错误
                res.writeHead(500);
                res.end(`Server Error: ${error.code}`);
            }
        } else {
            // 成功
            res.writeHead(200, { 
                'Content-Type': contentType,
                'Cache-Control': 'no-cache' // 禁用缓存，方便开发
            });
            res.end(content, 'utf-8');
        }
    });
});

server.listen(PORT, HOST, () => {
    console.log('\n╔════════════════════════════════════════════════════════════════╗');
    console.log('║          ⚡ REKRYPT DEBUG SERVER STARTED ⚡                  ║');
    console.log('╚════════════════════════════════════════════════════════════════╝\n');
    console.log(`🌐 Server running at: http://${HOST}:${PORT}/`);
});

process.on('SIGINT', () => {
    console.log('\n\n🛑 Server shutting down...');
    server.close(() => {
        console.log('✓ Server closed');
        process.exit(0);
    });
});

server.on('error', (err) => {
    if (err.code === 'EADDRINUSE') {
        console.error(`\n[ERROR] Port ${PORT} is already in use!`);
        process.exit(1);
    } else {
        console.error('[ERROR] Server error:', err);
        process.exit(1);
    }
});

