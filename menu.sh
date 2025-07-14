#!/bin/bash

# =================================================================
#      图片画廊 企业级重构版 - 一体化部署与管理脚本 (v8.1)
#
#   作者: 编码助手
#   功能: 修复菜单显示与逻辑错误，优化用户体验和脚本健壮性。
# =================================================================

# --- 配置 ---
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

APP_NAME="image-gallery-pro"
INSTALL_DIR=$(pwd)/image-gallery-pro-app
DB_FILE="gallery.db"
BACKUP_DIR=$(pwd)/gallery-backups

# --- 核心功能：文件生成 (此部分与 v8.0 相同，保持不变) ---
generate_files() {
    echo -e "${YELLOW}--> 正在创建项目目录结构: ${INSTALL_DIR}${NC}"
    mkdir -p "${INSTALL_DIR}/public/uploads" "${INSTALL_DIR}/data" "${INSTALL_DIR}/routes/api" "${INSTALL_DIR}/middleware"
    cd "${INSTALL_DIR}" || exit

    echo "--> 正在生成 package.json (包含新依赖)..."
cat << 'EOF' > package.json
{
  "name": "image-gallery-pro-v8",
  "version": "8.1.0",
  "description": "A robust, scalable, and secure full-stack image gallery application.",
  "main": "server.js",
  "scripts": {
    "start": "node server.js",
    "setup": "node setup.js"
  },
  "dependencies": {
    "bcrypt": "^5.1.0",
    "better-sqlite3": "^9.4.0",
    "cookie-parser": "^1.4.6",
    "dotenv": "^16.3.1",
    "express": "^4.18.2",
    "express-validator": "^7.0.1",
    "jsonwebtoken": "^9.0.2",
    "multer": "^1.4.5-lts.1",
    "sharp": "^0.33.0"
  }
}
EOF

    echo "--> 正在生成数据库管理模块 data/database.js..."
cat << 'EOF' > data/database.js
const Database = require('better-sqlite3');
const path = require('path');

const dbPath = path.join(__dirname, 'gallery.db');
const db = new Database(dbPath);

function initDB() {
    db.exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL);`);
    db.exec(`CREATE TABLE IF NOT EXISTS categories (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL);`);
    db.exec(`CREATE TABLE IF NOT EXISTS images (id TEXT PRIMARY KEY, category_id INTEGER, description TEXT, filename_orig TEXT NOT NULL, path_orig TEXT NOT NULL, path_display TEXT NOT NULL, path_thumb TEXT NOT NULL, size_orig INTEGER, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (category_id) REFERENCES categories (id));`);
    
    const uncategorized = db.prepare('SELECT id FROM categories WHERE name = ?').get('未分类');
    if (!uncategorized) {
        db.prepare('INSERT INTO categories (name) VALUES (?)').run('未分类');
    }
}

module.exports = { db, initDB };
EOF

    echo "--> 正在生成安装设置脚本 setup.js (用于密码哈希)..."
cat << 'EOF' > setup.js
const { db, initDB } = require('./data/database.js');
const bcrypt = require('bcrypt');
require('dotenv').config();

async function setup() {
    try {
        console.log('Initializing database schema...');
        initDB();

        const username = process.env.ADMIN_USERNAME;
        const password = process.env.ADMIN_PASSWORD;

        if (!username || !password) {
            console.error('Error: ADMIN_USERNAME and ADMIN_PASSWORD must be temporarily set in .env for setup script to run.');
            process.exit(1);
        }

        const existingUser = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
        const saltRounds = 10;
        const hash = await bcrypt.hash(password, saltRounds);

        if (existingUser) {
            console.log(`User "${username}" already exists. Updating password.`);
            db.prepare('UPDATE users SET password_hash = ? WHERE username = ?').run(hash, username);
            console.log(`Password for user "${username}" has been updated.`);
        } else {
            console.log(`Creating new admin user: ${username}`);
            db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)')
              .run(username, hash);
            console.log(`Admin user "${username}" created successfully.`);
        }
    } catch (error) {
        console.error('An error occurred during setup:', error);
        process.exit(1);
    }
}

setup();
EOF

    echo "--> 正在生成后端服务器 server.js (企业级重构)..."
cat << 'EOF' > server.js
require('dotenv').config();
const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const { initDB } = require('./data/database.js');

initDB();

const authRoutes = require('./routes/auth');
const apiRoutes = require('./routes/api');
const { authMiddleware } = require('./middleware/authMiddleware');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(express.static(path.join(__dirname, 'public')));
app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));

app.use('/api/auth', authRoutes);
app.use('/api', apiRoutes);

app.get('/admin.html', authMiddleware, (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/admin', authMiddleware, (req, res) => res.redirect('/admin.html'));

app.use((req, res) => res.status(404).send("Sorry, can't find that!"));
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ message: 'Something broke!', error: err.message });
});

app.listen(PORT, () => console.log(`Server is running on http://localhost:${PORT}`));
EOF

    echo "--> 正在生成认证中间件 middleware/authMiddleware.js..."
cat << 'EOF' > middleware/authMiddleware.js
const jwt = require('jsonwebtoken');

const authMiddleware = (req, res, next) => {
    const token = req.cookies.token;
    if (!token) {
        return req.accepts('html') ? res.redirect('/login.html') : res.status(401).json({ message: 'Access denied. No token provided.' });
    }
    try {
        req.user = jwt.verify(token, process.env.JWT_SECRET);
        next();
    } catch (ex) {
        return req.accepts('html') ? res.redirect('/login.html') : res.status(400).json({ message: 'Invalid token.' });
    }
};

module.exports = { authMiddleware };
EOF
    echo "--> 正在生成路由模块 routes/auth.js..."
cat << 'EOF' > routes/auth.js
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const { db } = require('../data/database.js');
const router = express.Router();

router.post('/login', [
    body('username').trim().notEmpty(),
    body('password').notEmpty()
], async (req, res) => {
    if (!validationResult(req).isEmpty()) return res.redirect('/login.html?error=Username or password cannot be empty');
    
    const { username, password } = req.body;
    try {
        const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
        if (!user || !await bcrypt.compare(password, user.password_hash)) {
            return res.redirect('/login.html?error=Invalid credentials');
        }
        
        const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: 24 * 60 * 60 * 1000 });
        res.redirect('/admin.html');
    } catch (error) {
        console.error("Login error:", error);
        res.redirect('/login.html?error=Server error');
    }
});

router.get('/logout', (req, res) => {
    res.clearCookie('token');
    res.redirect('/login.html');
});

module.exports = router;
EOF

    echo "--> 正在生成核心API路由模块 routes/api.js..."
cat << 'EOF' > routes/api.js
const express = require('express');
const { authMiddleware } = require('../middleware/authMiddleware');
const categoryRoutes = require('./api/categories');
const imageRoutes = require('./api/images');
const router = express.Router();

// Public routes
router.get('/categories/public', categoryRoutes.getPublicCategories);
router.get('/images/public', imageRoutes.getPublicImages);

// Protected admin routes
router.use('/admin', authMiddleware);
router.get('/admin/categories', categoryRoutes.getAllCategories);
router.post('/admin/categories', categoryRoutes.createCategory);
router.put('/admin/categories/:id', categoryRoutes.updateCategory);
router.delete('/admin/categories/:id', categoryRoutes.deleteCategory);
router.get('/admin/images', imageRoutes.getAdminImages);
router.post('/admin/images/upload', imageRoutes.uploadImage);
router.put('/admin/images/:id', imageRoutes.updateImage);
router.delete('/admin/images/:id', imageRoutes.deleteImage);

module.exports = router;
EOF

    echo "--> 正在生成API子模块 routes/api/categories.js..."
cat << 'EOF' > routes/api/categories.js
const { db } = require('../../data/database.js');
const { body, validationResult } = require('express-validator');

exports.getPublicCategories = (req, res) => {
    try {
        const query = `SELECT c.id, c.name FROM categories c WHERE EXISTS (SELECT 1 FROM images i WHERE i.category_id = c.id) OR c.name = '未分类' ORDER BY CASE WHEN c.name = '未分类' THEN 0 ELSE 1 END, c.name COLLATE NOCASE`;
        res.json(db.prepare(query).all());
    } catch (e) { res.status(500).json({ message: 'Error fetching categories' }); }
};
exports.getAllCategories = (req, res) => {
    try {
        res.json(db.prepare(`SELECT * FROM categories ORDER BY CASE WHEN name = '未分类' THEN 0 ELSE 1 END, name COLLATE NOCASE`).all());
    } catch (e) { res.status(500).json({ message: 'Error fetching categories' }); }
};
exports.createCategory = [
    body('name').trim().notEmpty().isLength({ min: 1, max: 50 }),
    (req, res) => {
        if (!validationResult(req).isEmpty()) return res.status(400).json({ message: 'Invalid category name' });
        try {
            const info = db.prepare('INSERT INTO categories (name) VALUES (?)').run(req.body.name);
            res.status(201).json({ id: info.lastInsertRowid, name: req.body.name });
        } catch (e) { res.status(e.code === 'SQLITE_CONSTRAINT_UNIQUE' ? 409 : 500).json({ message: 'Category exists or server error' }); }
    }
];
exports.updateCategory = [
    body('name').trim().notEmpty().isLength({ min: 1, max: 50 }),
    (req, res) => {
        if (!validationResult(req).isEmpty()) return res.status(400).json({ message: 'Invalid category name' });
        const cat = db.prepare('SELECT name FROM categories WHERE id = ?').get(req.params.id);
        if (!cat) return res.status(404).json({ message: 'Category not found' });
        if (cat.name === '未分类') return res.status(403).json({ message: 'Cannot rename "未分类"' });
        try {
            db.prepare('UPDATE categories SET name = ? WHERE id = ?').run(req.body.name, req.params.id);
            res.json({ id: Number(req.params.id), name: req.body.name });
        } catch (e) { res.status(e.code === 'SQLITE_CONSTRAINT_UNIQUE' ? 409 : 500).json({ message: 'Category name exists or server error' }); }
    }
];
exports.deleteCategory = (req, res) => {
    const cat = db.prepare('SELECT name FROM categories WHERE id = ?').get(req.params.id);
    if (!cat) return res.status(404).json({ message: 'Category not found' });
    if (cat.name === '未分类') return res.status(403).json({ message: 'Cannot delete "未分类"' });
    try {
        const uncategorized = db.prepare(`SELECT id FROM categories WHERE name = '未分类'`).get();
        if (!uncategorized) throw new Error('Default category missing');
        db.transaction(() => {
            db.prepare('UPDATE images SET category_id = ? WHERE category_id = ?').run(uncategorized.id, req.params.id);
            db.prepare('DELETE FROM categories WHERE id = ?').run(req.params.id);
        })();
        res.status(200).json({ message: 'Category deleted' });
    } catch (e) { res.status(500).json({ message: 'Error deleting category' }); }
};
EOF

    echo "--> 正在生成API子模块 routes/api/images.js..."
cat << 'EOF' > routes/api/images.js
const { db } = require('../../data/database.js');
const { body, validationResult } = require('express-validator');
const multer = require('multer');
const sharp = require('sharp');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');

const UPLOADS_DIR = path.join(__dirname, '..', '..', 'public', 'uploads');
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 }, fileFilter: (req, file, cb) => /jpeg|jpg|png|gif/.test(file.mimetype) ? cb(null, true) : cb(new Error('Only image files are allowed!')) }).single('image');

const getBaseQuery = () => `SELECT i.id, i.description, i.created_at, i.path_orig, i.path_display, i.path_thumb, i.filename_orig, i.size_orig, c.name as category_name, c.id as category_id FROM images i JOIN categories c ON i.category_id = c.id`;

const processAndSaveImage = async (buffer, originalname) => {
    const uniqueSuffix = uuidv4();
    const extension = path.extname(originalname);
    const nameWithoutExt = path.parse(originalname).name.replace(/[^a-zA-Z0-9]/g, '_');

    const originalFilename = `${uniqueSuffix}${extension}`;
    const webpFilename = `${uniqueSuffix}.webp`;
    const thumbFilename = `thumb-${uniqueSuffix}.webp`;

    const originalPath = path.join(UPLOADS_DIR, originalFilename);
    const displayPath = path.join(UPLOADS_DIR, webpFilename);
    const thumbPath = path.join(UPLOADS_DIR, thumbFilename);

    await fs.promises.writeFile(originalPath, buffer);
    const imageProcessor = sharp(buffer);
    await imageProcessor.clone().resize({ width: 1920, height: 1080, fit: 'inside', withoutEnlargement: true }).webp({ quality: 80 }).toFile(displayPath);
    await imageProcessor.clone().resize({ width: 400, height: 400, fit: 'inside' }).webp({ quality: 75 }).toFile(thumbPath);

    return {
        path_orig: `/uploads/${originalFilename}`,
        path_display: `/uploads/${webpFilename}`,
        path_thumb: `/uploads/${thumbFilename}`
    };
};

exports.getPublicImages = (req, res) => {
    const { category, search, page = 1, limit = 15 } = req.query;
    let where = [], params = [], orderBy = 'ORDER BY i.created_at DESC';
    if (category && category !== 'all' && category !== 'random') { where.push("c.name = ?"); params.push(category); }
    if (search) { where.push("(i.description LIKE ? OR i.filename_orig LIKE ?)"); params.push(`%${search}%`, `%${search}%`); }
    if (category === 'random') orderBy = 'ORDER BY RANDOM()';

    const whereClause = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';
    try {
        const total = db.prepare(`SELECT COUNT(*) as total FROM images i JOIN categories c ON i.category_id = c.id ${whereClause}`).get(params).total;
        const images = db.prepare(`${getBaseQuery()} ${whereClause} ${orderBy} LIMIT ? OFFSET ?`).all(...params, limit, (page - 1) * limit);
        res.json({ images, totalPages: Math.ceil(total / limit), currentPage: Number(page) });
    } catch (e) { res.status(500).json({ message: 'Error fetching images' }); }
};

exports.getAdminImages = (req, res) => {
    const { category, search, page = 1, limit = 10 } = req.query;
    let where = [], params = [], orderBy = 'ORDER BY i.created_at DESC';
    if (category && category !== 'all') { where.push("c.id = ?"); params.push(category); }
    if (search) { where.push("(i.description LIKE ? OR i.filename_orig LIKE ?)"); params.push(`%${search}%`, `%${search}%`); }
    
    const whereClause = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';
    try {
        const total = db.prepare(`SELECT COUNT(*) as total FROM images i JOIN categories c ON i.category_id = c.id ${whereClause}`).get(params).total;
        const images = db.prepare(`${getBaseQuery()} ${whereClause} ${orderBy} LIMIT ? OFFSET ?`).all(...params, limit, (page - 1) * limit);
        res.json({ images, totalPages: Math.ceil(total / limit), currentPage: Number(page) });
    } catch (e) { res.status(500).json({ message: 'Error fetching images' }); }
};

exports.uploadImage = (req, res) => {
    upload(req, res, async (err) => {
        if (err) return res.status(400).json({ message: err.message });
        if (!req.file) return res.status(400).json({ message: 'No file uploaded.' });
        if (!req.body.category_id) return res.status(400).json({ message: 'Category is required.' });
        try {
            const paths = await processAndSaveImage(req.file.buffer, req.file.originalname);
            db.prepare(`INSERT INTO images (id, category_id, description, filename_orig, size_orig, path_orig, path_display, path_thumb) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(uuidv4(), req.body.category_id, req.body.description || null, req.file.originalname, req.file.size, paths.path_orig, paths.path_display, paths.path_thumb);
            res.status(201).json({ message: 'Upload successful' });
        } catch (e) { res.status(500).json({ message: 'Error processing image.' }); }
    });
};

exports.updateImage = [
    body('category_id').isInt({ min: 1 }), body('description').optional().isString().trim(),
    (req, res) => {
        if (!validationResult(req).isEmpty()) return res.status(400).json({ message: 'Invalid data' });
        const result = db.prepare('UPDATE images SET category_id = ?, description = ? WHERE id = ?').run(req.body.category_id, req.body.description, req.params.id);
        if (result.changes === 0) return res.status(404).json({ message: 'Image not found' });
        res.status(200).json({ message: 'Image updated' });
    }
];

exports.deleteImage = (req, res) => {
    const image = db.prepare('SELECT path_orig, path_display, path_thumb FROM images WHERE id = ?').get(req.params.id);
    if (!image) return res.status(404).json({ message: 'Image not found' });
    const result = db.prepare('DELETE FROM images WHERE id = ?').run(req.params.id);
    if (result.changes > 0) {
        Object.values(image).forEach(p => p && fs.unlink(path.join(UPLOADS_DIR, path.basename(p)), err => err && console.error(`Failed to delete file: ${p}`, err)));
    }
    res.status(200).json({ message: 'Image deleted' });
};
EOF

    # Frontend files are large and less prone to change, so they are condensed here for brevity.
    # The actual content is identical to the v8.0 response.
    echo "--> 正在生成主画廊 public/index.html (重构优化)..."
    # Same public/index.html content as v8.0 response
cat << 'EOF' > public/index.html
<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>图片画廊</title><meta name="description" content="一个展示精彩瞬间的瀑布流图片画廊。"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;700&family=Noto+Sans+SC:wght@400;500;700&display=swap" rel="stylesheet"><script src="https://cdn.tailwindcss.com"></script><style>body{font-family:'Inter','Noto Sans SC',sans-serif;background-color:#f0fdf4;color:#14532d;display:flex;flex-direction:column;min-height:100vh}body.lightbox-open{overflow:hidden}.filter-btn{padding:0.5rem 1rem;border-radius:9999px;font-weight:500;transition:all .2s ease;border:1px solid transparent;cursor:pointer}.filter-btn:hover{background-color:#dcfce7}.filter-btn.active{background-color:#22c55e;color:#fff;border-color:#16a34a}.grid-gallery{column-count:1;column-gap:1rem;width:100%}@media (min-width: 640px){.grid-gallery{column-count:2}}@media (min-width: 768px){.grid-gallery{column-count:3}}@media (min-width: 1024px){.grid-gallery{column-count:4}}@media (min-width: 1280px){.grid-gallery{column-count:5}}.grid-item{margin-bottom:1rem;break-inside:avoid;position:relative;border-radius:.5rem;overflow:hidden;background-color:#e4e4e7;box-shadow:0 4px 6px -1px #0000001a,0 2px 4px -2px #0000001a;opacity:0;transform:translateY(20px);transition:opacity .5s ease-out,transform .5s ease-out,box-shadow .3s ease}.grid-item.is-visible{opacity:1;transform:translateY(0)}.grid-item img{cursor:pointer;width:100%;height:auto;display:block;transition:transform .4s ease}.grid-item:hover img{transform:scale(1.05)}.lightbox{position:fixed;top:0;left:0;width:100%;height:100%;background-color:#000000e6;display:flex;justify-content:center;align-items:center;z-index:1000;opacity:0;visibility:hidden;transition:opacity .3s ease}.lightbox.active{opacity:1;visibility:visible}.lightbox-image{max-width:85vw;max-height:85vh;display:block;-o-object-fit:contain;object-fit:contain}.lightbox-btn{position:absolute;top:50%;transform:translateY(-50%);background-color:#ffffff1a;color:#fff;border:none;font-size:2.5rem;cursor:pointer;padding:.5rem 1rem;border-radius:.5rem;transition:background-color .2s}.lightbox-btn:hover{background-color:#ffffff33}.lb-prev{left:1rem}.lb-next{right:1rem}.lb-close{top:1rem;right:1rem;font-size:2rem}.lb-counter{position:absolute;top:1.5rem;left:50%;transform:translateX(-50%);color:#fff;font-size:1rem;background-color:#0000004d;padding:.25rem .75rem;border-radius:9999px}.back-to-top{position:fixed;bottom:2rem;right:2rem;background-color:#22c55e;color:#fff;width:3rem;height:3rem;border-radius:9999px;display:flex;align-items:center;justify-content:center;box-shadow:0 4px 8px #00000033;cursor:pointer;opacity:0;visibility:hidden;transform:translateY(20px);transition:all .3s ease}.back-to-top.visible{opacity:1;visibility:visible;transform:translateY(0)}.lb-download{position:absolute;bottom:1rem;right:1rem;background-color:#22c55e;color:#fff;border:none;padding:.5rem 1rem;border-radius:.5rem;cursor:pointer;transition:background-color .2s;font-size:1rem}.lb-download:hover{background-color:#16a34a}.header-sticky{padding-top:1rem;padding-bottom:1rem;background-color:#f0fdf400;position:sticky;top:0;z-index:40;transition:padding .3s ease-in-out,background-color .3s ease-in-out;backdrop-filter:blur(0)}.header-sticky.state-scrolled-partially{padding-top:.75rem;padding-bottom:.75rem;background-color:#f0fdf4cc;backdrop-filter:blur(8px);box-shadow:0 4px 6px -1px #0000001a,0 2px 4px -2px #0000001a}.loader{text-align:center;padding:2rem;color:#166534;display:none}</style></head><body class="antialiased"><header class="text-center header-sticky"><div class="container mx-auto px-4"><h1 class="text-4xl md:text-5xl font-bold text-green-900 mb-4">图片画廊</h1><div class="max-w-3xl mx-auto mb-4"><div class="relative"><input type="search" id="search-input" placeholder="搜索图片描述或文件名..." class="w-full pl-10 pr-4 py-2 border border-green-300 rounded-full focus:ring-2 focus:ring-green-500 focus:outline-none"><div class="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none"><svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg></div></div></div><div id="filter-buttons" class="flex justify-center flex-wrap gap-2"><button class="filter-btn active" data-filter="all">全部</button><button class="filter-btn" data-filter="random">随机</button></div></div></header><main class="container mx-auto px-4 sm:px-6 py-8 md:py-10 flex-grow"><div id="gallery-container" class="grid-gallery"></div><div id="loader" class="loader"></div></main><footer class="text-center py-8 mt-auto border-t border-green-200"><p class="text-green-700">© 2025 图片画廊</p></footer><div class="lightbox"><span class="lb-counter"></span><button class="lightbox-btn lb-close">&times;</button><button class="lightbox-btn lb-prev">&lsaquo;</button><img class="lightbox-image" alt=""><button class="lightbox-btn lb-next">&rsaquo;</button><a class="lb-download" download>下载原图</a></div><a class="back-to-top" title="返回顶部"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 19V5M5 12l7-7 7 7"/></svg></a><script>
document.addEventListener('DOMContentLoaded', () => {
    const galleryContainer = document.getElementById('gallery-container');
    const loader = document.getElementById('loader');
    const searchInput = document.getElementById('search-input');
    
    let state = { currentPage: 1, totalPages: 1, currentFilter: 'all', currentSearch: '', isLoading: false, galleryItems: [], currentLightboxIndex: 0 };

    const apiFetch = async (url) => {
        try {
            const response = await fetch(url);
            if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
            return await response.json();
        } catch (error) { loader.textContent = '加载失败，请刷新。'; return null; }
    };

    const createFilterButtons = async () => {
        const data = await apiFetch('/api/categories/public');
        if (!data) return;
        const container = document.getElementById('filter-buttons');
        container.querySelectorAll('.dynamic-filter').forEach(btn => btn.remove());
        data.forEach(category => {
            const button = document.createElement('button');
            button.className = 'filter-btn dynamic-filter'; button.dataset.filter = category.name; button.textContent = category.name; container.appendChild(button);
        });
        addFilterButtonListeners();
    };

    const addFilterButtonListeners = () => {
        document.querySelectorAll('.filter-btn').forEach(button => {
            button.addEventListener('click', () => {
                if (state.isLoading) return;
                state.currentFilter = button.dataset.filter;
                document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
                button.classList.add('active'); resetAndLoadImages();
            });
        });
    };
    
    const debounce = (func, delay) => { let timeout; return (...args) => { clearTimeout(timeout); timeout = setTimeout(() => func.apply(this, args), delay); }; };

    searchInput.addEventListener('input', debounce(() => { state.currentSearch = searchInput.value.trim(); resetAndLoadImages(); }, 500));

    const resetAndLoadImages = () => { galleryContainer.innerHTML = ''; state.currentPage = 1; state.totalPages = 1; state.galleryItems = []; window.scrollTo(0, 0); loadImages(); };

    const loadImages = async () => {
        if (state.isLoading || state.currentPage > state.totalPages) return;
        state.isLoading = true; loader.style.display = 'block'; loader.textContent = '正在加载...';
        const params = new URLSearchParams({ category: state.currentFilter, search: state.currentSearch, page: state.currentPage, limit: 15 });
        const data = await apiFetch(`/api/images/public?${params.toString()}`);
        state.isLoading = false;
        if (!data) { loader.style.display = 'none'; return; }
        if (data.images.length === 0 && state.currentPage === 1) { loader.textContent = '没有找到图片。'; } else { loader.style.display = 'none'; }
        state.totalPages = data.totalPages; appendImages(data.images); state.currentPage++;
    };

    const appendImages = (images) => {
        const fragment = document.createDocumentFragment();
        images.forEach(data => {
            const item = document.createElement('div');
            item.className = 'grid-item'; item.dataset.index = state.galleryItems.length;
            const img = document.createElement('img');
            img.src = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7"; img.dataset.src = data.path_thumb; img.alt = data.description;
            img.onload = () => { item.style.backgroundColor = 'transparent'; item.classList.add('is-visible'); };
            item.appendChild(img); fragment.appendChild(item); state.galleryItems.push(data); imageObserver.observe(item);
        });
        galleryContainer.appendChild(fragment);
    };

    const imageObserver = new IntersectionObserver((entries, observer) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                const item = entry.target; const img = item.querySelector('img'); img.src = img.dataset.src; observer.unobserve(item);
            }
        });
    }, { rootMargin: '0px 0px 300px 0px' });

    // Lightbox Logic
    const lightbox = document.querySelector('.lightbox'); const lightboxImage = lightbox.querySelector('.lightbox-image'); const lbCounter = lightbox.querySelector('.lb-counter'); const lbPrev = lightbox.querySelector('.lb-prev'); const lbNext = lightbox.querySelector('.lb-next'); const lbClose = lightbox.querySelector('.lb-close'); const lbDownload = lightbox.querySelector('.lb-download');
    galleryContainer.addEventListener('click', (e) => { const item = e.target.closest('.grid-item'); if (item) { state.currentLightboxIndex = parseInt(item.dataset.index); updateLightbox(); lightbox.classList.add('active'); document.body.classList.add('lightbox-open'); } });
    const updateLightbox = () => {
        if (state.galleryItems.length === 0) return;
        const currentItem = state.galleryItems[state.currentLightboxIndex];
        lightboxImage.src = currentItem.path_display; lightboxImage.alt = currentItem.description; lbDownload.href = currentItem.path_orig; lbCounter.textContent = `${state.currentLightboxIndex + 1} / ${state.galleryItems.length}`;
    };
    const showPrevImage = () => { state.currentLightboxIndex = (state.currentLightboxIndex - 1 + state.galleryItems.length) % state.galleryItems.length; updateLightbox(); };
    const showNextImage = () => { state.currentLightboxIndex = (state.currentLightboxIndex + 1) % state.galleryItems.length; updateLightbox(); };
    const closeLightbox = () => { lightbox.classList.remove('active'); document.body.classList.remove('lightbox-open'); };
    lbPrev.addEventListener('click', showPrevImage); lbNext.addEventListener('click', showNextImage); lbClose.addEventListener('click', closeLightbox);
    lightbox.addEventListener('click', (e) => e.target === lightbox && closeLightbox());
    document.addEventListener('keydown', (e) => { if (!lightbox.classList.contains('active')) return; if (e.key === 'ArrowLeft') showPrevImage(); if (e.key === 'ArrowRight') showNextImage(); if (e.key === 'Escape') closeLightbox(); });

    // Scroll handling
    const backToTopBtn = document.querySelector('.back-to-top'); const header = document.querySelector('.header-sticky');
    window.addEventListener('scroll', () => {
        if (window.innerHeight + window.scrollY >= document.body.offsetHeight - 500 && !state.isLoading) { loadImages(); }
        const isScrolled = window.scrollY > 50;
        backToTopBtn.classList.toggle('visible', window.scrollY > 300);
        header.classList.toggle('state-scrolled-partially', isScrolled);
    }, { passive: true });
    backToTopBtn.addEventListener('click', () => window.scrollTo({ top: 0, behavior: 'smooth' }));

    (async () => { await createFilterButtons(); await loadImages(); })();
});
</script></body></html>
EOF

    echo "--> 正在生成后台登录页 public/login.html..."
    # Same public/login.html content as v8.0 response
cat << 'EOF' > public/login.html
<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>后台登录 - 图片画廊</title><script src="https://cdn.tailwindcss.com"></script><style> body { background-color: #f0fdf4; } </style></head><body class="antialiased text-green-900"><div class="min-h-screen flex items-center justify-center p-4"><div class="max-w-md w-full bg-white p-8 rounded-lg shadow-lg"><h1 class="text-3xl font-bold text-center text-green-900 mb-6">后台管理登录</h1><div id="error-message" class="hidden bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4" role="alert"><strong class="font-bold">登录失败！</strong><span id="error-text" class="block sm:inline"></span></div><form action="/api/auth/login" method="POST"><div class="mb-4"><label for="username" class="block text-green-800 text-sm font-bold mb-2">用户名</label><input type="text" id="username" name="username" required class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:ring-2 focus:ring-green-500"></div><div class="mb-6"><label for="password" class="block text-green-800 text-sm font-bold mb-2">密码</label><input type="password" id="password" name="password" required class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 mb-3 leading-tight focus:outline-none focus:ring-2 focus:ring-green-500"></div><div class="flex items-center justify-between"><button type="submit" class="w-full bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded-lg focus:outline-none focus:shadow-outline transition-colors"> 登 录 </button></div></form></div></div><script> const urlParams = new URLSearchParams(window.location.search); const error = urlParams.get('error'); if (error) { document.getElementById('error-text').textContent = decodeURIComponent(error); document.getElementById('error-message').classList.remove('hidden'); } </script></body></html>
EOF

    echo "--> 正在生成后台管理页 public/admin.html (全新响应式UI)..."
    # Same public/admin.html content as v8.0 response
cat << 'EOF' > public/admin.html
<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>后台管理 - 图片画廊</title><script src="https://cdn.tailwindcss.com"></script><style>body{background-color:#f0fdf4}dialog::backdrop{background-color:rgba(0,0,0,0.5)}.category-item.active{background-color:#dcfce7;font-weight:bold}</style></head><body class="antialiased text-green-900"><header class="bg-white shadow-md p-4 flex justify-between items-center sticky top-0 z-20"><h1 class="text-xl sm:text-2xl font-bold text-green-900">内容管理</h1><div><a href="/" target="_blank" class="text-green-600 hover:text-green-800 mr-2 sm:mr-4">查看前台</a><a href="/api/auth/logout" class="bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-3 sm:px-4 rounded transition-colors text-sm sm:text-base">退出</a></div></header><main class="p-4 sm:p-6 lg:p-8"><div class="grid grid-cols-1 lg:grid-cols-12 gap-8"><div class="lg:col-span-4 xl:col-span-3 space-y-8"><section class="bg-white p-6 rounded-lg shadow-md"><h2 class="text-xl font-semibold mb-4">上传新图片</h2><form id="upload-form" class="space-y-4"><label for="image-input" class="w-full flex flex-col items-center justify-center p-4 border-2 border-dashed border-gray-300 rounded-lg cursor-pointer hover:bg-gray-50"><svg class="w-8 h-8 mb-2 text-gray-500" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 20 16"><path stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 13h3a3 3 0 0 0 0-6h-.025A5.56 5.56 0 0 0 16 6.5 5.5 5.5 0 0 0 5.207 5.021C5.137 5.017 5.071 5 5 5a4 4 0 0 0 0 8h2.167M10 15V6m0 0L8 8m2-2 2 2"/></svg><p class="text-sm text-gray-500"><span class="font-semibold">点击选择文件</span></p><input id="image-input" name="image" type="file" class="hidden" required accept="image/png, image/jpeg, image/gif"/></label><div id="file-info-wrapper" class="mt-2 text-xs text-gray-500 hidden"><p id="file-name-info"></p><p id="file-size-info"></p></div><div><label for="category-select" class="block text-sm font-medium mb-1">图片分类</label><select name="category_id" id="category-select" required class="w-full border rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-green-500"></select></div><div><label for="description" class="block text-sm font-medium mb-1">图片描述</label><input type="text" name="description" id="description" placeholder="对图片的简短描述" class="w-full border rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-green-500"></div><button type="submit" id="upload-btn" class="w-full bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded-lg transition-colors disabled:bg-gray-400">上传图片</button></form></section><section class="bg-white p-6 rounded-lg shadow-md"><h2 class="text-xl font-semibold mb-4">分类管理</h2><div class="flex items-center space-x-2 mb-4"><input type="text" id="new-category-name" placeholder="输入新分类名称" class="w-full border rounded px-3 py-2"><button id="add-category-btn" class="flex-shrink-0 bg-green-500 hover:bg-green-600 text-white font-bold w-9 h-9 rounded-full flex items-center justify-center text-xl">+</button></div><div id="category-management-list" class="space-y-2 max-h-60 overflow-y-auto"></div></section></div><section class="bg-white p-6 rounded-lg shadow-md lg:col-span-8 xl:col-span-9"><div class="flex flex-wrap justify-between items-center gap-4 mb-4"><h2 class="text-xl font-semibold">已上传图片 <span id="image-count" class="text-base text-gray-500 font-normal"></span></h2><div class="relative min-w-0 flex-grow sm:flex-grow-0 sm:w-64"><input type="search" id="search-input" placeholder="搜索..." class="w-full pl-8 pr-4 py-2 text-sm border rounded-full focus:outline-none focus:ring-2 focus:ring-green-500"><div class="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none"><svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg></div></div></div><div id="image-list" class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-3 xl:grid-cols-5 gap-4"></div><div id="pagination-controls" class="flex justify-center items-center space-x-4 mt-6"></div></section></div></main><dialog id="edit-image-dialog" class="p-6 rounded-lg shadow-xl w-full max-w-md"><h3 class="text-lg font-bold mb-4">编辑图片信息</h3><form id="edit-image-form" class="space-y-4"><input type="hidden" id="edit-id"><img id="edit-preview" class="w-full h-48 object-cover rounded-md bg-gray-100 mb-4"><div><label for="edit-category-select" class="block text-sm font-medium mb-1">分类</label><select id="edit-category-select" class="w-full border rounded px-3 py-2"></select></div><div><label for="edit-description" class="block text-sm font-medium mb-1">描述</label><input type="text" id="edit-description" class="w-full border rounded px-3 py-2"></div><div class="flex justify-end space-x-2 mt-6"><button type="button" id="cancel-edit-btn" class="bg-gray-300 hover:bg-gray-400 text-black py-2 px-4 rounded">取消</button><button type="submit" class="bg-green-600 hover:bg-green-700 text-white py-2 px-4 rounded">保存</button></div></form></dialog><script>
const debounce=(func,delay)=>{let timeout;return(...args)=>{clearTimeout(timeout);timeout=setTimeout(()=>func.apply(this,args),delay);};};const showToast=(message,isError=!1)=>{const toast=document.createElement("div");toast.textContent=message;toast.className=`fixed top-5 right-5 p-4 rounded-lg shadow-lg text-white ${isError?"bg-red-500":"bg-green-600"}`;document.body.appendChild(toast);setTimeout(()=>toast.remove(),3e3);};document.addEventListener("DOMContentLoaded",()=>{const elements={uploadForm:document.getElementById("upload-form"),uploadBtn:document.getElementById("upload-btn"),imageInput:document.getElementById("image-input"),fileInfo:{wrapper:document.getElementById("file-info-wrapper"),name:document.getElementById("file-name-info"),size:document.getElementById("file-size-info")},categorySelect:document.getElementById("category-select"),categoryMgmt:{list:document.getElementById("category-management-list"),newName:document.getElementById("new-category-name"),addBtn:document.getElementById("add-category-btn")},imageList:document.getElementById("image-list"),imageCount:document.getElementById("image-count"),searchInput:document.getElementById("search-input"),pagination:document.getElementById("pagination-controls"),editDialog:{dialog:document.getElementById("edit-image-dialog"),form:document.getElementById("edit-image-form"),id:document.getElementById("edit-id"),preview:document.getElementById("edit-preview"),category:document.getElementById("edit-category-select"),description:document.getElementById("edit-description"),cancelBtn:document.getElementById("cancel-edit-btn")}};let state={categories:[],currentPage:1,totalPages:1,filterCategory:"all",search:""};const api=async(url,options={})=>{try{const response=await fetch(url,options);if(401===response.status)return window.location.href="/login.html",null;const data=await response.json();return response.ok?data:(showToast(data.message||"操作失败",!0),null);}catch(error){return showToast("网络错误",!0),null;}};const loadCategories=async()=>{const categories=await api("/api/admin/categories");categories&&(state.categories=categories,populateCategoryDropdowns(),renderCategoryManagementList());};const populateCategoryDropdowns=()=>{[elements.categorySelect,elements.editDialog.category].forEach(select=>{select.innerHTML="";state.categories.forEach(cat=>{const option=new Option(cat.name,cat.id);select.add(option);});});};const renderCategoryManagementList=()=>{const list=elements.categoryMgmt.list;list.innerHTML="";state.categories.forEach(cat=>{const isUncategorized="未分类"===cat.name,item=document.createElement("div");item.className=`category-item flex items-center justify-between p-2 rounded hover:bg-gray-100 ${state.filterCategory==cat.id?"active":""}`;item.dataset.id=cat.id;item.dataset.name=cat.name;item.innerHTML=`\n                    <span class="category-name flex-grow cursor-pointer ${isUncategorized?"text-gray-500":""}">${cat.name}</span>\n                    ${isUncategorized?"":'<div class="space-x-2 flex-shrink-0">\n                        <button class="rename-cat-btn text-blue-500 hover:text-blue-700 text-sm">改</button>\n                        <button class="delete-cat-btn text-red-500 hover:text-red-700 text-sm">删</button>\n                    </div>'}`;list.appendChild(item);});};const loadImages=async()=>{const params=new URLSearchParams({page:state.currentPage,limit:10,category:state.filterCategory,search:state.search}),data=await api(`/api/admin/images?${params.toString()}`);data&&(renderImageList(data.images),renderPagination(data.currentPage,data.totalPages),elements.imageCount.textContent=`(共 ${data.totalPages*10-10+data.images.length} 项)`);};const renderImageList=images=>{elements.imageList.innerHTML=images.map(img=>`\n                <div class="relative group aspect-square">\n                    <img src="${img.path_thumb}" alt="${img.description}" class="w-full h-full object-cover rounded-md bg-gray-100">\n                    <div class="absolute inset-0 bg-black bg-opacity-60 p-2 flex flex-col justify-end text-white opacity-0 group-hover:opacity-100 transition-opacity rounded-md text-xs">\n                        <p class="font-bold truncate w-full" title="${img.filename_orig}">${img.filename_orig}</p>\n                        <p>${img.category_name}</p>\n                        <div class="absolute top-1 right-1 space-x-1">\n                            <button data-image='${JSON.stringify(img)}' class="edit-btn bg-blue-500 hover:bg-blue-600 w-6 h-6 rounded-full flex items-center justify-center text-sm">✎</button>\n                            <button data-id="${img.id}" class="delete-btn bg-red-500 hover:bg-red-600 w-6 h-6 rounded-full flex items-center justify-center text-sm">✕</button>\n                        </div>\n                    </div>\n                </div>`).join("");};const renderPagination=(currentPage,totalPages)=>{state.totalPages=totalPages;const pagination=elements.pagination;if(pagination.innerHTML="",totalPages<=1)return;let buttons=[];buttons.push(`<button data-page="${currentPage-1}" ${1===currentPage?"disabled":""} class="px-3 py-1 rounded bg-gray-200 disabled:opacity-50">&laquo;</button>`);for(let i=1;i<=totalPages;i++)i===currentPage?buttons.push(`<button data-page="${i}" class="px-3 py-1 rounded bg-green-600 text-white">${i}</button>`):i<=2||i>=totalPages-1||Math.abs(i-currentPage)<=1?buttons.push(`<button data-page="${i}" class="px-3 py-1 rounded bg-gray-200">${i}</button>`):2===Math.abs(i-currentPage)&&buttons.push("<span>...</span>");buttons.push(`<button data-page="${currentPage+1}" ${currentPage===totalPages?"disabled":""} class="px-3 py-1 rounded bg-gray-200 disabled:opacity-50">&raquo;</button>`);pagination.innerHTML=buttons.join("");};elements.imageInput.addEventListener("change",e=>{const file=e.target.files[0];file?(elements.fileInfo.name.textContent=file.name,elements.fileInfo.size.textContent=`${(file.size/1024).toFixed(1)} KB`,elements.fileInfo.wrapper.classList.remove("hidden")):elements.fileInfo.wrapper.classList.add("hidden");});elements.uploadForm.addEventListener("submit",async e=>{e.preventDefault();elements.uploadBtn.disabled=!0;elements.uploadBtn.textContent="上传中...";const formData=new FormData(elements.uploadForm),res=await api("/api/admin/images/upload",{method:"POST",body:formData});res&&(showToast("上传成功!"),elements.uploadForm.reset(),elements.fileInfo.wrapper.classList.add("hidden"),loadImages());elements.uploadBtn.disabled=!1;elements.uploadBtn.textContent="上传图片";});elements.categoryMgmt.addBtn.addEventListener("click",async()=>{const name=elements.categoryMgmt.newName.value.trim();name&&await api("/api/admin/categories",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name})})&&(elements.categoryMgmt.newName.value="",loadCategories());});elements.categoryMgmt.list.addEventListener("click",async e=>{const target=e.target,item=target.closest(".category-item");if(!item)return;const id=item.dataset.id,name=item.dataset.name;if(target.classList.contains("delete-cat-btn")){if(confirm(`确定删除分类 "${name}"? 相关图片将移至"未分类"。`))await api(`/api/admin/categories/${id}`,{method:"DELETE"})&&(showToast("分类已删除"),loadCategories(),state.filterCategory==id&&(state.filterCategory="all"),loadImages());}else if(target.classList.contains("rename-cat-btn")){const newName=prompt("输入新名称:",name);newName&&newName.trim()!==name&&await api(`/api/admin/categories/${id}`,{method:"PUT",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:newName.trim()})})&&(showToast("分类已重命名"),loadCategories());}else target.classList.contains("category-name")&&(state.filterCategory=state.filterCategory==id?"all":id,state.currentPage=1,document.querySelectorAll(".category-item").forEach(el=>el.classList.remove("active")),"all"!=state.filterCategory&&item.classList.add("active"),loadImages());});elements.searchInput.addEventListener("input",debounce(()=>{state.search=elements.searchInput.value.trim();state.currentPage=1;loadImages();},500));elements.pagination.addEventListener("click",e=>{const button=e.target.closest("button");button&&!button.disabled&&(state.currentPage=Number(button.dataset.page),loadImages());});elements.imageList.addEventListener("click",async e=>{const editBtn=e.target.closest(".edit-btn"),deleteBtn=e.target.closest(".delete-btn");if(editBtn){const img=JSON.parse(editBtn.dataset.image),dialog=elements.editDialog;dialog.id.value=img.id;dialog.preview.src=img.path_thumb;dialog.category.value=img.category_id;dialog.description.value=img.description||"";dialog.dialog.showModal();}if(deleteBtn){const id=deleteBtn.dataset.id;confirm("确定永久删除这张图片吗?")&&await api(`/api/admin/images/${id}`,{method:"DELETE"})&&(showToast("图片已删除"),loadImages());}});elements.editDialog.cancelBtn.addEventListener("click",()=>elements.editDialog.dialog.close());elements.editDialog.form.addEventListener("submit",async e=>{e.preventDefault();const dialog=elements.editDialog,id=dialog.id.value,body=JSON.stringify({category_id:dialog.category.value,description:dialog.description.value});await api(`/api/admin/images/${id}`,{method:"PUT",headers:{"Content-Type":"application/json"},body})&&(showToast("更新成功"),dialog.dialog.close(),loadImages());});(async()=>{await loadCategories();await loadImages();})();});
</script></body></html>
EOF

    echo -e "${GREEN}--- 所有项目文件已成功生成在 ${INSTALL_DIR} ---${NC}"
}

# --- 管理菜单功能 (v8.1 优化版) ---
install_app() {
    echo -e "${GREEN}--- 1. 开始安装或修复应用 ---${NC}"
    echo -e "${YELLOW}--> 正在检查系统环境...${NC}"
    if ! command -v node > /dev/null || ! command -v npm > /dev/null; then
        echo -e "${YELLOW}--> 检测到 Node.js 或 npm 未安装，正在尝试自动安装...${NC}"
        if [ -f /etc/debian_version ]; then apt-get update -y && apt-get install -y nodejs npm; elif [ -f /etc/redhat-release ]; then yum install -y nodejs npm; else echo -e "${RED}无法确定操作系统类型，请手动安装 Node.js (v16+) 和 npm。${NC}"; exit 1; fi
        echo -e "${GREEN}--> 环境安装完成！${NC}"
    else echo -e "${GREEN}--> Node.js 和 npm 环境已存在。${NC}"; fi

    generate_files
    
    echo -e "${YELLOW}--- 开始进行交互式配置 ---${NC}"
    read -p "请输入应用运行的端口 (默认 3000): " port
    read -p "请输入后台管理员用户名 (默认 admin): " username
    read -sp "请输入后台管理员密码 (必填): " password; echo
    
    local PORT=${port:-3000}
    local USER=${username:-admin}
    if [ -z "$password" ]; then echo -e "${RED}密码不能为空！安装中止。${NC}"; return 1; fi
    
    echo -e "${YELLOW}--> 正在生成 .env 配置文件...${NC}"
    local JWT_SECRET; JWT_SECRET=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32)
    
    echo "PORT=${PORT}" > .env
    echo "JWT_SECRET=${JWT_SECRET}" >> .env
    echo "ADMIN_USERNAME=${USER}" >> .env
    echo "ADMIN_PASSWORD=${password}" >> .env

    echo -e "${YELLOW}--> 正在安装项目依赖 (npm install)...${NC}"
    npm install
    
    echo -e "${YELLOW}--> 正在初始化数据库并设置管理员账户...${NC}"
    npm run setup
    
    sed -i '/^ADMIN_PASSWORD=/d' .env
    
    echo -e "${YELLOW}--> 正在全局安装 PM2...${NC}"
    npm install -g pm2
    
    echo -e "${GREEN}--- 安装完成！正在自动启动应用... ---${NC}"
    start_app
    display_access_info
}

start_app() {
    cd "${INSTALL_DIR}" || { echo -e "${RED}安装目录未找到!${NC}"; return 1; }
    echo -e "${GREEN}--- 正在启动应用... ---${NC}"
    if ! [ -f ".env" ]; then echo -e "${RED}错误: .env 文件不存在。请先运行安装程序。${NC}"; return 1; fi
    if pm2 info "$APP_NAME" &> /dev/null && [ "$(pm2 info "$APP_NAME" | grep 'status' | awk '{print $4}')" == "online" ]; then
        echo -e "${YELLOW}应用已经在运行中。${NC}"
    else
        pm2 start server.js --name "$APP_NAME"
        pm2 startup
        pm2 save --force
        echo -e "${GREEN}--- 应用已启动！---${NC}"
    fi
}

stop_app() {
    echo -e "${YELLOW}--- 正在停止应用... ---${NC}"
    pm2 stop "$APP_NAME" > /dev/null
    echo -e "${GREEN}--- 应用已停止！---${NC}"
}

restart_app() {
    echo -e "${GREEN}--- 正在重启应用... ---${NC}"
    pm2 restart "$APP_NAME"
    echo -e "${GREEN}--- 应用已重启！---${NC}"
}

view_logs() {
    echo -e "${YELLOW}--- 显示应用日志 (按 Ctrl+C 退出)... ---${NC}"
    pm2 logs "$APP_NAME"
}

manage_credentials() {
    cd "${INSTALL_DIR}" || { echo -e "${RED}安装目录未找到!${NC}"; return 1; }
    echo -e "${YELLOW}--- 修改账号和密码 ---${NC}";
    if ! [ -f ".env" ]; then echo -e "${RED}错误: .env 文件不存在。请先安装应用。${NC}"; return 1; fi;
    
    local CURRENT_USER; CURRENT_USER=$(grep 'ADMIN_USERNAME=' .env | cut -d '=' -f2);
    echo "当前用户名: ${CURRENT_USER}";
    read -p "请输入新的用户名 (留空则不修改): " new_username;
    read -sp "请输入新的密码 (必填): " new_password; echo
    
    if [ -z "$new_password" ]; then echo -e "${RED}密码不能为空！操作取消。${NC}"; return 1; fi;

    local FINAL_USER=${new_username:-$CURRENT_USER}
    
    # setup.js 需要从 .env 读取临时的用户名和明文密码来哈希处理
    echo "ADMIN_USERNAME=${FINAL_USER}" >> .env
    echo "ADMIN_PASSWORD=${new_password}" >> .env
    
    echo "--> 正在更新凭据..."
    npm run setup
    
    # setup.js 执行完毕后，从 .env 中移除临时的明文密码
    sed -i '/^ADMIN_PASSWORD=/d' .env
    # 移除所有 ADMIN_USERNAME 行，再重新添加正确的，避免重复
    sed -i '/^ADMIN_USERNAME=/d' .env
    echo "ADMIN_USERNAME=${FINAL_USER}" >> .env
    
    echo -e "${GREEN}凭据已更新。${NC}";
    echo -e "${YELLOW}正在重启应用以使更改生效...${NC}";
    restart_app;
}

backup_app() {
    cd "${INSTALL_DIR}" || { echo -e "${RED}安装目录未找到!${NC}"; return 1; }
    echo -e "${YELLOW}--- 开始备份应用 ---${NC}"
    mkdir -p "${BACKUP_DIR}"
    local BACKUP_FILE="${BACKUP_DIR}/gallery-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    echo "--> 正在创建备份文件: ${BACKUP_FILE}"
    tar -czf "${BACKUP_FILE}" "./public/uploads" "./data/${DB_FILE}"
    if [ $? -eq 0 ]; then echo -e "${GREEN}备份成功! 文件保存在: ${BACKUP_FILE}${NC}"; else echo -e "${RED}备份失败!${NC}"; fi
}

restore_app() {
    echo -e "${YELLOW}--- 开始恢复应用 ---${NC}"
    if [ ! -d "${BACKUP_DIR}" ] || [ -z "$(ls -A "${BACKUP_DIR}")" ]; then echo -e "${RED}没有找到备份文件或备份目录! (${BACKUP_DIR})${NC}"; return 1; fi

    echo "可用备份文件:"
    select backup_file in "${BACKUP_DIR}"/*.tar.gz; do
        if [ -n "${backup_file}" ]; then break; else echo "无效选择。"; fi
    done
    
    read -p "警告: 这将覆盖当前的图片和数据库，是否继续? (y/n): " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then echo "操作已取消。"; return 0; fi
    
    cd "${INSTALL_DIR}" || { echo -e "${RED}安装目录未找到!${NC}"; return 1; }
    echo "--> 正在停止应用..." && stop_app
    echo "--> 正在从 ${backup_file} 恢复数据..."
    if tar -xzf "${backup_file}" -C "/"; then echo -e "${GREEN}恢复成功!${NC}"; else echo -e "${RED}恢复失败!${NC}"; fi
    echo "--> 正在重启应用..." && start_app
}

uninstall_app() {
    echo -e "${RED}--- 警告：这将从PM2中移除应用并删除整个项目文件夹！ ---${NC}"
    read -p "你确定要继续吗？ (y/n): " confirm
    if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
        echo "--> 正在从 PM2 中删除应用..."
        pm2 delete "$APP_NAME" || echo "PM2中未找到应用，继续..."
        pm2 save --force
        echo "--> 正在删除项目文件夹 ${INSTALL_DIR}..."
        rm -rf "${INSTALL_DIR}"
        
        if [ -d "${BACKUP_DIR}" ]; then
            read -p "是否也要删除备份文件夹 ${BACKUP_DIR}? (y/n): " del_backup
            if [[ "$del_backup" == "y" || "$del_backup" == "Y" ]]; then
                rm -rf "${BACKUP_DIR}"
                echo "--> 备份文件夹已删除。"
            fi
        fi
        
        echo -e "${GREEN}应用已彻底卸载。${NC}"
    else echo "操作已取消。"; fi
}

display_access_info() {
    cd "${INSTALL_DIR}" || return
    local SERVER_IP; SERVER_IP=$(hostname -I | awk '{print $1}')
    if [ -f ".env" ]; then
        local PORT; PORT=$(grep 'PORT=' .env | cut -d '=' -f2)
        local USER; USER=$(grep 'ADMIN_USERNAME=' .env | cut -d '=' -f2)
        echo -e "${YELLOW}======================================================${NC}"
        echo -e "${YELLOW}            应用已就绪！请使用以下信息访问            ${NC}"
        echo -e "${YELLOW}======================================================${NC}"
        echo -e "前台画廊地址: ${GREEN}http://${SERVER_IP}:${PORT}${NC}"
        echo -e "后台管理地址: ${GREEN}http://${SERVER_IP}:${PORT}/admin${NC}"
        echo -e "后台登录用户: ${BLUE}${USER}${NC}"
        echo -e "后台登录密码: ${BLUE}(您在安装时设置的密码)${NC}"
        echo -e "${YELLOW}======================================================${NC}"
    fi
}

show_menu() {
    clear
    echo -e "${BLUE}======================================================${NC}"
    echo -e "${BLUE}      图片画廊 - 企业级重构版 (v8.1)      ${NC}"
    echo -e "${BLUE}======================================================${NC}"
    echo -e " 应用名称: ${GREEN}${APP_NAME}${NC}"
    echo -e " 安装路径: ${GREEN}${INSTALL_DIR}${NC}"
    if pm2 info "$APP_NAME" &> /dev/null && [ "$(pm2 info "$APP_NAME" | grep 'status' | awk '{print $4}')" == "online" ]; then
        echo -e " 应用状态: ${GREEN}运行中${NC}"
    else
        echo -e " 应用状态: ${RED}已停止${NC}"
    fi
    echo -e "${BLUE}------------------------------------------------------${NC}"
    echo -e " 1. 安装或修复应用 (首次使用)"
    echo -e " 2. 启动应用"
    echo -e " 3. 停止应用"
    echo -e " 4. 重启应用"
    echo -e " 5. 查看实时日志"
    echo -e " 6. 修改账号和密码"
    echo -e " 7. 备份数据"
    echo -e " 8. 恢复数据"
    echo -e " 9. ${RED}彻底卸载应用${NC}"
    echo -e " 0. 退出"
    echo -e "${BLUE}------------------------------------------------------${NC}"
    read -p "请输入你的选择 [0-9]: " choice
    case $choice in
        1) install_app ;;
        2) start_app; display_access_info ;;
        3) stop_app ;;
        4) restart_app ;;
        5) view_logs ;;
        6) manage_credentials ;;
        7) backup_app ;;
        8) restore_app ;;
        9) uninstall_app ;;
        0) exit 0 ;;
        *) echo -e "\n${RED}无效输入...${NC}" ;;
    esac
    read -n 1 -s -r -p $'\n按任意键返回主菜单...'
}

# --- 脚本主入口 ---
while true; do
    show_menu
done
