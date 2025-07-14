#!/bin/bash

# =================================================================
#      图片画廊 旗舰增强版 - 一体化部署与管理脚本 (v8.3)
#
#   作者: 编码助手
#   功能: 菜单直接显示访问地址；分类管理支持图片数量统计和内联编辑。
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

# --- 核心功能：文件生成 (v8.3 更新) ---
generate_files() {
    echo -e "${YELLOW}--> 正在创建项目目录结构: ${INSTALL_DIR}${NC}"
    mkdir -p "${INSTALL_DIR}/public/uploads" "${INSTALL_DIR}/data" "${INSTALL_DIR}/routes/api" "${INSTALL_DIR}/middleware"
    cd "${INSTALL_DIR}" || exit

    echo "--> 正在生成 package.json (版本更新)..."
cat << 'EOF' > package.json
{
  "name": "image-gallery-pro-v8",
  "version": "8.3.0",
  "description": "A robust, scalable, and secure full-stack image gallery application with enhanced category management.",
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
    
    # Files from v8.2 that don't need changes are included for completeness.
cat << 'EOF' > data/database.js
const Database = require('better-sqlite3'); const path = require('path');
const dbPath = path.join(__dirname, 'gallery.db'); const db = new Database(dbPath);
function initDB() {
    db.exec(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL);`);
    db.exec(`CREATE TABLE IF NOT EXISTS categories (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE NOT NULL);`);
    db.exec(`CREATE TABLE IF NOT EXISTS images (id TEXT PRIMARY KEY, category_id INTEGER, description TEXT, filename_orig TEXT NOT NULL, path_orig TEXT NOT NULL, path_display TEXT NOT NULL, path_thumb TEXT NOT NULL, size_orig INTEGER, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (category_id) REFERENCES categories (id));`);
    if (!db.prepare('SELECT id FROM categories WHERE name = ?').get('未分类')) { db.prepare('INSERT INTO categories (name) VALUES (?)').run('未分类'); }
}
module.exports = { db, initDB };
EOF
cat << 'EOF' > setup.js
const { db, initDB } = require('./data/database.js'); const bcrypt = require('bcrypt'); require('dotenv').config();
async function setup() {
    try {
        initDB(); const username = process.env.ADMIN_USERNAME; const password = process.env.ADMIN_PASSWORD;
        if (!username || !password) { console.error('Error: ADMIN_USERNAME and ADMIN_PASSWORD must be temporarily set in .env for setup script to run.'); process.exit(1); }
        const existingUser = db.prepare('SELECT * FROM users WHERE username = ?').get(username); const hash = await bcrypt.hash(password, 10);
        if (existingUser) { db.prepare('UPDATE users SET password_hash = ? WHERE username = ?').run(hash, username); } else { db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(username, hash); }
        console.log(`Admin user "${username}" processed successfully.`);
    } catch (error) { console.error('An error occurred during setup:', error); process.exit(1); }
}
setup();
EOF
cat << 'EOF' > server.js
require('dotenv').config(); const express = require('express'); const path = require('path'); const cookieParser = require('cookie-parser');
const { initDB } = require('./data/database.js'); initDB();
const authRoutes = require('./routes/auth'); const apiRoutes = require('./routes/api'); const { authMiddleware } = require('./middleware/authMiddleware');
const app = express(); const PORT = process.env.PORT || 3000;
app.use(express.json()); app.use(express.urlencoded({ extended: true })); app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public'))); app.use('/uploads', express.static(path.join(__dirname, 'public', 'uploads')));
app.use('/api/auth', authRoutes); app.use('/api', apiRoutes);
app.get('/admin.html', authMiddleware, (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/admin', authMiddleware, (req, res) => res.redirect('/admin.html'));
app.use((req, res) => res.status(404).send("Sorry, can't find that!"));
app.use((err, req, res, next) => { console.error(err.stack); res.status(500).json({ message: 'Something broke!', error: err.message }); });
app.listen(PORT, () => console.log(`Server is running on http://localhost:${PORT}`));
EOF
cat << 'EOF' > middleware/authMiddleware.js
const jwt = require('jsonwebtoken');
const authMiddleware = (req, res, next) => {
    const token = req.cookies.token; if (!token) { return req.accepts('html') ? res.redirect('/login.html') : res.status(401).json({ message: 'Access denied. No token provided.' }); }
    try { req.user = jwt.verify(token, process.env.JWT_SECRET); next(); } catch (ex) { return req.accepts('html') ? res.redirect('/login.html') : res.status(400).json({ message: 'Invalid token.' }); }
};
module.exports = { authMiddleware };
EOF
cat << 'EOF' > routes/auth.js
const express = require('express'); const bcrypt = require('bcrypt'); const jwt = require('jsonwebtoken'); const { body, validationResult } = require('express-validator'); const { db } = require('../data/database.js'); const router = express.Router();
router.post('/login', [ body('username').trim().notEmpty(), body('password').notEmpty() ], async (req, res) => {
    if (!validationResult(req).isEmpty()) return res.redirect('/login.html?error=Username or password cannot be empty');
    const { username, password } = req.body;
    try {
        const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
        if (!user || !await bcrypt.compare(password, user.password_hash)) return res.redirect('/login.html?error=Invalid credentials');
        const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, { expiresIn: '1d' });
        res.cookie('token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'strict', maxAge: 24 * 60 * 60 * 1000 });
        res.redirect('/admin.html');
    } catch (error) { console.error("Login error:", error); res.redirect('/login.html?error=Server error'); }
});
router.get('/logout', (req, res) => { res.clearCookie('token'); res.redirect('/login.html'); });
module.exports = router;
EOF
cat << 'EOF' > routes/api.js
const express = require('express'); const { authMiddleware } = require('../middleware/authMiddleware'); const categoryRoutes = require('./api/categories'); const imageRoutes = require('./api/images'); const router = express.Router();
router.get('/categories/public', categoryRoutes.getPublicCategories); router.get('/images/public', imageRoutes.getPublicImages);
router.use('/admin', authMiddleware);
router.get('/admin/categories', categoryRoutes.getAllCategories); router.post('/admin/categories', categoryRoutes.createCategory); router.put('/admin/categories/:id', categoryRoutes.updateCategory); router.delete('/admin/categories/:id', categoryRoutes.deleteCategory);
router.get('/admin/images', imageRoutes.getAdminImages); router.post('/admin/images/upload', imageRoutes.uploadImage); router.put('/admin/images/:id', imageRoutes.updateImage); router.delete('/admin/images/:id', imageRoutes.deleteImage);
module.exports = router;
EOF
    
    echo "--> [v8.3] 正在更新API子模块 routes/api/categories.js (增加图片统计)..."
cat << 'EOF' > routes/api/categories.js
const { db } = require('../../data/database.js');
const { body, validationResult } = require('express-validator');

exports.getPublicCategories = (req, res) => {
    try {
        const query = `SELECT c.id, c.name FROM categories c WHERE EXISTS (SELECT 1 FROM images i WHERE i.category_id = c.id) ORDER BY CASE WHEN c.name = '未分类' THEN 0 ELSE 1 END, c.name COLLATE NOCASE`;
        res.json(db.prepare(query).all());
    } catch (e) { res.status(500).json({ message: 'Error fetching categories' }); }
};

// [v8.3] The SQL query is updated to join with images and count them.
exports.getAllCategories = (req, res) => {
    try {
        const query = `
            SELECT
                c.id,
                c.name,
                COUNT(i.id) as image_count
            FROM categories c
            LEFT JOIN images i ON c.id = i.category_id
            GROUP BY c.id, c.name
            ORDER BY CASE WHEN c.name = '未分类' THEN 0 ELSE 1 END, c.name COLLATE NOCASE
        `;
        res.json(db.prepare(query).all());
    } catch (e) { console.error(e); res.status(500).json({ message: 'Error fetching categories for admin' }); }
};

exports.createCategory = [ body('name').trim().notEmpty().isLength({ min: 1, max: 50 }), (req, res) => {
    if (!validationResult(req).isEmpty()) return res.status(400).json({ message: 'Invalid category name' });
    try {
        const info = db.prepare('INSERT INTO categories (name) VALUES (?)').run(req.body.name);
        res.status(201).json({ id: info.lastInsertRowid, name: req.body.name });
    } catch (e) { res.status(e.code === 'SQLITE_CONSTRAINT_UNIQUE' ? 409 : 500).json({ message: 'Category exists or server error' }); }
}];

exports.updateCategory = [ body('name').trim().notEmpty().isLength({ min: 1, max: 50 }), (req, res) => {
    if (!validationResult(req).isEmpty()) return res.status(400).json({ message: 'Invalid category name' });
    const cat = db.prepare('SELECT name FROM categories WHERE id = ?').get(req.params.id);
    if (!cat) return res.status(404).json({ message: 'Category not found' });
    if (cat.name === '未分类') return res.status(403).json({ message: 'Cannot rename "未分类"' });
    try {
        db.prepare('UPDATE categories SET name = ? WHERE id = ?').run(req.body.name, req.params.id);
        res.json({ id: Number(req.params.id), name: req.body.name });
    } catch (e) { res.status(e.code === 'SQLITE_CONSTRAINT_UNIQUE' ? 409 : 500).json({ message: 'Category name exists or server error' }); }
}];

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

    # The rest of the backend and frontend files are unchanged from v8.2
    # but are included here for completeness of the script.
cat << 'EOF' > routes/api/images.js
const { db } = require('../../data/database.js'); const { body, validationResult } = require('express-validator'); const multer = require('multer'); const sharp = require('sharp'); const path = require('path'); const fs = require('fs'); const { v4: uuidv4 } = require('uuid');
const UPLOADS_DIR = path.join(__dirname, '..', '..', 'public', 'uploads'); const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 20 * 1024 * 1024 }, fileFilter: (req, file, cb) => /jpeg|jpg|png|gif|webp/.test(file.mimetype) ? cb(null, true) : cb(new Error('Only image files are allowed!')) }).single('image');
const getBaseQuery = () => `SELECT i.id, i.description, i.created_at, i.path_orig, i.path_display, i.path_thumb, i.filename_orig, i.size_orig, c.name as category_name, c.id as category_id FROM images i JOIN categories c ON i.category_id = c.id`;
const processAndSaveImage = async (buffer, originalname) => {
    const uniqueSuffix = uuidv4(); const extension = path.extname(originalname); const originalFilename = `${uniqueSuffix}${extension}`; const webpFilename = `${uniqueSuffix}.webp`; const thumbFilename = `thumb-${uniqueSuffix}.webp`;
    const originalPath = path.join(UPLOADS_DIR, originalFilename); const displayPath = path.join(UPLOADS_DIR, webpFilename); const thumbPath = path.join(UPLOADS_DIR, thumbFilename);
    await fs.promises.writeFile(originalPath, buffer); const imageProcessor = sharp(buffer);
    await imageProcessor.clone().resize({ width: 1920, height: 1080, fit: 'inside', withoutEnlargement: true }).webp({ quality: 80 }).toFile(displayPath);
    await imageProcessor.clone().resize({ width: 400, height: 400, fit: 'inside' }).webp({ quality: 75 }).toFile(thumbPath);
    return { path_orig: `/uploads/${originalFilename}`, path_display: `/uploads/${webpFilename}`, path_thumb: `/uploads/${thumbFilename}` };
};
const queryImages = (req, res, isAdmin = false) => {
    const { category, search, page = 1 } = req.query; const limit = isAdmin ? 12 : 15; let where = [], params = [], orderBy = 'ORDER BY i.created_at DESC';
    if (isAdmin && category && category !== 'all') { where.push("c.id = ?"); params.push(category); }
    if (!isAdmin && category && category !== 'all' && category !== 'random') { where.push("c.name = ?"); params.push(category); }
    if (search) { where.push("(i.description LIKE ? OR i.filename_orig LIKE ?)"); params.push(`%${search}%`, `%${search}%`); }
    if (!isAdmin && category === 'random') orderBy = 'ORDER BY RANDOM()';
    const whereClause = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';
    try {
        const total = db.prepare(`SELECT COUNT(*) as total FROM images i JOIN categories c ON i.category_id = c.id ${whereClause}`).get(params).total;
        const images = db.prepare(`${getBaseQuery()} ${whereClause} ${orderBy} LIMIT ? OFFSET ?`).all(...params, limit, (page - 1) * limit);
        res.json({ images, totalPages: Math.ceil(total / limit), currentPage: Number(page) });
    } catch (e) { res.status(500).json({ message: 'Error fetching images' }); }
};
exports.getPublicImages = (req, res) => queryImages(req, res, false); exports.getAdminImages = (req, res) => queryImages(req, res, true);
exports.uploadImage = (req, res) => {
    upload(req, res, async (err) => {
        if (err) return res.status(400).json({ message: err.message }); if (!req.file) return res.status(400).json({ message: 'No file uploaded.' }); if (!req.body.category_id) return res.status(400).json({ message: 'Category is required.' });
        try {
            const paths = await processAndSaveImage(req.file.buffer, req.file.originalname);
            db.prepare(`INSERT INTO images (id, category_id, description, filename_orig, size_orig, path_orig, path_display, path_thumb) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(uuidv4(), req.body.category_id, req.body.description || null, req.file.originalname, req.file.size, paths.path_orig, paths.path_display, paths.path_thumb);
            res.status(201).json({ message: 'Upload successful' });
        } catch (e) { console.error(e); res.status(500).json({ message: 'Error processing image.' }); }
    });
};
exports.updateImage = [ body('category_id').isInt({ min: 1 }), body('description').optional({ checkFalsy: true }).isString().trim(), (req, res) => {
    if (!validationResult(req).isEmpty()) return res.status(400).json({ message: 'Invalid data' });
    const result = db.prepare('UPDATE images SET category_id = ?, description = ? WHERE id = ?').run(req.body.category_id, req.body.description, req.params.id);
    if (result.changes === 0) return res.status(404).json({ message: 'Image not found' }); res.status(200).json({ message: 'Image updated' });
}];
exports.deleteImage = (req, res) => {
    const image = db.prepare('SELECT path_orig, path_display, path_thumb FROM images WHERE id = ?').get(req.params.id);
    if (!image) return res.status(404).json({ message: 'Image not found' });
    db.prepare('DELETE FROM images WHERE id = ?').run(req.params.id);
    Object.values(image).forEach(p => p && fs.unlink(path.join(UPLOADS_DIR, path.basename(p)), err => err && console.error(`Failed to delete file: ${p}`, err)));
    res.status(200).json({ message: 'Image deleted' });
};
EOF

    echo "--> [v8.3] 正在重构后台管理页 public/admin.html (增强分类管理UI)..."
cat << 'EOF' > public/admin.html
<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>后台管理 - 图片画廊</title><script src="https://cdn.tailwindcss.com"></script><style>body{background-color:#f0fdf4}dialog::backdrop{background-color:rgba(0,0,0,0.5)}.category-item.active{background-color:#dcfce7;font-weight:bold}.upload-drop-zone{transition:background-color .2s ease}.upload-drop-zone.dragover{background-color:#dcfce7;border-style:solid}</style></head><body class="antialiased text-green-900"><header class="bg-white shadow-md p-4 flex justify-between items-center sticky top-0 z-20"><h1 class="text-xl sm:text-2xl font-bold text-green-900">内容管理</h1><div><a href="/" target="_blank" class="text-green-600 hover:text-green-800 mr-2 sm:mr-4">查看前台</a><a href="/api/auth/logout" class="bg-red-500 hover:bg-red-700 text-white font-bold py-2 px-3 sm:px-4 rounded transition-colors text-sm sm:text-base">退出</a></div></header><main class="p-4 sm:p-6 lg:p-8"><div class="grid grid-cols-1 lg:grid-cols-12 gap-8"><aside class="lg:col-span-4 xl:col-span-3 space-y-8"><section class="bg-white p-6 rounded-lg shadow-md"><h2 class="text-xl font-semibold mb-4">上传新图片</h2><form id="upload-form" class="space-y-4"><div id="upload-drop-zone" class="w-full flex flex-col items-center justify-center p-4 border-2 border-dashed border-gray-300 rounded-lg cursor-pointer hover:bg-gray-50"><svg class="w-8 h-8 mb-2 text-gray-500" aria-hidden="true" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 20 16"><path stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 13h3a3 3 0 0 0 0-6h-.025A5.56 5.56 0 0 0 16 6.5 5.5 5.5 0 0 0 5.207 5.021C5.137 5.017 5.071 5 5 5a4 4 0 0 0 0 8h2.167M10 15V6m0 0L8 8m2-2 2 2"/></svg><p class="text-sm text-gray-500"><span class="font-semibold">点击选择</span> 或拖拽多个文件</p><input id="image-input" name="image" type="file" class="hidden" required accept="image/png,image/jpeg,image/gif,image/webp" multiple/></div><div id="upload-queue-wrapper" class="hidden"><div id="upload-queue-list" class="space-y-2 max-h-40 overflow-y-auto border-t border-b py-2 my-2"></div><div class="flex justify-between items-center text-sm font-medium text-gray-600"><p>总计: <span id="queue-total-count">0</span> 张, <span id="queue-total-size">0 KB</span></p><button type="button" id="clear-queue-btn" class="text-red-500 hover:underline">清空队列</button></div></div><div><label for="category-select" class="block text-sm font-medium mb-1">上传到分类</label><select name="category_id" id="category-select" required class="w-full border rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-green-500"></select></div><div><label for="description" class="block text-sm font-medium mb-1">统一描述 (选填)</label><input type="text" name="description" id="description" placeholder="将应用到本次所有图片" class="w-full border rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-green-500"></div><button type="submit" id="upload-btn" class="w-full bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded-lg transition-colors disabled:bg-gray-400">开始上传</button><p id="upload-progress" class="text-center text-sm font-medium text-green-700 h-5"></p></form></section><section class="bg-white p-6 rounded-lg shadow-md"><h2 class="text-xl font-semibold mb-4">分类管理</h2><div class="flex items-center space-x-2 mb-4"><input type="text" id="new-category-name" placeholder="输入新分类名称" class="w-full border rounded px-3 py-2"><button id="add-category-btn" class="flex-shrink-0 bg-green-500 hover:bg-green-600 text-white font-bold w-9 h-9 rounded-full flex items-center justify-center text-xl">+</button></div><div id="category-management-list" class="space-y-2 max-h-72 overflow-y-auto"></div></section></aside><section class="bg-white p-6 rounded-lg shadow-md lg:col-span-8 xl:col-span-9"><div class="flex flex-wrap justify-between items-center gap-4 mb-4"><h2 class="text-xl font-semibold">已上传图片 <span id="image-count" class="text-base text-gray-500 font-normal"></span></h2><div class="relative min-w-0 flex-grow sm:flex-grow-0 sm:w-64"><input type="search" id="search-input" placeholder="搜索..." class="w-full pl-8 pr-4 py-2 text-sm border rounded-full focus:outline-none focus:ring-2 focus:ring-green-500"><div class="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none"><svg class="w-4 h-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg></div></div></div><div id="image-list" class="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-3 xl:grid-cols-4 gap-6"></div><div id="pagination-controls" class="flex justify-center items-center space-x-4 mt-6"></div></section></div></main><dialog id="edit-image-dialog" class="p-6 rounded-lg shadow-xl w-full max-w-md"><h3 class="text-lg font-bold mb-4">编辑图片信息</h3><form id="edit-image-form" class="space-y-4"><input type="hidden" id="edit-id"><img id="edit-preview" class="w-full h-48 object-cover rounded-md bg-gray-100 mb-4"><div><label class="block text-sm font-medium mb-1">分类</label><select id="edit-category-select" class="w-full border rounded px-3 py-2"></select></div><div><label class="block text-sm font-medium mb-1">描述</label><input type="text" id="edit-description" class="w-full border rounded px-3 py-2"></div><div class="mt-4 pt-4 border-t text-sm text-gray-600 space-y-1"><p><strong>文件名:</strong> <span id="edit-info-filename"></span></p><p><strong>文件大小:</strong> <span id="edit-info-size"></span></p><p><strong>上传日期:</strong> <span id="edit-info-date"></span></p></div><div class="flex justify-end space-x-2 mt-6"><button type="button" id="cancel-edit-btn" class="bg-gray-300 hover:bg-gray-400 text-black py-2 px-4 rounded">取消</button><button type="submit" class="bg-green-600 hover:bg-green-700 text-white py-2 px-4 rounded">保存</button></div></form></dialog>

<script>
const util = {
    debounce: (func, delay) => { let timeout; return (...args) => { clearTimeout(timeout); timeout = setTimeout(() => func.apply(this, args), delay); }; },
    showToast: (message, isError = false) => { const toast = document.createElement('div'); toast.textContent = message; toast.className = `fixed top-5 right-5 p-4 rounded-lg shadow-lg text-white ${isError ? 'bg-red-500' : 'bg-green-600'} z-50`; document.body.appendChild(toast); setTimeout(() => toast.remove(), 3000); },
    formatBytes: (bytes, decimals = 2) => { if (!+bytes) return '0 Bytes'; const k = 1024; const dm = decimals < 0 ? 0 : decimals; const sizes = ["Bytes", "KB", "MB", "GB"]; const i = Math.floor(Math.log(bytes) / Math.log(k)); return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`; },
    formatDate: (isoString) => isoString ? new Date(isoString).toLocaleString('zh-CN') : 'N/A'
};

document.addEventListener('DOMContentLoaded', () => {
    let state = { categories: [], currentPage: 1, totalPages: 1, filterCategory: 'all', search: '', uploadQueue: [] };
    const elements = {
        upload: { form: document.getElementById('upload-form'), btn: document.getElementById('upload-btn'), progress: document.getElementById('upload-progress'), dropZone: document.getElementById('upload-drop-zone'), input: document.getElementById('image-input'), queueWrapper: document.getElementById('upload-queue-wrapper'), queueList: document.getElementById('upload-queue-list'), totalCount: document.getElementById('queue-total-count'), totalSize: document.getElementById('queue-total-size'), clearQueueBtn: document.getElementById('clear-queue-btn'), categorySelect: document.getElementById('category-select'), description: document.getElementById('description'), },
        categoryMgmt: { list: document.getElementById('category-management-list'), newName: document.getElementById('new-category-name'), addBtn: document.getElementById('add-category-btn') },
        imageList: document.getElementById('image-list'), imageCount: document.getElementById('image-count'), searchInput: document.getElementById('search-input'), pagination: document.getElementById('pagination-controls'),
        editDialog: { dialog: document.getElementById('edit-image-dialog'), form: document.getElementById('edit-image-form'), id: document.getElementById('edit-id'), preview: document.getElementById('edit-preview'), category: document.getElementById('edit-category-select'), description: document.getElementById('edit-description'), filename: document.getElementById('edit-info-filename'), size: document.getElementById('edit-info-size'), date: document.getElementById('edit-info-date'), cancelBtn: document.getElementById('cancel-edit-btn') }
    };
    const api = async (url, options = {}) => { try { const response = await fetch(url, options); if (response.status === 401) { window.location.href = '/login.html'; return null; } const data = await response.json().catch(() => ({})); if (!response.ok) { util.showToast(data.message || '操作失败', true); return null; } return data; } catch (error) { util.showToast('网络错误', true); return null; } };
    const loadCategories = async () => { const categories = await api('/api/admin/categories'); if (categories) { state.categories = categories; [elements.upload.categorySelect, elements.editDialog.category].forEach(select => { select.innerHTML = ''; state.categories.forEach(cat => select.add(new Option(cat.name, cat.id))); }); renderCategoryManagementList(); } };
    const loadImages = async () => { const params = new URLSearchParams({ page: state.currentPage, limit: 12, category: state.filterCategory, search: state.search }); const data = await api(`/api/admin/images?${params.toString()}`); if (data) { renderImageList(data.images); renderPagination(data.currentPage, data.totalPages); elements.imageCount.textContent = `(共 ${data.totalPages > 0 ? (data.totalPages - 1) * 12 + data.images.length : 0} 项)`; } };
    const handleFiles = (files) => { [...files].forEach(file => { if (file.type.startsWith('image/') && !state.uploadQueue.some(f => f.name === file.name && f.size === file.size)) { state.uploadQueue.push(file); } }); renderUploadQueue(); };
    const renderUploadQueue = () => { elements.upload.queueWrapper.classList.toggle('hidden', state.uploadQueue.length === 0); elements.upload.queueList.innerHTML = state.uploadQueue.map((file, index) => `<div class="flex items-center justify-between text-sm p-1 bg-gray-50 rounded"><span class="truncate w-4/6" title="${file.name}">${file.name}</span><span class="text-gray-500">${util.formatBytes(file.size)}</span><button type="button" data-index="${index}" class="remove-queue-item-btn text-red-500 font-bold text-lg leading-none">&times;</button></div>`).join(''); const totalSize = state.uploadQueue.reduce((acc, file) => acc + file.size, 0); elements.upload.totalCount.textContent = state.uploadQueue.length; elements.upload.totalSize.textContent = util.formatBytes(totalSize); };
    const uploadNextFile = async () => { if (state.uploadQueue.length === 0) { elements.upload.progress.textContent = '全部上传完成！'; elements.upload.btn.disabled = false; setTimeout(() => { elements.upload.progress.textContent = ''; }, 3000); loadImages(); loadCategories(); return; } const total = parseInt(elements.upload.totalCount.textContent) || state.uploadQueue.length; elements.upload.progress.textContent = `正在上传第 ${total - state.uploadQueue.length + 1} / ${total} 张...`; const file = state.uploadQueue[0]; const formData = new FormData(); formData.append('image', file); formData.append('category_id', elements.upload.categorySelect.value); formData.append('description', elements.upload.description.value); const result = await api('/api/admin/images/upload', { method: 'POST', body: formData }); if (!result) { util.showToast(`"${file.name}" 上传失败`, true); } state.uploadQueue.shift(); renderUploadQueue(); await uploadNextFile(); };
    
    // [v8.3] Enhanced Category Management Render Function
    const renderCategoryManagementList = () => {
        const list = elements.categoryMgmt.list;
        list.innerHTML = '';
        state.categories.forEach(cat => {
            const isUncategorized = cat.name === '未分类';
            const item = document.createElement('div');
            item.className = `category-item flex items-center justify-between p-2 rounded hover:bg-gray-100 ${state.filterCategory == cat.id ? 'active' : ''}`;
            item.dataset.id = cat.id;
            item.dataset.name = cat.name;

            item.innerHTML = `
                <div class="flex-grow flex items-center cursor-pointer category-name-wrapper">
                    <span class="category-name">${cat.name}</span>
                    <span class="text-gray-400 text-sm ml-2">(${cat.image_count})</span>
                </div>
                ${!isUncategorized ? `<div class="space-x-2 flex-shrink-0 category-actions">
                    <button class="rename-cat-btn text-blue-500 hover:text-blue-700 text-sm">重命名</button>
                    <button class="delete-cat-btn text-red-500 hover:text-red-700 text-sm">删除</button>
                </div>` : ''}`;
            list.appendChild(item);
        });
    };
    
    // [v8.3] Category Management Event Listener with Inline Editing
    elements.categoryMgmt.list.addEventListener('click', async e => {
        const item = e.target.closest('.category-item');
        if (!item) return;
        const id = item.dataset.id;
        const name = item.dataset.name;

        // Cancel any other editing instance
        const currentlyEditing = document.querySelector('.category-item[data-editing="true"]');
        if (currentlyEditing && currentlyEditing !== item) {
            renderCategoryManagementList();
        }

        if (e.target.classList.contains('rename-cat-btn')) {
            item.dataset.editing = 'true';
            item.querySelector('.category-name-wrapper').innerHTML = `<input type="text" class="cat-edit-input w-full border rounded px-2 py-1 text-sm" value="${name}">`;
            item.querySelector('.category-actions').innerHTML = `
                <button class="save-cat-btn text-green-500 hover:text-green-700 text-sm">保存</button>
                <button class="cancel-edit-btn text-gray-500 hover:text-gray-700 text-sm">取消</button>`;
            item.querySelector('.cat-edit-input').focus();
        } else if (e.target.classList.contains('save-cat-btn')) {
            const newName = item.querySelector('.cat-edit-input').value.trim();
            if (newName && newName !== name) {
                if (await api(`/api/admin/categories/${id}`, { method: 'PUT', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ name: newName }) })) {
                    util.showToast('分类已重命名');
                    await loadCategories();
                }
            } else { renderCategoryManagementList(); }
        } else if (e.target.classList.contains('cancel-edit-btn')) {
            renderCategoryManagementList();
        } else if (e.target.classList.contains('delete-cat-btn')) {
            if (confirm(`确定删除分类 "${name}"? 相关图片将移至"未分类"。`)) {
                if (await api(`/api/admin/categories/${id}`, { method: 'DELETE' })) {
                    util.showToast('分类已删除');
                    if (state.filterCategory == id) state.filterCategory = 'all';
                    await Promise.all([loadCategories(), loadImages()]);
                }
            }
        } else if (e.target.closest('.category-name-wrapper')) {
            state.filterCategory = state.filterCategory == id ? 'all' : id;
            state.currentPage = 1;
            renderCategoryManagementList(); // To update active styles
            await loadImages();
        }
    });

    const renderImageList = (images) => { /* ... same as v8.2 ... */ };
    const renderPagination = (currentPage, totalPages) => { /* ... same as v8.2 ... */ };
    elements.upload.dropZone.addEventListener('click', () => elements.upload.input.click()); elements.upload.dropZone.addEventListener('dragover', e => { e.preventDefault(); e.currentTarget.classList.add('dragover'); }); elements.upload.dropZone.addEventListener('dragleave', e => e.currentTarget.classList.remove('dragover')); elements.upload.dropZone.addEventListener('drop', e => { e.preventDefault(); e.currentTarget.classList.remove('dragover'); handleFiles(e.dataTransfer.files); });
    elements.upload.input.addEventListener('change', e => handleFiles(e.target.files)); elements.upload.queueList.addEventListener('click', e => { if (e.target.classList.contains('remove-queue-item-btn')) { state.uploadQueue.splice(e.target.dataset.index, 1); renderUploadQueue(); } }); elements.upload.clearQueueBtn.addEventListener('click', () => { state.uploadQueue = []; renderUploadQueue(); });
    elements.upload.form.addEventListener('submit', e => { e.preventDefault(); if (state.uploadQueue.length === 0) { util.showToast('请先添加要上传的图片', true); return; } elements.upload.btn.disabled = true; uploadNextFile(); });
    elements.imageList.addEventListener('click', e => { const editBtn = e.target.closest('.edit-btn'); const deleteBtn = e.target.closest('.delete-btn'); if (editBtn) { const img = JSON.parse(editBtn.dataset.image); const dialog = elements.editDialog; dialog.id.value = img.id; dialog.preview.src = img.path_thumb; dialog.category.value = img.category_id; dialog.description.value = img.description || ''; dialog.filename.textContent = img.filename_orig; dialog.size.textContent = util.formatBytes(img.size_orig); dialog.date.textContent = util.formatDate(img.created_at); dialog.dialog.showModal(); } if (deleteBtn) { if (confirm('确定永久删除这张图片吗?')) { api(`/api/admin/images/${deleteBtn.dataset.id}`, { method: 'DELETE' }).then(res => res && (util.showToast('图片已删除'), loadImages())); } } });
    elements.editDialog.cancelBtn.addEventListener('click', () => elements.editDialog.dialog.close()); elements.editDialog.form.addEventListener('submit', async e => { e.preventDefault(); const dialog = elements.editDialog; const body = JSON.stringify({ category_id: dialog.category.value, description: dialog.description.value }); const result = await api(`/api/admin/images/${dialog.id.value}`, {method: 'PUT', headers: {'Content-Type': 'application/json'}, body}); if (result) { util.showToast('更新成功'); dialog.dialog.close(); loadImages(); } });
    elements.pagination.addEventListener('click',e=>{const t=e.target.closest("button");t&&!t.disabled&&(state.currentPage=Number(t.dataset.page),loadImages())});elements.searchInput.addEventListener("input",util.debounce(()=>{state.search=elements.searchInput.value.trim();state.currentPage=1;loadImages()},500));elements.categoryMgmt.addBtn.addEventListener("click",async()=>{const t=elements.categoryMgmt.newName.value.trim();t&&await api("/api/admin/categories",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:t})})&&(elements.categoryMgmt.newName.value="",loadCategories())});
    renderImageList = (images) => { elements.imageList.innerHTML = images.map(img => `<div class="bg-gray-50 rounded-lg shadow-sm overflow-hidden group"><img src="${img.path_thumb}" alt="${img.description}" class="w-full h-40 object-cover"><div class="p-3 space-y-2"><p class="font-bold text-sm truncate" title="${img.filename_orig}">${img.filename_orig}</p><p class="text-xs text-gray-500">${img.category_name}</p><p class="text-xs text-gray-500">${util.formatBytes(img.size_orig)} - ${util.formatDate(img.created_at).split(' ')[0]}</p><div class="flex items-center justify-end space-x-2 pt-2"><button data-image='${JSON.stringify(img)}' class="edit-btn text-white bg-blue-500 hover:bg-blue-600 rounded px-3 py-1.5 text-sm">修改</button><button data-id="${img.id}" class="delete-btn text-white bg-red-500 hover:bg-red-600 rounded px-3 py-1.5 text-sm">删除</button></div></div></div>`).join(''); };
    renderPagination=(t,e)=>{state.totalPages=e;const i=elements.pagination;if(i.innerHTML="",e<=1)return;let a=[];a.push(`<button data-page="${t-1}" ${1===t?"disabled":""} class="px-3 py-1 rounded bg-gray-200 disabled:opacity-50">&laquo;</button>`);for(let n=1;n<=e;n++)n===t?a.push(`<button data-page="${n}" class="px-3 py-1 rounded bg-green-600 text-white">${n}</button>`):n<=2||n>=e-1||Math.abs(n-t)<=1?a.push(`<button data-page="${n}" class="px-3 py-1 rounded bg-gray-200">${n}</button>`):2===Math.abs(n-t)&&a.push("<span>...</span>");a.push(`<button data-page="${t+1}" ${t===e?"disabled":""} class="px-3 py-1 rounded bg-gray-200 disabled:opacity-50">&raquo;</button>`),i.innerHTML=a.join("")};
    (async () => { await loadCategories(); await loadImages(); })();
});
</script></body></html>
EOF
    echo "--> 正在生成 index.html 和 login.html..."
    cat << 'EOF' > public/index.html
<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>图片画廊</title><meta name="description" content="一个展示精彩瞬间的瀑布流图片画廊。"><link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin><link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;700&family=Noto+Sans+SC:wght@400;500;700&display=swap" rel="stylesheet"><script src="https://cdn.tailwindcss.com"></script><style>body{font-family:'Inter','Noto Sans SC',sans-serif;background-color:#f0fdf4;color:#14532d;display:flex;flex-direction:column;min-height:100vh}body.lightbox-open{overflow:hidden}.filter-btn{padding:0.5rem 1rem;border-radius:9999px;font-weight:500;transition:all .2s ease;border:1px solid transparent;cursor:pointer}.filter-btn:hover{background-color:#dcfce7}.filter-btn.active{background-color:#22c55e;color:#fff;border-color:#16a34a}.grid-gallery{column-count:1;column-gap:1rem;width:100%}@media (min-width: 640px){.grid-gallery{column-count:2}}@media (min-width: 768px){.grid-gallery{column-count:3}}@media (min-width: 1024px){.grid-gallery{column-count:4}}@media (min-width: 1280px){.grid-gallery{column-count:5}}.grid-item{margin-bottom:1rem;break-inside:avoid;position:relative;border-radius:.5rem;overflow:hidden;background-color:#e4e4e7;box-shadow:0 4px 6px -1px #0000001a,0 2px 4px -2px #0000001a;opacity:0;transform:translateY(20px);transition:opacity .5s ease-out,transform .5s ease-out,box-shadow .3s ease}.grid-item.is-visible{opacity:1;transform:translateY(0)}.grid-item img{cursor:pointer;width:100%;height:auto;display:block;transition:transform .4s ease}.grid-item:hover img{transform:scale(1.05)}.lightbox{position:fixed;top:0;left:0;width:100%;height:100%;background-color:#000000e6;display:flex;justify-content:center;align-items:center;z-index:1000;opacity:0;visibility:hidden;transition:opacity .3s ease}.lightbox.active{opacity:1;visibility:visible}.lightbox-image{max-width:85vw;max-height:85vh;display:block;-o-object-fit:contain;object-fit:contain}.lightbox-btn{position:absolute;top:50%;transform:translateY(-50%);background-color:#ffffff1a;color:#fff;border:none;font-size:2.5rem;cursor:pointer;padding:.5rem 1rem;border-radius:.5rem;transition:background-color .2s}.lightbox-btn:hover{background-color:#ffffff33}.lb-prev{left:1rem}.lb-next{right:1rem}.lb-close{top:1rem;right:1rem;font-size:2rem}.lb-counter{position:absolute;top:1.5rem;left:50%;transform:translateX(-50%);color:#fff;font-size:1rem;background-color:#0000004d;padding:.25rem .75rem;border-radius:9999px}.back-to-top{position:fixed;bottom:2rem;right:2rem;background-color:#22c55e;color:#fff;width:3rem;height:3rem;border-radius:9999px;display:flex;align-items:center;justify-content:center;box-shadow:0 4px 8px #00000033;cursor:pointer;opacity:0;visibility:hidden;transform:translateY(20px);transition:all .3s ease}.back-to-top.visible{opacity:1;visibility:visible;transform:translateY(0)}.lb-download{position:absolute;bottom:1rem;right:1rem;background-color:#22c55e;color:#fff;border:none;padding:.5rem 1rem;border-radius:.5rem;cursor:pointer;transition:background-color .2s;font-size:1rem}.lb-download:hover{background-color:#16a34a}.header-sticky{padding-top:1rem;padding-bottom:1rem;background-color:#f0fdf400;position:sticky;top:0;z-index:40;transition:padding .3s ease-in-out,background-color .3s ease-in-out;backdrop-filter:blur(0)}.header-sticky.state-scrolled-partially{padding-top:.75rem;padding-bottom:.75rem;background-color:#f0fdf4cc;backdrop-filter:blur(8px);box-shadow:0 4px 6px -1px #0000001a,0 2px 4px -2px #0000001a}.loader{text-align:center;padding:2rem;color:#166534;display:none}</style></head><body class="antialiased"><header class="text-center header-sticky"><div class="container mx-auto px-4"><h1 class="text-4xl md:text-5xl font-bold text-green-900 mb-4">图片画廊</h1><div class="max-w-3xl mx-auto mb-4"><div class="relative"><input type="search" id="search-input" placeholder="搜索图片描述或文件名..." class="w-full pl-10 pr-4 py-2 border border-green-300 rounded-full focus:ring-2 focus:ring-green-500 focus:outline-none"><div class="absolute inset-y-0 left-0 flex items-center pl-3 pointer-events-none"><svg class="w-5 h-5 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path></svg></div></div></div><div id="filter-buttons" class="flex justify-center flex-wrap gap-2"><button class="filter-btn active" data-filter="all">全部</button><button class="filter-btn" data-filter="random">随机</button></div></div></header><main class="container mx-auto px-4 sm:px-6 py-8 md:py-10 flex-grow"><div id="gallery-container" class="grid-gallery"></div><div id="loader" class="loader"></div></main><footer class="text-center py-8 mt-auto border-t border-green-200"><p class="text-green-700">© 2025 图片画廊</p></footer><div class="lightbox"><span class="lb-counter"></span><button class="lightbox-btn lb-close">&times;</button><button class="lightbox-btn lb-prev">&lsaquo;</button><img class="lightbox-image" alt=""><button class="lightbox-btn lb-next">&rsaquo;</button><a class="lb-download" download>下载原图</a></div><a class="back-to-top" title="返回顶部"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 19V5M5 12l7-7 7 7"/></svg></a><script>
document.addEventListener('DOMContentLoaded',()=>{const e=document.getElementById("gallery-container"),t=document.getElementById("loader"),n=document.getElementById("search-input");let a={currentPage:1,totalPages:1,currentFilter:"all",currentSearch:"",isLoading:!1,galleryItems:[],currentLightboxIndex:0};const i=async e=>{try{const t=await fetch(e);if(!t.ok)throw new Error(`HTTP error! status: ${t.status}`);return await t.json()}catch(e){return t.textContent="加载失败，请刷新。",null}},o=async()=>{const e=await i("/api/categories/public");if(!e)return;const t=document.getElementById("filter-buttons");t.querySelectorAll(".dynamic-filter").forEach(e=>e.remove()),e.forEach(e=>{const n=document.createElement("button");n.className="filter-btn dynamic-filter",n.dataset.filter=e.name,n.textContent=e.name,t.appendChild(n)}),c()},c=()=>{document.querySelectorAll(".filter-btn").forEach(e=>{e.addEventListener("click",()=>{a.isLoading||(a.currentFilter=e.dataset.filter,document.querySelectorAll(".filter-btn").forEach(e=>e.classList.remove("active")),e.classList.add("active"),l())})})},r=(e,t)=>{let n;return(...a)=>{clearTimeout(n),n=setTimeout(()=>e.apply(this,a),t)}};n.addEventListener("input",r(()=>{a.currentSearch=n.value.trim(),l()},500));const l=()=>{e.innerHTML="",a.currentPage=1,a.totalPages=1,a.galleryItems=[],window.scrollTo(0,0),d()},d=async()=>{if(a.isLoading||a.currentPage>a.totalPages)return;a.isLoading=!0,t.style.display="block",t.textContent="正在加载...";const n=new URLSearchParams({category:a.currentFilter,search:a.currentSearch,page:a.currentPage,limit:15}),o=await i(`/api/images/public?${n.toString()}`);a.isLoading=!1,o?(0===o.images.length&&1===a.currentPage?t.textContent="没有找到图片。":t.style.display="none",a.totalPages=o.totalPages,s(o.images),a.currentPage++):t.style.display="none"},s=t=>{const n=document.createDocumentFragment();t.forEach(t=>{const i=document.createElement("div");i.className="grid-item",i.dataset.index=a.galleryItems.length;const o=document.createElement("img");o.src="data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7",o.dataset.src=t.path_thumb,o.alt=t.description,o.onload=()=>{i.style.backgroundColor="transparent",i.classList.add("is-visible")},i.appendChild(o),n.appendChild(i),a.galleryItems.push(t),u.observe(i)}),e.appendChild(n)},u=new IntersectionObserver((e,t)=>{e.forEach(e=>{if(e.isIntersecting){const n=e.target,a=n.querySelector("img");a.src=a.dataset.src,t.unobserve(n)}})},{rootMargin:"0px 0px 300px 0px"}),m=document.querySelector(".lightbox"),p=m.querySelector(".lightbox-image"),h=m.querySelector(".lb-counter"),g=m.querySelector(".lb-prev"),f=m.querySelector(".lb-next"),b=m.querySelector(".lb-close"),y=m.querySelector(".lb-download");e.addEventListener("click",e=>{const t=e.target.closest(".grid-item");t&&(a.currentLightboxIndex=parseInt(t.dataset.index),k(),m.classList.add("active"),document.body.classList.add("lightbox-open"))});const k=()=>{if(0===a.galleryItems.length)return;const e=a.galleryItems[a.currentLightboxIndex];p.src=e.path_display,p.alt=e.description,y.href=e.path_orig,h.textContent=`${a.currentLightboxIndex+1} / ${a.galleryItems.length}`},v=()=>{a.currentLightboxIndex=(a.currentLightboxIndex-1+a.galleryItems.length)%a.galleryItems.length,k()},w=()=>{a.currentLightboxIndex=(a.currentLightboxIndex+1)%a.galleryItems.length,k()},L=()=>{m.classList.remove("active"),document.body.classList.remove("lightbox-open")};g.addEventListener("click",v),f.addEventListener("click",w),b.addEventListener("click",L),m.addEventListener("click",e=>e.target===m&&L()),document.addEventListener("keydown",e=>{m.classList.contains("active")&&("ArrowLeft"===e.key&&v(),"ArrowRight"===e.key&&w(),"Escape"===e.key&&L())});constE=document.querySelector(".back-to-top"),S=document.querySelector(".header-sticky");window.addEventListener("scroll",()=>{window.innerHeight+window.scrollY>=document.body.offsetHeight-500&&!a.isLoading&&d();const e=window.scrollY>50;E.classList.toggle("visible",window.scrollY>300),S.classList.toggle("state-scrolled-partially",e)},{passive:!0}),E.addEventListener("click",()=>window.scrollTo({top:0,behavior:"smooth"})),(async()=>{await o(),await d()})()});
</script></body></html>
EOF
cat << 'EOF' > public/login.html
<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>后台登录 - 图片画廊</title><script src="https://cdn.tailwindcss.com"></script><style> body { background-color: #f0fdf4; } </style></head><body class="antialiased text-green-900"><div class="min-h-screen flex items-center justify-center p-4"><div class="max-w-md w-full bg-white p-8 rounded-lg shadow-lg"><h1 class="text-3xl font-bold text-center text-green-900 mb-6">后台管理登录</h1><div id="error-message" class="hidden bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative mb-4" role="alert"><strong class="font-bold">登录失败！</strong><span id="error-text" class="block sm:inline"></span></div><form action="/api/auth/login" method="POST"><div class="mb-4"><label for="username" class="block text-green-800 text-sm font-bold mb-2">用户名</label><input type="text" id="username" name="username" required class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:ring-2 focus:ring-green-500"></div><div class="mb-6"><label for="password" class="block text-green-800 text-sm font-bold mb-2">密码</label><input type="password" id="password" name="password" required class="shadow appearance-none border rounded w-full py-2 px-3 text-gray-700 mb-3 leading-tight focus:outline-none focus:ring-2 focus:ring-green-500"></div><div class="flex items-center justify-between"><button type="submit" class="w-full bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded-lg focus:outline-none focus:shadow-outline transition-colors"> 登 录 </button></div></form></div></div><script> const urlParams = new URLSearchParams(window.location.search); const error = urlParams.get('error'); if (error) { document.getElementById('error-text').textContent = decodeURIComponent(error); document.getElementById('error-message').classList.remove('hidden'); } </script></body></html>
EOF

    echo -e "${GREEN}--- 所有项目文件已成功生成在 ${INSTALL_DIR} ---${NC}"
}

# --- [v8.3] 管理菜单功能 (菜单显示优化) ---
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
    local PORT=${port:-3000}; local USER=${username:-admin}
    if [ -z "$password" ]; then echo -e "${RED}密码不能为空！安装中止。${NC}"; return 1; fi
    echo -e "${YELLOW}--> 正在生成 .env 配置文件...${NC}"
    local JWT_SECRET; JWT_SECRET=$(head /dev/urandom | tr -dc A-Za-z0-9 | head -c 32)
    echo "PORT=${PORT}" > .env; echo "JWT_SECRET=${JWT_SECRET}" >> .env; echo "ADMIN_USERNAME=${USER}" >> .env; echo "ADMIN_PASSWORD=${password}" >> .env
    echo -e "${YELLOW}--> 正在安装项目依赖 (npm install)...${NC}"; npm install
    echo -e "${YELLOW}--> 正在初始化数据库并设置管理员账户...${NC}"; npm run setup
    sed -i '/^ADMIN_PASSWORD=/d' .env
    echo -e "${YELLOW}--> 正在全局安装 PM2...${NC}"; npm install -g pm2
    echo -e "${GREEN}--- 安装完成！正在自动启动应用... ---${NC}"; start_app; display_access_info
}
start_app() {
    cd "${INSTALL_DIR}" || { echo -e "${RED}安装目录未找到!${NC}"; return 1; }
    echo -e "${GREEN}--- 正在启动应用... ---${NC}"
    if ! [ -f ".env" ]; then echo -e "${RED}错误: .env 文件不存在。请先运行安装程序。${NC}"; return 1; fi
    if pm2 info "$APP_NAME" &> /dev/null && [ "$(pm2 info "$APP_NAME" | grep 'status' | awk '{print $4}')" == "online" ]; then
        echo -e "${YELLOW}应用已经在运行中。${NC}"
    else
        pm2 start server.js --name "$APP_NAME"; pm2 startup; pm2 save --force
        echo -e "${GREEN}--- 应用已启动！---${NC}"
    fi
}
stop_app() { echo -e "${YELLOW}--- 正在停止应用... ---${NC}"; pm2 stop "$APP_NAME" > /dev/null; echo -e "${GREEN}--- 应用已停止！---${NC}"; }
restart_app() { echo -e "${GREEN}--- 正在重启应用... ---${NC}"; pm2 restart "$APP_NAME"; echo -e "${GREEN}--- 应用已重启！---${NC}"; }
view_logs() { echo -e "${YELLOW}--- 显示应用日志 (按 Ctrl+C 退出)... ---${NC}"; pm2 logs "$APP_NAME"; }
manage_credentials() {
    cd "${INSTALL_DIR}" || { echo -e "${RED}安装目录未找到!${NC}"; return 1; }
    echo -e "${YELLOW}--- 修改账号和密码 ---${NC}";
    if ! [ -f ".env" ]; then echo -e "${RED}错误: .env 文件不存在。请先安装应用。${NC}"; return 1; fi;
    local CURRENT_USER; CURRENT_USER=$(grep 'ADMIN_USERNAME=' .env | cut -d '=' -f2);
    echo "当前用户名: ${CURRENT_USER}"; read -p "请输入新的用户名 (留空则不修改): " new_username; read -sp "请输入新的密码 (必填): " new_password; echo
    if [ -z "$new_password" ]; then echo -e "${RED}密码不能为空！操作取消。${NC}"; return 1; fi;
    local FINAL_USER=${new_username:-$CURRENT_USER}
    echo "ADMIN_USERNAME=${FINAL_USER}" >> .env; echo "ADMIN_PASSWORD=${new_password}" >> .env
    echo "--> 正在更新凭据..."; npm run setup
    sed -i '/^ADMIN_PASSWORD=/d' .env; sed -i '/^ADMIN_USERNAME=/d' .env; echo "ADMIN_USERNAME=${FINAL_USER}" >> .env
    echo -e "${GREEN}凭据已更新。${NC}"; echo -e "${YELLOW}正在重启应用以使更改生效...${NC}"; restart_app;
}
backup_app() {
    cd "${INSTALL_DIR}" || { echo -e "${RED}安装目录未找到!${NC}"; return 1; }
    echo -e "${YELLOW}--- 开始备份应用 ---${NC}"; mkdir -p "${BACKUP_DIR}"
    local BACKUP_FILE="${BACKUP_DIR}/gallery-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
    echo "--> 正在创建备份文件: ${BACKUP_FILE}"
    tar -czf "${BACKUP_FILE}" "./public/uploads" "./data/${DB_FILE}"
    if [ $? -eq 0 ]; then echo -e "${GREEN}备份成功! 文件保存在: ${BACKUP_FILE}${NC}"; else echo -e "${RED}备份失败!${NC}"; fi
}
restore_app() {
    echo -e "${YELLOW}--- 开始恢复应用 ---${NC}"
    if [ ! -d "${BACKUP_DIR}" ] || [ -z "$(ls -A "${BACKUP_DIR}")" ]; then echo -e "${RED}没有找到备份文件或备份目录! (${BACKUP_DIR})${NC}"; return 1; fi
    echo "可用备份文件:"; select backup_file in "${BACKUP_DIR}"/*.tar.gz; do if [ -n "${backup_file}" ]; then break; else echo "无效选择。"; fi; done
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
        echo "--> 正在从 PM2 中删除应用..."; pm2 delete "$APP_NAME" || echo "PM2中未找到应用，继续..."; pm2 save --force
        echo "--> 正在删除项目文件夹 ${INSTALL_DIR}..."; rm -rf "${INSTALL_DIR}"
        if [ -d "${BACKUP_DIR}" ]; then
            read -p "是否也要删除备份文件夹 ${BACKUP_DIR}? (y/n): " del_backup
            if [[ "$del_backup" == "y" || "$del_backup" == "Y" ]]; then rm -rf "${BACKUP_DIR}"; echo "--> 备份文件夹已删除。"; fi
        fi
        echo -e "${GREEN}应用已彻底卸载。${NC}"
    else echo "操作已取消。"; fi
}
display_access_info() {
    cd "${INSTALL_DIR}" || return; local SERVER_IP; SERVER_IP=$(hostname -I | awk '{print $1}');
    if [ -f ".env" ]; then
        local PORT; PORT=$(grep 'PORT=' .env | cut -d '=' -f2); local USER; USER=$(grep 'ADMIN_USERNAME=' .env | cut -d '=' -f2);
        echo -e "${YELLOW}======================================================${NC}"; echo -e "${YELLOW}            应用已就绪！请使用以下信息访问            ${NC}"; echo -e "${YELLOW}======================================================${NC}"
        echo -e "前台画廊地址: ${GREEN}http://${SERVER_IP}:${PORT}${NC}"; echo -e "后台管理地址: ${GREEN}http://${SERVER_IP}:${PORT}/admin${NC}";
        echo -e "后台登录用户: ${BLUE}${USER}${NC}"; echo -e "后台登录密码: ${BLUE}(您在安装时设置的密码)${NC}";
        echo -e "${YELLOW}======================================================${NC}"
    fi
}
show_menu() {
    clear
    echo -e "${BLUE}======================================================${NC}"
    echo -e "${BLUE}      图片画廊 - 旗舰增强版 (v8.3)      ${NC}"
    echo -e "${BLUE}======================================================${NC}"
    echo -e " 应用名称: ${GREEN}${APP_NAME}${NC}"
    echo -e " 安装路径: ${GREEN}${INSTALL_DIR}${NC}"
    # [v8.3] Enhanced Status Display
    if pm2 info "$APP_NAME" &> /dev/null && [ "$(pm2 info "$APP_NAME" | grep 'status' | awk '{print $4}')" == "online" ]; then
        echo -e " 应用状态: ${GREEN}运行中${NC}"
        if [ -f "${INSTALL_DIR}/.env" ]; then
            local SERVER_IP; SERVER_IP=$(hostname -I | awk '{print $1}')
            local PORT; PORT=$(grep 'PORT=' "${INSTALL_DIR}/.env" | cut -d '=' -f2)
            echo -e "   ├─ 前台地址: ${GREEN}http://${SERVER_IP}:${PORT}${NC}"
            echo -e "   └─ 后台地址: ${GREEN}http://${SERVER_IP}:${PORT}/admin${NC}"
        fi
    else
        echo -e " 应用状态: ${RED}已停止${NC}"
    fi
    echo -e "${BLUE}------------------------------------------------------${NC}"
    echo -e " 1. 安装或修复应用 (首次使用)      6. 修改账号和密码"
    echo -e " 2. 启动应用                       7. 备份数据"
    echo -e " 3. 停止应用                       8. 恢复数据"
    echo -e " 4. 重启应用"
    echo -e " 5. 查看实时日志                   9. ${RED}彻底卸载应用${NC}"
    echo -e " 0. 退出"
    echo -e "${BLUE}------------------------------------------------------${NC}"
    read -p "请输入你的选择 [0-9]: " choice
    case $choice in
        1) install_app ;; 2) start_app; ;; 3) stop_app ;; 4) restart_app ;; 5) view_logs ;; 6) manage_credentials ;; 7) backup_app ;; 8) restore_app ;; 9) uninstall_app ;; 0) exit 0 ;; *) echo -e "\n${RED}无效输入...${NC}" ;;
    esac
    read -n 1 -s -r -p $'\n按任意键返回主菜单...'
}
while true; do show_menu; done
