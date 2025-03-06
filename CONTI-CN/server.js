require('dotenv').config();

const express = require('express');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const ejs = require('ejs');
const multer = require('multer');
const nodemailer = require('nodemailer');
const cors = require('cors');

// 添加域名配置
const DOMAIN = process.env.DOMAIN || 'http://3.22.241.231';
const BASE_URL = process.env.BASE_URL || DOMAIN;

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const ADMIN_PASSWORD = 'ContiTechOrg$%GFEH&*31HSc88JCEBSKkEcesf';
const EMAIL_USER = process.env.EMAIL_USER || 'contitechorg@gmail.com';
const EMAIL_PASS = process.env.EMAIL_PASS || '';

// 基础中间件配置
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname)));
app.use('/uploads', express.static('uploads'));

// 添加CORS配置
app.use(cors({
    origin: function(origin, callback) {
        // 允许所有来源访问
        callback(null, true);
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept'],
    credentials: true
}));

// 添加请求日志中间件
app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.url}`);
    console.log('请求头:', req.headers);
    if (req.body && Object.keys(req.body).length > 0) {
        console.log('请求体:', req.body);
    }
    next();
});

// 配置文件上传
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadDir = 'uploads';
        if (!fs.existsSync(uploadDir)) {
            fs.mkdirSync(uploadDir);
        }
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ 
    storage: storage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 限制5MB
    },
    fileFilter: function (req, file, cb) {
        if (!file.originalname.match(/\.(jpg|jpeg|png|gif|bmp)$/i)) {
            return cb(new Error('只允许上传图片文件！(支持jpg、jpeg、png、gif、bmp格式)'));
        }
        cb(null, true);
    }
});

// 配置邮件发送
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: EMAIL_USER,
        pass: EMAIL_PASS
    },
    debug: true,
    logger: true,
    secure: true
});

// 验证邮件配置
transporter.verify(function(error, success) {
    if (error) {
        console.error('邮件服务配置错误:', error);
        console.error('请检查 EMAIL_USER 和 EMAIL_PASS 配置');
        console.error('当前配置:', {
            user: EMAIL_USER,
            pass: EMAIL_PASS ? '已设置' : '未设置'
        });
    } else {
        console.log('邮件服务配置成功，准备发送邮件');
    }
});

// 在顶部添加未捕获异常处理
process.on('uncaughtException', (err) => {
    console.error('未捕获的异常:', err);
    // 记录错误但不退出进程
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('未处理的 Promise 拒绝:', reason);
    // 记录错误但不退出进程
});

// 在数据库连接部分添加重试逻辑
const connectDB = (retries = 5) => {
    return new Promise((resolve, reject) => {
        const db = new sqlite3.Database('news.db', (err) => {
            if (err) {
                console.error('数据库连接失败:', err);
                if (retries > 0) {
                    console.log(`剩余重试次数: ${retries}，3秒后重试...`);
                    setTimeout(() => {
                        resolve(connectDB(retries - 1));
                    }, 3000);
                } else {
                    reject(err);
                }
            } else {
                console.log('数据库连接成功');
                resolve(db);
            }
        });
    });
};

// 创建数据库连接
const db = new sqlite3.Database('news.db', (err) => {
    if (err) {
        console.error('----------------------------------------');
        console.error('数据库连接错误:', err);
        console.error('----------------------------------------');
        process.exit(1);
    } else {
        console.log('----------------------------------------');
        console.log('成功连接到数据库');
        
        // 初始化所有数据表
        db.serialize(() => {
            // 创建新闻表
            db.run(`CREATE TABLE IF NOT EXISTS news (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                image_url TEXT,
                date TEXT NOT NULL
            )`, (err) => {
                if (err) {
                    console.error('创建新闻表失败:', err);
                    process.exit(1);
                } else {
                    console.log('新闻表创建或已存在');
                }
            });

            // 创建新闻订阅者表
            db.run(`CREATE TABLE IF NOT EXISTS subscribers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                status TEXT DEFAULT 'active',
                subscription_date TEXT NOT NULL
            )`, (err) => {
                if (err) {
                    console.error('创建新闻订阅者表失败:', err);
                } else {
                    console.log('新闻订阅者表创建或已存在');
                }
            });

            // 创建岗位表
            db.run(`CREATE TABLE IF NOT EXISTS positions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                type TEXT NOT NULL,
                description TEXT NOT NULL,
                requirements TEXT NOT NULL,
                responsibilities TEXT NOT NULL,
                date TEXT NOT NULL
            )`, (err) => {
                if (err) {
                    console.error('创建岗位表失败:', err);
                } else {
                    console.log('岗位表创建或已存在');
                }
            });

            // 创建岗位订阅者表
            db.run(`CREATE TABLE IF NOT EXISTS positions_subscribers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                status TEXT DEFAULT 'active',
                subscription_date TEXT NOT NULL
            )`, (err) => {
                if (err) {
                    console.error('创建岗位订阅者表失败:', err);
                } else {
                    console.log('岗位订阅者表创建或已存在');
                }
            });

            // 创建项目表
            db.run(`CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                category TEXT NOT NULL,
                status TEXT NOT NULL,
                blocks TEXT NOT NULL,
                date TEXT NOT NULL
            )`, (err) => {
                if (err) {
                    console.error('创建项目表失败:', err);
                } else {
                    console.log('项目表创建或已存在');
                    
                    // 检查项目表是否有数据
                    db.get('SELECT COUNT(*) as count FROM projects', [], (err, row) => {
                        if (err) {
                            console.error('检查项目数量失败:', err);
                            return;
                        }
                        
                        // 如果没有数据，插入一些示例数据
                        if (row.count === 0) {
                            console.log('项目表为空，插入示例数据');
                            
                            const sampleProject = {
                                title: '示例项目',
                                category: '自然语言处理',
                                status: '进行中',
                                blocks: JSON.stringify([
                                    {
                                        type: 'text',
                                        content: '这是一个示例项目，用于测试系统功能。'
                                    }
                                ]),
                                date: new Date().toISOString()
                            };
                            
                            db.run('INSERT INTO projects (title, category, status, blocks, date) VALUES (?, ?, ?, ?, ?)',
                                [sampleProject.title, sampleProject.category, sampleProject.status, sampleProject.blocks, sampleProject.date],
                                function(err) {
                                    if (err) {
                                        console.error('插入示例项目失败:', err);
                                    } else {
                                        console.log('示例项目插入成功，ID:', this.lastID);
                                    }
                                }
                            );
                        } else {
                            console.log(`项目表中已有 ${row.count} 条数据`);
                        }
                    });
                }
            });

            // 所有表创建完成后启动服务器
            startServer(PORT);
        });
    }
});

// 数据库操作函数
async function saveToDatabase(newsItem) {
    return new Promise((resolve, reject) => {
        console.log('开始数据库保存操作');
        const { title, content, image_url, date } = newsItem;
        
        if (!title || !content || !date) {
            const error = new Error('缺少必要的新闻数据');
            console.error('数据库验证失败:', error);
            reject(error);
            return;
        }

        db.run(
            'INSERT INTO news (title, content, image_url, date) VALUES (?, ?, ?, ?)',
            [title, content, image_url, date],
            function(err) {
                if (err) {
                    console.error('数据库插入失败:', err);
                    reject(err);
                } else {
                    console.log('数据库插入成功，ID:', this.lastID);
                    resolve(this.lastID);
                }
            }
        );
    });
}

async function getNewsFromDatabase() {
    return new Promise((resolve, reject) => {
        db.all('SELECT * FROM news ORDER BY date DESC', [], (err, rows) => {
            if (err) reject(err);
            else resolve(rows);
        });
    });
}

// 更新HTML文件的函数
async function updateNewsHtmlFile() {
    try {
        console.log('开始更新HTML文件');
        const news = await getNewsFromDatabase();
        console.log('获取到新闻数据:', news.length, '条');
        
        const templatePath = path.join(__dirname, 'views', 'news.ejs');
        if (!fs.existsSync(templatePath)) {
            throw new Error('找不到模板文件: ' + templatePath);
        }
        
        const template = fs.readFileSync(templatePath, 'utf8');
        const html = ejs.render(template, { news });
        
        const outputPath = path.join(__dirname, 'news.html');
        fs.writeFileSync(outputPath, html);
        console.log('HTML文件更新成功:', outputPath);
    } catch (error) {
        console.error('更新HTML文件失败:', error);
        throw error;
    }
}

// 添加域名中间件
app.use((req, res, next) => {
    res.locals.domain = DOMAIN;
    res.locals.baseUrl = BASE_URL;
    next();
});

// 添加API路由中间件
app.use('/api', (req, res, next) => {
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    next();
});

// 根路由测试
app.get('/', (req, res) => {
    res.json({ message: '服务器正在运行' });
});

// 测试数据库连接
app.get('/api/test-db', (req, res) => {
    // 插入测试数据
    console.log('开始数据库测试...');
    const testNews = {
        title: '测试新闻',
        content: '这是一条测试新闻',
        date: new Date().toISOString()
    };
    
    console.log('准备插入测试数据:', testNews);
    console.log('开始数据库保存操作');
    
    db.run('INSERT INTO news (title, content, date) VALUES (?, ?, ?)',
        [testNews.title, testNews.content, testNews.date],
        function(err) {
            if (err) {
                console.error('数据库插入失败:', err);
                return res.status(500).json({
                    success: false,
                    error: err.message
                });
            }
            
            console.log('数据库插入成功，ID:', this.lastID);
            const insertedId = this.lastID;
            
            // 查询测试数据
            console.log('测试数据插入成功，ID:', insertedId);
            console.log('准备查询数据...');
            
            db.get('SELECT COUNT(*) as count FROM news', [], (err, row) => {
                if (err) {
                    console.error('数据库查询失败:', err);
                    return res.status(500).json({
                        success: false,
                        error: err.message
                    });
                }
                
                console.log('测试数据查询成功，新闻数量:', row.count);
                
                db.get('SELECT * FROM news ORDER BY id DESC LIMIT 1', [], (err, latestNews) => {
                    if (err) {
                        console.error('获取最新新闻失败:', err);
                        return res.status(500).json({
                            success: false,
                            error: err.message
                        });
                    }
                    
                    res.json({
                        success: true,
                        message: '数据库测试成功',
                        newsCount: row.count,
                        latestNews
                    });
                });
            });
        }
    );
});

// 管理员登录
app.post('/api/admin/login', (req, res) => {
    console.log('收到登录请求:', req.body);
    const { password } = req.body;

    if (!password) {
        console.log('登录失败：密码为空');
        return res.status(400).json({ 
            success: false, 
            error: '请输入密码' 
        });
    }

    if (password === ADMIN_PASSWORD) {
        const token = jwt.sign({ admin: true }, JWT_SECRET, { expiresIn: '24h' });
        console.log('登录成功，生成token');
        res.json({ 
            success: true, 
            token,
            message: '登录成功' 
        });
    } else {
        console.log('登录失败：密码错误');
        res.status(401).json({ 
            success: false, 
            error: '密码错误' 
        });
    }
});

// 验证管理员Token的中间件
const verifyAdminToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ error: '未提供认证token' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        if (decoded.admin) {
            next();
        } else {
            res.status(403).json({ error: '无权限访问' });
        }
    } catch (err) {
        res.status(401).json({ error: 'token无效或已过期' });
    }
};

// 新闻管理路由
let newsItems = [];

// 订阅相关的数据库函数
async function addSubscriber(email) {
    return new Promise((resolve, reject) => {
        const date = new Date().toISOString();
        
        // 先检查是否存在
        db.get('SELECT * FROM subscribers WHERE email = ?', [email], (err, row) => {
            if (err) {
                reject(err);
                return;
            }
            
            if (row) {
                if (row.status === 'inactive') {
                    // 如果存在但是未激活，则重新激活
                    db.run(
                        'UPDATE subscribers SET status = ?, subscription_date = ? WHERE email = ?',
                        ['active', date, email],
                        function(err) {
                            if (err) reject(err);
                            else resolve(this.lastID);
                        }
                    );
                } else {
                    reject(new Error('该邮箱已经订阅'));
                }
            } else {
                // 如果不存在，创建新订阅
                db.run(
                    'INSERT INTO subscribers (email, status, subscription_date) VALUES (?, ?, ?)',
                    [email, 'active', date],
                    function(err) {
                        if (err) reject(err);
                        else resolve(this.lastID);
                    }
                );
            }
        });
    });
}

async function removeSubscriber(email) {
    return new Promise((resolve, reject) => {
        db.run(
            'UPDATE subscribers SET status = ? WHERE email = ?',
            ['inactive', email],
            function(err) {
                if (err) {
                    reject(err);
                } else if (this.changes === 0) {
                    reject(new Error('未找到该订阅邮箱'));
                } else {
                    resolve(true);
                }
            }
        );
    });
}

async function getActiveSubscribers() {
    return new Promise((resolve, reject) => {
        db.all(
            'SELECT email FROM subscribers WHERE status = ?',
            ['active'],
            (err, rows) => {
                if (err) reject(err);
                else resolve(rows.map(row => row.email));
            }
        );
    });
}

// 订阅路由
app.post('/api/subscribe', async (req, res) => {
    try {
        const { email } = req.body;
        console.log('收到订阅请求:', email);
        
        if (!email) {
            console.log('订阅失败：邮箱地址为空');
            return res.status(400).json({ success: false, error: '邮箱地址不能为空' });
        }

        console.log('开始添加订阅者到数据库...');
        await addSubscriber(email);
        console.log('订阅者添加成功');
        
        // 发送欢迎邮件
        try {
            console.log('开始发送欢迎邮件...');
            const info = await transporter.sendMail({
                from: {
                    name: 'CONTI News',
                    address: EMAIL_USER
                },
                to: email,
                subject: '欢迎订阅 CONTI 新闻',
                html: `
                    <h2>感谢您订阅 CONTI 新闻！</h2>
                    <p>您将收到我们的最新动态和更新。</p>
                    <p>如果想要取消订阅，请访问我们的网站。</p>
                `
            });
            console.log('欢迎邮件发送成功:', info.response);
            console.log('预览URL:', nodemailer.getTestMessageUrl(info));
        } catch (emailError) {
            console.error('发送欢迎邮件失败:', emailError);
            // 继续执行，不影响订阅流程
        }

        res.json({ success: true, message: '订阅成功' });
    } catch (error) {
        console.error('订阅处理失败:', error);
        res.status(400).json({ success: false, error: error.message });
    }
});

app.post('/api/unsubscribe', async (req, res) => {
    try {
        const { email } = req.body;
        console.log('收到取消订阅请求:', email);
        
        if (!email) {
            console.log('取消订阅失败：邮箱地址为空');
            return res.status(400).json({ success: false, error: '邮箱地址不能为空' });
        }

        console.log('开始从数据库中更新订阅状态...');
        await removeSubscriber(email);
        console.log('订阅状态更新成功');

        res.json({ success: true, message: '已取消订阅' });
    } catch (error) {
        console.error('取消订阅处理失败:', error);
        res.status(400).json({ success: false, error: error.message });
    }
});

// 添加一个用于测试的路由，查看所有订阅者
app.get('/api/subscribers', async (req, res) => {
    try {
        const subscribers = await new Promise((resolve, reject) => {
            db.all('SELECT * FROM subscribers', [], (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        });
        res.json({ success: true, subscribers });
    } catch (error) {
        console.error('获取订阅者列表失败:', error);
        res.status(500).json({ success: false, error: error.message });
    }
});

// 修改新闻发布路由，添加邮件通知
const oldPostNews = app.post.bind(app, '/api/admin/news');
app.post('/api/admin/news', verifyAdminToken, upload.single('image'), async (req, res) => {
    try {
        console.log('收到新闻发布请求');
        console.log('请求体:', req.body);
        console.log('文件信息:', req.file);

        const { title, content } = req.body;
        const image_url = req.file ? `/uploads/${req.file.filename}` : null;

        console.log('准备插入数据库的数据:', {
            title,
            content,
            image_url
        });

        const stmt = db.prepare('INSERT INTO news (title, content, image_url, date) VALUES (?, ?, ?, ?)');
        try {
            const result = stmt.run(title, content, image_url, new Date().toISOString());
            console.log('数据库插入结果:', result);

            // 获取活跃订阅者并发送邮件通知
            try {
                const subscribers = await getActiveSubscribers();
                console.log('正在向订阅者发送通知:', subscribers);

                if (subscribers.length > 0) {
                    const mailOptions = {
                        from: {
                            name: 'CONTI News',
                            address: EMAIL_USER
                        },
                        subject: `CONTI 新闻更新: ${title}`,
                        html: `
                            <h2>${title}</h2>
                            <p>${content}</p>
                            ${image_url ? `<img src="${BASE_URL}${image_url}" alt="新闻图片" style="max-width: 600px;">` : ''}
                            <p><a href="${BASE_URL}/news">查看更多新闻</a></p>
                            <hr>
                            <p>如果想要取消订阅，请访问我们的网站。</p>
                        `
                    };

                    // 分别发送给每个订阅者
                    for (const email of subscribers) {
                        try {
                            mailOptions.to = email;
                            console.log(`正在发送邮件到: ${email}`);
                            const info = await transporter.sendMail(mailOptions);
                            console.log('邮件发送成功:', info.response);
                            console.log('预览URL:', nodemailer.getTestMessageUrl(info));
                        } catch (emailError) {
                            console.error('发送邮件失败:', email);
                            console.error('错误详情:', emailError);
                        }
                    }
                }
            } catch (emailError) {
                console.error('处理邮件通知时出错:', emailError);
                // 不影响新闻发布的成功状态
            }

            res.json({ success: true, message: '新闻发布成功' });
        } catch (dbError) {
            console.error('数据库错误:', dbError);
            res.status(500).json({ success: false, error: '数据库操作失败: ' + dbError.message });
        }
    } catch (error) {
        console.error('服务器错误:', error);
        res.status(500).json({ success: false, error: '发布新闻失败: ' + error.message });
    }
});

app.get('/api/admin/news', verifyAdminToken, async (req, res) => {
    try {
        const news = await getNewsFromDatabase();
        res.json(news);
    } catch (error) {
        console.error('获取新闻列表失败:', error);
        res.status(500).json({ error: '获取新闻列表失败' });
    }
});

// 动态新闻页面路由
app.get('/news', async (req, res) => {
    try {
        const news = await getNewsFromDatabase();
        res.render('news', { news });
    } catch (error) {
        console.error('渲染新闻页面失败:', error);
        res.status(500).send('服务器错误');
    }
});

// 更新新闻
app.put('/api/admin/news/:id', verifyAdminToken, upload.single('image'), async (req, res) => {
    try {
        const { id } = req.params;
        const { title, content, currentImage } = req.body;
        const image_url = req.file ? `/uploads/${req.file.filename}` : currentImage;
        const date = new Date().toISOString();

        // 如果上传了新图片，删除旧图片
        if (req.file && currentImage) {
            const oldImagePath = path.join(__dirname, currentImage);
            if (fs.existsSync(oldImagePath)) {
                fs.unlinkSync(oldImagePath);
            }
        }

        await new Promise((resolve, reject) => {
            db.run(
                'UPDATE news SET title = ?, content = ?, image_url = ?, date = ? WHERE id = ?',
                [title, content, image_url, date, id],
                function(err) {
                    if (err) reject(err);
                    else resolve();
                }
            );
        });

        await updateNewsHtmlFile();
        res.json({ success: true });
    } catch (error) {
        console.error('更新新闻失败:', error);
        if (req.file) {
            fs.unlinkSync(req.file.path);
        }
        res.status(500).json({ success: false, error: '更新新闻失败' });
    }
});

// 删除新闻
app.delete('/api/admin/news/:id', verifyAdminToken, async (req, res) => {
    try {
        const { id } = req.params;

        await new Promise((resolve, reject) => {
            db.run('DELETE FROM news WHERE id = ?', [id], function(err) {
                if (err) reject(err);
                else resolve();
            });
        });

        await updateNewsHtmlFile();
        res.json({ success: true });
    } catch (error) {
        console.error('删除新闻失败:', error);
        res.status(500).json({ success: false, error: '删除新闻失败' });
    }
});

// 岗位管理路由
app.get('/api/admin/positions', verifyAdminToken, async (req, res) => {
    try {
        const positions = await new Promise((resolve, reject) => {
            db.all('SELECT * FROM positions ORDER BY date DESC', [], (err, rows) => {
                if (err) reject(err);
                else resolve(rows.map(row => ({
                    ...row,
                    requirements: JSON.parse(row.requirements),
                    responsibilities: JSON.parse(row.responsibilities)
                })));
            });
        });
        res.json({ success: true, positions });
    } catch (error) {
        console.error('获取岗位列表失败:', error);
        res.status(500).json({ success: false, error: '获取岗位列表失败' });
    }
});

// 岗位订阅相关的数据库函数
async function addPositionSubscriber(email) {
    return new Promise((resolve, reject) => {
        const date = new Date().toISOString();
        
        // 先检查是否存在
        db.get('SELECT * FROM positions_subscribers WHERE email = ?', [email], (err, row) => {
            if (err) {
                reject(err);
                return;
            }
            
            if (row) {
                if (row.status === 'inactive') {
                    // 如果存在但是未激活，则重新激活
                    db.run(
                        'UPDATE positions_subscribers SET status = ?, subscription_date = ? WHERE email = ?',
                        ['active', date, email],
                        function(err) {
                            if (err) reject(err);
                            else resolve(this.lastID);
                        }
                    );
                } else {
                    reject(new Error('该邮箱已经订阅'));
                }
            } else {
                // 如果不存在，创建新订阅
                db.run(
                    'INSERT INTO positions_subscribers (email, status, subscription_date) VALUES (?, ?, ?)',
                    [email, 'active', date],
                    function(err) {
                        if (err) reject(err);
                        else resolve(this.lastID);
                    }
                );
            }
        });
    });
}

async function removePositionSubscriber(email) {
    return new Promise((resolve, reject) => {
        db.run(
            'UPDATE positions_subscribers SET status = ? WHERE email = ?',
            ['inactive', email],
            function(err) {
                if (err) {
                    reject(err);
                } else if (this.changes === 0) {
                    reject(new Error('未找到该订阅邮箱'));
                } else {
                    resolve(true);
                }
            }
        );
    });
}

async function getActivePositionSubscribers() {
    return new Promise((resolve, reject) => {
        db.all(
            'SELECT email FROM positions_subscribers WHERE status = ?',
            ['active'],
            (err, rows) => {
                if (err) reject(err);
                else resolve(rows.map(row => row.email));
            }
        );
    });
}

// 岗位订阅路由
app.post('/api/subscribe-positions', verifyAdminToken, async (req, res) => {
    try {
        const { email } = req.body;
        console.log('收到岗位订阅请求:', email);
        
        if (!email) {
            console.log('订阅失败：邮箱地址为空');
            return res.status(400).json({ success: false, error: '邮箱地址不能为空' });
        }

        console.log('开始添加订阅者到数据库...');
        await addPositionSubscriber(email);
        console.log('订阅者添加成功');
        
        // 发送欢迎邮件
        try {
            console.log('开始发送欢迎邮件...');
            const info = await transporter.sendMail({
                from: {
                    name: 'CONTI Technology Organization',
                    address: EMAIL_USER
                },
                to: email,
                subject: 'Welcome to CONTI Job Positions Subscription',
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                        <h2 style="color: #333;">欢迎订阅 CONTI 岗位更新！</h2>
                        <p style="color: #666; line-height: 1.6;">
                            您好！感谢您订阅 CONTI 岗位更新。从现在开始，您将第一时间收到我们的最新职位发布通知。
                        </p>
                        <p style="color: #666; line-height: 1.6;">
                            如果您没有订阅我们的岗位更新，请忽略此邮件。
                        </p>
                        <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #eee;">
                            <p style="color: #999; font-size: 12px;">
                                此邮件由系统自动发送，请勿直接回复。<br>
                                如需取消订阅，请访问我们的网站。
                            </p>
                        </div>
                    </div>
                `
            });
            console.log('欢迎邮件发送成功:', info.response);
        } catch (emailError) {
            console.error('发送欢迎邮件失败:', emailError);
        }

        res.json({ success: true, message: '订阅成功' });
    } catch (error) {
        console.error('订阅处理失败:', error);
        res.status(400).json({ success: false, error: error.message });
    }
});

app.post('/api/unsubscribe-positions', verifyAdminToken, async (req, res) => {
    try {
        const { email } = req.body;
        console.log('收到取消岗位订阅请求:', email);
        
        if (!email) {
            console.log('取消订阅失败：邮箱地址为空');
            return res.status(400).json({ success: false, error: '邮箱地址不能为空' });
        }

        console.log('开始从数据库中更新订阅状态...');
        await removePositionSubscriber(email);
        console.log('订阅状态更新成功');

        res.json({ success: true, message: '已取消订阅' });
    } catch (error) {
        console.error('取消订阅处理失败:', error);
        res.status(400).json({ success: false, error: error.message });
    }
});

// 修改添加岗位的路由，添加邮件通知功能
app.post('/api/admin/positions', verifyAdminToken, async (req, res) => {
    try {
        const { title, type, description, requirements, responsibilities } = req.body;
        const date = new Date().toISOString();
        
        // 确保requirements和responsibilities是数组
        const requirementsArray = Array.isArray(requirements) ? requirements : JSON.parse(requirements);
        const responsibilitiesArray = Array.isArray(responsibilities) ? responsibilities : JSON.parse(responsibilities);
        
        const result = await new Promise((resolve, reject) => {
            db.run(
                'INSERT INTO positions (title, type, description, requirements, responsibilities, date) VALUES (?, ?, ?, ?, ?, ?)',
                [title, type, description, JSON.stringify(requirementsArray), JSON.stringify(responsibilitiesArray), date],
                function(err) {
                    if (err) reject(err);
                    else resolve(this.lastID);
                }
            );
        });

        // 获取活跃订阅者并发送邮件通知
        try {
            const subscribers = await getActivePositionSubscribers();
            console.log('正在向岗位订阅者发送通知:', subscribers);

            if (subscribers.length > 0) {
                const mailOptions = {
                    from: {
                        name: 'CONTI Jobs',
                        address: EMAIL_USER
                    },
                    subject: `CONTI 新岗位发布: ${title}`,
                    html: `
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
                            <h2 style="color: #333;">新岗位发布通知</h2>
                            <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
                                <h3 style="color: #1a73e8; margin-bottom: 10px;">${title}</h3>
                                <span style="display: inline-block; background: #e8f0fe; color: #1a73e8; padding: 4px 12px; border-radius: 16px; font-size: 14px;">${type}</span>
                                <p style="margin: 15px 0;">${description}</p>
                                <h4 style="color: #333;">岗位要求：</h4>
                                <ul>
                                    ${requirementsArray.map(req => `<li>${req}</li>`).join('')}
                                </ul>
                                <h4 style="color: #333;">工作职责：</h4>
                                <ul>
                                    ${responsibilitiesArray.map(resp => `<li>${resp}</li>`).join('')}
                                </ul>
                            </div>
                            <p><a href="${BASE_URL}/join.html" style="color: #1a73e8; text-decoration: none;">查看更多职位并投递简历 →</a></p>
                            <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
                            <p style="color: #999; font-size: 12px;">
                                此邮件由系统自动发送，请勿直接回复。<br>
                                如需取消订阅，请访问我们的网站。
                            </p>
                        </div>
                    `
                };

                // 分别发送给每个订阅者
                for (const email of subscribers) {
                    try {
                        mailOptions.to = email;
                        console.log(`正在发送邮件到: ${email}`);
                        const info = await transporter.sendMail(mailOptions);
                        console.log('邮件发送成功:', info.response);
                    } catch (emailError) {
                        console.error('发送邮件失败:', email);
                        console.error('错误详情:', emailError);
                    }
                }
            }
        } catch (emailError) {
            console.error('处理邮件通知时出错:', emailError);
            console.error('错误详情:', emailError);
        }
        
        res.json({ success: true, message: '岗位添加成功' });
    } catch (error) {
        console.error('添加岗位失败:', error);
        res.status(500).json({ success: false, error: '添加岗位失败' });
    }
});

app.get('/api/admin/positions/:id', verifyAdminToken, async (req, res) => {
    try {
        const { id } = req.params;
        const position = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM positions WHERE id = ?', [id], (err, row) => {
                if (err) reject(err);
                else if (!row) reject(new Error('岗位不存在'));
                else resolve({
                    ...row,
                    requirements: JSON.parse(row.requirements),
                    responsibilities: JSON.parse(row.responsibilities)
                });
            });
        });
        res.json({ success: true, position });
    } catch (error) {
        console.error('获取岗位详情失败:', error);
        res.status(500).json({ success: false, error: '获取岗位详情失败' });
    }
});

app.put('/api/admin/positions/:id', verifyAdminToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { title, type, description, requirements, responsibilities } = req.body;
        const date = new Date().toISOString();
        
        await new Promise((resolve, reject) => {
            db.run(
                'UPDATE positions SET title = ?, type = ?, description = ?, requirements = ?, responsibilities = ?, date = ? WHERE id = ?',
                [title, type, description, JSON.stringify(requirements), JSON.stringify(responsibilities), date, id],
                function(err) {
                    if (err) reject(err);
                    else if (this.changes === 0) reject(new Error('岗位不存在'));
                    else resolve();
                }
            );
        });
        
        res.json({ success: true, message: '岗位更新成功' });
    } catch (error) {
        console.error('更新岗位失败:', error);
        res.status(500).json({ success: false, error: '更新岗位失败' });
    }
});

app.delete('/api/admin/positions/:id', verifyAdminToken, async (req, res) => {
    try {
        const { id } = req.params;
        
        await new Promise((resolve, reject) => {
            db.run('DELETE FROM positions WHERE id = ?', [id], function(err) {
                if (err) reject(err);
                else if (this.changes === 0) reject(new Error('岗位不存在'));
                else resolve();
            });
        });
        
        res.json({ success: true, message: '岗位删除成功' });
    } catch (error) {
        console.error('删除岗位失败:', error);
        res.status(500).json({ success: false, error: '删除岗位失败' });
    }
});

// 公开的岗位列表路由（不需要认证）
app.get('/api/positions', async (req, res) => {
    try {
        const positions = await new Promise((resolve, reject) => {
            db.all('SELECT * FROM positions ORDER BY date DESC', [], (err, rows) => {
                if (err) reject(err);
                else resolve(rows.map(row => ({
                    ...row,
                    requirements: JSON.parse(row.requirements),
                    responsibilities: JSON.parse(row.responsibilities)
                })));
            });
        });
        res.json({ success: true, positions });
    } catch (error) {
        console.error('获取岗位列表失败:', error);
        res.status(500).json({ success: false, error: '获取岗位列表失败' });
    }
});

// 项目管理路由
app.get('/api/admin/projects', verifyAdminToken, async (req, res) => {
    try {
        const projects = await new Promise((resolve, reject) => {
            db.all('SELECT * FROM projects ORDER BY date DESC', [], (err, rows) => {
                if (err) reject(err);
                else resolve(rows.map(row => ({
                    ...row,
                    blocks: JSON.parse(row.blocks)
                })));
            });
        });
        res.json({ success: true, projects });
    } catch (error) {
        console.error('获取项目列表失败:', error);
        res.status(500).json({ success: false, error: '获取项目列表失败' });
    }
});

app.post('/api/admin/projects', verifyAdminToken, async (req, res) => {
    try {
        const { title, category, status, blocks } = req.body;
        const date = new Date().toISOString();

        const result = await new Promise((resolve, reject) => {
            db.run(
                'INSERT INTO projects (title, category, status, blocks, date) VALUES (?, ?, ?, ?, ?)',
                [title, category, status, JSON.stringify(blocks), date],
                function(err) {
                    if (err) reject(err);
                    else resolve(this.lastID);
                }
            );
        });

        res.json({ success: true, id: result });
    } catch (error) {
        console.error('添加项目失败:', error);
        res.status(500).json({ success: false, error: '添加项目失败' });
    }
});

app.get('/api/admin/projects/:id', verifyAdminToken, async (req, res) => {
    try {
        const { id } = req.params;
        const project = await new Promise((resolve, reject) => {
            db.get('SELECT * FROM projects WHERE id = ?', [id], (err, row) => {
                if (err) reject(err);
                else if (!row) reject(new Error('项目不存在'));
                else resolve({
                    ...row,
                    blocks: JSON.parse(row.blocks)
                });
            });
        });
        res.json({ success: true, project });
    } catch (error) {
        console.error('获取项目详情失败:', error);
        res.status(500).json({ success: false, error: '获取项目详情失败' });
    }
});

app.put('/api/admin/projects/:id', verifyAdminToken, async (req, res) => {
    try {
        const { id } = req.params;
        const { title, category, status, blocks } = req.body;
        const date = new Date().toISOString();

        await new Promise((resolve, reject) => {
            db.run(
                'UPDATE projects SET title = ?, category = ?, status = ?, blocks = ?, date = ? WHERE id = ?',
                [title, category, status, JSON.stringify(blocks), date, id],
                function(err) {
                    if (err) reject(err);
                    else if (this.changes === 0) reject(new Error('项目不存在'));
                    else resolve();
                }
            );
        });

        res.json({ success: true });
    } catch (error) {
        console.error('更新项目失败:', error);
        res.status(500).json({ success: false, error: '更新项目失败' });
    }
});

app.delete('/api/admin/projects/:id', verifyAdminToken, async (req, res) => {
    try {
        const { id } = req.params;
        
        await new Promise((resolve, reject) => {
            db.run('DELETE FROM projects WHERE id = ?', [id], function(err) {
                if (err) reject(err);
                else if (this.changes === 0) reject(new Error('项目不存在'));
                else resolve();
            });
        });

        res.json({ success: true });
    } catch (error) {
        console.error('删除项目失败:', error);
        res.status(500).json({ success: false, error: '删除项目失败' });
    }
});

// 获取所有项目
app.get('/api/projects', (req, res) => {
    console.log('收到获取项目列表请求');
    
    // 使用更好的错误处理
    db.all('SELECT * FROM projects ORDER BY date DESC', [], (err, projects) => {
        if (err) {
            console.error('获取项目列表失败:', err);
            return res.status(500).json({
                success: false,
                error: '获取项目列表失败',
                message: err.message
            });
        }
        
        // 确保项目是有效数据
        if (!projects || !Array.isArray(projects)) {
            console.log('项目数据为空或格式不正确');
            return res.json({
                success: true,
                projects: []
            });
        }
        
        // 格式化输出
        const formattedProjects = projects.map(project => {
            try {
                // 解析 blocks 字段，它应该是一个 JSON 字符串
                const blocks = JSON.parse(project.blocks || '[]');
                return {
                    ...project,
                    blocks
                };
            } catch (parseError) {
                console.error('解析项目 blocks 失败:', parseError);
                return {
                    ...project,
                    blocks: []
                };
            }
        });
        
        console.log(`成功获取 ${formattedProjects.length} 个项目`);
        res.json({
            success: true,
            projects: formattedProjects
        });
    });
});

// 图片上传路由
app.post('/api/upload', verifyAdminToken, upload.single('image'), (req, res) => {
    try {
        if (!req.file) {
            throw new Error('没有上传文件');
        }
        res.json({
            success: true,
            url: `/${req.file.path.replace(/\\/g, '/')}`
        });
    } catch (error) {
        console.error('文件上传失败:', error);
        res.status(500).json({ success: false, error: '文件上传失败' });
    }
});

// 添加测试路由
app.get('/api/test-admin', verifyAdminToken, (req, res) => {
    res.json({ 
        success: true, 
        message: '管理员认证成功' 
    });
});

// 修改启动逻辑
const startServer = (port) => {
    return new Promise((resolve, reject) => {
        const server = app.listen(port, '0.0.0.0', () => {
            console.log('----------------------------------------');
            console.log(`服务器启动成功！`);
            console.log(`本地访问: http://localhost:${port}`);
            console.log(`远程访问: http://${process.env.DOMAIN}:${port}`);
            console.log('----------------------------------------');
            resolve(server);
        }).on('error', (err) => {
            console.error('服务器启动失败:', err);
            reject(err);
        });
    });
};

// 直接启动服务器
startServer(PORT);

// 添加错误处理中间件
app.use((err, req, res, next) => {
    console.error('服务器错误:', err);
    res.status(500).json({
        success: false,
        error: '服务器内部错误'
    });
});
