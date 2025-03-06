// 在文件开头添加域名配置
const DOMAIN = process.env.DOMAIN || 'http://3.22.241.231';
const BASE_URL = process.env.BASE_URL || DOMAIN;

// 添加域名中间件
app.use((req, res, next) => {
    res.locals.domain = DOMAIN;
    res.locals.baseUrl = BASE_URL;
    next();
});

// 添加CORS配置
app.use(cors({
    origin: function(origin, callback) {
        const allowedOrigins = [DOMAIN, BASE_URL];
        if(!origin || allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('CORS policy violation'));
        }
    }
}));

// 修改静态文件服务
app.use(express.static(path.join(__dirname), {
    setHeaders: (res, path) => {
        res.setHeader('Access-Control-Allow-Origin', '*');
    }
})); 