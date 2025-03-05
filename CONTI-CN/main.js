// 导航栏滚动效果
window.addEventListener('scroll', function() {
    const navbar = document.querySelector('.navbar');
    if (window.scrollY > 50) {
        navbar.style.background = 'rgba(255, 255, 255, 0.98)';
        navbar.style.boxShadow = '0 2px 10px rgba(0, 0, 0, 0.1)';
    } else {
        navbar.style.background = 'rgba(255, 255, 255, 0.95)';
        navbar.style.boxShadow = 'none';
    }
});

// 平滑滚动
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();
        const target = document.querySelector(this.getAttribute('href'));
        if (target) {
            target.scrollIntoView({
                behavior: 'smooth'
            });
        }
    });
});

// Hero背景动画效果
function createParticleEffect() {
    const hero = document.querySelector('.hero-background');
    // 这里可以添加粒子效果或其他动画
    // 可以使用第三方库如particles.js
}

// 项目卡片动画
const projectCards = document.querySelectorAll('.project-card');
projectCards.forEach(card => {
    card.addEventListener('mouseenter', function() {
        this.style.transform = 'translateY(-10px)';
    });
    
    card.addEventListener('mouseleave', function() {
        this.style.transform = 'translateY(0)';
    });
});

// 页面加载完成后的初始化
document.addEventListener('DOMContentLoaded', function() {
    // 添加页面载入动画
    document.body.classList.add('loaded');
    
    // 初始化其他功能
    createParticleEffect();
});

// 可选：添加移动端导航菜单
function initMobileNav() {
    const burger = document.createElement('div');
    burger.className = 'burger';
    burger.innerHTML = '<span></span><span></span><span></span>';
    
    const nav = document.querySelector('.navbar');
    nav.appendChild(burger);
    
    burger.addEventListener('click', function() {
        document.querySelector('.nav-links').classList.toggle('active');
        this.classList.toggle('active');
    });
}

// 初始化移动端导航
if (window.innerWidth <= 768) {
    initMobileNav();
} 