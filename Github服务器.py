# GithubKEY.py - 修复版最高安全规格版本（企业级安全防护 + 访问者记录）
from flask import Flask, request, jsonify, g
import requests
import base64
import time
import os
import hmac
import hashlib
import re
import secrets
import string
import logging
from functools import wraps
from collections import defaultdict
import threading
from dotenv import load_dotenv
import ipaddress
import urllib.parse
import json
from datetime import datetime

# 加载环境变量
load_dotenv()

# 初始化Flask应用
app = Flask(__name__)

# ==================== 日志配置 ====================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_service.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('SecurityService')

# ==================== 企业级安全配置 ====================
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN', '')
REPO_OWNER = os.getenv('REPO_OWNER', 'k1vinvin224')
REPO_NAME = os.getenv('REPO_NAME', 'Kevin')
FILE_PATH = os.getenv('FILE_PATH', 'key.txt')

# 安全密钥
API_SECRET_KEY = os.getenv('API_SECRET_KEY', '')
ADMIN_TOKEN = os.getenv('ADMIN_TOKEN', '')

# 安全配置常量
MAX_REQUESTS_PER_MINUTE = 60
MAX_REQUESTS_PER_HOUR = 1000
MAX_ADMIN_REQUESTS_PER_MINUTE = 30
REQUEST_TIMEOUT = 8

# 文件路径配置
IP_BLACKLIST_FILE = "IP黑名单列表/IP黑名单.txt"
IP_WHITELIST_FILE = "IP黑名单列表/IP白名单.txt"
VISITOR_LOG_FILE = "信息/IP.txt"

# 安全检查
if not all([GITHUB_TOKEN, API_SECRET_KEY, ADMIN_TOKEN]):
    logger.error("缺少必要的环境变量配置")
    raise ValueError("缺少必要的环境变量配置: GITHUB_TOKEN, API_SECRET_KEY, ADMIN_TOKEN")

# ==================== 访问者记录系统 ====================

# 访问者日志存储
visitor_logs = []
visitor_lock = threading.Lock()

def ensure_visitor_directory():
    """确保访问者日志目录存在"""
    directory = os.path.dirname(VISITOR_LOG_FILE)
    if directory and not os.path.exists(directory):
        os.makedirs(directory, exist_ok=True)
        logger.info(f"创建访问者日志目录: {directory}")

def get_detailed_location(ip_address):
    """获取IP的详细地理位置信息"""
    # 本地和内网IP处理
    if ip_address in ['127.0.0.1', '::1']:
        return {
            'country': '本地',
            'region': '本地网络',
            'city': '内网地址',
            'isp': '本地',
            'timezone': '本地时间',
            'accuracy': '高'
        }
    
    # 内网IP判断
    try:
        ip = ipaddress.ip_address(ip_address)
        if ip.is_private:
            return {
                'country': '中国',
                'region': '内网地址', 
                'city': '局域网',
                'isp': '内网',
                'timezone': 'Asia/Shanghai',
                'accuracy': '高'
            }
    except:
        pass

    # 使用多个免费IP地理位置API（提高成功率）
    apis = [
        {
            'url': f"http://ip-api.com/json/{ip_address}?lang=zh-CN",
            'parser': lambda data: {
                'country': data.get('country', '未知'),
                'region': data.get('regionName', '未知'),
                'city': data.get('city', '未知'),
                'isp': data.get('isp', '未知'),
                'timezone': data.get('timezone', '未知'),
                'accuracy': '中'
            } if data.get('status') == 'success' else None
        },
        {
            'url': f"https://ipapi.co/{ip_address}/json/",
            'parser': lambda data: {
                'country': data.get('country_name', '未知'),
                'region': data.get('region', '未知'),
                'city': data.get('city', '未知'),
                'isp': data.get('org', '未知'),
                'timezone': data.get('timezone', '未知'),
                'accuracy': '中'
            } if data.get('country') else None
        }
    ]
    
    for api in apis:
        try:
            response = requests.get(api['url'], timeout=5)
            if response.status_code == 200:
                data = response.json()
                location = api['parser'](data)
                if location:
                    return location
        except:
            continue
    
    # 如果所有API都失败，返回默认信息
    return {
        'country': '未知',
        'region': '未知',
        'city': '未知', 
        'isp': '未知',
        'timezone': '未知',
        'accuracy': '低'
    }

def log_visitor_info(ip_address, user_agent, route, method, status_code, response_time):
    """记录访问者信息到内存和文件"""
    # 获取地理位置信息
    location = get_detailed_location(ip_address)
    
    # 构建访问记录
    visitor_record = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'ip': ip_address,
        'country': location['country'],
        'region': location['region'],
        'city': location['city'],
        'isp': location['isp'],
        'route': route,
        'method': method,
        'status_code': status_code,
        'response_time': f"{response_time:.2f}ms",
        'user_agent': user_agent[:100]  # 限制长度
    }
    
    # 添加到内存日志
    with visitor_lock:
        visitor_logs.append(visitor_record)
        # 限制内存中的日志数量
        if len(visitor_logs) > 1000:
            visitor_logs.pop(0)
    
    # 异步保存到文件
    threading.Thread(target=save_visitor_to_file, args=(visitor_record,), daemon=True).start()
    
    return visitor_record

def save_visitor_to_file(visitor_record):
    """将访问者信息保存到文件"""
    try:
        ensure_visitor_directory()
        
        log_entry = (
            f"[{visitor_record['timestamp']}] "
            f"IP: {visitor_record['ip']} | "
            f"位置: {visitor_record['country']}-{visitor_record['region']}-{visitor_record['city']} | "
            f"运营商: {visitor_record['isp']} | "
            f"访问: {visitor_record['method']} {visitor_record['route']} | "
            f"状态: {visitor_record['status_code']} | "
            f"响应: {visitor_record['response_time']} | "
            f"设备: {visitor_record['user_agent']}\n"
        )
        
        with open(VISITOR_LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(log_entry)
            
    except Exception as e:
        logger.error(f"保存访问者日志失败: {e}")

def load_visitor_logs():
    """从文件加载访问者日志"""
    ensure_visitor_directory()
    
    if not os.path.exists(VISITOR_LOG_FILE):
        return []
    
    try:
        with open(VISITOR_LOG_FILE, 'r', encoding='utf-8') as f:
            logs = []
            for line in f:
                if line.strip():
                    logs.append(line.strip())
            return logs
    except Exception as e:
        logger.error(f"加载访问者日志失败: {e}")
        return []

# ==================== 企业级保护机制 ====================

# 多层频率限制存储
request_limits_minute = defaultdict(list)
request_limits_hour = defaultdict(list)
request_limits_admin = defaultdict(list)
limit_lock = threading.Lock()

# IP黑名单和白名单（内存中）
ip_blacklist = set()
ip_whitelist = set()
blacklist_lock = threading.Lock()

# 安全事件日志
security_log = []
log_lock = threading.Lock()

# DDoS防护统计
ddos_stats = {
    'total_requests': 0,
    'blocked_requests': 0,
    'last_reset': time.time()
}
ddos_lock = threading.Lock()

# 缓存配置
key_cache = {
    'keys': [],
    'last_update': 0,
    'cache_duration': 300,
    'lock': threading.Lock()
}

# WAF规则集
waf_rules = [
    (r'(\bUNION\b.*\bSELECT\b|\bINSERT\b.*\bINTO\b|\bDROP\b.*\bTABLE\b|\bOR\b.*1=1|\bAND\b.*1=1)', 'SQL_INJECTION'),
    (r'(<script|javascript:|onload=|onerror=|onclick=)', 'XSS_ATTACK'),
    (r'(\.\./|\.\.\\|~/|/etc/passwd)', 'PATH_TRAVERSAL'),
    (r'(\bexec\b|\bsystem\b|\bshell_exec\b|\bpassthru\b|\|\||&&)', 'COMMAND_INJECTION'),
    (r'(include\(|require\(|include_once|require_once)', 'FILE_INCLUSION'),
]

def ensure_security_directory():
    """确保安全目录存在"""
    directories = [os.path.dirname(IP_BLACKLIST_FILE), os.path.dirname(IP_WHITELIST_FILE)]
    for directory in directories:
        if directory and not os.path.exists(directory):
            os.makedirs(directory, exist_ok=True)
            logger.info(f"创建安全目录: {directory}")

def load_ip_list(file_path, default_header):
    """从文件加载IP列表（黑名单或白名单）"""
    ensure_security_directory()
    
    if not os.path.exists(file_path):
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(default_header)
            f.write("# 每行一个IP地址或CIDR，以#开头的为注释\n")
            f.write("# 示例:\n")
            f.write("# 192.168.1.100\n")
            f.write("# 10.0.0.0/8\n")
        logger.info(f"创建IP列表文件: {file_path}")
        return set()
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        ip_set = set()
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if is_valid_ip_or_cidr(line):
                ip_set.add(line)
            else:
                logger.warning(f"文件中无效的IP/CIDR: {line}")
        
        logger.info(f"从文件加载 {len(ip_set)} 个IP/CIDR: {file_path}")
        return ip_set
        
    except Exception as e:
        logger.error(f"加载IP列表文件失败 {file_path}: {e}")
        return set()

def save_ip_list(ip_set, file_path, header):
    """保存IP列表到文件"""
    try:
        ensure_security_directory()
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(header)
            f.write("# 每行一个IP地址或CIDR，以#开头的为注释\n")
            f.write("# 生成时间: " + time.strftime('%Y-%m-%d %H:%M:%S') + "\n\n")
            
            for ip in sorted(ip_set):
                f.write(ip + "\n")
        
        logger.info(f"IP列表已保存到文件: {file_path} (共{len(ip_set)}个)")
        return True
        
    except Exception as e:
        logger.error(f"保存IP列表文件失败 {file_path}: {e}")
        return False

def load_ip_blacklist():
    """从文件加载IP黑名单"""
    return load_ip_list(IP_BLACKLIST_FILE, "# IP黑名单列表\n")

def load_ip_whitelist():
    """从文件加载IP白名单"""
    return load_ip_list(IP_WHITELIST_FILE, "# IP白名单列表\n")

def save_ip_blacklist():
    """保存IP黑名单到文件"""
    with blacklist_lock:
        return save_ip_list(ip_blacklist, IP_BLACKLIST_FILE, "# IP黑名单列表\n")

def save_ip_whitelist():
    """保存IP白名单到文件"""
    with blacklist_lock:
        return save_ip_list(ip_whitelist, IP_WHITELIST_FILE, "# IP白名单列表\n")

def is_valid_ip_or_cidr(ip):
    """验证IP地址或CIDR格式"""
    try:
        ipaddress.ip_network(ip, strict=False)
        return True
    except:
        return False

def is_ip_in_set(ip_address, ip_set):
    """检查IP是否在IP集合中（支持CIDR）"""
    try:
        ip = ipaddress.ip_address(ip_address)
        for network_str in ip_set:
            network = ipaddress.ip_network(network_str, strict=False)
            if ip in network:
                return True
    except:
        pass
    return False

def add_to_blacklist(ip_address):
    """添加IP到黑名单（内存和文件）"""
    if not is_valid_ip_or_cidr(ip_address):
        return False
    
    with blacklist_lock:
        if not is_ip_in_set(ip_address, ip_blacklist):
            ip_blacklist.add(ip_address)
            # 从白名单移除（如果存在）
            if is_ip_in_set(ip_address, ip_whitelist):
                ip_whitelist.discard(ip_address)
            save_ip_blacklist()
            save_ip_whitelist()
            return True
    return False

def remove_from_blacklist(ip_address):
    """从黑名单移除IP（内存和文件）"""
    with blacklist_lock:
        if is_ip_in_set(ip_address, ip_blacklist):
            # 需要找到确切匹配项
            to_remove = None
            for item in ip_blacklist:
                if is_ip_in_set(ip_address, {item}):
                    to_remove = item
                    break
            if to_remove:
                ip_blacklist.remove(to_remove)
                save_ip_blacklist()
                return True
    return False

# ==================== 修复1: 添加白名单移除函数 ====================

def remove_from_whitelist(ip_address):
    """从白名单移除IP（内存和文件）"""
    with blacklist_lock:
        if is_ip_in_set(ip_address, ip_whitelist):
            # 需要找到确切匹配项
            to_remove = None
            for item in ip_whitelist:
                if is_ip_in_set(ip_address, {item}):
                    to_remove = item
                    break
            if to_remove:
                ip_whitelist.remove(to_remove)
                save_ip_whitelist()
                return True
    return False

def add_to_whitelist(ip_address):
    """添加IP到白名单（内存和文件）"""
    if not is_valid_ip_or_cidr(ip_address):
        return False
    
    with blacklist_lock:
        if not is_ip_in_set(ip_address, ip_whitelist):
            ip_whitelist.add(ip_address)
            # 从黑名单移除（如果存在）
            if is_ip_in_set(ip_address, ip_blacklist):
                ip_blacklist.discard(ip_address)
            save_ip_whitelist()
            save_ip_blacklist()
            return True
    return False

def log_security_event(event_type, ip_address, details, level="INFO"):
    """记录安全事件"""
    with log_lock:
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        event = {
            'timestamp': timestamp,
            'type': event_type,
            'ip': ip_address,
            'details': details,
            'level': level
        }
        security_log.append(event)
        # 保持日志大小可控
        if len(security_log) > 5000:
            security_log.pop(0)
        
        # 使用logging替代print
        log_message = f"{timestamp} - {event_type} - {ip_address} - {details}"
        if level == "HIGH":
            logger.error(log_message)
        elif level == "MEDIUM":
            logger.warning(log_message)
        else:
            logger.info(log_message)

def update_ddos_stats(blocked=False):
    """更新DDoS统计"""
    with ddos_lock:
        ddos_stats['total_requests'] += 1
        if blocked:
            ddos_stats['blocked_requests'] += 1
        
        # 每小时重置统计
        if time.time() - ddos_stats['last_reset'] > 3600:
            ddos_stats['total_requests'] = 0
            ddos_stats['blocked_requests'] = 0
            ddos_stats['last_reset'] = time.time()

def check_rate_limit(identifier, max_requests, window_seconds, limits_dict):
    """高级频率限制检查"""
    now = time.time()
    
    with limit_lock:
        # 清理过期记录
        limits_dict[identifier] = [
            req_time for req_time in limits_dict[identifier] 
            if now - req_time < window_seconds
        ]
        
        if len(limits_dict[identifier]) >= max_requests:
            return False
        
        limits_dict[identifier].append(now)
        return True

def check_multi_layer_rate_limit(ip_address, is_admin=False):
    """多层频率限制检查"""
    if is_admin:
        # 管理员频率限制
        if not check_rate_limit(f"admin_{ip_address}", MAX_ADMIN_REQUESTS_PER_MINUTE, 60, request_limits_admin):
            return False
    else:
        # 普通用户频率限制
        if not check_rate_limit(f"minute_{ip_address}", MAX_REQUESTS_PER_MINUTE, 60, request_limits_minute):
            return False
        if not check_rate_limit(f"hour_{ip_address}", MAX_REQUESTS_PER_HOUR, 3600, request_limits_hour):
            return False
    
    return True

def is_ip_blacklisted(ip_address):
    """检查IP是否在黑名单中"""
    with blacklist_lock:
        return is_ip_in_set(ip_address, ip_blacklist)

def is_ip_whitelisted(ip_address):
    """检查IP是否在白名单中"""
    with blacklist_lock:
        return is_ip_in_set(ip_address, ip_whitelist)

def waf_check(input_data):
    """Web应用防火墙检查"""
    if not input_data:
        return None
    
    input_str = str(input_data).lower()
    
    for pattern, attack_type in waf_rules:
        if re.search(pattern, input_str, re.IGNORECASE):
            return attack_type
    
    return None

def verify_signature(data, signature, timestamp):
    """验证请求签名"""
    try:
        # 检查时间戳有效性（防止重放攻击）
        if abs(time.time() - int(timestamp)) > 300:  # 5分钟有效期
            return False
        
        # 生成预期签名
        message = f"{timestamp}{data}".encode('utf-8')
        expected_signature = hmac.new(
            API_SECRET_KEY.encode('utf-8'),
            message,
            hashlib.sha256
        ).hexdigest()
        
        return hmac.compare_digest(expected_signature, signature)
    except:
        return False

def generate_secure_token(length=32):
    """生成安全随机令牌"""
    alphabet = string.ascii_letters + string.digits + '-_'
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def validate_key_format(key):
    """严格的卡密格式验证"""
    if not key or len(key) < 8 or len(key) > 64:
        return False
    
    # 只允许安全的字符
    if not re.match(r'^[a-zA-Z0-9\-_=+!@#$%^&*()]{8,64}$', key):
        return False
    
    # WAF检查
    if waf_check(key):
        return False
    
    return True

def deep_sanitize_input(text):
    """深度输入清理和验证"""
    if not text:
        return ""
    
    # 移除危险字符
    text = re.sub(r'[<>"\']', '', text)
    
    # 移除控制字符
    text = ''.join(char for char in text if ord(char) >= 32)
    
    # URL解码（防止双重编码攻击）
    try:
        text = urllib.parse.unquote(text)
    except:
        pass
    
    # 再次清理
    text = re.sub(r'[<>"\']', '', text)
    
    # 限制长度
    text = text[:100]
    
    # WAF检查
    attack_type = waf_check(text)
    if attack_type:
        log_security_event("WAF_BLOCKED", getattr(g, 'client_ip', 'unknown'), 
                         f"攻击类型: {attack_type}, 输入: {text[:50]}", "HIGH")
        return ""
    
    return text

def get_client_ip():
    """获取真实客户端IP（支持代理）"""
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        ip = request.headers.get('X-Real-IP')
    else:
        ip = request.remote_addr
    
    # 验证IP格式
    if is_valid_ip_or_cidr(ip.split(':')[0]):  # 处理IPv6
        return ip.split(':')[0]
    return request.remote_addr

# ==================== 全局安全中间件 ====================

@app.before_request
def global_security_middleware():
    """全局安全中间件 - 对所有请求生效"""
    g.start_time = time.time()
    g.client_ip = get_client_ip()
    
    # 更新DDoS统计
    update_ddos_stats()
    
    # === 全局白名单检查（绕过所有安全检查）===
    if is_ip_whitelisted(g.client_ip):
        return None  # 继续处理请求
    
    # === 全局黑名单检查 ===
    if is_ip_blacklisted(g.client_ip):
        update_ddos_stats(blocked=True)
        log_security_event("GLOBAL_BLOCKED_BLACKLIST", g.client_ip, 
                          f"黑名单IP访问 {request.method} {request.path}", "HIGH")
        
        if request.path.startswith(('/admin', '/verify', '/status', '/refresh')):
            return jsonify({'status': 'error', 'message': '访问被拒绝'}), 403
        else:
            return "<h1>访问被拒绝</h1><p>你的IP地址在黑名单中</p>", 403
    
    # === 全局频率限制 ===
    is_admin_route = request.path.startswith('/admin')
    if not check_multi_layer_rate_limit(g.client_ip, is_admin_route):
        update_ddos_stats(blocked=True)
        log_security_event("GLOBAL_RATE_LIMIT", g.client_ip, 
                          f"频率限制触发 {request.method} {request.path}", "MEDIUM")
        return jsonify({'status': 'error', 'message': '请求过于频繁'}), 429
    
    # === 全局WAF检查 ===
    # 检查URL参数
    for key, values in request.args.lists():
        for value in values:
            attack_type = waf_check(value)
            if attack_type:
                update_ddos_stats(blocked=True)
                log_security_event("WAF_BLOCKED_PARAMS", g.client_ip, 
                                 f"攻击类型: {attack_type}, 参数: {key}={value[:50]}", "HIGH")
                return jsonify({'status': 'error', 'message': '非法请求'}), 400
    
    # 检查POST数据
    if request.is_json:
        data = request.get_json(silent=True) or {}
        for key, value in data.items():
            attack_type = waf_check(str(value))
            if attack_type:
                update_ddos_stats(blocked=True)
                log_security_event("WAF_BLOCKED_JSON", g.client_ip, 
                                 f"攻击类型: {attack_type}, 字段: {key}", "HIGH")
                return jsonify({'status': 'error', 'message': '非法请求'}), 400
    
    # 检查Headers
    user_agent = request.headers.get('User-Agent', '')
    attack_type = waf_check(user_agent)
    if attack_type:
        update_ddos_stats(blocked=True)
        log_security_event("WAF_BLOCKED_UA", g.client_ip, 
                         f"攻击类型: {attack_type}, UA: {user_agent[:100]}", "HIGH")
        return jsonify({'status': 'error', 'message': '非法请求'}), 400

# ==================== 修复2: 增强安全头 ====================

@app.after_request
def after_request(response):
    """全局响应后处理 - 增强版安全头"""
    # 设置安全头
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;"
    response.headers['Server'] = 'SecureAPI'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    
    # 记录请求耗时
    response_time = 0
    if hasattr(g, 'start_time'):
        response_time = (time.time() - g.start_time) * 1000
        response.headers['X-Response-Time'] = f'{response_time:.2f}ms'
    
    # 记录访问者信息（排除静态文件和某些路由）
    if hasattr(g, 'client_ip') and request.path not in ['/favicon.ico']:
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        # 记录访问者信息
        visitor_record = log_visitor_info(
            ip_address=g.client_ip,
            user_agent=user_agent,
            route=request.path,
            method=request.method,
            status_code=response.status_code,
            response_time=response_time
        )
        
        # 记录到安全日志（INFO级别）
        log_security_event(
            "VISITOR_ACCESS", 
            g.client_ip, 
            f"访问 {request.method} {request.path} - 位置: {visitor_record['country']}-{visitor_record['city']} - 运营商: {visitor_record['isp']}",
            "INFO"
        )
    
    return response

# ==================== 认证装饰器 ====================

def require_auth(f):
    """客户端认证装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 全局中间件已处理基本安全检查，这里主要处理API签名
        
        # 验证API签名（对于写操作）
        if request.method in ['POST', 'PUT', 'DELETE']:
            signature = request.headers.get('X-Signature', '')
            timestamp = request.headers.get('X-Timestamp', '')
            
            if request.is_json:
                data = str(request.get_json())
            else:
                data = request.query_string.decode('utf-8')
            
            if not verify_signature(data, signature, timestamp):
                log_security_event("INVALID_SIGNATURE", g.client_ip, "API签名验证失败", "MEDIUM")
                return jsonify({'status': 'error', 'message': '签名验证失败'}), 401
        
        return f(*args, **kwargs)
    return decorated_function

def require_admin(f):
    """管理员权限装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        admin_token = request.headers.get('X-Admin-Token') or request.args.get('admin_token')
        
        if not admin_token or not hmac.compare_digest(admin_token, ADMIN_TOKEN):
            log_security_event("UNAUTHORIZED_ADMIN_ACCESS", g.client_ip, "未授权管理员访问尝试", "HIGH")
            return jsonify({'status': 'error', 'message': '管理员权限不足'}), 403
        
        return f(*args, **kwargs)
    return decorated_function

# ==================== GitHub操作函数 ====================

def get_keys_from_github():
    """从GitHub私有仓库获取卡密列表 - 安全版本"""
    try:
        url = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{FILE_PATH}"
        headers = {
            'Authorization': f'token {GITHUB_TOKEN}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'SecureKeyServer/1.0'
        }
        
        # 添加超时和重试机制
        response = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        
        if response.status_code == 200:
            content = response.json()['content']
            decoded_content = base64.b64decode(content).decode('utf-8')
            
            # 安全过滤卡密
            keys = []
            for line in decoded_content.split('\n'):
                key = line.strip()
                if key and validate_key_format(key):
                    keys.append(key)
            
            logger.info(f"安全获取 {len(keys)} 个有效卡密")
            return keys
        else:
            logger.error(f"GitHub API错误: {response.status_code}")
            log_security_event("GITHUB_API_ERROR", g.client_ip, f"状态码: {response.status_code}", "MEDIUM")
            return []
            
    except requests.exceptions.Timeout:
        logger.error("GitHub API请求超时")
        log_security_event("GITHUB_TIMEOUT", g.client_ip, "API请求超时", "MEDIUM")
        return []
    except Exception as e:
        logger.error(f"从GitHub获取密钥错误: {e}")
        log_security_event("GITHUB_ERROR", g.client_ip, f"异常: {str(e)}", "MEDIUM")
        return []

def get_valid_keys_with_cache():
    """带缓存的获取卡密列表 - 线程安全版本"""
    current_time = time.time()
    
    with key_cache['lock']:
        # 检查缓存是否有效
        cache_valid = (key_cache['keys'] and 
                      current_time - key_cache['last_update'] < key_cache['cache_duration'])
        
        if cache_valid:
            return key_cache['keys'].copy()
        
        keys = get_keys_from_github()
        if keys:
            key_cache['keys'] = keys
            key_cache['last_update'] = current_time
        
        return keys.copy() if keys else key_cache['keys'].copy()

# ==================== 修复3: 自动缓存刷新机制 ====================

def start_auto_refresh():
    """启动自动缓存刷新线程"""
    def refresh_loop():
        while True:
            time.sleep(300)  # 5分钟
            try:
                keys = get_keys_from_github()
                if keys:
                    with key_cache['lock']:
                        key_cache['keys'] = keys
                        key_cache['last_update'] = time.time()
                    logger.info(f"自动刷新卡密缓存完成，共{len(keys)}个卡密")
                else:
                    logger.warning("自动刷新卡密缓存失败")
            except Exception as e:
                logger.error(f"自动刷新缓存异常: {e}")
    
    thread = threading.Thread(target=refresh_loop, daemon=True)
    thread.start()
    logger.info("自动缓存刷新线程已启动")

# ==================== 路由处理 ====================

@app.route('/')
def index():
    """根路径 - 显示访问统计"""
    with visitor_lock:
        total_visits = len(visitor_logs)
        unique_ips = len(set(log['ip'] for log in visitor_logs))
    
    return f"""
    <h1>安全验证服务</h1>
    <p>服务运行正常</p>
    <p>总访问次数: {total_visits}</p>
    <p>独立访客: {unique_ips}</p>
    <p><small>© 2024 企业级安全API服务</small></p>
    <style>body{{font-family:Arial,sans-serif;max-width:800px;margin:0 auto;padding:20px}}</style>
    """

@app.route('/verify', methods=['GET', 'POST'])
@require_auth
def verify_key():
    """验证卡密接口 - 企业级安全版本"""
    try:
        # 获取并深度清理输入
        if request.method == 'GET':
            key = deep_sanitize_input(request.args.get('key', '').strip())
        else:
            data = request.get_json(silent=True) or {}
            key = deep_sanitize_input(data.get('key', '').strip())
        
        if not key:
            return jsonify({'status': 'error', 'message': '卡密不能为空'}), 400
        
        if not validate_key_format(key):
            log_security_event("INVALID_KEY_FORMAT", g.client_ip, f"无效格式: {key[:8]}***", "MEDIUM")
            return jsonify({'status': 'error', 'message': '卡密格式无效'}), 400
        
        # 获取有效卡密
        valid_keys = get_valid_keys_with_cache()
        
        if not valid_keys:
            return jsonify({'status': 'error', 'message': '系统维护中'}), 503
        
        # 验证卡密（恒定时间比较，防止时序攻击）
        is_valid = False
        for valid_key in valid_keys:
            if hmac.compare_digest(key, valid_key):
                is_valid = True
                break
        
        if is_valid:
            log_security_event("KEY_VALIDATION_SUCCESS", g.client_ip, "卡密验证成功", "INFO")
            return jsonify({
                'status': 'success', 
                'message': '验证成功',
                'timestamp': int(time.time()),
                'valid': True
            })
        else:
            log_security_event("KEY_VALIDATION_FAILED", g.client_ip, f"卡密无效: {key[:8]}***", "INFO")
            return jsonify({
                'status': 'error', 
                'message': '卡密无效',
                'valid': False
            }), 404
            
    except Exception as e:
        log_security_event("SYSTEM_ERROR", g.client_ip, f"验证过程异常: {str(e)}", "HIGH")
        return jsonify({'status': 'error', 'message': '系统错误'}), 500

@app.route('/refresh', methods=['POST'])
@require_admin
def refresh_cache():
    """手动刷新缓存接口 - 仅管理员"""
    keys = get_keys_from_github()
    if keys:
        with key_cache['lock']:
            key_cache['keys'] = keys
            key_cache['last_update'] = time.time()
        
        log_security_event("CACHE_REFRESHED", g.client_ip, f"缓存更新: {len(keys)}个卡密", "INFO")
        return jsonify({'status': 'success', 'message': f'缓存已更新，共{len(keys)}个卡密'})
    
    return jsonify({'status': 'error', 'message': '更新失败'}), 500

@app.route('/status', methods=['GET'])
@require_auth
def system_status():
    """系统状态检查"""
    key_count = len(key_cache['keys'])
    last_update = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(key_cache['last_update']))
    
    with ddos_lock:
        ddos_total = ddos_stats['total_requests']
        ddos_blocked = ddos_stats['blocked_requests']
    
    with visitor_lock:
        total_visits = len(visitor_logs)
        unique_visitors = len(set(log['ip'] for log in visitor_logs))
    
    return jsonify({
        'status': 'running',
        'key_count': key_count,
        'last_update': last_update,
        'server_time': int(time.time()),
        'blacklist_count': len(ip_blacklist),
        'whitelist_count': len(ip_whitelist),
        'visitor_stats': {
            'total_visits': total_visits,
            'unique_visitors': unique_visitors
        },
        'security': {
            'total_requests': ddos_total,
            'blocked_requests': ddos_blocked,
            'block_rate': f"{(ddos_blocked/ddos_total*100):.1f}%" if ddos_total > 0 else "0%"
        }
    })

# ==================== 新增访问者管理路由 ====================

@app.route('/admin/visitors', methods=['GET'])
@require_admin
def get_visitors():
    """获取访问者记录 - 仅管理员"""
    with visitor_lock:
        return jsonify({
            'visitors': visitor_logs[-100:],  # 返回最近100条
            'total_count': len(visitor_logs),
            'file_path': VISITOR_LOG_FILE
        })

@app.route('/admin/visitors/file', methods=['GET'])
@require_admin
def get_visitors_file():
    """获取访问者日志文件内容 - 仅管理员"""
    try:
        file_logs = load_visitor_logs()
        return jsonify({
            'file_content': file_logs[-200:],  # 返回最近200条
            'total_lines': len(file_logs)
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'读取文件失败: {e}'}), 500

@app.route('/admin/security/logs', methods=['GET'])
@require_admin
def get_security_logs():
    """获取安全日志 - 仅管理员"""
    with log_lock:
        return jsonify({'logs': security_log[-200:]})  # 返回最近200条

@app.route('/admin/blacklist', methods=['GET', 'POST', 'DELETE'])
@require_admin
def manage_blacklist():
    """管理IP黑名单 - 仅管理员"""
    if request.method == 'GET':
        with blacklist_lock:
            return jsonify({
                'blacklist': list(ip_blacklist),
                'total_count': len(ip_blacklist),
                'file_path': IP_BLACKLIST_FILE
            })
    
    elif request.method == 'POST':
        data = request.get_json() or {}
        ip_to_add = data.get('ip', '').strip()
        
        if not ip_to_add:
            return jsonify({'status': 'error', 'message': 'IP地址不能为空'}), 400
        
        if not is_valid_ip_or_cidr(ip_to_add):
            return jsonify({'status': 'error', 'message': '无效的IP地址格式'}), 400
        
        if add_to_blacklist(ip_to_add):
            log_security_event("MANUAL_BLACKLIST_ADD", g.client_ip, f"手动添加: {ip_to_add}", "INFO")
            return jsonify({'status': 'success', 'message': f'已添加 {ip_to_add} 到黑名单'})
        else:
            return jsonify({'status': 'error', 'message': 'IP已在黑名单中'}), 400
    
    elif request.method == 'DELETE':
        data = request.get_json() or {}
        ip_to_remove = data.get('ip', '').strip()
        
        if not ip_to_remove:
            return jsonify({'status': 'error', 'message': 'IP地址不能为空'}), 400
        
        if remove_from_blacklist(ip_to_remove):
            log_security_event("MANUAL_BLACKLIST_REMOVE", g.client_ip, f"手动移除: {ip_to_remove}", "INFO")
            return jsonify({'status': 'success', 'message': f'已从黑名单移除 {ip_to_remove}'})
        else:
            return jsonify({'status': 'error', 'message': 'IP不在黑名单中'}), 400
    
    return jsonify({'status': 'error', 'message': '操作失败'}), 400

# ==================== 修复4: 修复白名单删除路由 ====================

@app.route('/admin/whitelist', methods=['GET', 'POST', 'DELETE'])
@require_admin
def manage_whitelist():
    """管理IP白名单 - 修复版"""
    if request.method == 'GET':
        with blacklist_lock:
            return jsonify({
                'whitelist': list(ip_whitelist),
                'total_count': len(ip_whitelist),
                'file_path': IP_WHITELIST_FILE
            })
    
    elif request.method == 'POST':
        data = request.get_json() or {}
        ip_to_add = data.get('ip', '').strip()
        
        if not ip_to_add:
            return jsonify({'status': 'error', 'message': 'IP地址不能为空'}), 400
        
        if not is_valid_ip_or_cidr(ip_to_add):
            return jsonify({'status': 'error', 'message': '无效的IP地址格式'}), 400
        
        if add_to_whitelist(ip_to_add):
            log_security_event("MANUAL_WHITELIST_ADD", g.client_ip, f"手动添加: {ip_to_add}", "INFO")
            return jsonify({'status': 'success', 'message': f'已添加 {ip_to_add} 到白名单'})
        else:
            return jsonify({'status': 'error', 'message': 'IP已在白名单中'}), 400
    
    elif request.method == 'DELETE':
        data = request.get_json() or {}
        ip_to_remove = data.get('ip', '').strip()
        
        if not ip_to_remove:
            return jsonify({'status': 'error', 'message': 'IP地址不能为空'}), 400
        
        # 修复：调用正确的白名单移除函数
        if remove_from_whitelist(ip_to_remove):
            log_security_event("MANUAL_WHITELIST_REMOVE", g.client_ip, f"手动移除: {ip_to_remove}", "INFO")
            return jsonify({'status': 'success', 'message': f'已从白名单移除 {ip_to_remove}'})
        else:
            return jsonify({'status': 'error', 'message': 'IP不在白名单中'}), 400
    
    return jsonify({'status': 'error', 'message': '操作失败'}), 400

@app.route('/admin/blacklist/reload', methods=['POST'])
@require_admin
def reload_blacklist():
    """重新加载黑名单文件 - 仅管理员"""
    global ip_blacklist
    with blacklist_lock:
        ip_blacklist = load_ip_blacklist()
    
    log_security_event("BLACKLIST_RELOADED", g.client_ip, f"重新加载黑名单: {len(ip_blacklist)}个IP", "INFO")
    return jsonify({'status': 'success', 'message': f'黑名单已重新加载，共{len(ip_blacklist)}个IP'})

@app.route('/admin/security/stats', methods=['GET'])
@require_admin
def get_security_stats():
    """获取安全统计信息 - 仅管理员"""
    with ddos_lock:
        with log_lock:
            with visitor_lock:
                high_events = len([e for e in security_log if e.get('level') == 'HIGH'])
                medium_events = len([e for e in security_log if e.get('level') == 'MEDIUM'])
                
                return jsonify({
                    'ddos_protection': {
                        'total_requests': ddos_stats['total_requests'],
                        'blocked_requests': ddos_stats['blocked_requests'],
                        'block_rate': f"{(ddos_stats['blocked_requests']/ddos_stats['total_requests']*100):.1f}%" if ddos_stats['total_requests'] > 0 else "0%"
                    },
                    'security_events': {
                        'total': len(security_log),
                        'high_level': high_events,
                        'medium_level': medium_events,
                        'last_24h': len([e for e in security_log if time.time() - time.mktime(time.strptime(e['timestamp'], '%Y-%m-%d %H:%M:%S')) < 86400])
                    },
                    'visitor_stats': {
                        'total_visits': len(visitor_logs),
                        'unique_visitors': len(set(log['ip'] for log in visitor_logs)),
                        'recent_visitors': len([log for log in visitor_logs[-100:]])
                    },
                    'ip_lists': {
                        'blacklist_count': len(ip_blacklist),
                        'whitelist_count': len(ip_whitelist)
                    }
                })

# ==================== 错误处理 ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'status': 'error', 'message': '接口不存在'}), 404

@app.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'status': 'error', 'message': '方法不允许'}), 405

@app.errorhandler(500)
def internal_error(error):
    log_security_event("INTERNAL_SERVER_ERROR", getattr(g, 'client_ip', 'unknown'), 
                      f"500错误: {str(error)}", "HIGH")
    return jsonify({'status': 'error', 'message': '服务器内部错误'}), 500

# ==================== 健康检查端点 ====================

@app.route('/health', methods=['GET'])
def health_check():
    """健康检查端点（用于负载均衡器）"""
    with visitor_lock:
        total_visits = len(visitor_logs)
    
    health_status = {
        'status': 'healthy',
        'timestamp': int(time.time()),
        'version': '2.2.0',
        'services': {
            'github_api': 'ok',
            'cache': 'ok' if key_cache['keys'] else 'empty',
            'blacklist': f'{len(ip_blacklist)} IPs',
            'whitelist': f'{len(ip_whitelist)} IPs',
            'visitor_tracking': f'{total_visits} visits',
            'security': 'active',
            'auto_refresh': 'enabled'
        }
    }
    return jsonify(health_status)

# ==================== 启动应用 ====================

if __name__ == '__main__':
    # 初始化安全系统
    logger.info("=== 启动修复版企业级安全验证服务 ===")
    logger.info("🔧 初始化安全系统...")
    
    # 加载黑白名单
    ip_blacklist = load_ip_blacklist()
    ip_whitelist = load_ip_whitelist()
    
    # 加载访问者日志
    file_logs = load_visitor_logs()
    logger.info(f"已加载 {len(file_logs)} 条历史访问记录")
    
    logger.info(f"已加载 {len(ip_blacklist)} 个IP黑名单")
    logger.info(f"已加载 {len(ip_whitelist)} 个IP白名单")
    logger.info(f"访问者日志文件: {VISITOR_LOG_FILE}")
    
    # 启动自动缓存刷新
    start_auto_refresh()
    
    logger.info("🛡️ 修复特性:")
    logger.info("- 修复白名单删除Bug")
    logger.info("- 增强安全头设置")
    logger.info("- 自动缓存刷新机制")
    logger.info("- 使用logging替代print")
    logger.info("- 移除冗余CLIENT_KEYS配置")
    
    # 验证必要环境变量
    if not GITHUB_TOKEN:
        logger.error("GITHUB_TOKEN 环境变量未设置!")
        exit(1)
    
    # 检查是否安装了waitress
    try:
        from waitress import serve
        logger.info("使用 Waitress 生产服务器启动...")
        logger.info(f"服务地址: http://127.0.0.1:49152")
        logger.info(f"黑名单文件: {IP_BLACKLIST_FILE}")
        logger.info(f"白名单文件: {IP_WHITELIST_FILE}")
        logger.info(f"访问者日志: {VISITOR_LOG_FILE}")
        logger.info(f"启动时间: {time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        # 使用 Waitress 生产服务器
        serve(app, host='127.0.0.1', port=49152, threads=12, connection_limit=1000)
        
    except ImportError:
        logger.warning("Waitress 未安装，使用开发服务器")
        app.run(host='127.0.0.1', port=49152, debug=False, threaded=True)