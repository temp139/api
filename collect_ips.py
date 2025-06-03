import logging
import sys
import os
import subprocess
import requests
from bs4 import BeautifulSoup
import re
import csv
import threading
import time
import shutil
import argparse
import platform
from collections import defaultdict
from typing import List, Tuple
from charset_normalizer import detect
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed

# 配置日志
LOG_FILE = "speedtest.log"
LOG_DIR = os.path.dirname(os.path.abspath(__file__))
os.makedirs(LOG_DIR, exist_ok=True)
LOG_PATH = os.path.join(LOG_DIR, LOG_FILE)

logging.basicConfig(
    level=logging.INFO,
    format='%(message)s',
    handlers=[
        logging.FileHandler(LOG_PATH, encoding="utf-8", mode="w"),
        logging.StreamHandler(sys.stdout)
    ],
    force=True
)
logger = logging.getLogger(__name__)

# 禁用 stdout 缓冲
sys.stdout.reconfigure(line_buffering=True)

# 配置
IP_LIST_FILE = "./ip.txt"
IPS_FILE = "ips.txt"
FINAL_CSV = "ip.csv"
TEMP_FILE = "./temp_proxy.csv"
WEB_URLS = [
    'https://ip.164746.xyz/ipTop10.html',
    'https://cf.090227.xyz'
]
CSV_URLS = [
    "https://bihai.cf/CFIP/CUCC/standard.csv",
    "https://bihai.cf/CFIP/CMCC/standard.csv"
]
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}
DEFAULT_PORTS = [443, 2053, 2083, 2087, 2096, 8443]
DESIRED_COUNTRIES = ['TW', 'JP', 'HK', 'SG', 'KR', 'IN', 'KP', 'VN', 'TH', 'MM']
MAX_CONCURRENT_DOWNLOADS = 5

# 必需依赖
REQUIRED_MODULES = {
    'requests': 'requests',
    'beautifulsoup4': 'bs4',
    'charset-normalizer': 'charset_normalizer'
}

# 国家代码和标签
COUNTRY_LABELS = {
    'JP': ('🇯🇵', '日本'), 'KR': ('🇰🇷', '韩国'), 'SG': ('🇸🇬', '新加坡'), 'TW': ('🇹🇼', '台湾'), 'HK': ('🇭🇰', '香港'),
    'MY': ('🇲🇾', '马来西亚'), 'TH': ('🇹🇭', '泰国'), 'ID': ('🇮🇩', '印度尼西亚'), 'PH': ('🇵🇭', '菲律宾'), 'VN': ('🇻🇳', '越南'),
    'IN': ('🇮🇳', '印度'), 'MO': ('🇲🇴', '澳门'), 'KH': ('🇰🇭', '柬埔寨'), 'LA': ('🇱🇦', '老挝'), 'MM': ('🇲🇲', '缅甸'),
    'MN': ('🇲🇳', '蒙古'), 'KP': ('🇰🇵', '朝鲜'), 'CN': ('🇨🇳', '中国'), 'BD': ('🇧🇩', '孟加拉国'), 'PK': ('🇵🇰', '巴基斯坦'),
    'LK': ('🇱🇰', '斯里兰卡'), 'NP': ('🇳🇵', '尼泊尔'), 'MV': ('🇲🇻', '马尔代夫'), 'BN': ('🇧🇳', '文莱'),
    'SA': ('🇸🇦', '沙特阿拉伯'), 'AE': ('🇦🇪', '阿联酋'), 'QA': ('🇶🇦', '卡塔尔'), 'IL': ('🇮🇱', '以色列'), 'TR': ('🇹🇷', '土耳其'),
    'IR': ('🇮🇷', '伊朗'), 'KW': ('🇰🇼', '科威特'), 'BH': ('🇧🇭', '巴林'), 'OM': ('🇴🇲', '阿曼'), 'JO': ('🇯🇴', '约旦'),
    'LB': ('🇱🇧', '黎巴嫩'), 'SY': ('🇸🇾', '叙利亚'), 'IQ': ('🇮🇶', '伊拉克'), 'YE': ('🇾🇪', '也门'),
    'GB': ('🇬🇧', '英国'), 'DE': ('🇩🇪', '德国'), 'FR': ('🇫🇷', '法国'), 'IT': ('🇮🇹', '意大利'), 'ES': ('🇪🇸', '西班牙'),
    'NL': ('🇳🇱', '荷兰'), 'FI': ('🇫🇮', '芬兰'), 'SE': ('🇸🇪', '瑞典'), 'NO': ('🇳🇴', '挪威'), 'DK': ('🇩🇰', '丹麦'),
    'CH': ('🇨🇭', '瑞士'), 'AT': ('🇦🇹', '奥地利'), 'BE': ('🇧🇪', '比利时'), 'IE': ('🇮🇪', '爱尔兰'), 'PT': ('🇵🇹', '葡萄牙'),
    'GR': ('🇬🇷', '希腊'), 'EG': ('🇪🇬', 'EG'), 'AU': ('🇦🇺', '澳大利亚'), 'US': ('🇺🇸', '美国'), 'BG': ('🇧🇬', '保加利亚'), 'SK': ('🇸🇰', '斯洛伐克'), 'SI': ('🇸🇮', '斯洛文尼亚'), 'AW': ('🇦', 'AW'),
 'AM': ('🇦🇲', 'AM')
}

# 国家别名
COUNTRY_ALIASES = {
    'SOUTH KOREA': 'KR', 'KORE': 'KR', 'REPUBLIC OF KOREA': 'KR', 'KOREA, REPUBLIC OF': 'KR', '韩国': 'KR',
    'HONG KONG': 'HK', 'HONGKONG': 'HK', 'HK SAR': 'HK', '香港': 'HK',
    'UNITED STATES': 'US', 'USA': 'US', 'U.S.': 'US', 'UNITED STATES OF AMERICA': 'US', '美国': 'US',
    'UNITED KINGDOM': 'UK', 'GREAT BRITAIN': 'GB', '英国': 'GB',
    'JAPAN': 'JP', 'JPN': 'JP', '日本': 'JP',
    'TAIWAN': 'TW', 'TWN': 'TW', 'TAIWAN, PROVINCE OF CHINA': 'TW', '台湾': 'TW',
    'SINGAPORE': 'SG', 'SGP': 'SG', '新加坡': 'SG',
    'FRANCE': 'FR', 'FRA': 'FR', '法国': 'FR',
    'GERMANY': 'DE', 'DEU': 'DE', '德国': 'DE',
    'NETHERLANDS': 'NL', 'NLD': 'NL', '荷兰': 'NL',
    'AUSTRALIA': 'AU', 'AUS': 'AU', '澳大利亚': 'AU',
    'CANADA': 'CA', 'CAN': 'CA', '加拿大': 'CA',
    'BRAZIL': 'BR', 'BRA': 'BR', '巴西': 'BR',
    'RUSSIA': 'RU', 'RUS': 'RU', '俄罗斯': 'RU',
    'INDIA': 'IN', 'IND': 'IN', '印度': 'IN',
    'CHINA': 'CN', 'CHN': 'CN', '中国': 'CN',
    'VIETNAM': 'VN', 'VIET NAM': 'VN', '越南': 'VN',
    'THAILAND': 'TH', 'THA': 'TH', '泰国': 'TH',
    'BURMA': 'MM', 'MYANMAR': 'MM', '缅甸': 'MM',
    'NORTH KOREA': 'KP', 'KOREA, DEMOCRATIC PEOPLE\'S REPUBLIC OF': 'KP', '朝鲜': 'KP',
    'BRUNEI': 'BN', 'BRUNEI DARUSSALAM': 'BN', '文莱': 'BN',
    'MALDIVES': 'MV', '马尔代夫': 'MV',
    # 城市映射
    'SINGAPORE': 'SG', '新加坡': 'SG',
    'HONGKONG': 'HK', '香港': 'HK',
    'MUMBAI': 'IN', '孟买': 'IN',
    'BANGALORE': 'IN', '班加罗尔': 'IN',
    'LOSANGELES': 'US', '洛杉矶': 'US',
    'TOKYO': 'JP', '东京': 'JP',
    'SEOUL': 'KR', '首尔': 'KR',
    'TAIPEI': 'TW', '台北': 'TW',
    'OSAKA': 'JP', '大阪': 'JP',
    'STOCKHOLM': 'SE', '斯德哥尔摩': 'SE'
}

def check_and_install_dependencies(auto_install: bool, pip_source: str = None) -> bool:
    """检测并自动安装缺失的依赖"""
    missing_modules = []
    for module_name, import_name in REQUIRED_MODULES.items():
        try:
            __import__(import_name)
            logger.debug(f"Module {module_name} is installed")
        except ImportError:
            missing_modules.append(module_name)
    
    if not missing_modules:
        logger.info("All required dependencies are installed")
        return True
    
    logger.warning(f"Missing dependencies: {', '.join(missing_modules)}")
    
    if not auto_install:
        logger.error(f"Please install missing dependencies with: pip install {' '.join(missing_modules)}")
        return False
    
    logger.info(f"Attempting to install missing dependencies: {', '.join(missing_modules)}")
    try:
        pip_cmd = [sys.executable, "-m", "pip", "install"] + missing_modules
        if pip_source:
            pip_cmd += ["-i", pip_source]
        result = subprocess.run(pip_cmd, check=True, capture_output=True, text=True)
        logger.info(f"Successfully installed dependencies: {result.stdout.strip()}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install dependencies: {e.stderr.strip()}")
        logger.error(f"Please install manually with: pip install {' '.join(missing_modules)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during dependency installation: {e}")
        return False

def find_speedtest_script() -> str:
    system = platform.system().lower()
    candidates = []
    if system == "windows":
        candidates = ["iptest.bat", ".\\iptest.bat"]
    else:
        candidates = ["iptest.sh", "./iptest.sh", "iptest", "./iptest"]
    for candidate in candidates:
        if os.path.exists(candidate):
            if not os.access(candidate, os.X_OK) and system != "windows":
                try:
                    os.chmod(candidate, 0o755)
                    logger.info(f"Added execute permission to {candidate}")
                except Exception as e:
                    logger.error(f"Failed to add execute permission to {candidate}: {e}")
                    continue
            logger.info(f"Found speedtest script: {candidate}")
            return candidate
    logger.error("Speedtest script not found, ensure iptest.sh or iptest.bat exists")
    sys.exit(1)

SPEEDTEST_SCRIPT = find_speedtest_script()

def is_valid_ip(ip: str) -> bool:
    ipv4_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    return bool(ipv4_pattern.match(ip))

def is_valid_port(port: str) -> bool:
    try:
        port_num = int(port)
        return 0 <= port_num <= 65535
    except (ValueError, TypeError):
        return False

def is_country_like(value: str) -> bool:
    if not value:
        return False
    value_upper = value.upper().strip()
    if re.match(r'^[A-Z]{2}$', value_upper) and value_upper in COUNTRY_LABELS:
        return True
    if value_upper in COUNTRY_ALIASES:
        return True
    value_clean = re.sub(r'[^a-zA-Z\s\u4e00-\u9fff]', '', value_upper).strip()
    if value_clean in COUNTRY_ALIASES:
        return True
    value_clean_no_space = value_clean.replace(' ', '')
    for alias in COUNTRY_ALIASES:
        alias_clean = alias.replace(' ', '')
        if value_clean_no_space == alias_clean:
            return True
    return False

def standardize_country(value: str) -> str:
    if not value:
        return ''
    value_clean = re.sub(r'[^\w\s\u4e00-\u9fff]', '', value).strip().upper()
    if value_clean in COUNTRY_LABELS:
        return value_clean
    if value_clean in COUNTRY_ALIASES:
        return COUNTRY_ALIASES[value_clean]
    value_no_space = value_clean.replace(' ', '')
    for alias, code in COUNTRY_ALIASES.items():
        alias_clean = alias.replace(' ', '')
        if value_no_space == alias_clean:
            return code
    for code, (_, name) in COUNTRY_LABELS.items():
        if value.strip() == name or value_no_space == name.replace(' ', ''):
            return code
    return ''

def find_country_column(header: List[str]) -> int:
    country_col = -1
    for idx, col in enumerate(header):
        col_lower = col.strip().lower()
        if col_lower in ['country', '国家', 'country_code', 'countrycode', '国际代码', 'nation', 'location', 'region', 'geo', 'area']:
            country_col = idx
            logger.info(f"检测到国家列: 第 {idx + 1} 列 (字段名: {col})")
            break
    return country_col

def extract_country_from_row(row: List[str], country_col: int) -> str:
    if country_col != -1 and country_col < len(row):
        country = standardize_country(row[country_col].strip())
        if country:
            return country
    for col, field in enumerate(row):
        field = field.strip()
        if is_country_like(field):
            country = standardize_country(field)
            if country:
                logger.info(f"从第 {col + 1} 列提取国家: {field} -> {country}")
                return country
    return ''

def detect_delimiter(lines: List[str]) -> str:
    sample_lines = [line for line in lines[:5] if line.strip()]
    delimiters = [',', ';', '\t', ' ', '|']
    max_count = 0
    detected = ','
    for delimiter in delimiters:
        counts = [len(line.split(delimiter)) for line in sample_lines]
        if counts and max(counts) == min(counts):
            avg_count = sum(counts) / len(counts)
            if avg_count > max_count:
                max_count = avg_count
                detected = delimiter
    logger.info(f"Detected delimiter: '{detected}'")
    return detected

def extract_ips_from_web(url: str, proxies: dict = None) -> List[Tuple[str, int, str]]:
    logger.info(f"Extracting IPs from web page: {url}")
    ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
    port_pattern = r':(\d{1,5})'
    ip_ports = []
    try:
        session = requests.Session()
        retry = Retry(total=3, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
        session.mount('https://', HTTPAdapter(max_retries=retry))
        response = session.get(url, headers=HEADERS, proxies=proxies, timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        tags_to_try = ['tr', 'td', 'li', 'div', 'p', 'span', 'pre', 'code']
        ip_matches = []
        for tag in tags_to_try:
            elements = soup.find_all(tag)
            for element in elements:
                element_text = element.get_text()
                matches = re.findall(ip_pattern, element_text)
                ip_matches.extend(matches)
                ports = re.findall(port_pattern, element_text)
                if matches:
                    logger.info(f"Extracted {len(matches)} IPs from <{tag}> tag")
                    break
        if not ip_matches:
            matches = re.findall(ip_pattern, soup.get_text())
            ip_matches.extend(matches)
            ports = re.findall(port_pattern, soup.get_text())
            if matches:
                logger.info(f"Extracted {len(matches)} IPs from page text")
        ip_matches = list(dict.fromkeys(ip_matches))
        for i, ip in enumerate(ip_matches):
            if is_valid_ip(ip):
                port = int(ports[i]) if i < len(ports) and is_valid_port(ports[i]) else DEFAULT_PORTS[i % len(DEFAULT_PORTS)]
                ip_ports.append((ip, port, ''))
        logger.info(f"Extracted {len(ip_ports)} valid IPs from {url}")
        return ip_ports
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to extract IPs from {url}: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error extracting IPs from {url}: {e}")
        return []

def fetch_and_save_to_temp_file(url: str, index: int, proxies: dict = None) -> str:
    temp_file = f"temp_proxy_{index}.csv"
    logger.info(f"Downloading CSV: {url} to {temp_file}")
    try:
        session = requests.Session()
        retry = Retry(total=5, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        session.mount('https://', HTTPAdapter(max_retries=retry))
        response = session.get(url, headers=HEADERS, proxies=proxies, timeout=60)
        response.raise_for_status()
        with open(temp_file, "wb") as f:
            f.write(response.content)
        with open(temp_file, "rb") as f:
            raw_data = f.read()
        encoding = detect(raw_data).get("encoding", "utf-8")
        content = raw_data.decode(encoding, errors='replace')
        lines = content.strip().splitlines()
        if not lines:
            logger.error(f"Downloaded file {temp_file} is empty")
            return ''
        logger.debug(f"CSV sample (first 5 lines):\n{chr(10).join(lines[:5])}")
        return temp_file
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to download CSV from {url}: {e}")
        return ''
    except Exception as e:
        logger.error(f"Unexpected error downloading CSV from {url}: {e}")
        return ''

def extract_ip_ports_from_csv(file_path: str) -> List[Tuple[str, int, str]]:
    if not os.path.exists(file_path):
        logger.error(f"File {file_path} does not exist")
        return []
    with open(file_path, "rb") as f:
        raw_data = f.read()
    encoding = detect(raw_data).get("encoding", "utf-8")
    try:
        content = raw_data.decode(encoding, errors='replace')
    except UnicodeDecodeError:
        logger.warning(f"Failed to decode with {encoding}, trying fallback encodings")
        for fallback_encoding in ['latin1', 'iso-8859-1', 'gbk']:
            try:
                content = raw_data.decode(fallback_encoding, errors='replace')
                logger.info(f"Successfully decoded with {fallback_encoding}")
                break
            except UnicodeDecodeError:
                continue
        else:
            logger.error(f"Failed to decode file {file_path} with any encoding")
            return []
    
    lines = content.replace('\r\n', '\n').replace('\r', '\n').splitlines()
    if not lines:
        logger.error("File content is empty")
        return []

    delimiter = detect_delimiter(lines)
    ip_col, port_col, country_col = 0, 1, -1
    lines_to_process = lines
    if lines and lines[0].strip() and not lines[0].startswith('#'):
        header = lines[0].strip().split(delimiter)
        logger.info(f"CSV header: {header}")
        for idx, col in enumerate(header):
            col_lower = col.strip().lower()
            if col_lower in ['ip', 'address', 'ip_address', 'ip地址', 'ip_addr']:
                ip_col = idx
            elif col_lower in ['port', '端口']:
                port_col = idx
            elif col_lower in ['country', '国家', 'country_code', '国际代码', 'location', 'country_name']:
                country_col = idx
        if country_col == -1:
            country_col = find_country_column(header)
        lines_to_process = lines[1:]

    ip_ports = []
    country_counts = defaultdict(int)
    for line in lines_to_process:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        fields = line.split(delimiter)
        if len(fields) <= max(ip_col, port_col, country_col):
            continue
        ip = fields[ip_col].strip()
        port = fields[port_col].strip()
        country = extract_country_from_row(fields, country_col)
        if country:
            country_counts[country] += 1
        if is_valid_ip(ip) and is_valid_port(port):
            ip_ports.append((ip, int(port), country))
    logger.info(f"Extracted {len(ip_ports)} nodes from CSV {file_path}")
    if country_counts:
        logger.debug(f"Country distribution in CSV: {dict(country_counts)}")
    return list(dict.fromkeys(ip_ports))

def fetch_csv_files_concurrently(urls: List[str], proxies: dict = None, fallback_file: str = None, use_fallback: bool = True) -> List[str]:
    temp_files = []
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT_DOWNLOADS) as executor:
        future_to_url = {executor.submit(fetch_and_save_to_temp_file, url, i, proxies): url for i, url in enumerate(urls)}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                temp_file = future.result()
                if temp_file:
                    temp_files.append(temp_file)
                    logger.info(f"Successfully fetched CSV from {url}")
                else:
                    logger.warning(f"Failed to fetch CSV from {url}")
            except Exception as e:
                logger.error(f"Error fetching CSV from {url}: {e}")
    
    if not temp_files and fallback_file and os.path.exists(fallback_file) and use_fallback:
        logger.info(f"No CSV files downloaded, using fallback file: {fallback_file}")
        temp_files.append(fallback_file)
    return temp_files

def write_ip_list(ip_ports: List[Tuple[str, int, str]]) -> str:
    if not ip_ports:
        logger.error("No IPs to write to ip list")
        return None
    try:
        web_ip_ports = [(ip, port, country, 'web') for ip, port, country in ip_ports if not country]
        csv_ip_ports = [(ip, port, country, 'csv') for ip, port, country in ip_ports if country]
        desired_countries = set(DESIRED_COUNTRIES) if DESIRED_COUNTRIES else set()
        
        # 过滤 CSV 节点
        filtered_csv_ip_ports = [(ip, port, country, source) for ip, port, country, source in csv_ip_ports if not desired_countries or country in desired_countries]
        
        # 合并网页和 CSV 节点
        filtered_ip_ports = web_ip_ports + filtered_csv_ip_ports
        
        if not filtered_ip_ports:
            logger.error("No IPs match desired countries or available")
            return None
        
        # 去重
        unique_ip_ports = []
        seen = set()
        for ip, port, country, source in filtered_ip_ports:
            key = (ip, port)
            if key not in seen:
                seen.add(key)
                unique_ip_ports.append((ip, port, country, source))
        
        # 写入 ip.txt
        with open(IP_LIST_FILE, "w", encoding="utf-8-sig") as f:
            for ip, port, _, _ in unique_ip_ports:
                f.write(f"{ip} {port}\n")
        
        # 写入网页节点到单独文件
        with open("web_ips.txt", "w", encoding="utf-8-sig") as f:
            for ip, port, _, _ in web_ip_ports:
                f.write(f"{ip} {port}\n")
        logger.info(f"Wrote {len(web_ip_ports)} web IPs to web_ips.txt")
        
        logger.info(f"Included {len(web_ip_ports)} IPs from WEB_URLS (no country filter)")
        logger.info(f"Included {len(filtered_csv_ip_ports)} IPs from CSV_URLS (filtered by DESIRED_COUNTRIES)")
        logger.info(f"Generated {IP_LIST_FILE} with {len(unique_ip_ports)} nodes")
        return IP_LIST_FILE
    except PermissionError as e:
        logger.error(f"Failed to write {IP_LIST_FILE}: {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error writing {IP_LIST_FILE}: {e}")
        return None

def run_speed_test() -> str:
    if not os.path.exists(IP_LIST_FILE):
        logger.error(f"{IP_LIST_FILE} does not exist")
        return None
    
    logger.info(f"Starting speed test with script: {SPEEDTEST_SCRIPT}")
    system = platform.system().lower()
    is_termux = os.getenv("TERMUX_VERSION") is not None
    try:
        if system == "windows":
            command = [SPEEDTEST_SCRIPT]
        elif is_termux:
            command = ["bash", SPEEDTEST_SCRIPT]
        else:
            bash_path = shutil.which("bash") or "bash"
            command = ["stdbuf", "-oL", bash_path, SPEEDTEST_SCRIPT]
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8',
            errors='replace'
        )
        stdout_lines, stderr_lines = [], []
        def read_stream(stream, lines, is_stderr=False):
            while True:
                line = stream.readline()
                if not line:
                    break
                lines.append(line.strip())
                logger.info(line.strip()) if not is_stderr else logger.warning(line.strip())
        stdout_thread = threading.Thread(target=read_stream, args=(process.stdout, stdout_lines))
        stderr_thread = threading.Thread(target=read_stream, args=(process.stderr, stderr_lines, True))
        stdout_thread.start()
        stderr_thread.start()
        stdout_thread.join()
        stderr_thread.join()
        return_code = process.wait()
        
        if return_code != 0:
            logger.error(f"Speed test failed with code: {return_code}")
            logger.error(f"STDERR: {''.join(stderr_lines)}")
            return None
        
        if not os.path.exists(FINAL_CSV):
            logger.error(f"{FINAL_CSV} not generated")
            return None
        
        if os.path.getsize(FINAL_CSV) < 10:
            logger.error(f"{FINAL_CSV} is too small or empty")
            try:
                with open(FINAL_CSV, 'r', encoding='utf-8', errors='replace') as f:
                    content = f.read().strip()
                    logger.debug(f"Content: {content}")
            except Exception as e:
                logger.error(f"Failed to read {FINAL_CSV}: {e}")
            return None
        
        try:
            with open(FINAL_CSV, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                header = next(reader, None)
                rows = [row for row in reader]
                if not header:
                    logger.error(f"{FINAL_CSV} has no valid header")
                    return None
                if not rows:
                    logger.error(f"{FINAL_CSV} has no data rows")
                    return None
                logger.info(f"Speed test completed, generated {FINAL_CSV} with {len(rows)} data rows")
        except Exception as e:
            logger.error(f"Failed to validate {FINAL_CSV}: {e}")
            return None
        
        return FINAL_CSV
    except Exception as e:
        logger.error(f"Speed test failed: {e}")
        return None

def generate_ips_file(csv_file: str) -> int:
    start_time = time.time()
    if not os.path.exists(csv_file):
        logger.error(f"{csv_file} does not exist")
        return 0
    
    final_nodes = []
    try:
        with open(csv_file, "r", encoding="utf-8-sig") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if not header:
                logger.error(f"No valid header in {csv_file}")
                return 0
            logger.info(f"CSV header: {', '.join(header)}")
            
            country_col = find_country_column(header)
            ip_col, port_col = 0, 1
            for idx, col in enumerate(header):
                col_lower = col.strip().lower()
                if col_lower in ['ip', 'address', 'ip_address', 'ip_addr', 'ip地址']:
                    ip_col = idx
                elif col_lower in ['port', '端口']:
                    port_col = idx
            
            row_count = 0
            for row in reader:
                row_count += 1
                if len(row) <= max(ip_col, port_col, country_col):
                    logger.debug(f"Skipping invalid row {row_count}: {row}")
                    continue
                ip = row[ip_col].strip()
                port = str(row[port_col]).strip()
                country = extract_country_from_row(row, country_col)
                if not is_valid_ip(ip) or not is_valid_port(port):
                    logger.debug(f"Invalid IP/port in row {row_count}: {ip}:{port}")
                    continue
                final_nodes.append((ip, int(port), country, 'csv'))
            logger.info(f"Read {row_count} rows from {csv_file}, found {len(final_nodes)} valid nodes")
    except Exception as e:
        logger.error(f"Failed to read {csv_file}: {e}")
        return 0
    
    # 读取网页节点
    web_nodes = []
    if os.path.exists("web_ips.txt"):
        try:
            with open("web_ips.txt", "r", encoding="utf-8-sig") as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2 and is_valid_ip(parts[0]) and is_valid_port(parts[1]):
                        web_nodes.append((parts[0], int(parts[1]), '', 'web'))
            logger.info(f"Read {len(web_nodes)} web nodes from web_ips.txt")
        except Exception as e:
            logger.error(f"Failed to read web_ips.txt: {e}")
    
    # 合并节点
    all_nodes = final_nodes + web_nodes
    if not all_nodes:
        logger.error(f"No valid nodes found in {csv_file} or web_ips.txt")
        return 0
        
    logger.info(f"Found {len(all_nodes)} nodes before deduplication")
    country_count = defaultdict(int)
    country_seq = defaultdict(int)
    labeled_nodes = []
    for ip, port, country, source in sorted(all_nodes, key=lambda x: x[2] or 'ZZ'):
        country = country or 'UNKNOWN'
        country_count[country] += 1
        country_seq[country] += 1
        emoji, name = COUNTRY_LABELS.get(country, ('🌈', '未知地区'))
        label = f"{emoji}{name}-{country_seq[country]} ({source})"
        labeled_nodes.append((ip, port, label))
    
    unique_nodes = []
    seen = set()
    for ip, port, label in labeled_nodes:
        key = (ip, port)
        if key not in seen:
            seen.add(key)
            unique_nodes.append((ip, port, label))
    
    try:
        with open(IPS_FILE, "w", encoding="utf-8-sig") as f:
            for ip, port, label in unique_nodes:
                f.write(f"{ip}:{port}#{label}\n")
        logger.info(f"Generated {IPS_FILE} with {len(unique_nodes)} unique nodes")
        logger.debug(f"Country distribution: {{ {', '.join(f'{k}: {v}' for k, v in sorted(country_count.items()))} }}")
        return len(unique_nodes)
    except PermissionError as e:
        logger.error(f"Failed to write {IPS_FILE}: {e}")
        return 0
    except Exception as e:
        logger.error(f"Failed to write {IPS_FILE}: {e}")
        return 0

def main():
    parser = argparse.ArgumentParser(description="Fetch IPs from web and CSV, perform speed tests")
    parser.add_argument('--csv-url', type=str, help='Comma-separated CSV URLs')
    parser.add_argument('--no-web', action='store_true', help='Skip web scraping')
    parser.add_argument('--auto-install', action='store_true', help='Auto-install dependencies')
    parser.add_argument('--pip-url', type=str, help='Custom pip source (e.g., https://pypi.tuna.tsinghua.edu.cn/simple)')
    parser.add_argument('--proxy', type=str, help='Proxy URL (e.g., http://user:pass@host:port)')
    parser.add_argument('--local-csv', type=str, help='Path to local CSV file (default: local_ips.csv)', default='local_ips.csv')
    args = parser.parse_args()

    csv_urls = CSV_URLS if not args.csv_url else [url.strip() for url in args.csv_url.split(',') if url.strip()]
    proxies = None
    if args.proxy:
        proxies = {'http': args.proxy, 'https': args.proxy}
        logger.info(f"Using proxy: {args.proxy}")

    if not check_and_install_dependencies(args.auto_install, args.pip_url):
        sys.exit(1)

    try:
        for file in [IP_LIST_FILE, IPS_FILE, FINAL_CSV, TEMP_FILE, "web_ips.txt"]:
            if os.path.exists(file):
                os.remove(file)
                logger.info(f"Removed old file: {file}")
        for i in range(len(csv_urls)):
            temp_file = f"temp_proxy_{i}.csv"
            if os.path.exists(temp_file):
                os.remove(temp_file)
                logger.info(f"Removed temp file: {temp_file}")

        ip_ports = []
        if not args.no_web:
            if not WEB_URLS:
                logger.info("WEB_URLS is empty, skipping web scraping")
            else:
                for url in WEB_URLS:
                    ip_ports.extend(extract_ips_from_web(url, proxies))
                    time.sleep(1)

        if not WEB_URLS and not csv_urls and not os.path.exists(args.local_csv):
            logger.error(f"No WEB_URLS or CSV_URLS provided, and local CSV file {args.local_csv} does not exist")
            sys.exit(1)

        use_fallback = not (WEB_URLS or csv_urls)
        temp_files = fetch_csv_files_concurrently(csv_urls, proxies, fallback_file=args.local_csv, use_fallback=use_fallback)
        for temp_file in temp_files:
            ip_ports.extend(extract_ip_ports_from_csv(temp_file))
        
        if not ip_ports:
            logger.error("No valid IPs collected from web or CSV sources")
            sys.exit(1)

        ip_list_file = write_ip_list(ip_ports)
        if not ip_list_file:
            logger.error("Failed to generate IP list")
            sys.exit(1)

        csv_file = run_speed_test()
        if not csv_file:
            logger.error("Speed test failed")
            sys.exit(1)

        node_count = generate_ips_file(csv_file)
        if not node_count:
            logger.error("Failed to generate IPs file")
            sys.exit(1)

        logger.info(f"Completed successfully, generated {node_count} nodes")
    finally:
        for i in range(len(csv_urls)):
            temp_file = f"temp_proxy_{i}.csv"
            if os.path.exists(temp_file):
                os.remove(temp_file)
                logger.info(f"Cleaned up: {temp_file}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Script failed: {e}")
        sys.exit(1)
