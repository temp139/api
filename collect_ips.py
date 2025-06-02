import requests
from bs4 import BeautifulSoup
import re
import os
import subprocess
import threading
import time
import shutil
import sys
import logging
import csv
from typing import List, Tuple
from collections import defaultdict

# 配置日志，输出到控制台和文件
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

# 禁用 stdout 缓冲，确保实时输出
sys.stdout.reconfigure(line_buffering=True)

# 常量
INPUT_CSV = "ip.csv"
OUTPUT_FILE = "ips.txt"
IP_FILE = "ip.txt"
IPTEST_SH = "iptest.sh"
IPTEST_BIN = "iptest"

# 国家标签和别名
COUNTRY_LABELS = {
    'JP': ('🇯🇵', '日本'), 'KR': ('🇰🇷', '韩国'), 'SG': ('🇸🇬', '新加坡'),
    'TW': ('🇹🇼', '台湾'), 'HK': ('🇭🇰', '香港'), 'MY': ('🇲🇾', '马来西亚'),
    'TH': ('🇹🇭', '泰国'), 'ID': ('🇮🇩', '印度尼西亚'), 'PH': ('🇵🇭', '菲律宾'),
    'VN': ('🇻🇳', '越南'), 'IN': ('🇮🇳', '印度'), 'MO': ('🇲🇴', '澳门'),
    'KH': ('🇰🇭', '柬埔寨'), 'LA': ('🇱🇦', '老挝'), 'MM': ('🇲🇲', '缅甸'),
    'MN': ('🇲🇳', '蒙古'), 'KP': ('🇰🇵', '朝鲜'), 'US': ('🇺🇸', '美国'),
    'GB': ('🇬🇧', '英国'), 'DE': ('🇩🇪', '德国'), 'FR': ('🇫🇷', '法国'),
    'IT': ('🇮🇹', '意大利'), 'ES': ('🇪🇸', '西班牙'), 'NL': ('🇳🇱', '荷兰'),
    'FI': ('🇫🇮', '芬兰'), 'AU': ('🇦🇺', '澳大利亚'), 'CA': ('🇨🇦', '加拿大'),
    'NZ': ('🇳🇿', '新西兰'), 'BR': ('🇧🇷', '巴西'), 'RU': ('🇷🇺', '俄罗斯'),
    'PL': ('🇵🇱', '波兰'), 'UA': ('🇺🇦', '乌克兰'), 'CZ': ('🇨🇿', '捷克'),
    'HU': ('🇭🇺', '匈牙利'), 'RO': ('🇷🇴', '罗马尼亚'), 'SA': ('🇸🇦', '沙特阿拉伯'),
    'AE': ('🇦🇪', '阿联酋'), 'QA': ('🇶🇦', '卡塔尔'), 'IL': ('🇮🇱', '以色列'),
    'TR': ('🇹🇷', '土耳其'), 'IR': ('🇮🇷', '伊朗'),
    'CN': ('🇨🇳', '中国'), 'BD': ('🇧🇩', '孟加拉国'), 'PK': ('🇵🇰', '巴基斯坦'),
    'LK': ('🇱🇰', '斯里兰卡'), 'NP': ('🇳🇵', '尼泊尔'), 'BT': ('🇧🇹', '不丹'),
    'MV': ('🇲🇻', '马尔代夫'), 'BN': ('🇧🇳', '文莱'), 'TL': ('🇹🇱', '东帝汶'),
    'EG': ('🇪🇬', '埃及'), 'ZA': ('🇿🇦', '南非'), 'NG': ('🇳🇬', '尼日利亚'),
    'KE': ('🇰🇪', '肯尼亚'), 'GH': ('🇬🇭', '加纳'), 'MA': ('🇲🇦', '摩洛哥'),
    'DZ': ('🇩🇿', '阿尔及利亚'), 'TN': ('🇹🇳', '突尼斯'), 'AR': ('🇦🇷', '阿根廷'),
    'CL': ('🇨🇱', '智利'), 'CO': ('🇨🇴', '哥伦比亚'), 'PE': ('🇵🇪', '秘鲁'),
    'MX': ('🇲🇽', '墨西哥'), 'VE': ('🇻🇪', '委内瑞拉'), 'SE': ('🇸🇪', '瑞典'),
    'NO': ('🇳🇴', '挪威'), 'DK': ('🇩🇰', '丹麦'), 'CH': ('🇨🇭', '瑞士'),
    'AT': ('🇦🇹', '奥地利'), 'BE': ('🇧🇪', '比利时'), 'IE': ('🇮🇪', '爱尔兰'),
    'PT': ('🇵🇹', '葡萄牙'), 'GR': ('🇬🇷', '希腊'), 'BG': ('🇧🇬', '保加利亚'),
    'SK': ('🇸🇰', '斯洛伐克'), 'SI': ('🇸🇮', '斯洛文尼亚'), 'HR': ('🇭🇷', '克罗地亚'),
    'RS': ('🇷🇸', '塞尔维亚'), 'BA': ('🇧🇦', '波黑'), 'MK': ('🇲🇰', '北马其顿'),
    'AL': ('🇦🇱', '阿尔巴尼亚'), 'KZ': ('🇰🇿', '哈萨克斯坦'), 'UZ': ('🇺🇿', '乌兹别克斯坦'),
    'KG': ('🇰🇬', '吉尔吉斯斯坦'), 'TJ': ('🇹🇯', '塔吉克斯坦'), 'TM': ('🇹🇲', '土库曼斯坦'),
    'GE': ('🇬🇪', '格鲁吉亚'), 'AM': ('🇦🇲', '亚美尼亚'), 'AZ': ('🇦🇿', '阿塞拜疆'),
    'KW': ('🇰🇼', '科威特'), 'BH': ('🇧🇭', '巴林'), 'OM': ('🇴🇲', '阿曼'),
    'JO': ('🇯🇴', '约旦'), 'LB': ('🇱🇧', '黎巴嫩'), 'SY': ('🇸🇾', '叙利亚'),
    'IQ': ('🇮🇶', '伊拉克'), 'YE': ('🇾🇪', '也门'),
    'EE': ('🇪🇪', '爱沙尼亚'), 'LV': ('🇱🇻', '拉脱维亚'), 'LT': ('🇱🇹', '立陶宛')
}

COUNTRY_ALIASES = {
    'SOUTH KOREA': 'KR', 'KOREA': 'KR', 'REPUBLIC OF KOREA': 'KR', 'KOREA, REPUBLIC OF': 'KR',
    'HONG KONG': 'HK', 'HONGKONG': 'HK', 'HK SAR': 'HK',
    'UNITED STATES': 'US', 'USA': 'US', 'U.S.': 'US', 'UNITED STATES OF AMERICA': 'US',
    'UNITED KINGDOM': 'GB', 'UK': 'GB', 'GREAT BRITAIN': 'GB', '英国': 'GB',
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
    'VIET NAM': 'VN', 'VIETNAM': 'VN', '越南': 'VN',
    'THAILAND': 'TH', 'THA': 'TH', '泰国': 'TH',
    'BURMA': 'MM', 'MYANMAR': 'MM', '缅甸': 'MM',
    'NORTH KOREA': 'KP', 'KOREA, DEMOCRATIC PEOPLE\'S REPUBLIC OF': 'KP', '朝鲜': 'KP'
}

# 当前工作目录
current_dir = os.getcwd()

# 目标 URL 列表
urls = [
    'https://ip.164746.xyz/ipTop10.html',
    'https://cf.090227.xyz',
]

# IP 地址正则表达式
ip_pattern = r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'

# 端口列表
ports = [443, 2053, 2083, 2087, 2096, 8443]

# HTTP 请求头
headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
}

def is_valid_ip(ip: str) -> bool:
    ipv4_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
    ipv6_pattern = re.compile(r'^(?:[0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$')
    return bool(ipv4_pattern.match(ip) or ipv6_pattern.match(ip.strip('[]')))

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
    value_clean = re.sub(r'[^a-zA-Z\s]', '', value_upper).strip()
    if value_clean in COUNTRY_ALIASES:
        return True
    value_clean_no_space = value_clean.replace(' ', '')
    for alias in COUNTRY_ALIASES:
        alias_clean = alias.replace(' ', '')
        if value_clean_no_space == alias_clean:
            return True
    return False

def standardize_country(country: str) -> str:
    if not country:
        return ''
    country_clean = re.sub(r'[^a-zA-Z\s]', '', country).strip().upper()
    if country_clean in COUNTRY_LABELS:
        return country_clean
    if country_clean in COUNTRY_ALIASES:
        return COUNTRY_ALIASES[country_clean]
    country_clean_no_space = country_clean.replace(' ', '')
    for alias, code in COUNTRY_ALIASES.items():
        alias_clean = alias.replace(' ', '')
        if country_clean_no_space == alias_clean:
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

def generate_ips_txt(csv_file: str) -> int:
    start_time = time.time()
    if not os.path.exists(csv_file):
        logger.info(f"{csv_file} 不存在")
        return 0

    final_nodes = []
    try:
        with open(csv_file, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            header = next(reader, None)
            if not header:
                logger.error(f"{csv_file} 没有有效的表头")
                return 0
            logger.info(f"标头: {header}")

            country_col = find_country_column(header)
            ip_col, port_col = 0, 1

            for row in reader:
                if len(row) < 2:
                    continue
                ip, port = row[ip_col], row[port_col]
                if not is_valid_ip(ip) or not is_valid_port(port):
                    continue
                country = extract_country_from_row(row, country_col)
                final_nodes.append((ip, int(port), country))
    except Exception as e:
        logger.error(f"无法读取 {csv_file}: {e}")
        return 0

    if not final_nodes:
        logger.info(f"没有符合条件的节点")
        return 0

    country_count = defaultdict(int)
    labeled_nodes = []
    for ip, port, country in sorted(final_nodes, key=lambda x: x[2] or 'ZZ'):
        if country and country in COUNTRY_LABELS:
            country_count[country] += 1
            emoji, name = COUNTRY_LABELS[country]
            label = f"{emoji}{name}-{country_count[country]}"
            labeled_nodes.append((ip, port, label))
        else:
            labeled_nodes.append((ip, port, "🌐未知"))

    unique_nodes = []
    seen = set()
    for ip, port, label in labeled_nodes:
        key = (ip, port)
        if key not in seen:
            seen.add(key)
            unique_nodes.append((ip, port, label))

    with open(OUTPUT_FILE, "w", encoding="utf-8-sig") as f:
        for ip, port, label in unique_nodes:
            f.write(f"{ip}:{port}#{label}\n")

    logger.info(f"生成 {OUTPUT_FILE}，{len(unique_nodes)} 个节点 (耗时: {time.time() - start_time:.2f} 秒)")
    logger.info(f"国家分布: {dict(country_count)}")
    return len(unique_nodes)

def main():
    # 删除已存在的 ip.txt
    if os.path.exists(IP_FILE):
        logger.info(f"删除已存在的 {IP_FILE}")
        os.remove(IP_FILE)

    # 存储提取的 IP 地址
    ip_list = []

    try:
        # 遍历 URL 提取 IP
        for url in urls:
            logger.info(f"正在处理：{url}")
            try:
                response = requests.get(url, headers=headers, timeout=15)
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
                    if ip_matches:
                        logger.info(f"从 {url} 的 <{tag}> 标签提取到 {len(ip_matches)} 个IP地址")
                        break

                if not ip_matches:
                    matches = re.findall(ip_pattern, soup.get_text())
                    ip_matches.extend(matches)
                    if matches:
                        logger.info(f"从 {url} 的页面文本提取到 {len(matches)} 个IP地址")

                ip_list.extend(ip_matches)
                if not ip_matches:
                    logger.warning(f"从 {url} 未提取到任何IP地址")
                    debug_file = os.path.join(current_dir, f'debug_{url.split("/")[-1]}.html')
                    with open(debug_file, 'w', encoding='utf-8') as f:
                        f.write(response.text)

                time.sleep(1)

            except requests.exceptions.RequestException as e:
                logger.error(f"请求 {url} 失败：{e}")
                continue
            except Exception as e:
                logger.error(f"解析 {url} 时发生错误：{e}")
                continue

        # 去重 IP
        ip_list = list(dict.fromkeys(ip_list))
        if not ip_list:
            logger.error("未从任何网页中提取到有效IP地址")
            sys.exit(1)

        # 写入 ip.txt
        with open(IP_FILE, 'w', encoding='utf-8') as file:
            for i, ip in enumerate(ip_list):
                port = ports[i % len(ports)]
                file.write(f"{ip} {port}\n")
        logger.info(f"成功提取 {len(ip_list)} 个唯一IP地址，已保存到 {IP_FILE}")

        # 执行测速
        if os.path.exists(IPTEST_SH):
            logger.info(f"检测到 {IPTEST_SH}")
            try:
                os.chmod(IPTEST_SH, 0o755)
                logger.info(f"已确保 {IPTEST_SH} 具有可执行权限")
            except OSError as e:
                logger.error(f"无法设置 {IPTEST_SH} 权限：{e}")

            if os.path.exists(IPTEST_BIN):
                try:
                    os.chmod(IPTEST_BIN, 0o755)
                    logger.info(f"已确保 {IPTEST_BIN} 具有可执行权限")
                except OSError as e:
                    logger.error(f"无法设置 {IPTEST_BIN} 权限：{e}")
            else:
                logger.error(f"未找到 {IPTEST_BIN}，请确保文件存在")
                sys.exit(1)

            logger.info(f"调用 {IPTEST_SH} 进行测速")
            try:
                system = sys.platform.lower()
                is_termux = os.getenv("TERMUX_VERSION") is not None or "com.termux" in os.getenv("PREFIX", "")
                bash_path = shutil.which("bash") or "bash"
                if system == "windows":
                    command = [IPTEST_SH]
                elif is_termux:
                    command = [bash_path, IPTEST_SH]
                else:
                    command = ["stdbuf", "-oL", bash_path, IPTEST_SH]

                logger.info(f"执行命令：{' '.join(command)}")
                env = os.environ.copy()
                env["PYTHONUNBUFFERED"] = "1"

                process = subprocess.Popen(
                    command,
                    cwd=current_dir,
                    env=env,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    bufsize=1
                )

                stdout_lines, stderr_lines = [], []
                def read_stream(stream, lines, is_stderr=False):
                    while True:
                        line = stream.readline()
                        if not line:
                            break
                        lines.append(line)
                        logger.info(line.strip()) if not is_stderr else logger.error(line.strip())

                stdout_thread = threading.Thread(target=read_stream, args=(process.stdout, stdout_lines))
                stderr_thread = threading.Thread(target=read_stream, args=(process.stderr, stderr_lines, True))
                stdout_thread.start()
                stderr_thread.start()

                return_code = process.wait()
                stdout_thread.join()
                stderr_thread.join()

                stdout = ''.join(stdout_lines)
                stderr = ''.join(stderr_lines)
                if stdout:
                    logger.info(f"测速输出：\n{stdout}")
                if stderr:
                    logger.error(f"测速错误输出：\n{stderr}")

                if return_code == 0:
                    logger.info("测速完成")
                    if not os.path.exists(INPUT_CSV) or os.path.getsize(INPUT_CSV) < 10:
                        logger.error(f"{INPUT_CSV} 未生成或内容无效")
                        sys.exit(1)
                else:
                    logger.error(f"测速失败，返回码：{return_code}")
                    sys.exit(1)
            except OSError as e:
                logger.error(f"无法执行 {IPTEST_SH}：{e}")
                logger.info("可能的原因：")
                logger.info(f"1. {IPTEST_SH} 文件格式错误（可能包含 Windows 换行符）。运行：sudo apt-get install dos2unix && dos2unix {IPTEST_SH}")
                logger.info(f"2. {IPTEST_BIN} 二进制文件不可执行或与系统不兼容。检查：file {IPTEST_BIN}")
                sys.exit(1)
            except Exception as e:
                logger.error(f"执行 {IPTEST_SH} 时发生未知错误：{e}")
                sys.exit(1)
        else:
            logger.error(f"未找到 {IPTEST_SH}，请检查路径")
            sys.exit(1)

        # 生成 ips.txt
        node_count = generate_ips_txt(INPUT_CSV)
        if not node_count:
            logger.error("无法生成 ips.txt 文件")
            sys.exit(1)

        logger.info("脚本执行完成！")

    except Exception as e:
        logger.error(f"处理过程中发生错误：{e}")
        sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("用户中断操作，退出")
        sys.exit(1)
    except Exception as e:
        logger.error(f"程序异常：{e}")
        sys.exit(1)