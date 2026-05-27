import subprocess
import re
import sys
import platform
import ipaddress
import concurrent.futures
import pandas as pd
from pyvis.network import Network

# ---------- НАСТРОЙКИ ----------
EXCEL_FILE = "inventory.xlsx"      # путь к вашему Excel-файлу
SHEET_NAME = 0                     # номер листа (0 - первый) или имя листа

TARGET_SUBNETS = [
    ipaddress.ip_network('192.168.200.0/24'),
    ipaddress.ip_network('192.168.94.0/24')
]
# -------------------------------

SYSTEM = platform.system()  # 'Windows' или 'Linux'

def load_name_mapping(excel_path, sheet=0):
    """Читает Excel и возвращает словарь {IP: Name}. Ожидаются столбцы 'IP' и 'Name'."""
    df = pd.read_excel(excel_path, sheet_name=sheet)
    df.columns = [c.lower().strip() for c in df.columns]
    if 'ip' not in df.columns or 'name' not in df.columns:
        raise ValueError("Excel должен содержать столбцы 'IP' и 'Name' (регистр не важен)")
    mapping = {}
    for _, row in df.iterrows():
        ip = str(row['ip']).strip()
        name = str(row['name']).strip()
        if ip and name:
            mapping[ip] = name
    print(f"Загружено {len(mapping)} записей из Excel")
    return mapping

def is_in_target_subnets(ip_str):
    """Проверяет, входит ли IP-адрес в одну из целевых подсетей."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in subnet for subnet in TARGET_SUBNETS)
    except ValueError:
        return False

def subnet_for_ip(ip_str):
    """Возвращает строку с подсетью (или 'External'), к которой относится IP."""
    try:
        ip = ipaddress.ip_address(ip_str)
        for subnet in TARGET_SUBNETS:
            if ip in subnet:
                return str(subnet)
        return "External"
    except ValueError:
        return "External"

def ping_sweep(network, timeout_ms=800):
    """Параллельное ping-сканирование подсети, возвращает список ответивших IP."""
    live_ips = []
    if SYSTEM == 'Windows':
        base_cmd = ['ping', '-n', '1', '-w', str(timeout_ms)]
    else:
        base_cmd = ['ping', '-c', '1', '-W', str(timeout_ms/1000)]
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_ip = {
            executor.submit(
                subprocess.run,
                base_cmd + [str(ip)],
                capture_output=True,
                text=True,
                timeout=timeout_ms/1000 + 2
            ): str(ip)
            for ip in network.hosts()
        }
        for future in concurrent.futures.as_completed(future_to_ip):
            ip = future_to_ip[future]
            try:
                if future.result().returncode == 0:
                    live_ips.append(ip)
            except Exception:
                pass
    return live_ips

def arp_table():
    """Считывает ARP-таблицу системы и возвращает словарь {IP: MAC}."""
    arp = {}
    if SYSTEM == 'Windows':
        cmd = ['arp', '-a']
    else:
        cmd = ['arp', '-n']
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        output = result.stdout
        if SYSTEM == 'Windows':
            pattern = re.compile(r'^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+((?:[0-9a-fA-F]{1,2}[-:]){5}[0-9a-fA-F]{1,2})')
        else:
            pattern = re.compile(r'^\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+\S+\s+((?:[0-9a-fA-F]{1,2}:){5}[0-9a-fA-F]{1,2})')
        for line in output.splitlines():
            match = pattern.search(line)
            if match:
                ip = match.group(1)
                mac = match.group(2).replace('-', ':').upper()
                arp[ip] = mac
    except Exception as e:
        print(f"Ошибка при получении ARP: {e}")
    return arp

def traceroute(target, timeout_ms=2000, max_hops=15):
    """Трассировка до target (Windows/Linux), возвращает список IP на пути."""
    if SYSTEM == 'Windows':
        cmd = ['tracert', '-d', '-w', str(timeout_ms), '-h', str(max_hops), target]
    else:
        cmd = ['traceroute', '-n', '-q', '1', '-w', str(timeout_ms/1000), '-m', str(max_hops), target]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=max_hops*timeout_ms/1000+10)
        output = result.stdout
    except Exception:
        return []
    hops = []
    if SYSTEM == 'Windows':
        pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*$')
    else:
        pattern = re.compile(r'^\s*\d+\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    for line in output.splitlines():
        if '*' in line:
            continue
        match = pattern.search(line)
        if match:
            hops.append(match.group(1))
    return hops

def build_layered_routes(target_ips, name_map, arp_data):
    """
    Строит слоистую структуру маршрутов.
    Возвращает (layers, routes_info).
    layers[0] – словарь с 'workspace' (рабочая зона)
    routes_info – список кортежей (path, loop_detected)
    """
    routes_info = []
    for target in target_ips:
        raw_path = traceroute(target)
        if not raw_path:
            continue
        
        clean_path = []
        seen = set()
        loop_detected = False
        for ip in raw_path:
            if ip in seen:
                loop_detected = True
                clean_path.append(ip)  # последний узел перед петлёй
                break
            seen.add(ip)
            clean_path.append(ip)
        routes_info.append((clean_path, loop_detected))

    if not routes_info:
        return [], []

    max_hops = max(len(path) for path, _ in routes_info)
    layers = [{} for _ in range(max_hops + 1)]
    layers[0]['workspace'] = 'Рабочая зона'

    for path, loop in routes_info:
        for idx, ip in enumerate(path):
            level = idx + 1
            if ip not in layers[level]:
                name = name_map.get(ip, None)
                mac = arp_data.get(ip, '')
                if name:
                    label = f"{name}\n{ip}"
                else:
                    label = ip
                if mac:
                    label += f"\n({mac})"
                if loop and idx == len(path) - 1:
                    label += "\n⚠️ Loop detected"
                layers[level][ip] = label
    return layers, routes_info

def create_html(layers, routes_info, output_file="network_map.html"):
    """Генерирует интерактивную HTML-схему с помощью pyvis."""
    net = Network(height="800px", width="100%", directed=True)
    net.set_options("""
    {
      "layout": {
        "hierarchical": {
          "enabled": true,
          "direction": "LR",
          "sortMethod": "directed",
          "levelSeparation": 200,
          "nodeSpacing": 150
        }
      },
      "physics": {
        "hierarchicalRepulsion": {
          "centralGravity": 0.0,
          "springLength": 100,
          "nodeDistance": 150
        },
        "minVelocity": 0.75,
        "solver": "hierarchicalRepulsion"
      },
      "interaction": {
        "zoomView": true,
        "dragView": true,
        "dragNodes": false
      }
    }
    """)

    # Добавляем узлы по уровням
    for level, layer in enumerate(layers):
        for ip, label in layer.items():
            if ip == 'workspace':
                group = 'workspace'
            else:
                group = subnet_for_ip(ip)
            color = {
                '192.168.200.0/24': '#c6ecc6',
                '192.168.94.0/24': '#c6d9ec',
                'External': '#e0e0e0',
                'workspace': '#fffacd'
            }.get(group, 'white')
            net.add_node(f"{level}_{ip}", label=label, level=level, color=color,
                         shape='box', font={'size': 12})

    # Добавляем рёбра
    for path, _ in routes_info:
        if not path:
            continue
        net.add_edge("0_workspace", f"1_{path[0]}")
        for i in range(len(path)-1):
            src_level = i + 1
            dst_level = i + 2
            net.add_edge(f"{src_level}_{path[i]}", f"{dst_level}_{path[i+1]}")

    net.save_graph(output_file)
    print(f"Интерактивная схема сохранена в {output_file}")
    return output_file

if __name__ == "__main__":
    try:
        name_mapping = load_name_mapping(EXCEL_FILE, SHEET_NAME)
    except Exception as e:
        print(f"Ошибка загрузки Excel: {e}")
        sys.exit(1)

    print(f"\nОбнаружена ОС: {SYSTEM}")

    # 1. Сбор целей: ping + IP из Excel, входящие в целевые подсети
    print("\nСканирование подсетей (ping)...")
    ping_live = []
    for net in TARGET_SUBNETS:
        print(f"  {net}")
        live = ping_sweep(net, timeout_ms=1000)
        ping_live.extend(live)
        print(f"    Ping-ответов: {len(live)}")

    # Извлекаем IP из Excel, которые принадлежат целевым подсетям
    excel_target_ips = set()
    for ip_str in name_mapping.keys():
        if is_in_target_subnets(ip_str):
            excel_target_ips.add(ip_str)

    all_targets = set(ping_live) | excel_target_ips
    print(f"\nВсего целей для трассировки: {len(all_targets)} "
          f"(из ping: {len(ping_live)}, из Excel: {len(excel_target_ips)})")

    if not all_targets:
        print("Нет доступных устройств. Проверьте Excel и связность подсетей.")
        sys.exit(1)

    # 2. Сбор ARP (после пингов, чтобы заполнить кэш)
    print("\nСбор ARP-таблицы...")
    arp = arp_table()
    print(f"ARP-записей: {len(arp)}")

    # 3. Построение маршрутов
    print("\nПостроение маршрутов (traceroute)...")
    layers, routes_info = build_layered_routes(list(all_targets), name_mapping, arp)
    print(f"Слоёв (включая уровень 0): {len(layers)}")

    html_path = create_html(layers, routes_info)
    import webbrowser
    webbrowser.open(html_path)