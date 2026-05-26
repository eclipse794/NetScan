import subprocess
import re
import time
import sys
import os
from collections import defaultdict
from pathlib import Path

# Проверка зависимостей
try:
    from pyvis.network import Network
except ImportError:
    print("Ошибка: Библиотека pyvis не найдена. Установите её командой: pip install pyvis")
    sys.exit(1)

try:
    import openpyxl
except ImportError:
    print("Ошибка: Библиотека openpyxl не найдена. Установите её командой: pip install openpyxl")
    sys.exit(1)

class NetworkMapper:
    def __init__(self):
        self.subnets = ["192.168.200.0/24", "192.168.94.0/24"]
        self.inventory = {}  # IP -> {Name, Status}
        self.active_hosts = {}  # IP -> TTL
        self.routes = defaultdict(set)  # Host -> Set of Hops
        self.hops_info = {}  # Hop IP -> Info
        
        # Цвета для подсетей
        self.subnet_colors = {
            "192.168.200": "#3498db",  # Синий
            "192.168.94": "#2ecc71",   # Зеленый
            "default": "#95a5a6"       # Серый для шлюзов/промежуточных
        }

    def load_inventory(self, filename="inventory.xlsx"):
        """Загрузка данных из Excel"""
        if not os.path.exists(filename):
            print(f"Файл {filename} не найден. Создайте файл с колонками: IP, Status, Name")
            return

        print(f"Чтение инвентаризации из {filename}...")
        try:
            wb = openpyxl.load_workbook(filename)
            ws = wb.active
            
            # Поиск заголовков
            headers = [cell.value for cell in ws[1]]
            try:
                ip_idx = headers.index("IP")
                status_idx = headers.index("Status")
                name_idx = headers.index("Name")
            except ValueError:
                print("Ошибка: В Excel файле должны быть колонки: IP, Status, Name")
                return

            count = 0
            for row in ws.iter_rows(min_row=2, values_only=True):
                if row[ip_idx]:
                    ip = str(row[ip_idx]).strip()
                    status = str(row[status_idx]).strip() if row[status_idx] else "Unknown"
                    name = str(row[name_idx]).strip() if row[name_idx] else ""
                    self.inventory[ip] = {"status": status, "name": name}
                    count += 1
            
            print(f"Загружено {count} записей из Excel.")
        except Exception as e:
            print(f"Ошибка при чтении Excel: {e}")

    def ping_host(self, ip, timeout=1):
        """Проверка доступности хоста через ping"""
        param = '-n' if sys.platform == 'win32' else '-c'
        command = ['ping', param, '1', '-w', str(timeout * 1000), ip]
        
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout + 2)
            if result.returncode == 0:
                # Извлечение TTL
                ttl_match = re.search(r'TTL=(\d+)', result.stdout.decode('cp866', errors='ignore'))
                ttl = int(ttl_match.group(1)) if ttl_match else 64
                return True, ttl
            return False, 0
        except Exception:
            return False, 0

    def traceroute_host(self, ip, max_hops=15):
        """Трассировка маршрута до хоста"""
        if sys.platform == 'win32':
            command = ['tracert', '-d', '-h', str(max_hops), ip]
        else:
            command = ['traceroute', '-n', '-m', str(max_hops), ip]
        
        hops = []
        try:
            # Для Windows нужен больший таймаут
            timeout = 30 if sys.platform == 'win32' else 15
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            output = result.stdout.decode('cp866', errors='ignore') if sys.platform == 'win32' else result.stdout.decode('utf-8', errors='ignore')
            
            for line in output.split('\n'):
                # Поиск IP в строке трассировки (формат Windows: <мс> <мс> <мс> IP)
                # Формат Linux: номер: IP
                ip_match = re.search(r'\d+\.\d+\.\d+\.\d+', line)
                if ip_match:
                    hop_ip = ip_match.group(0)
                    if hop_ip != ip:  # Не добавляем сам целевой хост как промежуточный
                        hops.append(hop_ip)
        except subprocess.TimeoutExpired:
            print(f"  [WARN] Tracert до {ip} превысил таймаут.")
        except Exception as e:
            print(f"  [ERROR] Ошибка tracert до {ip}: {e}")
            
        return hops

    def scan_subnets(self):
        """Сканирование подсетей"""
        for subnet in self.subnets:
            base_ip = subnet.split('/')[0]
            prefix = '.'.join(base_ip.split('.')[:3])
            print(f"\nСканирование подсети {subnet}...")
            
            # Сканируем только .1 до .254
            for i in range(1, 255):
                ip = f"{prefix}.{i}"
                
                # Пинг
                is_up, ttl = self.ping_host(ip)
                
                expected_status = self.inventory.get(ip, {}).get("status", "")
                
                if is_up:
                    self.active_hosts[ip] = ttl
                    print(f"  [OK] {ip} (TTL: {ttl})")
                    
                    # Трассировка только для активных
                    hops = self.traceroute_host(ip)
                    for hop in hops:
                        self.routes[ip].add(hop)
                        # Сохраняем информацию о хопах
                        if hop not in self.hops_info:
                            self.hops_info[hop] = {"is_gateway": True}
                            
                elif expected_status.upper() == "UP":
                    print(f"  [WARN] {ip} должен быть Up (по Excel), но не пингуется!")
                    # Добавляем в активные как "недоступный", чтобы отобразить на карте
                    self.active_hosts[ip] = 0 
                else:
                    # Тихое игнорирование недоступных, которых нет в Excel или которые Down
                    pass

    def build_graph(self):
        """Построение графа сети и сохранение в HTML"""
        print("\nПостроение графа сети...")
        
        # Инициализация сети (ширина 100%, высота 800px)
        net = Network(width="100%", height="800px", bgcolor="#ffffff", font_color="#000000")
        
        # Настройка физики для "блочного" вида
        # Используем встроенные опции vis.js через options
        net.barnes_hut(
            gravity=-8000,
            central_gravity=0.3,
            spring_length=250,
            spring_strength=0.001,
            damping=0.09,
            overlap=0
        )
        
        # Словарь для отслеживания добавленных узлов
        added_nodes = set()
        
        def get_node_color(ip):
            """Определение цвета узла"""
            # Если есть в инвентаре и статус Down - красный
            if ip in self.inventory:
                if self.inventory[ip]["status"].upper() == "DOWN":
                    return "#e74c3c" # Красный
                # Если в инвентаре Up, но не пингуется (TTL=0) - тоже красный
                if self.active_hosts.get(ip, 0) == 0:
                     return "#e74c3c"

            # По подсети
            if ip.startswith("192.168.200"):
                return self.subnet_colors["192.168.200"]
            elif ip.startswith("192.168.94"):
                return self.subnet_colors["192.168.94"]
            else:
                return self.subnet_colors["default"]

        def get_node_label(ip):
            """Формирование подписи узла"""
            name = self.inventory.get(ip, {}).get("name", "")
            if name:
                return f"{ip}\n{name}"
            return ip

        # 1. Добавляем активные хосты из сканирования
        for ip, ttl in self.active_hosts.items():
            if ip not in added_nodes:
                color = get_node_color(ip)
                label = get_node_label(ip)
                
                # Размер узла зависит от типа
                size = 25
                if ip in self.inventory:
                    size = 30 # Важные узлы из Excel больше
                
                net.add_node(ip, label=label, title=f"TTL: {ttl}", color=color, size=size)
                added_nodes.add(ip)

        # 2. Добавляем промежуточные узлы (шлюзы, роутеры) из трассировки
        for target, hops in self.routes.items():
            for hop in hops:
                if hop not in added_nodes:
                    # Шлюзы серые или желтые
                    color = "#f1c40f" 
                    label = get_node_label(hop)
                    net.add_node(hop, label=label, title="Промежуточный узел", color=color, size=20)
                    added_nodes.add(hop)
                
                # Добавляем ребро
                net.add_edge(hop, target)
        
        # Настройка внешнего вида
        net.set_options("""
        var options = {
          "nodes": {
            "font": {
              "size": 14,
              "face": "Tahoma"
            },
            "borderWidth": 2,
            "borderColor": "#ffffff"
          },
          "edges": {
            "color": {
              "color": "#cccccc",
              "highlight": "#3498db"
            },
            "smooth": {
              "type": "continuous"
            },
            "width": 2
          },
          "physics": {
            "enabled": true,
            "barnesHut": {
              "gravitationalConstant": -8000,
              "centralGravity": 0.3,
              "springLength": 200,
              "springConstant": 0.04,
              "damping": 0.09
            },
            "stabilization": {
              "enabled": true,
              "iterations": 200
            }
          }
        }
        """)

        # Сохранение
        output_file = "network_map.html"
        net.save_graph(output_file)
        print(f"Карта сети сохранена в файл: {output_file}")
        print("Откройте этот файл в браузере для просмотра.")

def main():
    print("=== Network Mapper & Topology Visualizer ===")
    
    # Проверка прав администратора (для Windows)
    if sys.platform == 'win32':
        import ctypes
        try:
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if not is_admin:
                print("Предупреждение: Скрипт запущен не от имени администратора.")
                print("Tracert может работать некорректно или медленно.")
        except Exception:
            pass

    mapper = NetworkMapper()
    
    # Загрузка инвентаризации
    mapper.load_inventory("inventory.xlsx")
    
    # Сканирование
    mapper.scan_subnets()
    
    # Построение графа
    mapper.build_graph()

if __name__ == "__main__":
    main()
