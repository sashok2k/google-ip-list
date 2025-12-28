import json
import math
import os
import ipaddress
from collections import Counter
from datetime import datetime

class CIDRProcessor:
    """Класс для обработки CIDR с проверкой пересечений и дубликатов"""
    
    def __init__(self, input_file, output_dir="cidr_processed", chunk_size=1000):
        self.input_file = input_file
        self.output_dir = output_dir
        self.chunk_size = chunk_size
        self.cidr_list = []
        self.unique_cidrs = []
        self.duplicates = {}
        self.intersections = []
        self.processed_cidrs = []
        self.log_messages = []
        
        self.stats = {
            'total_original': 0,
            'total_unique': 0,
            'total_processed': 0,
            'duplicates_found': 0,
            'duplicate_count': 0,
            'intersections_found': 0,
            'files_created': 0,
            'chunk_size': chunk_size,
            'start_time': None,
            'end_time': None
        }
    
    def log(self, message, level="INFO"):
        """Добавляет сообщение в лог"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}"
        self.log_messages.append(log_entry)
        print(log_entry)
    
    def load_json(self):
        """Загружает и парсит JSON файл"""
        try:
            self.log(f"Загрузка файла: {self.input_file}")
            
            with open(self.input_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Извлекаем CIDR из разных возможных структур
            if 'prefixes' in data:
                self.cidr_list = [item.get('ip_prefix', '') for item in data['prefixes'] if item.get('ip_prefix')]
            elif 'ipv4_prefixes' in data:
                self.cidr_list = [item.get('ip_prefix', '') for item in data['ipv4_prefixes'] if item.get('ip_prefix')]
            else:
                self.cidr_list = self._extract_cidr_recursive(data)
            
            # Фильтруем пустые значения
            self.cidr_list = [cidr for cidr in self.cidr_list if cidr]
            self.stats['total_original'] = len(self.cidr_list)
            
            self.log(f"Загружено CIDR: {self.stats['total_original']}")
            
            # Проверяем на дубликаты
            self._check_duplicates()
            
            # Удаляем дубликаты
            self._remove_duplicates()
            
            return True
            
        except Exception as e:
            self.log(f"Ошибка при загрузке JSON: {e}", "ERROR")
            return False
    
    def _check_duplicates(self):
        """Проверяет список CIDR на наличие дубликатов"""
        counter = Counter(self.cidr_list)
        self.duplicates = {cidr: count for cidr, count in counter.items() if count > 1}
        
        if self.duplicates:
            self.stats['duplicates_found'] = len(self.duplicates)
            self.stats['duplicate_count'] = sum(self.duplicates.values()) - len(self.duplicates)
            
            self.log(f"Найдены дубликаты CIDR: {self.stats['duplicates_found']}")
            self.log(f"Всего повторений: {self.stats['duplicate_count']}")
            
            # Показываем самые частые дубликаты
            sorted_dups = sorted(self.duplicates.items(), key=lambda x: x[1], reverse=True)
            self.log("Самые частые дубликаты:")
            for cidr, count in sorted_dups[:5]:
                self.log(f"  {cidr} - {count} раз(а)")
        else:
            self.log("Дубликатов не найдено")
    
    def _remove_duplicates(self):
        """Удаляет дубликаты, сохраняя порядок"""
        if not self.duplicates:
            self.unique_cidrs = self.cidr_list.copy()
            return
        
        seen = set()
        unique_list = []
        removed_count = 0
        
        for cidr in self.cidr_list:
            if cidr not in seen:
                seen.add(cidr)
                unique_list.append(cidr)
            else:
                removed_count += 1
        
        self.unique_cidrs = unique_list
        self.log(f"Удалено дубликатов: {removed_count}")
        self.log(f"Уникальных CIDR осталось: {len(self.unique_cidrs)}")
    
    def check_intersections(self):
        """Проверяет пересечения диапазонов IP"""
        self.log("Проверка пересечений диапазонов IP...")
        
        try:
            # Преобразуем CIDR в объекты ipaddress
            networks = []
            for cidr in self.unique_cidrs:
                try:
                    networks.append((cidr, ipaddress.ip_network(cidr, strict=False)))
                except ValueError as e:
                    self.log(f"Ошибка парсинга CIDR {cidr}: {e}", "WARNING")
            
            # Сортируем сети по размеру (от больших к маленьким)
            networks.sort(key=lambda x: x[1].prefixlen)
            
            processed = []
            intersections = []
            
            for i, (cidr1, net1) in enumerate(networks):
                is_intersected = False
                
                for j, (cidr2, net2) in enumerate(processed):
                    if net1.overlaps(net2):
                        is_intersected = True
                        
                        # Определяем тип пересечения
                        if net1.subnet_of(net2):
                            # net1 полностью внутри net2
                            action = "удален (полностью внутри другого диапазона)"
                            intersections.append({
                                'cidr1': cidr1,
                                'cidr2': cidr2,
                                'type': 'subnet',
                                'action': 'remove',
                                'details': f"{cidr1} полностью внутри {cidr2}"
                            })
                            self.log(f"Пересечение: {cidr1} полностью внутри {cidr2} -> {cidr1} удален")
                        
                        elif net2.subnet_of(net1):
                            # net2 полностью внутри net1
                            # Оставляем больший диапазон, удаляем меньший
                            action = "оставлен (охватывает меньший диапазон)"
                            intersections.append({
                                'cidr1': cidr1,
                                'cidr2': cidr2,
                                'type': 'supernet',
                                'action': 'keep_larger',
                                'details': f"{cidr2} полностью внутри {cidr1}"
                            })
                            self.log(f"Пересечение: {cidr2} полностью внутри {cidr1} -> {cidr2} будет удален")
                            # Удаляем меньший диапазон из processed
                            processed[j] = (cidr1, net1)  # Заменяем на больший
                            is_intersected = False  # Больший диапазон остается
                            break
                        
                        else:
                            # Частичное пересечение
                            # Можно разбить на непересекающиеся части
                            action = "требуется разбивка"
                            intersections.append({
                                'cidr1': cidr1,
                                'cidr2': cidr2,
                                'type': 'partial',
                                'action': 'split',
                                'details': f"Частичное пересечение {cidr1} и {cidr2}"
                            })
                            self.log(f"Частичное пересечение: {cidr1} и {cidr2} -> требуется разбивка")
                
                if not is_intersected:
                    # Добавляем только если нет пересечений
                    if (cidr1, net1) not in processed:
                        processed.append((cidr1, net1))
            
            # Сохраняем обработанные CIDR
            self.processed_cidrs = [cidr for cidr, _ in processed]
            self.intersections = intersections
            self.stats['intersections_found'] = len(intersections)
            self.stats['total_processed'] = len(self.processed_cidrs)
            
            self.log(f"Найдено пересечений: {len(intersections)}")
            self.log(f"После обработки пересечений осталось CIDR: {len(self.processed_cidrs)}")
            
            return True
            
        except Exception as e:
            self.log(f"Ошибка при проверке пересечений: {e}", "ERROR")
            return False
    
    def split_intersecting_networks(self):
        """Разбивает пересекающиеся сети на непересекающиеся части"""
        self.log("Разбивка пересекающихся сетей на непересекающиеся части...")
        
        try:
            # Преобразуем CIDR в объекты ipaddress
            networks = []
            for cidr in self.unique_cidrs:
                try:
                    networks.append(ipaddress.ip_network(cidr, strict=False))
                except ValueError:
                    continue
            
            if not networks:
                self.processed_cidrs = self.unique_cidrs
                return True
            
            # Сортируем по начальному адресу
            networks.sort(key=lambda x: x.network_address)
            
            result_networks = []
            
            for net in networks:
                if not result_networks:
                    result_networks.append(net)
                    continue
                
                last_net = result_networks[-1]
                
                # Проверяем пересечение с последней сетью в результате
                if net.overlaps(last_net):
                    # Определяем тип пересечения
                    if net.subnet_of(last_net):
                        # Текущая сеть полностью внутри предыдущей
                        self.log(f"Сеть {net} полностью внутри {last_net} -> игнорируется")
                        continue
                    elif last_net.subnet_of(net):
                        # Предыдущая сеть полностью внутри текущей
                        # Заменяем предыдущую на текущую (большую)
                        self.log(f"Сеть {last_net} полностью внутри {net} -> заменена на {net}")
                        result_networks[-1] = net
                    else:
                        # Частичное пересечение
                        # Исключаем пересекающуюся часть
                        try:
                            # Вычитаем пересечение
                            remaining = list(net.address_exclude(last_net))
                            if remaining:
                                self.log(f"Сеть {net} частично пересекается с {last_net}")
                                self.log(f"  Оставшиеся части: {', '.join(str(r) for r in remaining)}")
                                result_networks.extend(remaining)
                        except ValueError:
                            # Если не получается вычесть, оставляем как есть
                            self.log(f"Не удалось разбить пересечение {net} и {last_net}", "WARNING")
                            result_networks.append(net)
                else:
                    # Нет пересечения
                    result_networks.append(net)
            
            # Удаляем дубликаты после разбивки
            unique_networks = []
            seen = set()
            for net in result_networks:
                if str(net) not in seen:
                    seen.add(str(net))
                    unique_networks.append(net)
            
            # Сортируем результаты
            unique_networks.sort(key=lambda x: (x.network_address, x.prefixlen))
            self.processed_cidrs = [str(net) for net in unique_networks]
            
            self.stats['total_processed'] = len(self.processed_cidrs)
            self.log(f"После разбивки осталось CIDR: {len(self.processed_cidrs)}")
            
            return True
            
        except Exception as e:
            self.log(f"Ошибка при разбивке сетей: {e}", "ERROR")
            return False
    
    def save_to_single_file(self):
        """Сохраняет все обработанные CIDR в один файл"""
        try:
            # Создаем директорию
            if not os.path.exists(self.output_dir):
                os.makedirs(self.output_dir)
            
            # Имя файла с датой
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = os.path.join(self.output_dir, f"cidr_all_{timestamp}.txt")
            
            # Сохраняем все CIDR в один файл
            with open(output_file, 'w', encoding='utf-8') as f:
                for cidr in self.processed_cidrs:
                    f.write(cidr + '\n')
            
            self.log(f"Все CIDR сохранены в один файл: {output_file}")
            
            # Сохраняем дополнительный файл с сортировкой по размеру префикса
            sorted_file = os.path.join(self.output_dir, f"cidr_sorted_{timestamp}.txt")
            sorted_cidrs = sorted(self.processed_cidrs, 
                                 key=lambda x: int(x.split('/')[1]) if '/' in x else 32)
            
            with open(sorted_file, 'w', encoding='utf-8') as f:
                for cidr in sorted_cidrs:
                    f.write(cidr + '\n')
            
            self.log(f"Сортированные CIDR сохранены в: {sorted_file}")
            
            return output_file, sorted_file
            
        except Exception as e:
            self.log(f"Ошибка при сохранении в файл: {e}", "ERROR")
            return None
    
    def save_to_chunks(self):
        """Сохраняет обработанные CIDR в несколько файлов"""
        try:
            # Создаем директорию
            if not os.path.exists(self.output_dir):
                os.makedirs(self.output_dir)
            
            # Вычисляем количество файлов
            total_cidrs = len(self.processed_cidrs)
            num_files = math.ceil(total_cidrs / self.chunk_size)
            
            self.log(f"Сохранение в {num_files} файлов по {self.chunk_size} записей")
            
            # Разбиваем и сохраняем
            for file_num in range(num_files):
                start_idx = file_num * self.chunk_size
                end_idx = min((file_num + 1) * self.chunk_size, total_cidrs)
                chunk = self.processed_cidrs[start_idx:end_idx]
                
                # Создаем имя файла
                filename = f"cidr_chunk_{file_num+1:03d}_of_{num_files:03d}.txt"
                filepath = os.path.join(self.output_dir, filename)
                
                # Сохраняем чанк
                with open(filepath, 'w', encoding='utf-8') as f:
                    for cidr in chunk:
                        f.write(cidr + '\n')
                
                self.stats['files_created'] += 1
                self.log(f"  Файл {file_num+1}/{num_files}: {filename} ({len(chunk)} записей)")
            
            return True
            
        except Exception as e:
            self.log(f"Ошибка при сохранении в чанки: {e}", "ERROR")
            return False
    
    def save_log(self):
        """Сохраняет лог обработки в файл"""
        try:
            log_file = os.path.join(self.output_dir, "processing_log.txt")
            
            with open(log_file, 'w', encoding='utf-8') as f:
                f.write("ЛОГ ОБРАБОТКИ CIDR\n")
                f.write("=" * 60 + "\n\n")
                
                # Общая информация
                f.write("ОБЩАЯ ИНФОРМАЦИЯ:\n")
                f.write("-" * 40 + "\n")
                f.write(f"Входной файл: {self.input_file}\n")
                f.write(f"Выходная директория: {self.output_dir}\n")
                f.write(f"Дата обработки: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Статистика
                f.write("СТАТИСТИКА:\n")
                f.write("-" * 40 + "\n")
                f.write(f"Всего CIDR (оригинал): {self.stats['total_original']}\n")
                f.write(f"Уникальных CIDR: {len(self.unique_cidrs)}\n")
                f.write(f"Дубликатов найдено: {self.stats['duplicates_found']}\n")
                f.write(f"Повторений удалено: {self.stats['duplicate_count']}\n")
                f.write(f"Пересечений найдено: {self.stats['intersections_found']}\n")
                f.write(f"CIDR после обработки: {self.stats['total_processed']}\n\n")
                
                # Подробный лог
                f.write("ПОДРОБНЫЙ ЛОГ ОБРАБОТКИ:\n")
                f.write("-" * 40 + "\n")
                for log_entry in self.log_messages:
                    f.write(log_entry + "\n")
            
            self.log(f"Лог сохранен в: {log_file}")
            return log_file
            
        except Exception as e:
            print(f"Ошибка при сохранении лога: {e}")
            return None
    
    def save_report(self):
        """Сохраняет подробный отчет"""
        try:
            report_file = os.path.join(self.output_dir, "detailed_report.txt")
            
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write("ПОДРОБНЫЙ ОТЧЕТ ОБРАБОТКИ CIDR\n")
                f.write("=" * 80 + "\n\n")
                
                # Общая информация
                f.write("ОБЩАЯ ИНФОРМАЦИЯ:\n")
                f.write("-" * 60 + "\n")
                f.write(f"Входной файл: {self.input_file}\n")
                f.write(f"Выходная директория: {self.output_dir}\n")
                f.write(f"Дата обработки: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                # Статистика в таблице
                f.write("СТАТИСТИКА ОБРАБОТКИ:\n")
                f.write("-" * 60 + "\n")
                stats_data = [
                    ("Всего CIDR в исходном файле", self.stats['total_original']),
                    ("Уникальных CIDR (после удаления дубликатов)", len(self.unique_cidrs)),
                    ("Найдено дубликатов", self.stats['duplicates_found']),
                    ("Удалено повторений", self.stats['duplicate_count']),
                    ("Найдено пересечений", self.stats['intersections_found']),
                    ("CIDR после обработки пересечений", self.stats['total_processed']),
                    ("Создано файлов", self.stats['files_created']),
                    ("Размер чанка", self.stats['chunk_size'])
                ]
                
                for label, value in stats_data:
                    f.write(f"{label:<50}: {value:>10}\n")
                f.write("\n")
                
                # Дубликаты
                if self.duplicates:
                    f.write("ДУБЛИКАТЫ (первые 20):\n")
                    f.write("-" * 60 + "\n")
                    sorted_dups = sorted(self.duplicates.items(), key=lambda x: x[1], reverse=True)
                    for i, (cidr, count) in enumerate(sorted_dups[:20], 1):
                        f.write(f"{i:3d}. {cidr:<20} - {count:>3} раз(а)\n")
                    f.write("\n")
                
                # Примеры CIDR
                f.write("ПРИМЕРЫ CIDR ПОСЛЕ ОБРАБОТКИ (первые 50):\n")
                f.write("-" * 60 + "\n")
                for i, cidr in enumerate(self.processed_cidrs[:50], 1):
                    f.write(f"{i:3d}. {cidr}\n")
                
                if len(self.processed_cidrs) > 50:
                    f.write(f"... и еще {len(self.processed_cidrs) - 50} CIDR\n")
                
                f.write("\n")
                
                # Распределение по размеру префикса
                f.write("РАСПРЕДЕЛЕНИЕ ПО РАЗМЕРУ ПРЕФИКСА:\n")
                f.write("-" * 60 + "\n")
                
                prefix_dist = {}
                for cidr in self.processed_cidrs:
                    if '/' in cidr:
                        prefix = cidr.split('/')[1]
                        prefix_dist[prefix] = prefix_dist.get(prefix, 0) + 1
                
                for prefix in sorted(prefix_dist.keys(), key=lambda x: int(x)):
                    f.write(f"  /{prefix:<4}: {prefix_dist[prefix]:>5} CIDR\n")
            
            self.log(f"Подробный отчет сохранен в: {report_file}")
            return report_file
            
        except Exception as e:
            self.log(f"Ошибка при сохранении отчета: {e}", "ERROR")
            return None
    
    def _extract_cidr_recursive(self, data):
        """Рекурсивно извлекает CIDR из любой структуры JSON"""
        cidr_list = []
        
        if isinstance(data, dict):
            for key, value in data.items():
                if key in ['ip_prefix', 'cidr', 'ipv4_prefix'] and isinstance(value, str):
                    cidr_list.append(value)
                else:
                    cidr_list.extend(self._extract_cidr_recursive(value))
        elif isinstance(data, list):
            for item in data:
                cidr_list.extend(self._extract_cidr_recursive(item))
        
        return cidr_list
    
    def process(self, save_chunks=False):
        """Основной метод обработки"""
        self.stats['start_time'] = datetime.now()
        
        self.log("=" * 60)
        self.log("НАЧАЛО ОБРАБОТКИ CIDR")
        self.log("=" * 60)
        
        # 1. Загрузка данных
        if not self.load_json():
            return False
        
        # 2. Проверка и обработка пересечений
        if not self.split_intersecting_networks():
            self.log("Используем простую обработку без разбивки пересечений", "WARNING")
            self.processed_cidrs = self.unique_cidrs.copy()
            self.stats['total_processed'] = len(self.processed_cidrs)
        
        # 3. Сохранение результатов
        self.log("\nСОХРАНЕНИЕ РЕЗУЛЬТАТОВ:")
        self.log("-" * 40)
        
        # Всегда сохраняем в один файл
        single_file = self.save_to_single_file()
        
        # Сохраняем в чанки если нужно
        if save_chunks:
            self.save_to_chunks()
        
        # 4. Сохранение логов и отчетов
        self.save_log()
        self.save_report()
        
        self.stats['end_time'] = datetime.now()
        duration = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
        
        self.log("\n" + "=" * 60)
        self.log("ОБРАБОТКА ЗАВЕРШЕНА")
        self.log("=" * 60)
        self.log(f"Общее время обработки: {duration:.2f} секунд")
        self.log(f"Результаты сохранены в: {os.path.abspath(self.output_dir)}/")
        
        return True
    
    def print_summary(self):
        """Выводит сводную информацию в консоль"""
        if self.stats['start_time'] and self.stats['end_time']:
            duration = (self.stats['end_time'] - self.stats['start_time']).total_seconds()
        else:
            duration = 0
        
        print("\n" + "=" * 70)
        print("СВОДКА ОБ ОБРАБОТКЕ")
        print("=" * 70)
        print(f"{'Входных CIDR:':<30} {self.stats['total_original']:>10}")
        print(f"{'Уникальных CIDR:':<30} {len(self.unique_cidrs):>10}")
        
        if self.duplicates:
            print(f"{'Дубликатов найдено:':<30} {self.stats['duplicates_found']:>10}")
            print(f"{'Повторений удалено:':<30} {self.stats['duplicate_count']:>10}")
        
        print(f"{'Пересечений найдено:':<30} {self.stats['intersections_found']:>10}")
        print(f"{'CIDR после обработки:':<30} {self.stats['total_processed']:>10}")
        print(f"{'Создано файлов:':<30} {self.stats['files_created']:>10}")
        print(f"{'Время обработки:':<30} {duration:>10.2f} сек")
        print("=" * 70)
        
        # Показываем примеры
        if self.processed_cidrs:
            print(f"\nПримеры CIDR после обработки (первые 10):")
            for i, cidr in enumerate(self.processed_cidrs[:10], 1):
                print(f"  {i:2d}. {cidr}")

# Основной скрипт
def main():
    """Основная функция скрипта"""
    # Конфигурация
    CONFIG = {
        'input_file': 'ip-ranges.json',
        'output_dir': 'cidr_processed',
        'chunk_size': 1000,
        'save_chunks': False  # True для сохранения в чанки, False для одного файла
    }
    
    print("🔍 ОБРАБОТКА CIDR С ПРОВЕРКОЙ ПЕРЕСЕЧЕНИЙ")
    print("=" * 70)
    
    # Создаем экземпляр класса
    processor = CIDRProcessor(
        input_file=CONFIG['input_file'],
        output_dir=CONFIG['output_dir'],
        chunk_size=CONFIG['chunk_size']
    )
    
    # Запускаем обработку
    if processor.process(save_chunks=CONFIG['save_chunks']):
        processor.print_summary()
        print("\n✅ Обработка завершена успешно!")
        
        # Ссылка на файлы
        output_path = os.path.abspath(CONFIG['output_dir'])
        print(f"📁 Результаты в директории: {output_path}/")
        
        # Показываем размер файлов
        if os.path.exists(CONFIG['output_dir']):
            files = os.listdir(CONFIG['output_dir'])
            txt_files = [f for f in files if f.endswith('.txt')]
            print(f"📄 Создано текстовых файлов: {len(txt_files)}")
    else:
        print("\n❌ Ошибка при обработке файла")

# Запуск скрипта
if __name__ == "__main__":
    main()