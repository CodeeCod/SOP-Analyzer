#!/usr/bin/env python3
"""
SOP Analyzer - Приложение для анализа .sop файлов
"""

import json
import zipfile
import zlib
import argparse
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import datetime

@dataclass
class RecordStats:
    """Статистика по записям"""
    total: int = 0
    deletes: int = 0
    strong_overwrites: int = 0

@dataclass
class TableInfo:
    """Информация о таблице"""
    name: str
    record_count: int
    actions: Dict[str, int]

class SOPAnalyzer:
    """Анализатор SOP файлов"""
    
    def __init__(self, sop_file_path: str):
        self.sop_file_path = Path(sop_file_path)
        self._data = None
    
    def load_data(self) -> Dict[str, Any]:
        """Загрузка и декодирование данных из SOP файла"""
        if self._data is not None:
            return self._data
            
        if not self.sop_file_path.exists():
            raise FileNotFoundError(f"SOP файл не найден: {self.sop_file_path}")
        
        try:
            with zipfile.ZipFile(self.sop_file_path, 'r') as sop_zip:
                # Ищем файл с данными
                data_files = [f for f in sop_zip.namelist() if f.endswith('.data')]
                if not data_files:
                    raise ValueError("В архиве не найден файл с данными (.data)")
                
                # Читаем данные из .data файла
                with sop_zip.open(data_files[0]) as data_file:
                    compressed_data = data_file.read()
                
                # Пробуем разные методы декомпрессии
                decompressed_data = self._decompress_data(compressed_data)
                self._data = json.loads(decompressed_data.decode('utf-8'))
                
                return self._data
                
        except zipfile.BadZipFile:
            raise ValueError("Некорректный ZIP архив")
        except json.JSONDecodeError as e:
            raise ValueError(f"Ошибка парсинга JSON: {e}")
    
    def _decompress_data(self, compressed_data: bytes) -> bytes:
        """Декомпрессия данных с использованием различных методов"""
        methods = [
            self._try_raw_deflate,
            self._try_zlib_deflate,
            self._try_gzip_format,
            self._try_with_headers
        ]
        
        for method in methods:
            try:
                result = method(compressed_data)
                print(f"✓ Успешная декомпрессия методом: {method.__name__}")
                return result
            except Exception as e:
                print(f"✗ Метод {method.__name__} не сработал: {e}")
                continue
        
        raise ValueError("Не удалось декомпрессировать данные ни одним из методов")
    
    def _try_raw_deflate(self, data: bytes) -> bytes:
        """Попытка RAW Deflate декомпрессии"""
        return zlib.decompress(data, -15)
    
    def _try_zlib_deflate(self, data: bytes) -> bytes:
        """Попытка Zlib декомпрессии"""
        return zlib.decompress(data)
    
    def _try_gzip_format(self, data: bytes) -> bytes:
        """Попытка декомпрессии как GZIP с заголовком"""
        # Добавляем простой gzip заголовок
        gzip_header = b'\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff'
        gzip_data = gzip_header + data + b'\x00\x00\x00\x00\x00\x00\x00\x00'
        return zlib.decompress(gzip_data, 15 + 32)
    
    def _try_with_headers(self, data: bytes) -> bytes:
        """Попытка с различными заголовками"""
        headers_to_try = [
            b'',  # Без заголовка
            b'\x78\x9c',  # Zlib заголовок
            b'\x78\x01',  # Zlib заголовок
            b'\x78\xda',  # Zlib заголовок
        ]
        
        for header in headers_to_try:
            try:
                return zlib.decompress(header + data)
            except:
                continue
        
        # Последняя попытка - убрать возможные лишние байты
        for i in range(min(10, len(data))):
            try:
                return zlib.decompress(data[i:], -15)
            except:
                continue
        
        raise ValueError("Все методы с заголовками не сработали")
    
    def get_metadata(self) -> Dict[str, Any]:
        """Получить метаданные пакета"""
        data = self.load_data()
        return {
            'name': data.get('name', 'Неизвестно'),
            'pack_application_id': data.get('pack_application_id', 'Неизвестно'),
            'timestamp': data.get('timestamp'),
            'version': data.get('version', 'Неизвестно')
        }
    
    def analyze_records(self) -> RecordStats:
        """Анализ статистики записей"""
        data = self.load_data()
        records = data.get('records', [])
        
        stats = RecordStats(total=len(records))
        
        for record in records:
            if record.get('action') == 'delete':
                stats.deletes += 1
            if record.get('is_strong_overwrite') is True:
                stats.strong_overwrites += 1
        
        return stats
    
    def analyze_tables(self) -> List[TableInfo]:
        """Анализ таблиц и их записей"""
        data = self.load_data()
        records = data.get('records', [])
        
        tables = {}
        
        for record in records:
            table_name = record.get('table_name', 'unknown')
            action = record.get('action', 'unknown')
            
            if table_name not in tables:
                tables[table_name] = {'count': 0, 'actions': {}}
            
            tables[table_name]['count'] += 1
            tables[table_name]['actions'][action] = tables[table_name]['actions'].get(action, 0) + 1
        
        # Сортируем таблицы по количеству записей
        sorted_tables = sorted(tables.items(), key=lambda x: x[1]['count'], reverse=True)
        
        return [
            TableInfo(
                name=table_name,
                record_count=table_data['count'],
                actions=table_data['actions']
            )
            for table_name, table_data in sorted_tables
        ]
    
    def get_actions_summary(self) -> Dict[str, int]:
        """Сводка по действиям"""
        data = self.load_data()
        records = data.get('records', [])
        
        actions = {}
        for record in records:
            action = record.get('action', 'unknown')
            actions[action] = actions.get(action, 0) + 1
        
        return actions
    
    def get_raw_data_info(self) -> Dict[str, Any]:
        """Получить информацию о сырых данных (для диагностики)"""
        try:
            with zipfile.ZipFile(self.sop_file_path, 'r') as sop_zip:
                data_files = [f for f in sop_zip.namelist() if f.endswith('.data')]
                if not data_files:
                    return {'error': 'No .data file found'}
                
                with sop_zip.open(data_files[0]) as data_file:
                    raw_data = data_file.read()
                
                return {
                    'data_file_size': len(raw_data),
                    'first_10_bytes': raw_data[:10].hex(),
                    'last_10_bytes': raw_data[-10:].hex(),
                    'files_in_archive': sop_zip.namelist()
                }
        except Exception as e:
            return {'error': str(e)}
    
    def generate_report(self) -> Dict[str, Any]:
        """Генерация полного отчета"""
        metadata = self.get_metadata()
        record_stats = self.analyze_records()
        tables = self.analyze_tables()
        actions = self.get_actions_summary()
        
        return {
            'metadata': metadata,
            'record_statistics': {
                'total_records': record_stats.total,
                'delete_operations': record_stats.deletes,
                'strong_overwrites': record_stats.strong_overwrites,
                'actions_breakdown': actions
            },
            'tables': [
                {
                    'name': table.name,
                    'record_count': table.record_count,
                    'actions': table.actions
                }
                for table in tables
            ],
            'file_info': {
                'file_path': str(self.sop_file_path),
                'file_size': self.sop_file_path.stat().st_size,
                'analysis_date': datetime.datetime.now().isoformat()
            }
        }


class OutputFormatter:
    """Форматирование вывода"""
    
    @staticmethod
    def print_table(headers: List[str], rows: List[List[str]], title: str = ""):
        """Печать таблицы"""
        if title:
            print(f"\n{title}")
            print("=" * 60)
        
        if not rows:
            print("Нет данных")
            return
        
        # Вычисляем ширину колонок
        col_widths = []
        for i, header in enumerate(headers):
            max_width = len(header)
            for row in rows:
                if i < len(row):
                    max_width = max(max_width, len(str(row[i])))
            col_widths.append(max_width + 2)
        
        # Печатаем заголовок
        header_line = "".join(f"{header:<{col_widths[i]}}" for i, header in enumerate(headers))
        print(header_line)
        print("-" * len(header_line))
        
        # Печатаем строки
        for row in rows:
            line = "".join(f"{str(cell):<{col_widths[i]}}" for i, cell in enumerate(row))
            print(line)
    
    @staticmethod
    def print_metadata(metadata: Dict[str, Any]):
        """Печать метаданных"""
        print("\n📦 МЕТАДАННЫЕ ПАКЕТА")
        print("=" * 40)
        for key, value in metadata.items():
            print(f"{key:>20}: {value}")
    
    @staticmethod
    def print_record_stats(stats: RecordStats, actions: Dict[str, int]):
        """Печать статистики записей"""
        print("\n📊 СТАТИСТИКА ЗАПИСЕЙ")
        print("=" * 40)
        print(f"{'Всего записей':>20}: {stats.total}")
        print(f"{'Операций удаления':>20}: {stats.deletes}")
        print(f"{'Сильных перезаписей':>20}: {stats.strong_overwrites}")
        
        if actions:
            print(f"\n{'Действия':>20}:")
            for action, count in sorted(actions.items()):
                print(f"{'':>22}  {action}: {count}")
    
    @staticmethod
    def print_tables_summary(tables: List[TableInfo]):
        """Печать сводки по таблицам"""
        if not tables:
            return
        
        headers = ["Таблица", "Записей", "Действия"]
        rows = []
        
        for table in tables:
            actions_str = ", ".join(f"{k}:{v}" for k, v in table.actions.items())
            rows.append([table.name, str(table.record_count), actions_str])
        
        OutputFormatter.print_table(headers, rows, "🗃️ ТАБЛИЦЫ")
    
    @staticmethod
    def print_raw_data_info(info: Dict[str, Any]):
        """Печать информации о сырых данных"""
        print("\n🔧 ДИАГНОСТИЧЕСКАЯ ИНФОРМАЦИЯ")
        print("=" * 40)
        for key, value in info.items():
            if key == 'files_in_archive':
                print(f"{'Файлы в архиве':>20}:")
                for file in value:
                    print(f"{'':>22}  {file}")
            else:
                print(f"{key:>20}: {value}")


def main():
    parser = argparse.ArgumentParser(
        description='SOP Analyzer - Анализ пакетов данных .sop',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Примеры использования:
  %(prog)s package.sop                    # Полный отчет
  %(prog)s package.sop --metadata         # Только метаданные
  %(prog)s package.sop --stats            # Статистика записей
  %(prog)s package.sop --tables           # Информация о таблицах
  %(prog)s package.sop --json             # Вывод в формате JSON
  %(prog)s package.sop --debug            # Диагностическая информация
        """
    )
    
    parser.add_argument('sop_file', help='Путь к .sop файлу')
    parser.add_argument('--metadata', action='store_true', help='Показать метаданные пакета')
    parser.add_argument('--stats', action='store_true', help='Показать статистику записей')
    parser.add_argument('--tables', action='store_true', help='Показать информацию о таблицах')
    parser.add_argument('--json', action='store_true', help='Вывод в формате JSON')
    parser.add_argument('--debug', action='store_true', help='Диагностическая информация')
    parser.add_argument('--verbose', '-v', action='store_true', help='Подробный вывод')
    
    args = parser.parse_args()
    
    # Проверка файла
    if not Path(args.sop_file).exists():
        print(f"❌ Ошибка: Файл {args.sop_file} не найден")
        sys.exit(1)
    
    try:
        analyzer = SOPAnalyzer(args.sop_file)
        
        # Режим отладки
        if args.debug:
            raw_info = analyzer.get_raw_data_info()
            OutputFormatter.print_raw_data_info(raw_info)
            return
        
        # JSON вывод
        if args.json:
            report = analyzer.generate_report()
            print(json.dumps(report, indent=2, ensure_ascii=False))
            return
        
        # Выбор режима отображения
        if args.metadata:
            OutputFormatter.print_metadata(analyzer.get_metadata())
        elif args.stats:
            stats = analyzer.analyze_records()
            actions = analyzer.get_actions_summary()
            OutputFormatter.print_record_stats(stats, actions)
        elif args.tables:
            tables = analyzer.analyze_tables()
            OutputFormatter.print_tables_summary(tables)
        else:
            # Полный отчет
            metadata = analyzer.get_metadata()
            stats = analyzer.analyze_records()
            actions = analyzer.get_actions_summary()
            tables = analyzer.analyze_tables()
            
            OutputFormatter.print_metadata(metadata)
            OutputFormatter.print_record_stats(stats, actions)
            OutputFormatter.print_tables_summary(tables)
            
            if args.verbose:
                print(f"\n📁 Файл: {args.sop_file}")
                print(f"📏 Размер: {Path(args.sop_file).stat().st_size} байт")
    
    except Exception as e:
        print(f"❌ Ошибка при анализе файла: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        
        # Показываем диагностическую информацию при ошибке
        try:
            analyzer = SOPAnalyzer(args.sop_file)
            raw_info = analyzer.get_raw_data_info()
            print("\n💡 Диагностическая информация:")
            OutputFormatter.print_raw_data_info(raw_info)
        except:
            pass
        
        sys.exit(1)


if __name__ == "__main__":
    main()