import pytest
import json
import zipfile
import zlib
import tempfile
import os
import subprocess
import sys
from pathlib import Path
from sop_analyzer import SOPAnalyzer, RecordStats, TableInfo, OutputFormatter


@pytest.fixture
def sample_data():
    """Создание тестовых данных"""
    return {
        "name": "test_package",
        "pack_application_id": "test_app_123",
        "timestamp": "2024-01-15T10:30:00Z",
        "version": "1.0",
        "records": [
            {
                "table_name": "users",
                "action": "insert",
                "is_strong_overwrite": False
            },
            {
                "table_name": "users",
                "action": "delete",
                "is_strong_overwrite": False
            },
            {
                "table_name": "products",
                "action": "update",
                "is_strong_overwrite": True
            },
            {
                "table_name": "orders",
                "action": "insert",
                "is_strong_overwrite": False
            }
        ]
    }


@pytest.fixture
def create_test_sop_file(sample_data):
    """Создание тестового SOP файла"""
    def _create_sop_file(compression_method=zlib.Z_BEST_COMPRESSION):
        # Создаем временный файл
        with tempfile.NamedTemporaryFile(suffix='.sop', delete=False) as f:
            sop_path = f.name
        
        # Создаем ZIP архив с данными
        with zipfile.ZipFile(sop_path, 'w', compression=zipfile.ZIP_DEFLATED) as sop_zip:
            # Конвертируем данные в JSON и сжимаем
            json_data = json.dumps(sample_data).encode('utf-8')
            compressed_data = zlib.compress(json_data, compression_method)
            
            # Добавляем сжатые данные в архив
            sop_zip.writestr('package.data', compressed_data)
        
        return sop_path
    
    return _create_sop_file


class TestSOPAnalyzer:
    """Тесты для SOPAnalyzer"""
    
    def test_analyzer_initialization(self):
        """Тест инициализации анализатора"""
        with tempfile.NamedTemporaryFile(suffix='.sop') as f:
            analyzer = SOPAnalyzer(f.name)
            assert analyzer.sop_file_path == Path(f.name)
            assert analyzer._data is None
    
    def test_file_not_found(self):
        """Тест обработки отсутствующего файла"""
        with pytest.raises(FileNotFoundError):
            analyzer = SOPAnalyzer("nonexistent.sop")
            analyzer.load_data()
    
    def test_invalid_zip_file(self):
        """Тест обработки некорректного ZIP файла"""
        with tempfile.NamedTemporaryFile(suffix='.sop') as f:
            # Записываем некорректные данные
            f.write(b"invalid zip data")
            f.flush()
            
            analyzer = SOPAnalyzer(f.name)
            with pytest.raises(ValueError, match="Некорректный ZIP архив"):
                analyzer.load_data()
    
    def test_load_data_success(self, create_test_sop_file):
        """Тест успешной загрузки данных"""
        sop_file = create_test_sop_file()
        try:
            analyzer = SOPAnalyzer(sop_file)
            data = analyzer.load_data()
            
            assert data is not None
            assert data["name"] == "test_package"
            assert len(data["records"]) == 4
            
            # Проверяем кэширование
            assert analyzer._data is not None
            assert analyzer.load_data() is data
            
        finally:
            os.unlink(sop_file)
    
    def test_get_metadata(self, create_test_sop_file):
        """Тест получения метаданных"""
        sop_file = create_test_sop_file()
        try:
            analyzer = SOPAnalyzer(sop_file)
            metadata = analyzer.get_metadata()
            
            assert metadata["name"] == "test_package"
            assert metadata["pack_application_id"] == "test_app_123"
            assert metadata["version"] == "1.0"
            assert "timestamp" in metadata
            
        finally:
            os.unlink(sop_file)
    
    def test_analyze_records(self, create_test_sop_file):
        """Тест анализа записей"""
        sop_file = create_test_sop_file()
        try:
            analyzer = SOPAnalyzer(sop_file)
            stats = analyzer.analyze_records()
            
            assert isinstance(stats, RecordStats)
            assert stats.total == 4
            assert stats.deletes == 1
            assert stats.strong_overwrites == 1
            
        finally:
            os.unlink(sop_file)
    
    def test_analyze_tables(self, create_test_sop_file):
        """Тест анализа таблиц"""
        sop_file = create_test_sop_file()
        try:
            analyzer = SOPAnalyzer(sop_file)
            tables = analyzer.analyze_tables()
            
            assert len(tables) == 3
            assert isinstance(tables[0], TableInfo)
            
            # Проверяем сортировку по количеству записей
            table_names = [table.name for table in tables]
            assert "users" in table_names
            assert "products" in table_names
            assert "orders" in table_names
            
            # Находим таблицу users
            users_table = next(table for table in tables if table.name == "users")
            assert users_table.record_count == 2
            assert users_table.actions["insert"] == 1
            assert users_table.actions["delete"] == 1
            
        finally:
            os.unlink(sop_file)
    
    def test_get_actions_summary(self, create_test_sop_file):
        """Тест получения сводки по действиям"""
        sop_file = create_test_sop_file()
        try:
            analyzer = SOPAnalyzer(sop_file)
            actions = analyzer.get_actions_summary()
            
            assert actions["insert"] == 2
            assert actions["delete"] == 1
            assert actions["update"] == 1
            
        finally:
            os.unlink(sop_file)
    
    def test_generate_report(self, create_test_sop_file):
        """Тест генерации полного отчета"""
        sop_file = create_test_sop_file()
        try:
            analyzer = SOPAnalyzer(sop_file)
            report = analyzer.generate_report()
            
            # Проверяем структуру отчета
            assert "metadata" in report
            assert "record_statistics" in report
            assert "tables" in report
            assert "file_info" in report
            
            # Проверяем содержимое
            assert report["metadata"]["name"] == "test_package"
            assert report["record_statistics"]["total_records"] == 4
            assert len(report["tables"]) == 3
            
            # Проверяем информацию о файле
            assert "file_path" in report["file_info"]
            assert "file_size" in report["file_info"]
            assert "analysis_date" in report["file_info"]
            
        finally:
            os.unlink(sop_file)
    
    def test_empty_records(self):
        """Тест с пустыми записями"""
        empty_data = {
            "name": "empty_package",
            "pack_application_id": "empty_app",
            "timestamp": "2024-01-15T10:30:00Z",
            "version": "1.0",
            "records": []
        }
        
        with tempfile.NamedTemporaryFile(suffix='.sop', delete=False) as f:
            sop_path = f.name
        
        try:
            # Создаем SOP файл с пустыми записями
            with zipfile.ZipFile(sop_path, 'w') as sop_zip:
                json_data = json.dumps(empty_data).encode('utf-8')
                compressed_data = zlib.compress(json_data)
                sop_zip.writestr('package.data', compressed_data)
            
            analyzer = SOPAnalyzer(sop_path)
            
            # Проверяем статистику
            stats = analyzer.analyze_records()
            assert stats.total == 0
            assert stats.deletes == 0
            assert stats.strong_overwrites == 0
            
            # Проверяем таблицы
            tables = analyzer.analyze_tables()
            assert len(tables) == 0
            
            # Проверяем действия
            actions = analyzer.get_actions_summary()
            assert len(actions) == 0
            
        finally:
            os.unlink(sop_path)
    
    def test_integration_with_cli(self, create_test_sop_file):
        """Интеграционный тест с CLI аргументами"""
        sop_file = create_test_sop_file()
        try:
            # Тест базового вызова
            result = subprocess.run([
                sys.executable, 'sop_analyzer.py', sop_file
            ], capture_output=True, text=True, timeout=30)
            
            assert result.returncode == 0
            assert "МЕТАДАННЫЕ ПАКЕТА" in result.stdout
            assert "СТАТИСТИКА ЗАПИСЕЙ" in result.stdout
            
            # Тест JSON вывода
            result = subprocess.run([
                sys.executable, 'sop_analyzer.py', sop_file, '--json'
            ], capture_output=True, text=True, timeout=30)
            
            assert result.returncode == 0
            json_output = json.loads(result.stdout)
            assert "metadata" in json_output
            assert "record_statistics" in json_output
            
        finally:
            os.unlink(sop_file)


class TestOutputFormatter:
    """Тесты для OutputFormatter"""
    
    def test_print_table_basic(self, capsys):
        """Тест базовой печати таблицы"""
        headers = ["Name", "Age", "City"]
        rows = [
            ["Alice", "25", "New York"],
            ["Bob", "30", "London"],
            ["Charlie", "35", "Tokyo"]
        ]
        
        OutputFormatter.print_table(headers, rows, "Test Table")
        
        captured = capsys.readouterr()
        output = captured.out
        
        assert "Test Table" in output
        assert "Name" in output
        assert "Alice" in output
        assert "Bob" in output
        assert "Charlie" in output
    
    def test_print_table_empty(self, capsys):
        """Тест печати пустой таблицы"""
        headers = ["Name", "Age"]
        rows = []
        
        OutputFormatter.print_table(headers, rows, "Empty Table")
        
        captured = capsys.readouterr()
        output = captured.out
        
        assert "Empty Table" в output
        assert "Нет данных" в output
    
    def test_print_metadata(self, capsys):
        """Тест печати метаданных"""
        metadata = {
            "name": "test_package",
            "version": "1.0",
            "timestamp": "2024-01-15T10:30:00Z"
        }
        
        OutputFormatter.print_metadata(metadata)
        
        captured = capsys.readouterr()
        output = captured.out
        
        assert "МЕТАДАННЫЕ ПАКЕТА" в output
        assert "test_package" в output
        assert "1.0" в output
    
    def test_print_record_stats(self, capsys):
        """Тест печати статистики записей"""
        stats = RecordStats(total=100, deletes=10, strong_overwrites=5)
        actions = {"insert": 60, "update": 30, "delete": 10}
        
        OutputFormatter.print_record_stats(stats, actions)
        
        captured = capsys.readouterr()
        output = captured.out
        
        assert "СТАТИСТИКА ЗАПИСЕЙ" в output
        assert "100" в output
        assert "10" в output
        assert "5" в output
        assert "insert: 60" в output
    
    def test_print_tables_summary(self, capsys):
        """Тест печати сводки по таблицам"""
        tables = [
            TableInfo(name="users", record_count=50, actions={"insert": 30, "update": 20}),
            TableInfo(name="products", record_count=25, actions={"insert": 25})
        ]
        
        OutputFormatter.print_tables_summary(tables)
        
        captured = capsys.readouterr()
        output = captured.out
        
        assert "ТАБЛИЦЫ" в output
        assert "users" в output
        assert "50" в output
        assert "insert:30" в output


class TestDataCompression:
    """Тесты различных методов сжатия"""
    
    def test_different_compression_levels(self, sample_data):
        """Тест различных уровней сжатия"""
        compression_levels = [
            zlib.Z_NO_COMPRESSION,
            zlib.Z_BEST_SPEED,
            zlib.Z_BEST_COMPRESSION,
            zlib.Z_DEFAULT_COMPRESSION
        ]
        
        for level in compression_levels:
            with tempfile.NamedTemporaryFile(suffix='.sop', delete=False) as f:
                sop_path = f.name
            
            try:
                # Создаем SOP файл с указанным уровнем сжатия
                with zipfile.ZipFile(sop_path, 'w') as sop_zip:
                    json_data = json.dumps(sample_data).encode('utf-8')
                    compressed_data = zlib.compress(json_data, level)
                    sop_zip.writestr('package.data', compressed_data)
                
                # Проверяем, что данные можно прочитать
                analyzer = SOPAnalyzer(sop_path)
                data = analyzer.load_data()
                
                assert data["name"] == "test_package"
                assert len(data["records"]) == 4
                
            finally:
                os.unlink(sop_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])