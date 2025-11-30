"""
Этап A: Инициализация и Загрузка (Ingestion)
Универсальный загрузчик для различных форматов логов
"""

import re
from datetime import datetime
from typing import Dict, List, Any, Iterator
from urllib.parse import urlparse, parse_qs
from ipaddress import IPv4Address
from sigma_probe.models.core import LogEvent, PipelineContext
from sigma_probe.pipeline.base import PipelineStage


class LogIngestionStage(PipelineStage):
    """Универсальный загрузчик логов"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.format = config.get('format', 'nginx')
        self.log_path = config.get('log_path', '')
        self.parsers = {
            'nginx': self._parse_nginx,
            'apache': self._parse_apache,
            'json': self._parse_json
        }
    
    def process(self, context: PipelineContext) -> PipelineContext:
        """Загружает и парсит логи"""
        print(f"Загрузка логов из {self.log_path} (формат: {self.format})")
        
        events = []
        parser = self.parsers.get(self.format)
        
        if not parser:
            raise ValueError(f"Неподдерживаемый формат: {self.format}")
        
        try:
            with open(self.log_path, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    try:
                        event = parser(line.strip())
                        if event:
                            events.append(event)
                    except Exception as e:
                        print(f"Ошибка парсинга строки {line_num}: {e}")
                        continue
            
            print(f"Загружено {len(events)} событий")
            context['events'] = events
            return context
            
        except FileNotFoundError:
            raise FileNotFoundError(f"Файл логов не найден: {self.log_path}")
    
    def _parse_nginx(self, line: str) -> LogEvent:
        """Парсинг Nginx логов"""
        # Стандартный формат Nginx: $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
        pattern = r'^(\S+) - \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) \d+ "([^"]*)" "([^"]*)"'
        match = re.match(pattern, line)
        
        if not match:
            raise ValueError(f"Неверный формат Nginx лога: {line}")
        
        ip_str, time_str, method, url_raw, status_code, referer, user_agent = match.groups()
        
        # Парсинг времени
        timestamp = datetime.strptime(time_str, '%d/%b/%Y:%H:%M:%S %z')
        
        # Нормализация URL
        url_normalized = self._normalize_url(url_raw)
        
        return LogEvent(
            source_ip=IPv4Address(ip_str),
            timestamp=timestamp,
            http_method=method,
            url_raw=url_raw,
            url_normalized=url_normalized,
            status_code=int(status_code),
            user_agent=user_agent
        )
    
    def _parse_apache(self, line: str) -> LogEvent:
        """Парсинг Apache логов"""
        # Стандартный формат Apache: %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
        pattern = r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) \S+" (\d+) \d+ "([^"]*)" "([^"]*)"'
        match = re.match(pattern, line)
        
        if not match:
            raise ValueError(f"Неверный формат Apache лога: {line}")
        
        ip_str, time_str, method, url_raw, status_code, referer, user_agent = match.groups()
        
        # Парсинг времени Apache
        timestamp = datetime.strptime(time_str, '%d/%b/%Y:%H:%M:%S %z')
        
        # Нормализация URL
        url_normalized = self._normalize_url(url_raw)
        
        return LogEvent(
            source_ip=IPv4Address(ip_str),
            timestamp=timestamp,
            http_method=method,
            url_raw=url_raw,
            url_normalized=url_normalized,
            status_code=int(status_code),
            user_agent=user_agent
        )
    
    def _parse_json(self, line: str) -> LogEvent:
        """Парсинг JSON логов"""
        import json
        
        try:
            data = json.loads(line)
            
            # Ожидаемые поля в JSON
            required_fields = ['source_ip', 'timestamp', 'http_method', 'url_raw', 'status_code', 'user_agent']
            
            for field in required_fields:
                if field not in data:
                    raise ValueError(f"Отсутствует обязательное поле: {field}")
            
            # Парсинг времени
            if isinstance(data['timestamp'], str):
                timestamp = datetime.fromisoformat(data['timestamp'].replace('Z', '+00:00'))
            else:
                timestamp = datetime.fromtimestamp(data['timestamp'])
            
            # Нормализация URL
            url_normalized = self._normalize_url(data['url_raw'])
            
            return LogEvent(
                source_ip=IPv4Address(data['source_ip']),
                timestamp=timestamp,
                http_method=data['http_method'],
                url_raw=data['url_raw'],
                url_normalized=url_normalized,
                status_code=int(data['status_code']),
                user_agent=data['user_agent']
            )
            
        except json.JSONDecodeError as e:
            raise ValueError(f"Ошибка парсинга JSON: {e}")
    
    def _normalize_url(self, url_raw: str) -> str:
        """Нормализует URL, убирая query-параметры"""
        try:
            parsed = urlparse(url_raw)
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        except Exception:
            # Если не удалось распарсить, возвращаем как есть
            return url_raw