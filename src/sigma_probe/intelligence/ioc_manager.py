"""
SIGMA-PROBE IoC Manager
Dynamic Threat Intelligence Integration

Принцип: Система должна уметь подгружать индикаторы компрометации (IoC) 
из внешних источников для динамического обновления эвристик.
"""

import requests
import yaml
import logging
from typing import Dict, List, Set, Optional
from datetime import datetime, timedelta
from pathlib import Path
import re

logger = logging.getLogger(__name__)

class IoCFeed:
    """Represents a single IoC feed"""
    
    def __init__(self, name: str, url: str, feed_type: str, enabled: bool = True):
        self.name = name
        self.url = url
        self.feed_type = feed_type
        self.enabled = enabled
        self.last_update = None
        self.patterns: Set[str] = set()
        self.error_count = 0
        self.max_errors = 3
    
    def load_patterns(self) -> bool:
        """Load patterns from the feed URL"""
        if not self.enabled:
            return False
            
        try:
            response = requests.get(self.url, timeout=10)
            response.raise_for_status()
            
            # Parse patterns from response
            patterns = set()
            for line in response.text.split('\n'):
                line = line.strip()
                if line and not line.startswith('#'):
                    patterns.add(line)
            
            self.patterns = patterns
            self.last_update = datetime.now()
            self.error_count = 0
            
            logger.info(f"IoC feed '{self.name}' loaded {len(patterns)} patterns")
            return True
            
        except Exception as e:
            self.error_count += 1
            logger.error(f"Failed to load IoC feed '{self.name}': {e}")
            
            if self.error_count >= self.max_errors:
                logger.warning(f"Disabling IoC feed '{self.name}' due to repeated failures")
                self.enabled = False
            
            return False
    
    def match_pattern(self, text: str) -> Optional[str]:
        """Check if text matches any pattern in this feed"""
        if not self.enabled or not self.patterns:
            return None
            
        for pattern in self.patterns:
            if pattern in text:
                return pattern
        return None

class IoCManager:
    """Manages dynamic IoC feeds for threat intelligence"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.feeds: Dict[str, IoCFeed] = {}
        self.update_interval = config.get('update_interval', 3600)
        self.last_update = None
        self.enabled = config.get('enabled', True)
        
        self._load_feeds()
    
    def _load_feeds(self):
        """Load feed configurations from config"""
        if not self.enabled:
            return
            
        feeds_config = self.config.get('feeds', [])
        
        for feed_config in feeds_config:
            feed = IoCFeed(
                name=feed_config['name'],
                url=feed_config['url'],
                feed_type=feed_config['type'],
                enabled=feed_config.get('enabled', True)
            )
            self.feeds[feed.name] = feed
    
    def update_feeds(self) -> bool:
        """Update all enabled feeds"""
        if not self.enabled:
            return False
            
        current_time = datetime.now()
        
        # Check if update is needed
        if (self.last_update and 
            current_time - self.last_update < timedelta(seconds=self.update_interval)):
            return True
        
        logger.info("Updating IoC feeds...")
        success_count = 0
        
        for feed in self.feeds.values():
            if feed.load_patterns():
                success_count += 1
        
        self.last_update = current_time
        logger.info(f"IoC feeds update complete: {success_count}/{len(self.feeds)} successful")
        
        return success_count > 0
    
    def check_user_agent(self, user_agent: str) -> Optional[Dict]:
        """Check user agent against malicious patterns"""
        for feed in self.feeds.values():
            if feed.feed_type == 'user_agent':
                pattern = feed.match_pattern(user_agent)
                if pattern:
                    return {
                        'feed': feed.name,
                        'pattern': pattern,
                        'confidence': 0.9,
                        'description': f'Malicious user agent pattern detected: {pattern}'
                    }
        return None
    
    def check_url_path(self, url_path: str) -> Optional[Dict]:
        """Check URL path against suspicious patterns"""
        for feed in self.feeds.values():
            if feed.feed_type == 'url_path':
                pattern = feed.match_pattern(url_path)
                if pattern:
                    return {
                        'feed': feed.name,
                        'pattern': pattern,
                        'confidence': 0.8,
                        'description': f'Suspicious URL path detected: {pattern}'
                    }
        return None
    
    def check_ip_address(self, ip: str) -> Optional[Dict]:
        """Check IP address against malicious IP lists"""
        for feed in self.feeds.values():
            if feed.feed_type == 'ip_address':
                pattern = feed.match_pattern(ip)
                if pattern:
                    return {
                        'feed': feed.name,
                        'pattern': pattern,
                        'confidence': 0.95,
                        'description': f'Malicious IP address detected: {pattern}'
                    }
        return None
    
    def check_url_pattern(self, url: str) -> Optional[Dict]:
        """Check URL against attack patterns (LFI, SQLi, XSS, etc.)"""
        for feed in self.feeds.values():
            if feed.feed_type == 'url_pattern':
                pattern = feed.match_pattern(url)
                if pattern:
                    attack_type = self._determine_attack_type(feed.name)
                    return {
                        'feed': feed.name,
                        'pattern': pattern,
                        'confidence': 0.85,
                        'description': f'{attack_type} attack pattern detected: {pattern}'
                    }
        return None
    
    def _determine_attack_type(self, feed_name: str) -> str:
        """Determine attack type from feed name"""
        if 'lfi' in feed_name.lower():
            return 'LFI'
        elif 'sqli' in feed_name.lower():
            return 'SQLi'
        elif 'xss' in feed_name.lower():
            return 'XSS'
        else:
            return 'Attack'
    
    def get_stats(self) -> Dict:
        """Get IoC manager statistics"""
        total_patterns = sum(len(feed.patterns) for feed in self.feeds.values())
        enabled_feeds = sum(1 for feed in self.feeds.values() if feed.enabled)
        
        return {
            'total_feeds': len(self.feeds),
            'enabled_feeds': enabled_feeds,
            'total_patterns': total_patterns,
            'last_update': self.last_update.isoformat() if self.last_update else None,
            'enabled': self.enabled
        } 