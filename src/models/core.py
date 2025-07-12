"""
SIGMA-PROBE Core Data Models
Архитектура v2.0 - 'Helios'

Принцип 1: Данные — это не таблицы, это Объекты.
"""

import re
import math
from datetime import datetime
from typing import Dict, List, Set, Any, Optional
from ipaddress import IPv4Address
from pydantic import BaseModel, Field
from dataclasses import dataclass
from collections import Counter


class LogEvent(BaseModel):
    """Enhanced log event with built-in feature calculation capabilities"""
    timestamp: datetime
    source_ip: str
    destination_ip: Optional[str] = None
    url: str
    method: str
    status_code: int
    user_agent: Optional[str] = None
    request_size: Optional[int] = None
    response_size: Optional[int] = None
    referer: Optional[str] = None
    
    # Computed features
    entropy: Optional[float] = None
    url_length: Optional[int] = None
    path_depth: Optional[int] = None
    query_params_count: Optional[int] = None
    is_suspicious: bool = False
    heuristic_flags: Set[str] = Field(default_factory=set)
    
    def calculate_features(self) -> None:
        """Calculate all features for this event"""
        self._calculate_entropy()
        self._calculate_url_features()
        self._apply_heuristics()
    
    def _calculate_entropy(self) -> None:
        """Calculate Shannon entropy of the URL"""
        if not self.url:
            self.entropy = 0.0
            return
            
        # Count character frequencies
        char_counts = Counter(self.url)
        total_chars = len(self.url)
        
        # Calculate entropy
        entropy = 0.0
        for count in char_counts.values():
            if count > 0:
                p = count / total_chars
                entropy -= p * math.log2(p)
        
        self.entropy = entropy
    
    def _calculate_url_features(self) -> None:
        """Calculate URL-based features"""
        self.url_length = len(self.url)
        
        # Calculate path depth
        path = self.url.split('?')[0]  # Remove query parameters
        self.path_depth = len([p for p in path.split('/') if p])
        
        # Count query parameters
        if '?' in self.url:
            query_part = self.url.split('?')[1]
            self.query_params_count = len(query_part.split('&'))
        else:
            self.query_params_count = 0
    
    def _apply_heuristics(self) -> None:
        """Apply heuristic rules to detect suspicious patterns"""
        self.heuristic_flags.clear()
        
        # LFI/RFI patterns
        lfi_patterns = [
            r'\.\./', r'\.\.\\',  # Directory traversal
            r'file://', r'ftp://', r'http://',  # Remote file inclusion
            r'php://', r'data://', r'zip://'   # PHP wrappers
        ]
        
        for pattern in lfi_patterns:
            if re.search(pattern, self.url, re.IGNORECASE):
                self.heuristic_flags.add('LFI_RFI')
                break
        
        # SQL Injection patterns
        sql_patterns = [
            r'(\'|\")(\s|%20)*(OR|AND)(\s|%20)*(\d+|\'[^\']*\')',
            r'UNION(\s|%20)*SELECT',
            r'DROP(\s|%20)*TABLE',
            r'EXEC(\s|%20)*xp_',
            r'(\'|\")(\s|%20)*(OR|AND)(\s|%20)*(\d+|\'[^\']*\')'
        ]
        
        for pattern in sql_patterns:
            if re.search(pattern, self.url, re.IGNORECASE):
                self.heuristic_flags.add('SQL_INJECTION')
                break
        
        # XSS patterns
        xss_patterns = [
            r'<script[^>]*>',
            r'javascript:',
            r'on\w+\s*=',
            r'<iframe[^>]*>',
            r'<object[^>]*>'
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, self.url, re.IGNORECASE):
                self.heuristic_flags.add('XSS')
                break
        
        # Command injection patterns
        cmd_patterns = [
            r'(\||&|;|`|\\$\(|\$\{).*?(cat|ls|pwd|whoami|id)',
            r'(\||&|;|`|\\$\(|\$\{).*?(wget|curl|nc|telnet)',
            r'(\||&|;|`|\\$\(|\$\{).*?(rm|del|format)'
        ]
        
        for pattern in cmd_patterns:
            if re.search(pattern, self.url, re.IGNORECASE):
                self.heuristic_flags.add('COMMAND_INJECTION')
                break
        
        # Suspicious file extensions
        suspicious_extensions = [
            '.php', '.asp', '.aspx', '.jsp', '.cgi', '.pl', '.py',
            '.exe', '.bat', '.cmd', '.com', '.pif', '.scr'
        ]
        
        for ext in suspicious_extensions:
            if ext.lower() in self.url.lower():
                self.heuristic_flags.add('SUSPICIOUS_EXTENSION')
                break
        
        # High entropy (encrypted/encoded content)
        if self.entropy and self.entropy > 4.5:
            self.heuristic_flags.add('HIGH_ENTROPY')
        
        # Long URLs (potential overflow attacks)
        if self.url_length > 2000:
            self.heuristic_flags.add('LONG_URL')
        
        # Many query parameters (potential parameter pollution)
        if self.query_params_count and self.query_params_count > 10:
            self.heuristic_flags.add('MANY_PARAMS')
        
        # Suspicious user agents
        if self.user_agent:
            suspicious_ua_patterns = [
                r'bot|crawler|spider|scraper',
                r'nmap|sqlmap|nikto|dirb',
                r'python|curl|wget|lynx'
            ]
            
            for pattern in suspicious_ua_patterns:
                if re.search(pattern, self.user_agent, re.IGNORECASE):
                    self.heuristic_flags.add('SUSPICIOUS_USER_AGENT')
                    break
        
        # Set overall suspicious flag
        self.is_suspicious = len(self.heuristic_flags) > 0

class ActorProfile(BaseModel):
    """Enhanced actor profile with tagging system and evidence trail"""
    ip_address: str
    events: List[LogEvent] = Field(default_factory=list)
    
    # Behavioral metrics
    total_requests: int = 0
    unique_urls: int = 0
    avg_entropy: float = 0.0
    max_entropy: float = 0.0
    url_diversity_ratio: float = 0.0
    anomaly_ratio: float = 0.0
    centrality: float = 0.0
    
    # Tagging system instead of single tactic
    tags: Set[str] = Field(default_factory=set)
    
    # Evidence trail for traceability
    evidence_trail: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Behavioral vector for clustering
    url_frequency_vector: Dict[str, float] = Field(default_factory=dict)
    
    def add_event(self, event: LogEvent) -> None:
        """Add event and update metrics"""
        self.events.append(event)
        self._update_metrics()
    
    def _update_metrics(self) -> None:
        """Update all metrics based on current events"""
        if not self.events:
            return
        
        self.total_requests = len(self.events)
        
        # URL diversity
        unique_urls = set(event.url for event in self.events)
        self.unique_urls = len(unique_urls)
        self.url_diversity_ratio = self.unique_urls / self.total_requests if self.total_requests > 0 else 0.0
        
        # Entropy metrics
        entropies = [event.entropy for event in self.events if event.entropy is not None]
        if entropies:
            self.avg_entropy = sum(entropies) / len(entropies)
            self.max_entropy = max(entropies)
        
        # Build URL frequency vector for clustering
        url_counts = Counter(event.url for event in self.events)
        total_events = len(self.events)
        self.url_frequency_vector = {
            url: count / total_events 
            for url, count in url_counts.items()
        }
    
    def add_evidence(self, source: str, evidence_type: str, details: str, confidence: float = 1.0) -> None:
        """Add evidence to the trail"""
        self.evidence_trail.append({
            'timestamp': datetime.now().isoformat(),
            'source': source,
            'type': evidence_type,
            'details': details,
            'confidence': confidence
        })
    
    def add_tag(self, tag: str, source: str = "unknown") -> None:
        """Add a tag to the actor"""
        self.tags.add(tag)
        self.add_evidence(source, "tag_added", f"Added tag: {tag}")
    
    def get_behavioral_vector(self) -> List[float]:
        """Get normalized behavioral vector for clustering"""
        # Normalize URL frequency vector to fixed size
        top_urls = sorted(self.url_frequency_vector.items(), key=lambda x: x[1], reverse=True)[:50]
        
        # Pad or truncate to 50 dimensions
        vector = [freq for _, freq in top_urls]
        while len(vector) < 50:
            vector.append(0.0)
        vector = vector[:50]
        
        # Normalize
        total = sum(vector)
        if total > 0:
            vector = [v / total for v in vector]
        
        return vector

class ThreatCampaign(BaseModel):
    """Enhanced threat campaign with evidence trail"""
    campaign_id: str
    actors: List[ActorProfile] = Field(default_factory=list)
    threat_score: float = 0.0
    primary_tags: Set[str] = Field(default_factory=set)
    campaign_type: str = "unknown"
    
    # Evidence trail
    evidence_trail: List[Dict[str, Any]] = Field(default_factory=list)
    
    def add_actor(self, actor: ActorProfile) -> None:
        """Add actor to campaign"""
        self.actors.append(actor)
        self._update_campaign_metrics()
    
    def _update_campaign_metrics(self) -> None:
        """Update campaign-level metrics"""
        if not self.actors:
            return
        
        # Aggregate threat scores
        scores = [actor.get('threat_score', 0.0) for actor in self.actors if hasattr(actor, 'get')]
        if scores:
            self.threat_score = sum(scores) / len(scores)
        
        # Aggregate tags
        all_tags = set()
        for actor in self.actors:
            if hasattr(actor, 'tags'):
                all_tags.update(actor.tags)
        self.primary_tags = all_tags
        
        # Determine campaign type based on most common tags
        tag_counts = Counter()
        for actor in self.actors:
            if hasattr(actor, 'tags'):
                for tag in actor.tags:
                    tag_counts[tag] += 1
        
        if tag_counts:
            self.campaign_type = tag_counts.most_common(1)[0][0]
    
    def add_evidence(self, source: str, evidence_type: str, details: str) -> None:
        """Add evidence to campaign trail"""
        self.evidence_trail.append({
            'timestamp': datetime.now().isoformat(),
            'source': source,
            'type': evidence_type,
            'details': details
        }) 