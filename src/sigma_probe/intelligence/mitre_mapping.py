"""
SIGMA-PROBE MITRE ATT&CK Mapping
Professional Threat Intelligence Integration

Принцип: Говорить с миром кибербезопасности на одном языке.
Любой безопасник в мире, увидев T1190, сразу поймет, о чем идет речь.
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass

@dataclass
class MitreTechnique:
    """MITRE ATT&CK техника"""
    technique_id: str
    name: str
    tactic: str
    description: str
    url: str

class MitreMapping:
    """Маппинг внутренних тегов на MITRE ATT&CK техники"""
    
    def __init__(self):
        self.mapping = self._initialize_mapping()
        self.techniques = self._initialize_techniques()
    
    def _initialize_mapping(self) -> Dict[str, List[str]]:
        """Инициализация маппинга тегов на MITRE техники"""
        return {
            # Web Application Attacks
            'LFI_ATTACK': ['T1083', 'T1190'],
            'RFI_ATTACK': ['T1190', 'T1105'],
            'SQLI_ATTACK': ['T1190'],
            'XSS_ATTACK': ['T1190'],
            'PATH_TRAVERSAL': ['T1083', 'T1190'],
            
            # Reconnaissance
            'AUTOMATED_SCAN': ['T1595'],
            'MANUAL_SCAN': ['T1595'],
            'DIRECTORY_ENUMERATION': ['T1083'],
            'VERSION_DISCOVERY': ['T1592'],
            
            # Bot Activity
            'BOT_ACTIVITY': ['T1071.001'],
            'CONFIRMED_BOTNET': ['T1071.001', 'T1071.002'],
            'BOTNET_ACTIVITY': ['T1071.001', 'T1071.002'],
            
            # Coordinated Attacks
            'COORDINATED_ATTACK': ['T1071.001', 'T1595'],
            'CONFIRMED_COORDINATED': ['T1071.001', 'T1595'],
            'MULTI_VECTOR': ['T1190', 'T1071.001'],
            
            # Sophisticated Attacks
            'CONFIRMED_SOPHISTICATED': ['T1190', 'T1071.001', 'T1595'],
            'ADAPTIVE_BEHAVIOR': ['T1071.001', 'T1595'],
            
            # File Operations
            'FILE_ACCESS': ['T1083'],
            'SYSTEM_FILE_ACCESS': ['T1083'],
            'CONFIG_FILE_ACCESS': ['T1083'],
            
            # Network Activity
            'HIGH_FREQUENCY': ['T1071.001'],
            'RHYTHMIC_PATTERNS': ['T1071.001'],
            'BURST_ACTIVITY': ['T1071.001'],
            
            # User Agent Analysis
            'MALICIOUS_UA': ['T1071.001'],
            'SCANNER_UA': ['T1595'],
            'BOT_UA': ['T1071.001'],
            
            # Error Analysis
            'ERROR_EXPLOITATION': ['T1190'],
            'DEBUG_INFO': ['T1592'],
            
            # Isolated Indicators
            'ISOLATED_INDICATOR': ['T1595'],
            'FALSE_POSITIVE': ['T1595'],
            'INCONSISTENT_TIMING': ['T1071.001']
        }
    
    def _initialize_techniques(self) -> Dict[str, MitreTechnique]:
        """Инициализация MITRE техник"""
        return {
            'T1083': MitreTechnique(
                technique_id='T1083',
                name='File and Directory Discovery',
                tactic='Discovery',
                description='Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information within a system.',
                url='https://attack.mitre.org/techniques/T1083'
            ),
            'T1190': MitreTechnique(
                technique_id='T1190',
                name='Exploit Public-Facing Application',
                tactic='Initial Access',
                description='Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program using software, data, or commands in order to cause unintended or unanticipated behavior.',
                url='https://attack.mitre.org/techniques/T1190'
            ),
            'T1595': MitreTechnique(
                technique_id='T1595',
                name='Active Scanning',
                tactic='Reconnaissance',
                description='Adversaries may execute active reconnaissance scans to gather information that can be used during targeting.',
                url='https://attack.mitre.org/techniques/T1595'
            ),
            'T1071.001': MitreTechnique(
                technique_id='T1071.001',
                name='Web Protocols',
                tactic='Command and Control',
                description='Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic.',
                url='https://attack.mitre.org/techniques/T1071/001'
            ),
            'T1071.002': MitreTechnique(
                technique_id='T1071.002',
                name='Non-Standard Ports',
                tactic='Command and Control',
                description='Adversaries may communicate using a protocol and port paring that are not commonly associated.',
                url='https://attack.mitre.org/techniques/T1071/002'
            ),
            'T1105': MitreTechnique(
                technique_id='T1105',
                name='Ingress Tool Transfer',
                tactic='Lateral Movement',
                description='Adversaries may transfer tools or other files from an external system into a compromised environment.',
                url='https://attack.mitre.org/techniques/T1105'
            ),
            'T1592': MitreTechnique(
                technique_id='T1592',
                name='Gather Victim Host Information',
                tactic='Reconnaissance',
                description='Adversaries may gather information about the victim\'s host that can be used during targeting.',
                url='https://attack.mitre.org/techniques/T1592'
            )
        }
    
    def get_techniques_for_tags(self, tags: List[str]) -> List[MitreTechnique]:
        """Возвращает MITRE техники для заданных тегов"""
        techniques = []
        technique_ids = set()
        
        for tag in tags:
            if tag in self.mapping:
                technique_ids.update(self.mapping[tag])
        
        for technique_id in technique_ids:
            if technique_id in self.techniques:
                techniques.append(self.techniques[technique_id])
        
        return techniques
    
    def get_technique_by_id(self, technique_id: str) -> Optional[MitreTechnique]:
        """Возвращает технику по ID"""
        return self.techniques.get(technique_id)
    
    def get_all_techniques_for_actor(self, actor) -> List[MitreTechnique]:
        """Возвращает все MITRE техники для актора"""
        if hasattr(actor, 'tags'):
            return self.get_techniques_for_tags(list(actor.tags))
        return []
    
    def get_all_techniques_for_campaign(self, campaign) -> List[MitreTechnique]:
        """Возвращает все MITRE техники для кампании"""
        if hasattr(campaign, 'primary_tags'):
            return self.get_techniques_for_tags(list(campaign.primary_tags))
        return []
    
    def format_technique_reference(self, technique_id: str) -> str:
        """Форматирует ссылку на MITRE технику"""
        technique = self.get_technique_by_id(technique_id)
        if technique:
            return f"{technique_id} - {technique.name} ({technique.tactic})"
        return technique_id
    
    def get_technique_summary(self, technique_ids: List[str]) -> Dict[str, Any]:
        """Возвращает сводку по техникам"""
        tactics = {}
        techniques = []
        
        for technique_id in technique_ids:
            technique = self.get_technique_by_id(technique_id)
            if technique:
                if technique.tactic not in tactics:
                    tactics[technique.tactic] = []
                tactics[technique.tactic].append(technique)
                techniques.append(technique)
        
        return {
            'total_techniques': len(techniques),
            'tactics': tactics,
            'techniques': techniques
        } 