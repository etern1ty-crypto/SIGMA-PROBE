"""
SIGMA-PROBE Reporting Engine
Архитектура v2.0 - 'Helios'

Принцип 5: Отчетность — это не просто вывод, это рассказ о том, что произошло.
"""

import json
import os
from datetime import datetime
from typing import Dict, List, Any
from pathlib import Path
import logging

from ..models.core import ActorProfile, ThreatCampaign

logger = logging.getLogger(__name__)

class ReportingStage:
    """Enhanced reporting stage with evidence trail support"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.output_formats = config.get('output_formats', ['html', 'json', 'text'])
        self.evidence_config = config.get('evidence_trail', {})
        self.sections = config.get('sections', ['summary', 'threat_actors', 'campaigns'])
        
    def generate_reports(self, data: Dict[str, Any]) -> Dict[str, str]:
        """Generate reports in all configured formats"""
        logger.info(f"Generating reports in formats: {self.output_formats}")
        
        reports = {}
        
        for format_type in self.output_formats:
            try:
                if format_type == 'html':
                    reports['html'] = self._generate_html_report(data)
                elif format_type == 'json':
                    reports['json'] = self._generate_json_report(data)
                elif format_type == 'text':
                    reports['text'] = self._generate_text_report(data)
                
                logger.info(f"Generated {format_type} report")
                
            except Exception as e:
                logger.error(f"Failed to generate {format_type} report: {e}")
        
        return reports
    
    def _generate_html_report(self, data: Dict[str, Any]) -> str:
        """Generate comprehensive HTML report with evidence trails"""
        actors = data.get('actors', [])
        campaigns = data.get('campaigns', [])
        context = data.get('context', {})
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SIGMA-PROBE Helios Threat Analysis Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #1a1a1a;
            color: #ffffff;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: #2d2d2d;
            padding: 30px;
            border-radius: 10px;
            box-shadow: 0 0 20px rgba(0,0,0,0.5);
        }}
        .header {{
            text-align: center;
            border-bottom: 2px solid #00ff88;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #00ff88;
            margin: 0;
            font-size: 2.5em;
        }}
        .section {{
            margin-bottom: 40px;
            padding: 20px;
            background-color: #3a3a3a;
            border-radius: 8px;
            border-left: 4px solid #00ff88;
        }}
        .section h2 {{
            color: #00ff88;
            margin-top: 0;
        }}
        .actor-card {{
            background-color: #4a4a4a;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            border-left: 3px solid #ff6b6b;
        }}
        .campaign-card {{
            background-color: #4a4a4a;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
            border-left: 3px solid #4ecdc4;
        }}
        .tags {{
            display: flex;
            flex-wrap: wrap;
            gap: 5px;
            margin: 10px 0;
        }}
        .tag {{
            background-color: #00ff88;
            color: #1a1a1a;
            padding: 2px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: bold;
        }}
        .evidence-trail {{
            background-color: #555;
            padding: 10px;
            margin: 10px 0;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }}
        .evidence-entry {{
            margin: 5px 0;
            padding: 5px;
            background-color: #666;
            border-radius: 3px;
        }}
        .threat-score {{
            font-size: 1.2em;
            font-weight: bold;
            color: #ff6b6b;
        }}
        .context-summary {{
            background-color: #4a4a4a;
            padding: 15px;
            border-radius: 5px;
            margin: 10px 0;
        }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-card {{
            background-color: #4a4a4a;
            padding: 15px;
            border-radius: 5px;
            text-align: center;
        }}
        .stat-value {{
            font-size: 2em;
            font-weight: bold;
            color: #00ff88;
        }}
        .stat-label {{
            color: #ccc;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚀 SIGMA-PROBE Helios</h1>
            <p>Advanced Threat Analysis Report</p>
            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="stats">
                <div class="stat-card">
                    <div class="stat-value">{len(actors)}</div>
                    <div class="stat-label">Threat Actors</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{len(campaigns)}</div>
                    <div class="stat-label">Threat Campaigns</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{sum(1 for a in actors if getattr(a, 'threat_score', 0) > 7.0)}</div>
                    <div class="stat-label">High Threat Actors</div>
                </div>
                <div class="stat-card">
                    <div class="stat-value">{len([a for a in actors if a.tags])}</div>
                    <div class="stat-label">Tagged Actors</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>🎯 Threat Actors Analysis</h2>
            {self._generate_actors_html(actors)}
        </div>
        
        <div class="section">
            <h2>🎭 Threat Campaigns</h2>
            {self._generate_campaigns_html(campaigns)}
        </div>
        
        <div class="section">
            <h2>🔍 Context Analysis</h2>
            {self._generate_context_html(context)}
        </div>
    </div>
</body>
</html>
        """
        
        return html
    
    def _generate_actors_html(self, actors: List[ActorProfile]) -> str:
        """Generate HTML for actors section"""
        html = ""
        
        # Sort actors by threat score
        sorted_actors = sorted(actors, key=lambda x: getattr(x, 'threat_score', 0), reverse=True)
        
        for i, actor in enumerate(sorted_actors[:10]):  # Show top 10
            tags_html = "".join([f'<span class="tag">{tag}</span>' for tag in actor.tags])
            
            evidence_html = ""
            if actor.evidence_trail:
                evidence_html = '<div class="evidence-trail">'
                for evidence in actor.evidence_trail[-3:]:  # Show last 3
                    evidence_html += f'''
                        <div class="evidence-entry">
                            <strong>{evidence['source']}</strong>: {evidence['details']}
                            <br><small>Confidence: {evidence.get('confidence', 'N/A')}</small>
                        </div>
                    '''
                evidence_html += '</div>'
            
            html += f"""
                <div class="actor-card">
                    <h3>Actor {i+1}: {actor.ip_address}</h3>
                    <div class="threat-score">Threat Score: {getattr(actor, 'threat_score', 0.0):.2f}</div>
                    <div class="tags">{tags_html}</div>
                    <p><strong>Requests:</strong> {actor.total_requests} | <strong>Unique URLs:</strong> {actor.unique_urls}</p>
                    <p><strong>Avg Entropy:</strong> {actor.avg_entropy:.2f} | <strong>Anomaly Ratio:</strong> {actor.anomaly_ratio:.2f}</p>
                    {evidence_html}
                </div>
            """
        
        if len(actors) > 10:
            html += f"<p><em>... and {len(actors) - 10} more actors</em></p>"
        
        return html
    
    def _generate_campaigns_html(self, campaigns: List[ThreatCampaign]) -> str:
        """Generate HTML for campaigns section"""
        html = ""
        
        for i, campaign in enumerate(campaigns):
            tags_html = "".join([f'<span class="tag">{tag}</span>' for tag in campaign.primary_tags])
            
            evidence_html = ""
            if campaign.evidence_trail:
                evidence_html = '<div class="evidence-trail">'
                for evidence in campaign.evidence_trail[-2:]:  # Show last 2
                    evidence_html += f'''
                        <div class="evidence-entry">
                            <strong>{evidence['source']}</strong>: {evidence['details']}
                        </div>
                    '''
                evidence_html += '</div>'
            
            html += f"""
                <div class="campaign-card">
                    <h3>Campaign {i+1}: {campaign.campaign_id}</h3>
                    <div class="threat-score">Threat Score: {campaign.threat_score:.2f}</div>
                    <div class="tags">{tags_html}</div>
                    <p><strong>Type:</strong> {campaign.campaign_type} | <strong>Actors:</strong> {len(campaign.actors)}</p>
                    {evidence_html}
                </div>
            """
        
        return html
    
    def _generate_context_html(self, context: Dict[str, Any]) -> str:
        """Generate HTML for context section"""
        html = ""
        
        for context_key, context_data in context.items():
            html += f'<div class="context-summary">'
            html += f'<h3>{context_key.upper()}</h3>'
            
            if isinstance(context_data, dict):
                for key, value in context_data.items():
                    html += f'<p><strong>{key}:</strong> {value}</p>'
            else:
                html += f'<p>{context_data}</p>'
            
            html += '</div>'
        
        return html
    
    def _generate_json_report(self, data: Dict[str, Any]) -> str:
        """Generate JSON report with evidence trails"""
        report_data = {
            'metadata': {
                'generated_at': datetime.now().isoformat(),
                'version': '2.0',
                'architecture': 'Helios'
            },
            'summary': {
                'total_actors': len(data.get('actors', [])),
                'total_campaigns': len(data.get('campaigns', [])),
                'high_threat_actors': len([a for a in data.get('actors', []) if getattr(a, 'threat_score', 0) > 7.0]),
                'tagged_actors': len([a for a in data.get('actors', []) if a.tags])
            },
            'actors': [],
            'campaigns': [],
            'context': data.get('context', {})
        }
        
        # Add actors with evidence trails
        for actor in data.get('actors', []):
            actor_data = {
                'ip_address': actor.ip_address,
                'threat_score': getattr(actor, 'threat_score', 0.0),
                'tags': list(actor.tags),
                'metrics': {
                    'total_requests': actor.total_requests,
                    'unique_urls': actor.unique_urls,
                    'avg_entropy': actor.avg_entropy,
                    'anomaly_ratio': actor.anomaly_ratio,
                    'centrality': actor.centrality
                },
                'evidence_trail': actor.evidence_trail
            }
            report_data['actors'].append(actor_data)
        
        # Add campaigns with evidence trails
        for campaign in data.get('campaigns', []):
            campaign_data = {
                'campaign_id': campaign.campaign_id,
                'threat_score': campaign.threat_score,
                'campaign_type': campaign.campaign_type,
                'primary_tags': list(campaign.primary_tags),
                'actor_count': len(campaign.actors),
                'evidence_trail': campaign.evidence_trail
            }
            report_data['campaigns'].append(campaign_data)
        
        return json.dumps(report_data, indent=2, default=str)
    
    def _generate_text_report(self, data: Dict[str, Any]) -> str:
        """Generate text report with evidence trails"""
        actors = data.get('actors', [])
        campaigns = data.get('campaigns', [])
        context = data.get('context', {})
        
        report = f"""
SIGMA-PROBE HELIOS THREAT ANALYSIS REPORT
=========================================

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Architecture: v2.0 - 'Helios'

EXECUTIVE SUMMARY
================
Total Threat Actors: {len(actors)}
Total Campaigns: {len(campaigns)}
High Threat Actors (>7.0): {sum(1 for a in actors if getattr(a, 'threat_score', 0) > 7.0)}
Tagged Actors: {len([a for a in actors if a.tags])}

THREAT ACTORS ANALYSIS
======================
"""
        
        # Sort actors by threat score
        sorted_actors = sorted(actors, key=lambda x: getattr(x, 'threat_score', 0), reverse=True)
        
        for i, actor in enumerate(sorted_actors[:10]):  # Show top 10
            report += f"""
Actor {i+1}: {actor.ip_address}
Threat Score: {getattr(actor, 'threat_score', 0.0):.2f}
Tags: {', '.join(actor.tags) if actor.tags else 'None'}
Requests: {actor.total_requests} | Unique URLs: {actor.unique_urls}
Avg Entropy: {actor.avg_entropy:.2f} | Anomaly Ratio: {actor.anomaly_ratio:.2f}

Evidence Trail:
"""
            
            for evidence in actor.evidence_trail[-3:]:  # Show last 3
                report += f"  - {evidence['source']}: {evidence['details']}\n"
            
            report += "\n"
        
        if len(actors) > 10:
            report += f"... and {len(actors) - 10} more actors\n\n"
        
        report += """
THREAT CAMPAIGNS
================
"""
        
        for i, campaign in enumerate(campaigns):
            report += f"""
Campaign {i+1}: {campaign.campaign_id}
Threat Score: {campaign.threat_score:.2f}
Type: {campaign.campaign_type}
Primary Tags: {', '.join(campaign.primary_tags) if campaign.primary_tags else 'None'}
Actors: {len(campaign.actors)}

Evidence Trail:
"""
            
            for evidence in campaign.evidence_trail[-2:]:  # Show last 2
                report += f"  - {evidence['source']}: {evidence['details']}\n"
            
            report += "\n"
        
        report += """
CONTEXT ANALYSIS
================
"""
        
        for context_key, context_data in context.items():
            report += f"{context_key.upper()}:\n"
            if isinstance(context_data, dict):
                for key, value in context_data.items():
                    report += f"  {key}: {value}\n"
            else:
                report += f"  {context_data}\n"
            report += "\n"
        
        return report 