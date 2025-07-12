#!/usr/bin/env python3
"""
SIGMA-PROBE Helios v2.0 System Test
Проверка работоспособности всех компонентов системы
"""

import sys
import os
import logging
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

def test_imports():
    """Test that all modules can be imported"""
    print("🔍 Testing imports...")
    
    try:
        from models.core import LogEvent, ActorProfile, ThreatCampaign
        print("✅ Core models imported successfully")
        
        from pipeline.ingestion import LogIngestionStage
        print("✅ Ingestion stage imported successfully")
        
        from pipeline.enrichment import EnrichmentStage
        print("✅ Enrichment stage imported successfully")
        
        from pipeline.profiling import ActorProfilingStage
        print("✅ Profiling stage imported successfully")
        
        from pipeline.detectors import FFTDetector, GraphDetector, AnomalyDetector, BehavioralClusteringDetector
        print("✅ Detectors imported successfully")
        
        from pipeline.rules_engine import ScoringRulesEngine
        print("✅ Rules engine imported successfully")
        
        from pipeline.scoring import ScoringEngine
        print("✅ Scoring engine imported successfully")
        
        from pipeline.reporting import ReportingStage
        print("✅ Reporting stage imported successfully")
        
        from main import HeliosPipeline
        print("✅ Main pipeline imported successfully")
        
        return True
        
    except Exception as e:
        print(f"❌ Import failed: {e}")
        return False

def test_data_models():
    """Test data model functionality"""
    print("\n🔍 Testing data models...")
    
    try:
        from models.core import LogEvent, ActorProfile
        from datetime import datetime
        
        # Test LogEvent with feature calculation
        event = LogEvent(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            url="/admin/login.php?id=1' OR '1'='1",
            method="GET",
            status_code=200,
            user_agent="Mozilla/5.0"
        )
        
        # Test feature calculation
        event.calculate_features()
        print(f"✅ LogEvent created with {len(event.heuristic_flags)} heuristic flags")
        print(f"   Flags: {list(event.heuristic_flags)}")
        
        # Test ActorProfile with tagging system
        actor = ActorProfile(ip_address="192.168.1.100")
        actor.add_event(event)
        actor.add_tag("SQL_INJECTION", "test")
        actor.add_tag("AUTOMATED_SCAN", "test")
        
        print(f"✅ ActorProfile created with {len(actor.tags)} tags")
        print(f"   Tags: {list(actor.tags)}")
        print(f"   Evidence entries: {len(actor.evidence_trail)}")
        
        # Test behavioral vector
        vector = actor.get_behavioral_vector()
        print(f"✅ Behavioral vector generated: {len(vector)} dimensions")
        
        return True
        
    except Exception as e:
        print(f"❌ Data model test failed: {e}")
        return False

def test_rules_engine():
    """Test rules engine functionality"""
    print("\n🔍 Testing rules engine...")
    
    try:
        from pipeline.rules_engine import ScoringRulesEngine
        from models.core import ActorProfile
        
        # Test configuration
        config = {
            'scoring_profiles': {
                'LFI_RFI': {
                    'base_score': 8.0,
                    'modifiers': [
                        {
                            'if': 'high_entropy',
                            'value': 1.3,
                            'evidence': 'LFI/RFI with high entropy'
                        }
                    ]
                }
            },
            'tag_combinations': {
                'LFI_RFI+COORDINATED_ATTACK': {
                    'multiplier': 1.8,
                    'evidence': 'LFI/RFI in coordinated attack'
                }
            }
        }
        
        rules_engine = ScoringRulesEngine(config)
        
        # Test actor with tags
        actor = ActorProfile(ip_address="192.168.1.100")
        actor.tags = {"LFI_RFI", "COORDINATED_ATTACK"}
        actor.avg_entropy = 5.0  # High entropy
        
        score, evidence = rules_engine.calculate_score(actor, {})
        
        print(f"✅ Rules engine calculated score: {score:.2f}")
        print(f"   Evidence entries: {len(evidence)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Rules engine test failed: {e}")
        return False

def test_configuration():
    """Test configuration loading"""
    print("\n🔍 Testing configuration...")
    
    try:
        import yaml
        
        # Test if config.yaml exists and is valid
        config_path = Path("config.yaml")
        if not config_path.exists():
            print("❌ config.yaml not found")
            return False
        
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        # Check required sections
        required_sections = ['ingestion', 'detection', 'scoring_engine', 'reporting']
        for section in required_sections:
            if section not in config:
                print(f"❌ Missing config section: {section}")
                return False
        
        print("✅ Configuration loaded successfully")
        print(f"   Detectors: {config['detection'].get('detectors', [])}")
        print(f"   Output formats: {config['reporting'].get('output_formats', [])}")
        print(f"   Parallel processing: {config.get('pipeline', {}).get('parallel', {}).get('enabled', False)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False

def test_sample_data():
    """Test with sample data"""
    print("\n🔍 Testing with sample data...")
    
    try:
        # Create sample log file if it doesn't exist
        sample_log = Path("sample_nginx.log")
        if not sample_log.exists():
            print("📝 Creating sample log file...")
            sample_data = [
                '192.168.1.100 - - [01/Jan/2024:10:00:00 +0000] "GET /admin/login.php?id=1\' OR \'1\'=\'1 HTTP/1.1" 200 1234 "Mozilla/5.0"',
                '192.168.1.101 - - [01/Jan/2024:10:00:05 +0000] "GET /wp-admin/ HTTP/1.1" 404 567 "python-requests/2.25.1"',
                '192.168.1.102 - - [01/Jan/2024:10:00:10 +0000] "GET /config.php HTTP/1.1" 200 890 "curl/7.68.0"',
                '192.168.1.100 - - [01/Jan/2024:10:00:15 +0000] "GET /admin/users.php?id=1 UNION SELECT 1,2,3 HTTP/1.1" 200 1234 "Mozilla/5.0"',
                '192.168.1.103 - - [01/Jan/2024:10:00:20 +0000] "GET /index.php?page=../../../etc/passwd HTTP/1.1" 200 456 "python-requests/2.25.1"'
            ]
            
            with open(sample_log, 'w') as f:
                for line in sample_data:
                    f.write(line + '\n')
        
        print("✅ Sample data ready")
        return True
        
    except Exception as e:
        print(f"❌ Sample data test failed: {e}")
        return False

def test_pipeline_initialization():
    """Test pipeline initialization"""
    print("\n🔍 Testing pipeline initialization...")
    
    try:
        from main import HeliosPipeline
        
        pipeline = HeliosPipeline()
        print("✅ Pipeline initialized successfully")
        
        # Test that all stages are initialized
        assert hasattr(pipeline, 'ingestion')
        assert hasattr(pipeline, 'enrichment')
        assert hasattr(pipeline, 'profiling')
        assert hasattr(pipeline, 'detectors')
        assert hasattr(pipeline, 'scoring_engine')
        assert hasattr(pipeline, 'reporting')
        
        print(f"   Detectors loaded: {len(pipeline.detectors)}")
        print(f"   Context initialized: {type(pipeline.context)}")
        print(f"   Parallel processing: {pipeline.config.get('pipeline', {}).get('parallel', {}).get('enabled', False)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Pipeline initialization failed: {e}")
        return False

def test_unit_tests():
    """Test that unit tests can be run"""
    print("\n🔍 Testing unit tests...")
    
    try:
        # Test that test files exist
        test_files = [
            "tests/test_scoring.py",
            "tests/test_detectors.py", 
            "tests/test_models.py"
        ]
        
        for test_file in test_files:
            if not Path(test_file).exists():
                print(f"❌ Test file not found: {test_file}")
                return False
        
        print("✅ Unit test files found")
        print("   To run unit tests: python -m pytest tests/")
        
        return True
        
    except Exception as e:
        print(f"❌ Unit test check failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🚀 SIGMA-PROBE Helios v2.0 System Test")
    print("=" * 50)
    
    tests = [
        test_imports,
        test_data_models,
        test_rules_engine,
        test_configuration,
        test_sample_data,
        test_pipeline_initialization,
        test_unit_tests
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! System is ready to use.")
        print("\nTo run the full analysis:")
        print("  python -m src.main")
        print("\nTo run unit tests:")
        print("  python -m pytest tests/")
    else:
        print("⚠️  Some tests failed. Please check the errors above.")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main()) 