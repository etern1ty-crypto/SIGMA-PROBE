ЁЯЪА SIGMA-PROBE Helios v2.0 System Test
==================================================
ЁЯФН Testing imports...
тЬЕ Core models imported successfully
тЭМ Import failed: expected an indented block after 'if' statement on line 76 (detectors.py, line 77)


ЁЯФН Testing data models...
тЬЕ LogEvent created with 2 heuristic flags
   Flags: ['SUSPICIOUS_EXTENSION', 'SQL_INJECTION']
тЬЕ ActorProfile created with 2 tags
   Tags: ['AUTOMATED_SCAN', 'SQL_INJECTION']
   Evidence entries: 2
тЬЕ Behavioral vector generated: 50 dimensions


ЁЯФН Testing rules engine...
тЭМ Rules engine test failed: expected an indented block after 'if' statement on line 76 (detectors.py, line 77)


ЁЯФН Testing configuration...
тЬЕ Configuration loaded successfully
   Detectors: ['FFTDetector', 'GraphDetector', 'AnomalyDetector', 'BehavioralClusteringDetector']
   Output formats: ['html', 'json', 'text']
   Parallel processing: False


ЁЯФН Testing with sample data...
тЬЕ Sample data ready


ЁЯФН Testing pipeline initialization...
тЭМ Pipeline initialization failed: expected an indented block after 'if' statement on line 76 (detectors.py, line 77)


ЁЯФН Testing unit tests...
тЬЕ Unit test files found
   To run unit tests: python -m pytest tests/

==================================================
ЁЯУК Test Results: 4/7 tests passed
тЪая╕П  Some tests failed. Please check the errors above.
