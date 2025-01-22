import logging
from pathlib import Path
from typing import Dict, List, Any, Set
import yara
import magic
import re
from dataclasses import dataclass, field
from collections import defaultdict

from utils.config import Config
from utils.exceptions import PhishingKitAnalyzerError

@dataclass
class StaticAnalysisResult:
    """Results of the static analysis."""
    file_types: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    suspicious_patterns: List[Dict[str, Any]] = field(default_factory=list)
    obfuscation_techniques: List[Dict[str, Any]] = field(default_factory=list)
    extracted_urls: Set[str] = field(default_factory=set)
    extracted_emails: Set[str] = field(default_factory=set)
    frameworks_detected: List[str] = field(default_factory=list)
    total_files: int = 0
    total_size: int = 0

class StaticAnalyzer:
    """Static analyzer for phishing kits."""

    def __init__(self, config: Config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._load_yara_rules()
        
        # Detection patterns
        self.url_pattern = re.compile(
            r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s]*'
        )
        self.email_pattern = re.compile(
            r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        )
        self.obfuscation_patterns = {
            'base64': re.compile(r'base64_decode\s*\('),
            'eval': re.compile(r'eval\s*\('),
            'gzinflate': re.compile(r'gzinflate\s*\('),
            'rot13': re.compile(r'str_rot13\s*\('),
            'hex': re.compile(r'hex2bin\s*\(|pack\s*\(')
        }

    def _load_yara_rules(self) -> None:
        """Loads YARA rules for detection."""
        try:
            rules_path = self.config.get_yara_rules_path()
            rules_file = rules_path / "phishing.yar"
            
            self.logger.info(f"Loading YARA rules from: {rules_file}")
            
            if not rules_file.exists():
                self.logger.error(f"YARA rules file not found: {rules_file}")
                self.yara_rules = None
                return

            try:
                self.yara_rules = yara.compile(filepath=str(rules_file))
                self.logger.info("YARA rules loaded successfully")
            except yara.Error as e:
                self.logger.error(f"Error compiling YARA rules: {e}")
                self.yara_rules = None
            except Exception as e:
                self.logger.error(f"Unexpected error loading YARA rules: {e}")
                self.yara_rules = None
                
        except Exception as e:
            self.logger.error(f"Error loading YARA rules: {e}")
            self.yara_rules = None

    def analyze(self, path: Path) -> StaticAnalysisResult:
        """Static analysis of a phishing kit."""
        if not path.exists():
            raise PhishingKitAnalyzerError(f"Path {path} does not exist")

        result = StaticAnalysisResult()
        
        try:
            self._analyze_directory(path, result)
            return result
        except Exception as e:
            raise PhishingKitAnalyzerError(f"Error during static analysis: {str(e)}")

    def _analyze_directory(self, path: Path, result: StaticAnalysisResult) -> None:
        """Recursive analysis of a directory."""
        for item in path.rglob('*'):
            if item.is_file():
                self._analyze_file(item, result)
                
                if result.total_files >= self.config.analysis.static.max_file_count:
                    self.logger.warning("Maximum file count reached")
                    break

    def _analyze_file(self, file_path: Path, result: StaticAnalysisResult) -> None:
        """Analyzes an individual file."""
        try:
            # File type verification
            mime_type = magic.from_file(str(file_path), mime=True)
            result.file_types[mime_type] += 1
            result.total_files += 1
            result.total_size += file_path.stat().st_size

            # Content analysis for text files
            if 'text' in mime_type or file_path.suffix in self.config.analysis.static.file_extensions:
                content = file_path.read_text(errors='ignore')
                self._analyze_content(content, result, file_path)

        except Exception as e:
            self.logger.error(f"Error analyzing file {file_path}: {e}")

    def _analyze_content(self, content: str, result: StaticAnalysisResult, file_path: Path) -> None:
        """Analyzes the content of a file."""
        # URL extraction
        urls = self.url_pattern.findall(content)
        result.extracted_urls.update(urls)

        # Email extraction
        emails = self.email_pattern.findall(content)
        result.extracted_emails.update(emails)

        # Obfuscation technique detection
        for technique, pattern in self.obfuscation_patterns.items():
            if pattern.search(content):
                result.obfuscation_techniques.append({
                    'technique': technique,
                    'file': str(file_path),
                    'line_count': len(pattern.findall(content))
                })

        # YARA analysis if available
        if self.yara_rules:
            matches = self.yara_rules.match(data=content)
            for match in matches:
                result.suspicious_patterns.append({
                    'rule': match.rule,
                    'file': str(file_path),
                    'tags': match.tags,
                    'strings': match.strings
                })

        # Framework detection
        self._detect_frameworks(content, result)

    def _detect_frameworks(self, content: str, result: StaticAnalysisResult) -> None:
        """Detects frameworks used in the code."""
        framework_patterns = {
            'WordPress': r'wp-content|wp-includes|wp-admin',
            'Joomla': r'com_content|com_users|com_modules',
            'Drupal': r'drupal_add_js|drupal_get_path',
            'Laravel': r'Illuminate\\|laravel',
            'CodeIgniter': r'CI_Controller|system/core/CodeIgniter',
            'Bootstrap': r'bootstrap.min.css|bootstrap.min.js',
            'jQuery': r'jquery.min.js|jquery-\d+.\d+.\d+',
            'React': r'react.production.min.js|react-dom',
            'Angular': r'angular.min.js|ng-controller',
            'Vue.js': r'vue.min.js|v-bind|v-model'
        }

        for framework, pattern in framework_patterns.items():
            if re.search(pattern, content, re.IGNORECASE):
                if framework not in result.frameworks_detected:
                    result.frameworks_detected.append(framework) 