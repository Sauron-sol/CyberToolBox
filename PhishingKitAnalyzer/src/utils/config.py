from dataclasses import dataclass
from pathlib import Path
from typing import List, Dict, Any, Optional

@dataclass
class GeneralConfig:
    debug: bool
    log_level: str
    temp_dir: str
    max_file_size: str

@dataclass
class StaticAnalysisConfig:
    max_file_count: int
    file_extensions: List[str]
    yara_rules_path: str

@dataclass
class DynamicAnalysisConfig:
    sandbox_type: str
    timeout: int
    max_memory: str
    network_capture: bool

@dataclass
class AnalysisConfig:
    timeout: int
    enabled_modules: List[str]
    static: StaticAnalysisConfig
    dynamic: DynamicAnalysisConfig

@dataclass
class DatabaseConfig:
    type: str
    path: str
    host: Optional[str] = None
    port: Optional[int] = None
    name: Optional[str] = None
    user: Optional[str] = None
    password: Optional[str] = None

@dataclass
class ReportingConfig:
    output_dir: str
    formats: List[str]
    include_screenshots: bool
    max_report_size: str

@dataclass
class APIConfig:
    host: str
    port: int
    workers: int
    rate_limit: str
    token_expiration: str
    cors_origins: List[str]

@dataclass
class MISPConfig:
    url: str
    api_key: str
    verify_ssl: bool
    publish_events: bool

@dataclass
class DetectionConfig:
    score_thresholds: Dict[str, int]
    custom_rules: Dict[str, Any]

@dataclass
class Config:
    version: str
    general: GeneralConfig
    analysis: AnalysisConfig
    api_keys: Dict[str, str]
    database: DatabaseConfig
    reporting: ReportingConfig
    api: APIConfig
    misp: MISPConfig
    detection: DetectionConfig

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Config':
        """Creates a Config instance from a dictionary."""
        return cls(
            version=data['version'],
            general=GeneralConfig(**data['general']),
            analysis=AnalysisConfig(
                timeout=data['analysis']['timeout'],
                enabled_modules=data['analysis']['enabled_modules'],
                static=StaticAnalysisConfig(**data['analysis']['static']),
                dynamic=DynamicAnalysisConfig(**data['analysis']['dynamic'])
            ),
            api_keys=data['api_keys'],
            database=DatabaseConfig(**data['database']),
            reporting=ReportingConfig(**data['reporting']),
            api=APIConfig(**data['api']),
            misp=MISPConfig(**data['misp']),
            detection=DetectionConfig(**data['detection'])
        )

    def get_temp_dir(self) -> Path:
        """Returns the path of the temporary directory."""
        return Path(self.general.temp_dir)

    def get_output_dir(self) -> Path:
        """Returns the path of the report output directory."""
        return Path(self.reporting.output_dir)

    def get_yara_rules_path(self) -> Path:
        """Returns the absolute path to the YARA rules directory."""
        # Get the base path of the project (parent directory of src)
        base_path = Path(__file__).parent.parent.parent
        
        # Construct the absolute path to the rules
        rules_path = base_path / self.analysis.static.yara_rules_path
        
        # Create the directory if it doesn't exist
        rules_path.mkdir(parents=True, exist_ok=True)
        
        return rules_path.resolve()

    def get_database_path(self) -> Path:
        """Returns the path of the SQLite database."""
        if self.database.type != 'sqlite':
            raise ValueError("This method is only valid for SQLite")
        return Path(self.database.path)

    def is_module_enabled(self, module_name: str) -> bool:
        """Checks if an analysis module is enabled."""
        return module_name in self.analysis.enabled_modules 