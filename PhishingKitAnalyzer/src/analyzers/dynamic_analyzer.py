import logging
import docker
import tempfile
import shutil
from pathlib import Path
from typing import Dict, Any, Optional
import time

from utils.config import Config
from utils.exceptions import PhishingKitAnalyzerError

class DynamicAnalyzer:
    """Dynamic analyzer for sandbox execution of phishing kits."""

    def __init__(self, config: Config):
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.docker_client = None
        self.container = None
        
        if not self.config.analysis.dynamic.sandbox_type == 'docker':
            self.logger.info("Sandbox type not configured for Docker")
            return
            
        try:
            self.docker_client = docker.from_env()
            self.docker_client.ping()
            self.logger.info("Docker initialized successfully")
        except docker.errors.DockerException as e:
            self.logger.warning(
                "Docker is not available. Ensure that : \n"
                "1. Docker is installed (sudo apt-get install docker.io)\n"
                "2. The service is started (sudo service docker start)\n"
                "3. Your user is in the docker group (sudo usermod -aG docker $USER)\n"
                f"Error : {str(e)}"
            )
        except Exception as e:
            self.logger.error(f"Unexpected error during Docker initialization: {e}")

    def analyze(self, path: Path) -> Optional[Dict[str, Any]]:
        """Performs dynamic analysis of a phishing kit."""
        if not self.docker_client:
            self.logger.warning(
                "Dynamic analysis disabled - Docker not available\n"
                "Analysis will continue without the dynamic part"
            )
            return None

        try:
            # Preparing the Docker environment
            self._prepare_docker_environment(path)
            
            # Running analysis with timeout
            start_time = time.time()
            results = {}
            
            while time.time() - start_time < self.config.analysis.dynamic.timeout:
                try:
                    results = self._run_analysis()
                    break
                except Exception as e:
                    self.logger.error(f"Error during analysis: {e}")
                    break
                    
            return results
            
        except Exception as e:
            self.logger.error(f"Error during dynamic analysis: {e}")
            return None
        finally:
            self._cleanup()

    def _prepare_docker_environment(self, path: Path) -> None:
        """Prepares the Docker environment for analysis."""
        try:
            # Checking the PHP image
            try:
                self.docker_client.images.get("php:7.4-apache")
            except docker.errors.ImageNotFound:
                self.logger.info("Downloading PHP image...")
                self.docker_client.images.pull("php:7.4-apache")

            # Creating the container
            self.container = self.docker_client.containers.run(
                "php:7.4-apache",
                detach=True,
                remove=True,
                ports={'80/tcp': None},
                volumes={
                    str(path.resolve()): {
                        'bind': '/var/www/html',
                        'mode': 'ro'
                    }
                }
            )

        except Exception as e:
            self.logger.error(f"Error during preparation of Docker environment: {e}")
            raise

    def _run_analysis(self) -> Dict[str, Any]:
        """Runs the analysis in the container."""
        results = {
            'requests': [],
            'responses': [],
            'errors': []
        }

        try:
            # Checking PHP files
            exit_code, output = self.container.exec_run(
                "find /var/www/html -name '*.php' -exec php -l {} \;"
            )
            results['syntax_check'] = {
                'exit_code': exit_code,
                'output': output.decode('utf-8', errors='ignore')
            }

            # Checking permissions
            exit_code, output = self.container.exec_run(
                "ls -la /var/www/html"
            )
            results['permissions'] = {
                'exit_code': exit_code,
                'output': output.decode('utf-8', errors='ignore')
            }

            # Searching for sensitive files
            exit_code, output = self.container.exec_run(
                "find /var/www/html -type f -exec grep -l -i 'password\\|user\\|login\\|email' {} \\;"
            )
            results['sensitive_files'] = {
                'exit_code': exit_code,
                'files': output.decode('utf-8', errors='ignore').splitlines()
            }

            return results

        except Exception as e:
            self.logger.error(f"Error during execution of analysis: {e}")
            return results

    def _cleanup(self) -> None:
        """Cleans up Docker resources."""
        try:
            if self.container:
                try:
                    self.container.stop(timeout=5)
                except:
                    pass
                try:
                    self.container.remove(force=True)
                except:
                    pass
        except Exception as e:
            self.logger.error(f"Error during cleanup: {e}") 