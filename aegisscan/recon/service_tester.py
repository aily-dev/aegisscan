"""
Service Authentication Tester and Brute Forcer
Tests connections to various services (FTP, SSH, SMTP, MySQL, etc.)
"""
import asyncio
import socket
import ftplib
import smtplib
import poplib
import imaplib
from typing import Dict, List, Optional, Tuple, Any
import logging
from ..utils.wordlists import WordlistManager

# Optional imports for service testing
try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

try:
    import pymysql
    HAS_PYMYSQL = True
except ImportError:
    HAS_PYMYSQL = False

try:
    import psycopg2
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

try:
    import redis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False

try:
    from pymongo import MongoClient
    from pymongo.errors import ServerSelectionTimeoutError, OperationFailure
    HAS_PYMONGO = True
except ImportError:
    HAS_PYMONGO = False


class ServiceTester:
    """Test service authentication and perform brute force"""
    
    def __init__(self, wordlist_manager: Optional[WordlistManager] = None, timeout: float = 5.0):
        self.wordlist_manager = wordlist_manager or WordlistManager()
        self.timeout = timeout
        self._logger = logging.getLogger(__name__)
        
        # Common usernames and passwords
        self.default_credentials = {
            "usernames": ["admin", "root", "user", "test", "guest", "administrator", "postgres", "mysql", "ftp", "anonymous"],
            "passwords": ["admin", "root", "password", "123456", "12345", "1234", "pass", "test", "guest", "", "admin123", "root123"]
        }
    
    async def test_service(self, host: str, port: int, service: str) -> Dict[str, Any]:
        """Test a service for authentication requirements"""
        result = {
            "host": host,
            "port": port,
            "service": service,
            "requires_auth": False,
            "anonymous_allowed": False,
            "tested": False,
            "error": None
        }
        
        try:
            if service.lower() == "ftp":
                result = await self._test_ftp(host, port)
            elif service.lower() == "ssh":
                result = await self._test_ssh(host, port)
            elif service.lower() == "smtp":
                result = await self._test_smtp(host, port)
            elif service.lower() == "pop3":
                result = await self._test_pop3(host, port)
            elif service.lower() == "imap":
                result = await self._test_imap(host, port)
            elif service.lower() == "mysql":
                result = await self._test_mysql(host, port)
            elif service.lower() == "postgresql":
                result = await self._test_postgresql(host, port)
            elif service.lower() == "redis":
                result = await self._test_redis(host, port)
            elif service.lower() == "mongodb":
                result = await self._test_mongodb(host, port)
            else:
                result["error"] = f"Service {service} not supported for testing"
        except Exception as e:
            result["error"] = str(e)
            self._logger.debug(f"Error testing {service} on {host}:{port}: {e}")
        
        return result
    
    async def _test_ftp(self, host: str, port: int) -> Dict[str, Any]:
        """Test FTP service"""
        result = {
            "host": host,
            "port": port,
            "service": "FTP",
            "requires_auth": True,
            "anonymous_allowed": False,
            "tested": True,
            "credentials": []
        }
        
        try:
            # Test anonymous login
            def test_anonymous():
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(host, port, timeout=self.timeout)
                    ftp.login("anonymous", "anonymous@")
                    ftp.quit()
                    return True
                except:
                    return False
            
            anonymous_allowed = await asyncio.get_event_loop().run_in_executor(None, test_anonymous)
            result["anonymous_allowed"] = anonymous_allowed
            
            if anonymous_allowed:
                result["requires_auth"] = False
                result["credentials"].append({"username": "anonymous", "password": "anonymous@", "valid": True})
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    async def _test_ssh(self, host: str, port: int) -> Dict[str, Any]:
        """Test SSH service"""
        result = {
            "host": host,
            "port": port,
            "service": "SSH",
            "requires_auth": True,
            "anonymous_allowed": False,
            "tested": True,
            "credentials": []
        }
        
        if not HAS_PARAMIKO:
            result["error"] = "paramiko not installed"
            return result
        
        try:
            # Test if SSH accepts connections (requires auth)
            def test_ssh_connection():
                try:
                    ssh = paramiko.SSHClient()
                    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    ssh.connect(host, port=port, username="test", password="test", timeout=self.timeout, allow_agent=False, look_for_keys=False)
                    ssh.close()
                    return True
                except paramiko.AuthenticationException:
                    # Auth required but failed - service requires auth
                    return False
                except:
                    return None
            
            test_result = await asyncio.get_event_loop().run_in_executor(None, test_ssh_connection)
            if test_result is False:
                result["requires_auth"] = True
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    async def _test_smtp(self, host: str, port: int) -> Dict[str, Any]:
        """Test SMTP service"""
        result = {
            "host": host,
            "port": port,
            "service": "SMTP",
            "requires_auth": False,
            "anonymous_allowed": False,
            "tested": True,
            "credentials": []
        }
        
        try:
            def test_smtp():
                try:
                    smtp = smtplib.SMTP(host, port, timeout=self.timeout)
                    smtp.helo()
                    smtp.quit()
                    return True
                except:
                    return False
            
            no_auth = await asyncio.get_event_loop().run_in_executor(None, test_smtp)
            if no_auth:
                result["requires_auth"] = False
                result["anonymous_allowed"] = True
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    async def _test_pop3(self, host: str, port: int) -> Dict[str, Any]:
        """Test POP3 service"""
        result = {
            "host": host,
            "port": port,
            "service": "POP3",
            "requires_auth": True,
            "anonymous_allowed": False,
            "tested": True,
            "credentials": []
        }
        
        # POP3 always requires authentication
        return result
    
    async def _test_imap(self, host: str, port: int) -> Dict[str, Any]:
        """Test IMAP service"""
        result = {
            "host": host,
            "port": port,
            "service": "IMAP",
            "requires_auth": True,
            "anonymous_allowed": False,
            "tested": True,
            "credentials": []
        }
        
        # IMAP always requires authentication
        return result
    
    async def _test_mysql(self, host: str, port: int) -> Dict[str, Any]:
        """Test MySQL service"""
        result = {
            "host": host,
            "port": port,
            "service": "MySQL",
            "requires_auth": True,
            "anonymous_allowed": False,
            "tested": True,
            "credentials": []
        }
        
        if not HAS_PYMYSQL:
            result["error"] = "pymysql not installed"
            return result
        
        try:
            # Test root with empty password
            def test_mysql_root():
                try:
                    conn = pymysql.connect(
                        host=host,
                        port=port,
                        user="root",
                        password="",
                        connect_timeout=self.timeout
                    )
                    conn.close()
                    return True
                except:
                    return False
            
            root_no_pass = await asyncio.get_event_loop().run_in_executor(None, test_mysql_root)
            if root_no_pass:
                result["requires_auth"] = False
                result["credentials"].append({"username": "root", "password": "", "valid": True})
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    async def _test_postgresql(self, host: str, port: int) -> Dict[str, Any]:
        """Test PostgreSQL service"""
        result = {
            "host": host,
            "port": port,
            "service": "PostgreSQL",
            "requires_auth": True,
            "anonymous_allowed": False,
            "tested": True,
            "credentials": []
        }
        
        if not HAS_PSYCOPG2:
            result["error"] = "psycopg2 not installed"
            return result
        
        try:
            # Test postgres user with empty password
            def test_postgres():
                try:
                    conn = psycopg2.connect(
                        host=host,
                        port=port,
                        user="postgres",
                        password="",
                        connect_timeout=self.timeout
                    )
                    conn.close()
                    return True
                except:
                    return False
            
            postgres_no_pass = await asyncio.get_event_loop().run_in_executor(None, test_postgres)
            if postgres_no_pass:
                result["requires_auth"] = False
                result["credentials"].append({"username": "postgres", "password": "", "valid": True})
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    async def _test_redis(self, host: str, port: int) -> Dict[str, Any]:
        """Test Redis service"""
        result = {
            "host": host,
            "port": port,
            "service": "Redis",
            "requires_auth": False,
            "anonymous_allowed": True,
            "tested": True,
            "credentials": []
        }
        
        if not HAS_REDIS:
            result["error"] = "redis not installed"
            return result
        
        try:
            def test_redis():
                try:
                    r = redis.Redis(host=host, port=port, socket_timeout=self.timeout, decode_responses=True)
                    r.ping()
                    return True
                except redis.exceptions.AuthenticationError:
                    result["requires_auth"] = True
                    return False
                except:
                    return False
            
            no_auth = await asyncio.get_event_loop().run_in_executor(None, test_redis)
            if no_auth:
                result["anonymous_allowed"] = True
                result["requires_auth"] = False
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    async def _test_mongodb(self, host: str, port: int) -> Dict[str, Any]:
        """Test MongoDB service"""
        result = {
            "host": host,
            "port": port,
            "service": "MongoDB",
            "requires_auth": False,
            "anonymous_allowed": True,
            "tested": True,
            "credentials": []
        }
        
        if not HAS_PYMONGO:
            result["error"] = "pymongo not installed"
            return result
        
        try:
            def test_mongodb():
                try:
                    client = MongoClient(host, port, serverSelectionTimeoutMS=int(self.timeout * 1000))
                    client.server_info()
                    client.close()
                    return True
                except OperationFailure:
                    result["requires_auth"] = True
                    return False
                except:
                    return False
            
            no_auth = await asyncio.get_event_loop().run_in_executor(None, test_mongodb)
            if no_auth:
                result["anonymous_allowed"] = True
                result["requires_auth"] = False
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    async def brute_force_service(
        self,
        host: str,
        port: int,
        service: str,
        usernames: Optional[List[str]] = None,
        passwords: Optional[List[str]] = None,
        max_attempts: int = 100
    ) -> Dict[str, Any]:
        """Brute force a service with provided credentials"""
        result = {
            "host": host,
            "port": port,
            "service": service,
            "found_credentials": [],
            "attempted": 0,
            "successful": 0,
            "failed": 0
        }
        
        if usernames is None:
            usernames = self.default_credentials["usernames"]
        if passwords is None:
            passwords = self.default_credentials["passwords"]
        
        # Limit attempts
        total_attempts = min(len(usernames) * len(passwords), max_attempts)
        attempts = 0
        
        try:
            if service.lower() == "ftp":
                result = await self._brute_force_ftp(host, port, usernames, passwords, max_attempts)
            elif service.lower() == "ssh":
                result = await self._brute_force_ssh(host, port, usernames, passwords, max_attempts)
            elif service.lower() == "mysql":
                result = await self._brute_force_mysql(host, port, usernames, passwords, max_attempts)
            elif service.lower() == "postgresql":
                result = await self._brute_force_postgresql(host, port, usernames, passwords, max_attempts)
            elif service.lower() == "redis":
                result = await self._brute_force_redis(host, port, passwords, max_attempts)
            else:
                result["error"] = f"Brute force not supported for {service}"
        except Exception as e:
            result["error"] = str(e)
            self._logger.debug(f"Error brute forcing {service} on {host}:{port}: {e}")
        
        return result
    
    async def _brute_force_ftp(self, host: str, port: int, usernames: List[str], passwords: List[str], max_attempts: int) -> Dict[str, Any]:
        """Brute force FTP"""
        result = {
            "host": host,
            "port": port,
            "service": "FTP",
            "found_credentials": [],
            "attempted": 0,
            "successful": 0,
            "failed": 0
        }
        
        attempts = 0
        for username in usernames:
            if attempts >= max_attempts:
                break
            for password in passwords:
                if attempts >= max_attempts:
                    break
                
                attempts += 1
                result["attempted"] = attempts
                
                try:
                    def test_ftp_creds():
                        try:
                            ftp = ftplib.FTP()
                            ftp.connect(host, port, timeout=self.timeout)
                            ftp.login(username, password)
                            ftp.quit()
                            return True
                        except:
                            return False
                    
                    success = await asyncio.get_event_loop().run_in_executor(None, test_ftp_creds)
                    if success:
                        result["found_credentials"].append({"username": username, "password": password})
                        result["successful"] += 1
                        self._logger.info(f"FTP credentials found: {username}:{password} on {host}:{port}")
                        # Stop after first success for this username
                        break
                    else:
                        result["failed"] += 1
                except Exception as e:
                    result["failed"] += 1
                    self._logger.debug(f"FTP brute force attempt failed: {e}")
        
        return result
    
    async def _brute_force_ssh(self, host: str, port: int, usernames: List[str], passwords: List[str], max_attempts: int) -> Dict[str, Any]:
        """Brute force SSH"""
        result = {
            "host": host,
            "port": port,
            "service": "SSH",
            "found_credentials": [],
            "attempted": 0,
            "successful": 0,
            "failed": 0
        }
        
        attempts = 0
        for username in usernames:
            if attempts >= max_attempts:
                break
            for password in passwords:
                if attempts >= max_attempts:
                    break
                
                attempts += 1
                result["attempted"] = attempts
                
                if not HAS_PARAMIKO:
                    result["error"] = "paramiko not installed"
                    return result
                
                try:
                    def test_ssh_creds():
                        try:
                            ssh = paramiko.SSHClient()
                            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                            ssh.connect(host, port=port, username=username, password=password, timeout=self.timeout, allow_agent=False, look_for_keys=False)
                            ssh.close()
                            return True
                        except paramiko.AuthenticationException:
                            return False
                        except:
                            return False
                    
                    success = await asyncio.get_event_loop().run_in_executor(None, test_ssh_creds)
                    if success:
                        result["found_credentials"].append({"username": username, "password": password})
                        result["successful"] += 1
                        self._logger.info(f"SSH credentials found: {username}:{password} on {host}:{port}")
                        break
                    else:
                        result["failed"] += 1
                except Exception as e:
                    result["failed"] += 1
                    self._logger.debug(f"SSH brute force attempt failed: {e}")
        
        return result
    
    async def _brute_force_mysql(self, host: str, port: int, usernames: List[str], passwords: List[str], max_attempts: int) -> Dict[str, Any]:
        """Brute force MySQL"""
        result = {
            "host": host,
            "port": port,
            "service": "MySQL",
            "found_credentials": [],
            "attempted": 0,
            "successful": 0,
            "failed": 0
        }
        
        attempts = 0
        for username in usernames:
            if attempts >= max_attempts:
                break
            for password in passwords:
                if attempts >= max_attempts:
                    break
                
                attempts += 1
                result["attempted"] = attempts
                
                if not HAS_PYMYSQL:
                    result["error"] = "pymysql not installed"
                    return result
                
                try:
                    def test_mysql_creds():
                        try:
                            conn = pymysql.connect(host=host, port=port, user=username, password=password, connect_timeout=self.timeout)
                            conn.close()
                            return True
                        except:
                            return False
                    
                    success = await asyncio.get_event_loop().run_in_executor(None, test_mysql_creds)
                    if success:
                        result["found_credentials"].append({"username": username, "password": password})
                        result["successful"] += 1
                        self._logger.info(f"MySQL credentials found: {username}:{password} on {host}:{port}")
                        break
                    else:
                        result["failed"] += 1
                except Exception as e:
                    result["failed"] += 1
                    self._logger.debug(f"MySQL brute force attempt failed: {e}")
        
        return result
    
    async def _brute_force_postgresql(self, host: str, port: int, usernames: List[str], passwords: List[str], max_attempts: int) -> Dict[str, Any]:
        """Brute force PostgreSQL"""
        result = {
            "host": host,
            "port": port,
            "service": "PostgreSQL",
            "found_credentials": [],
            "attempted": 0,
            "successful": 0,
            "failed": 0
        }
        
        attempts = 0
        for username in usernames:
            if attempts >= max_attempts:
                break
            for password in passwords:
                if attempts >= max_attempts:
                    break
                
                attempts += 1
                result["attempted"] = attempts
                
                if not HAS_PSYCOPG2:
                    result["error"] = "psycopg2 not installed"
                    return result
                
                try:
                    def test_postgres_creds():
                        try:
                            conn = psycopg2.connect(host=host, port=port, user=username, password=password, connect_timeout=self.timeout)
                            conn.close()
                            return True
                        except:
                            return False
                    
                    success = await asyncio.get_event_loop().run_in_executor(None, test_postgres_creds)
                    if success:
                        result["found_credentials"].append({"username": username, "password": password})
                        result["successful"] += 1
                        self._logger.info(f"PostgreSQL credentials found: {username}:{password} on {host}:{port}")
                        break
                    else:
                        result["failed"] += 1
                except Exception as e:
                    result["failed"] += 1
                    self._logger.debug(f"PostgreSQL brute force attempt failed: {e}")
        
        return result
    
    async def _brute_force_redis(self, host: str, port: int, passwords: List[str], max_attempts: int) -> Dict[str, Any]:
        """Brute force Redis (password only)"""
        result = {
            "host": host,
            "port": port,
            "service": "Redis",
            "found_credentials": [],
            "attempted": 0,
            "successful": 0,
            "failed": 0
        }
        
        attempts = 0
        for password in passwords:
            if attempts >= max_attempts:
                break
            
            attempts += 1
            result["attempted"] = attempts
            
            if not HAS_REDIS:
                result["error"] = "redis not installed"
                return result
            
            try:
                def test_redis_pass():
                    try:
                        r = redis.Redis(host=host, port=port, password=password if password else None, socket_timeout=self.timeout, decode_responses=True)
                        r.ping()
                        return True
                    except redis.exceptions.AuthenticationError:
                        return False
                    except:
                        return False
                
                success = await asyncio.get_event_loop().run_in_executor(None, test_redis_pass)
                if success:
                    result["found_credentials"].append({"password": password})
                    result["successful"] += 1
                    self._logger.info(f"Redis password found: {password} on {host}:{port}")
                    break
                else:
                    result["failed"] += 1
            except Exception as e:
                result["failed"] += 1
                self._logger.debug(f"Redis brute force attempt failed: {e}")
        
        return result

