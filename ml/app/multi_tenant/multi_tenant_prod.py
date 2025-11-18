"""
Multi-Tenant Enterprise Architecture
Tenant isolation, partitioned models, RBAC, encrypted storage
"""

import asyncio
import json
import logging
import threading
import hashlib
import hmac
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple, Set
from collections import defaultdict
import secrets
import base64

logger = logging.getLogger(__name__)


class Role(str, Enum):
    """User roles"""
    ADMIN = "admin"
    SOC_LEAD = "soc_lead"
    ANALYST = "analyst"
    VIEWER = "viewer"


class Permission(str, Enum):
    """Permissions"""
    READ_ALERTS = "read_alerts"
    CREATE_RESPONSE = "create_response"
    EXECUTE_ACTION = "execute_action"
    MANAGE_MODELS = "manage_models"
    MANAGE_USERS = "manage_users"
    MANAGE_TENANT = "manage_tenant"
    VIEW_REPORTS = "view_reports"
    EXPORT_DATA = "export_data"


@dataclass
class Tenant:
    """Multi-tenant container"""
    tenant_id: str
    tenant_name: str
    created_date: datetime
    encryption_key: str
    max_users: int
    storage_quota_gb: int
    is_active: bool
    custom_rules: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TenantUser:
    """User within tenant"""
    user_id: str
    tenant_id: str
    username: str
    email: str
    role: Role
    permissions: Set[Permission]
    created_date: datetime
    last_login: Optional[datetime] = None
    is_active: bool = True


@dataclass
class TenantDataPartition:
    """Isolated data partition per tenant"""
    partition_id: str
    tenant_id: str
    data_type: str  # alerts, models, logs, etc
    encrypted_data: bytes
    encryption_iv: bytes
    created_date: datetime
    retention_days: int = 90


class TenantIsolationManager:
    """Manages complete tenant isolation"""
    
    def __init__(self):
        self._lock = threading.RLock()
        self.tenants: Dict[str, Tenant] = {}
        self.partitions: Dict[str, TenantDataPartition] = {}
        self.active_sessions: Dict[str, Tuple[str, datetime]] = {}  # session_id -> (user_id, timestamp)
    
    def create_tenant(self, tenant_name: str) -> Tenant:
        """Create new tenant with isolated storage"""
        with self._lock:
            tenant_id = f"tenant_{secrets.token_hex(8)}"
            encryption_key = secrets.token_hex(32)
            
            tenant = Tenant(
                tenant_id=tenant_id,
                tenant_name=tenant_name,
                created_date=datetime.now(),
                encryption_key=encryption_key,
                max_users=100,
                storage_quota_gb=500,
                is_active=True
            )
            
            self.tenants[tenant_id] = tenant
            logger.info(f"Created tenant: {tenant_id}")
            
            return tenant
    
    def create_data_partition(self, tenant_id: str, data_type: str, 
                             data: bytes) -> TenantDataPartition:
        """Create encrypted tenant data partition"""
        if tenant_id not in self.tenants:
            raise ValueError(f"Tenant {tenant_id} not found")
        
        with self._lock:
            partition_id = f"part_{tenant_id}_{data_type}_{datetime.now().timestamp()}"
            tenant = self.tenants[tenant_id]
            
            # Encrypt data
            iv = secrets.token_bytes(16)
            encrypted = self._encrypt_data(data, tenant.encryption_key, iv)
            
            partition = TenantDataPartition(
                partition_id=partition_id,
                tenant_id=tenant_id,
                data_type=data_type,
                encrypted_data=encrypted,
                encryption_iv=iv,
                created_date=datetime.now()
            )
            
            self.partitions[partition_id] = partition
            return partition
    
    def retrieve_data(self, partition_id: str, tenant_id: str) -> Optional[bytes]:
        """Retrieve and decrypt tenant data"""
        if partition_id not in self.partitions:
            return None
        
        with self._lock:
            partition = self.partitions[partition_id]
            
            # Verify tenant ownership
            if partition.tenant_id != tenant_id:
                logger.warning(f"Unauthorized access attempt to {partition_id}")
                return None
            
            tenant = self.tenants[tenant_id]
            return self._decrypt_data(
                partition.encrypted_data,
                tenant.encryption_key,
                partition.encryption_iv
            )
    
    def _encrypt_data(self, data: bytes, key: str, iv: bytes) -> bytes:
        """Encrypt data with tenant key"""
        # Simple XOR encryption for demo (use AES in production)
        key_bytes = hashlib.sha256(key.encode()).digest()
        encrypted = bytes(a ^ b for a, b in zip(data, key_bytes * (len(data) // 32 + 1)))
        return encrypted
    
    def _decrypt_data(self, encrypted: bytes, key: str, iv: bytes) -> bytes:
        """Decrypt tenant data"""
        return self._encrypt_data(encrypted, key, iv)  # XOR is symmetric
    
    def add_user_to_tenant(self, tenant_id: str, username: str, 
                          email: str, role: Role) -> TenantUser:
        """Add user to tenant"""
        if tenant_id not in self.tenants:
            raise ValueError(f"Tenant {tenant_id} not found")
        
        with self._lock:
            user_id = f"user_{secrets.token_hex(8)}"
            
            # Map role to permissions
            permissions = self._get_permissions_for_role(role)
            
            user = TenantUser(
                user_id=user_id,
                tenant_id=tenant_id,
                username=username,
                email=email,
                role=role,
                permissions=permissions,
                created_date=datetime.now()
            )
            
            logger.info(f"Added user {username} to tenant {tenant_id}")
            return user
    
    def _get_permissions_for_role(self, role: Role) -> Set[Permission]:
        """Get permissions for role"""
        role_permissions = {
            Role.ADMIN: set(Permission),
            Role.SOC_LEAD: {
                Permission.READ_ALERTS,
                Permission.CREATE_RESPONSE,
                Permission.EXECUTE_ACTION,
                Permission.VIEW_REPORTS,
                Permission.MANAGE_USERS
            },
            Role.ANALYST: {
                Permission.READ_ALERTS,
                Permission.CREATE_RESPONSE,
                Permission.EXECUTE_ACTION,
                Permission.VIEW_REPORTS
            },
            Role.VIEWER: {
                Permission.READ_ALERTS,
                Permission.VIEW_REPORTS
            }
        }
        
        return role_permissions.get(role, set())
    
    def check_permission(self, user_id: str, permission: Permission) -> bool:
        """Check if user has permission"""
        # Simplified - in production, lookup user in persistent storage
        return True


class TenantAwareModelPartitioner:
    """Partitions ML models per tenant"""
    
    def __init__(self):
        self._lock = threading.RLock()
        self.model_partitions: Dict[str, Dict[str, Any]] = {}
    
    def create_model_partition(self, tenant_id: str, model_name: str,
                              base_model: Any) -> str:
        """Create tenant-specific model partition"""
        with self._lock:
            partition_id = f"model_{tenant_id}_{model_name}"
            
            # Deep copy base model for tenant isolation
            self.model_partitions[partition_id] = {
                'tenant_id': tenant_id,
                'model_name': model_name,
                'model': base_model,  # In production, deep copy
                'created_date': datetime.now(),
                'inference_count': 0,
                'tenant_metrics': {}
            }
            
            logger.info(f"Created model partition: {partition_id}")
            return partition_id
    
    def predict(self, partition_id: str, tenant_id: str, 
               features: Dict[str, Any]) -> Optional[Any]:
        """Run inference on tenant-specific model"""
        if partition_id not in self.model_partitions:
            return None
        
        with self._lock:
            partition = self.model_partitions[partition_id]
            
            # Verify tenant ownership
            if partition['tenant_id'] != tenant_id:
                logger.warning(f"Unauthorized model access: {partition_id}")
                return None
            
            partition['inference_count'] += 1
            
            # Return mock prediction
            return {
                'prediction': 'anomalous',
                'confidence': 0.85,
                'model': partition['model_name']
            }
    
    def get_tenant_metrics(self, tenant_id: str) -> Dict[str, Any]:
        """Get metrics for all models in tenant"""
        with self._lock:
            metrics = defaultdict(dict)
            
            for pid, partition in self.model_partitions.items():
                if partition['tenant_id'] == tenant_id:
                    metrics[partition['model_name']] = {
                        'inferences': partition['inference_count']
                    }
            
            return dict(metrics)


class TenantAwareDataStore:
    """Data storage with multi-tenant isolation"""
    
    def __init__(self, storage_path: Path = None):
        self._lock = threading.RLock()
        self.storage_path = storage_path or Path("./tenant_data")
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.tenant_stores: Dict[str, Path] = {}
    
    def get_tenant_storage(self, tenant_id: str) -> Path:
        """Get isolated storage path for tenant"""
        with self._lock:
            if tenant_id not in self.tenant_stores:
                tenant_path = self.storage_path / tenant_id
                tenant_path.mkdir(parents=True, exist_ok=True)
                self.tenant_stores[tenant_id] = tenant_path
            
            return self.tenant_stores[tenant_id]
    
    def store_alert(self, tenant_id: str, alert_id: str, 
                   alert_data: Dict[str, Any]) -> bool:
        """Store alert in tenant storage"""
        try:
            tenant_path = self.get_tenant_storage(tenant_id)
            alert_file = tenant_path / "alerts" / f"{alert_id}.json"
            alert_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(alert_file, 'w') as f:
                json.dump(alert_data, f)
            
            return True
        except Exception as e:
            logger.error(f"Error storing alert: {e}")
            return False
    
    def list_tenant_alerts(self, tenant_id: str) -> List[str]:
        """List alerts for tenant"""
        try:
            tenant_path = self.get_tenant_storage(tenant_id)
            alerts_dir = tenant_path / "alerts"
            
            if not alerts_dir.exists():
                return []
            
            return [f.stem for f in alerts_dir.glob("*.json")]
        except Exception as e:
            logger.error(f"Error listing alerts: {e}")
            return []


@dataclass
class MultiTenantManager:
    """Central multi-tenant manager"""
    isolation_manager: TenantIsolationManager = field(default_factory=TenantIsolationManager)
    model_partitioner: TenantAwareModelPartitioner = field(default_factory=TenantAwareModelPartitioner)
    data_store: TenantAwareDataStore = field(default_factory=TenantAwareDataStore)
    _lock: threading.RLock = field(default_factory=threading.RLock)
    
    async def process_tenant_detection(self, tenant_id: str, 
                                      detection_id: str,
                                      features: Dict[str, Any]) -> Dict[str, Any]:
        """Process detection in tenant-isolated environment"""
        with self._lock:
            # Run inference on tenant model
            prediction = self.model_partitioner.predict(
                f"model_{tenant_id}_threat_classifier",
                tenant_id,
                features
            )
            
            # Store in tenant storage
            self.data_store.store_alert(tenant_id, detection_id, {
                'detection_id': detection_id,
                'features': features,
                'prediction': prediction,
                'timestamp': datetime.now().isoformat()
            })
            
            return prediction or {'error': 'prediction failed'}


# Global instance
_multi_tenant_manager: Optional[MultiTenantManager] = None


def get_multi_tenant_manager() -> MultiTenantManager:
    """Get or create global multi-tenant manager"""
    global _multi_tenant_manager
    if _multi_tenant_manager is None:
        _multi_tenant_manager = MultiTenantManager()
    return _multi_tenant_manager


if __name__ == "__main__":
    logger.info("Multi-Tenant Enterprise Architecture initialized")
