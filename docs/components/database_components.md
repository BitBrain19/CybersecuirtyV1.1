# Database Components

## Overview

The SecurityAI Platform utilizes multiple database systems to efficiently store and manage different types of data. Each database is selected for its specific strengths in handling particular data characteristics and access patterns.

## Database Systems

### PostgreSQL

**Purpose**: Primary relational database for structured data with complex relationships.

**Data Stored**:
- User accounts and authentication
- Asset inventory and metadata
- Alert and incident records
- System configuration
- Vulnerability information
- Report definitions and metadata

**Characteristics**:
- ACID compliance for data integrity
- Complex query capabilities with JOIN operations
- Transaction support
- Robust indexing for fast lookups
- Schema enforcement for data consistency

**Implementation**:
- SQLAlchemy ORM for database interactions
- Alembic for schema migrations
- Connection pooling for performance
- Regular backups and point-in-time recovery

### InfluxDB

**Purpose**: Time-series database for metrics, events, and temporal data.

**Data Stored**:
- System performance metrics
- Security event timelines
- Network traffic statistics
- Resource utilization trends
- Behavioral baselines for UEBA

**Characteristics**:
- Optimized for time-series data
- High write throughput
- Efficient time-based queries
- Downsampling and retention policies
- Built-in aggregation functions

**Implementation**:
- Custom client for data insertion and querying
- Continuous queries for real-time analytics
- Retention policies for data lifecycle management
- Measurement partitioning for performance

### Elasticsearch

**Purpose**: Document store and search engine for logs and unstructured data.

**Data Stored**:
- System and application logs
- Security event details
- Threat intelligence data
- Full-text searchable content
- Document-based security artifacts

**Characteristics**:
- Full-text search capabilities
- Flexible schema for varied data types
- Distributed architecture for scalability
- Powerful aggregation framework
- Real-time indexing and search

**Implementation**:
- Elasticsearch client for data operations
- Index templates for consistent mapping
- Index lifecycle management
- Query DSL for complex searches
- Analyzer configurations for text processing

### Redis

**Purpose**: In-memory data store for caching, session management, and message brokering.

**Data Stored**:
- User sessions
- Authentication tokens
- Cached query results
- Real-time counters and statistics
- Task queue for Celery

**Characteristics**:
- High-speed in-memory operations
- Data structure server (strings, hashes, lists, sets)
- Pub/sub messaging capabilities
- Key expiration for automatic cleanup
- Persistence options for durability

**Implementation**:
- Redis client for direct operations
- Connection pooling for efficiency
- Serialization for complex objects
- Cache invalidation strategies
- Celery integration for task queues

## Data Models

### User and Authentication Models

**PostgreSQL Tables**:
- `users`: Core user information
- `roles`: Role definitions for RBAC
- `permissions`: Granular access controls
- `user_roles`: Many-to-many relationship mapping
- `user_settings`: User preferences and configurations

**Redis Structures**:
- `sessions:{session_id}`: Active user sessions
- `tokens:{user_id}`: Authentication tokens
- `rate_limits:{ip}`: API rate limiting counters

### Asset Management Models

**PostgreSQL Tables**:
- `assets`: Tracked systems and devices
- `asset_types`: Classification of asset categories
- `asset_groups`: Logical groupings of assets
- `asset_tags`: Tagging for flexible categorization
- `asset_relationships`: Connections between assets

**InfluxDB Measurements**:
- `asset_metrics`: Performance and health metrics
- `asset_events`: State changes and activities

### Security Event Models

**Elasticsearch Indices**:
- `logs-{source}-{date}`: Raw log data from various sources
- `events-{date}`: Normalized security events
- `threats-{date}`: Identified threat indicators

**InfluxDB Measurements**:
- `event_counts`: Aggregated event statistics
- `event_timelines`: Temporal event sequences

### Alert and Incident Models

**PostgreSQL Tables**:
- `alerts`: Security alerts and notifications
- `alert_types`: Classification of alert categories
- `alert_status`: Workflow state tracking
- `incidents`: Security incidents (collections of related alerts)
- `incident_timeline`: Chronological incident progression

**Elasticsearch Indices**:
- `alert_details-{date}`: Extended alert information
- `incident_artifacts-{date}`: Evidence and context

### UEBA Models

**PostgreSQL Tables**:
- `entity_profiles`: Core entity information
- `risk_scores`: Current and historical risk assessments

**InfluxDB Measurements**:
- `behavior_metrics`: Behavioral indicators over time
- `anomaly_scores`: Deviation measurements

**Elasticsearch Indices**:
- `anomalies-{date}`: Detailed anomaly records
- `behavior_patterns-{date}`: Identified behavioral patterns

### EDR Models

**PostgreSQL Tables**:
- `endpoint_agents`: Agent registration and status
- `endpoint_groups`: Logical endpoint groupings
- `policies`: Security policies for endpoints
- `policy_rules`: Individual policy components

**InfluxDB Measurements**:
- `endpoint_telemetry`: Performance and health metrics
- `endpoint_events`: Security-relevant activities

**Elasticsearch Indices**:
- `endpoint_processes-{date}`: Process execution details
- `endpoint_files-{date}`: File activity information
- `endpoint_network-{date}`: Network connection data

## Data Flow

### Data Collection

1. **Log Collection**:
   - Raw logs ingested from various sources
   - Parsed and normalized
   - Stored in Elasticsearch for full-text search
   - Relevant metrics extracted to InfluxDB
   - Significant events generate PostgreSQL records

2. **Telemetry Collection**:
   - Metrics collected from monitored systems
   - Stored in InfluxDB with appropriate retention
   - Aggregated for dashboard visualization
   - Anomalies trigger alert creation in PostgreSQL

3. **User Activity**:
   - Authentication events recorded in PostgreSQL
   - Session information stored in Redis
   - Activity details indexed in Elasticsearch
   - Behavioral metrics tracked in InfluxDB for UEBA

### Data Processing

1. **Real-time Analysis**:
   - Events analyzed as they arrive
   - Redis used for stateful processing
   - Immediate alerts stored in PostgreSQL
   - WebSocket notifications from Redis pub/sub

2. **Batch Processing**:
   - Scheduled analysis of historical data
   - Complex queries across multiple databases
   - Results stored for reporting and visualization

3. **Machine Learning**:
   - Training data extracted from all databases
   - Models applied to incoming data streams
   - Results stored appropriately by data type

## Data Retention and Lifecycle

### Short-term Storage

- Redis: Ephemeral data with TTL (minutes to hours)
- Memory-optimized PostgreSQL tables: Recent events (days)
- Hot InfluxDB shards: Recent metrics (days to weeks)

### Medium-term Storage

- Standard PostgreSQL tables: Active data (months)
- Warm InfluxDB shards: Historical metrics (weeks to months)
- Recent Elasticsearch indices: Searchable logs (weeks to months)

### Long-term Storage

- Archived PostgreSQL tables: Historical records (years)
- Cold InfluxDB shards: Aggregated historical metrics (months to years)
- Archived Elasticsearch indices: Historical logs (months to years)

## Backup and Recovery

### PostgreSQL

- Daily full backups
- Continuous WAL archiving
- Point-in-time recovery capability
- Standby replicas for high availability

### InfluxDB

- Regular snapshots
- Retention policy-based archiving
- Replication for data durability

### Elasticsearch

- Index snapshots to object storage
- Cross-cluster replication
- Index lifecycle management

### Redis

- RDB snapshots
- AOF persistence
- Replica instances

## Performance Considerations

### Query Optimization

- Appropriate indexing strategies for each database
- Query caching for frequent operations
- Materialized views for complex aggregations
- Partitioning for large tables and indices

### Scaling Strategies

- Vertical scaling for PostgreSQL (larger instances)
- Horizontal scaling for Elasticsearch (more nodes)
- Sharding for InfluxDB (time-based partitioning)
- Clustering for Redis (master-replica setup)

### Connection Management

- Connection pooling for all databases
- Timeout and retry policies
- Circuit breakers for fault tolerance
- Load balancing across replicas