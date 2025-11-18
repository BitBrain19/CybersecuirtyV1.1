# Troubleshooting Guide

## Overview

This guide provides solutions for common issues you might encounter while using the SecurityAI Platform. It covers problems related to installation, configuration, connectivity, performance, data collection, alerts, and integrations.

## Installation Issues

### Failed Installation

**Symptoms:**
- Installation process terminates with errors
- Components fail to deploy
- Services don't start after installation

**Possible Causes and Solutions:**

1. **Insufficient Resources**
   - **Issue:** The host system doesn't meet minimum requirements
   - **Solution:** Ensure your system meets the minimum requirements specified in the deployment guide
   - **Verification:** Check resource utilization with `kubectl top nodes` (Kubernetes) or system monitoring tools

2. **Network Connectivity Issues**
   - **Issue:** Container images can't be pulled or services can't communicate
   - **Solution:** Verify network connectivity to required endpoints
   - **Verification:** Test connectivity with `curl` or `wget` to required endpoints

3. **Permission Issues**
   - **Issue:** Installer lacks necessary permissions
   - **Solution:** Run the installer with appropriate privileges (e.g., sudo/admin)
   - **Verification:** Check installation logs for permission denied errors

4. **Conflicting Software**
   - **Issue:** Existing software conflicts with platform components
   - **Solution:** Identify and resolve port conflicts or service conflicts
   - **Verification:** Check for services using the same ports with `netstat -tulpn` (Linux) or `netstat -ano` (Windows)

### Upgrade Failures

**Symptoms:**
- Upgrade process fails to complete
- Services become unavailable after upgrade
- Mixed version components

**Possible Causes and Solutions:**

1. **Database Schema Incompatibility**
   - **Issue:** Database schema doesn't match the new version
   - **Solution:** Run database migration scripts manually
   - **Verification:** Check database migration logs

2. **Configuration Changes**
   - **Issue:** New version requires configuration changes
   - **Solution:** Update configuration files according to upgrade documentation
   - **Verification:** Compare your configuration with the new version's template

3. **Insufficient Disk Space**
   - **Issue:** Not enough space for upgrade files or database migrations
   - **Solution:** Free up disk space or expand storage
   - **Verification:** Check available disk space with `df -h` (Linux) or disk management tools

## Configuration Issues

### Service Startup Failures

**Symptoms:**
- Services fail to start
- Error messages in service logs
- Status checks fail

**Possible Causes and Solutions:**

1. **Invalid Configuration**
   - **Issue:** Configuration files contain errors or invalid settings
   - **Solution:** Validate configuration files against documentation
   - **Verification:** Check service logs for specific configuration errors

2. **Missing Dependencies**
   - **Issue:** Required dependencies are not installed or accessible
   - **Solution:** Install missing dependencies
   - **Verification:** Check service logs for dependency-related errors

3. **Port Conflicts**
   - **Issue:** Required ports are already in use
   - **Solution:** Change port configuration or stop conflicting services
   - **Verification:** Use `netstat -tulpn` (Linux) or `netstat -ano` (Windows) to identify port usage

### Authentication Problems

**Symptoms:**
- Unable to log in
- Authentication errors
- Session termination

**Possible Causes and Solutions:**

1. **LDAP/Active Directory Configuration**
   - **Issue:** Incorrect LDAP/AD settings
   - **Solution:** Verify LDAP/AD configuration parameters
   - **Verification:** Test LDAP connection with `ldapsearch` or similar tools

2. **Certificate Issues**
   - **Issue:** Expired or invalid certificates
   - **Solution:** Renew or replace certificates
   - **Verification:** Check certificate validity with `openssl x509 -noout -dates -in certificate.pem`

3. **Database Connection Issues**
   - **Issue:** Authentication service can't connect to the database
   - **Solution:** Verify database connection parameters
   - **Verification:** Test database connection with appropriate client tools

## Connectivity Issues

### API Connection Problems

**Symptoms:**
- API requests fail
- Timeout errors
- Connection refused errors

**Possible Causes and Solutions:**

1. **Network Firewall Blocking**
   - **Issue:** Firewall rules blocking API connections
   - **Solution:** Update firewall rules to allow necessary traffic
   - **Verification:** Test connectivity with `curl` or similar tools

2. **API Service Down**
   - **Issue:** API service is not running
   - **Solution:** Start or restart the API service
   - **Verification:** Check service status with appropriate commands

3. **Load Balancer Issues**
   - **Issue:** Load balancer not properly routing requests
   - **Solution:** Verify load balancer configuration
   - **Verification:** Check load balancer logs and status

### Agent Communication Problems

**Symptoms:**
- Agents show as disconnected
- Data not being received from agents
- Agent heartbeat failures

**Possible Causes and Solutions:**

1. **Network Connectivity**
   - **Issue:** Network issues between agents and platform
   - **Solution:** Verify network connectivity and firewall rules
   - **Verification:** Test connectivity with `ping`, `traceroute`, or `telnet`

2. **Agent Configuration**
   - **Issue:** Incorrect agent configuration
   - **Solution:** Verify agent configuration settings
   - **Verification:** Check agent logs for configuration errors

3. **Certificate Issues**
   - **Issue:** Agent certificates expired or invalid
   - **Solution:** Renew or replace agent certificates
   - **Verification:** Check certificate validity and expiration dates

4. **Agent Service Issues**
   - **Issue:** Agent service not running or crashing
   - **Solution:** Restart agent service or investigate crashes
   - **Verification:** Check agent service status and logs

## Performance Issues

### Slow UI Response

**Symptoms:**
- Dashboard loads slowly
- UI operations take excessive time
- Timeouts when loading data

**Possible Causes and Solutions:**

1. **Insufficient Resources**
   - **Issue:** Frontend services lack resources
   - **Solution:** Increase resources allocated to frontend services
   - **Verification:** Monitor resource usage during UI operations

2. **Database Performance**
   - **Issue:** Database queries taking too long
   - **Solution:** Optimize database queries or indexes
   - **Verification:** Check database query performance metrics

3. **Caching Issues**
   - **Issue:** Cache not working effectively
   - **Solution:** Verify cache configuration and operation
   - **Verification:** Monitor cache hit/miss rates

4. **Network Latency**
   - **Issue:** High network latency between components
   - **Solution:** Investigate and resolve network latency issues
   - **Verification:** Measure network latency between components

### High CPU/Memory Usage

**Symptoms:**
- System resources consistently high
- Performance degradation
- Out of memory errors

**Possible Causes and Solutions:**

1. **Resource Leaks**
   - **Issue:** Memory or resource leaks in services
   - **Solution:** Identify and fix leaking services
   - **Verification:** Monitor resource usage over time

2. **Inefficient Queries**
   - **Issue:** Inefficient database queries consuming resources
   - **Solution:** Optimize database queries
   - **Verification:** Analyze database query plans

3. **Excessive Concurrent Operations**
   - **Issue:** Too many concurrent operations
   - **Solution:** Implement rate limiting or increase resources
   - **Verification:** Monitor concurrent operation counts

4. **Inadequate Resource Allocation**
   - **Issue:** Services not allocated enough resources
   - **Solution:** Increase resource allocation
   - **Verification:** Compare resource usage with allocation

## Data Collection Issues

### Missing or Incomplete Data

**Symptoms:**
- Expected data not appearing in the platform
- Gaps in data collection
- Incomplete information in dashboards

**Possible Causes and Solutions:**

1. **Data Source Configuration**
   - **Issue:** Incorrect data source configuration
   - **Solution:** Verify data source configuration
   - **Verification:** Check data source connection logs

2. **Parser Errors**
   - **Issue:** Data parsers failing to process incoming data
   - **Solution:** Debug and fix parser issues
   - **Verification:** Check parser logs for errors

3. **Rate Limiting**
   - **Issue:** Data being dropped due to rate limiting
   - **Solution:** Adjust rate limits or optimize data flow
   - **Verification:** Check for rate limiting messages in logs

4. **Network Issues**
   - **Issue:** Network problems affecting data transmission
   - **Solution:** Resolve network connectivity issues
   - **Verification:** Monitor network performance metrics

### Data Processing Delays

**Symptoms:**
- Data appears in the system with significant delay
- Real-time dashboards not updating promptly
- Processing queue backlog

**Possible Causes and Solutions:**

1. **Processing Bottlenecks**
   - **Issue:** Insufficient processing capacity
   - **Solution:** Scale up processing components
   - **Verification:** Monitor processing queue lengths

2. **Database Write Performance**
   - **Issue:** Slow database write operations
   - **Solution:** Optimize database for write operations
   - **Verification:** Monitor database write latency

3. **Resource Contention**
   - **Issue:** Resources being consumed by other operations
   - **Solution:** Prioritize resources for data processing
   - **Verification:** Monitor resource allocation during processing

## Alert Issues

### Missing Alerts

**Symptoms:**
- Expected alerts not being generated
- Security events not triggering notifications
- Alert rules appear inactive

**Possible Causes and Solutions:**

1. **Rule Configuration**
   - **Issue:** Alert rules incorrectly configured
   - **Solution:** Review and correct alert rule configurations
   - **Verification:** Test alert rules with sample data

2. **Data Collection Issues**
   - **Issue:** Required data not being collected
   - **Solution:** Verify data collection for alert sources
   - **Verification:** Check if relevant data exists in the system

3. **Rule Disabled or Suppressed**
   - **Issue:** Rules inadvertently disabled or suppressed
   - **Solution:** Check rule status and suppression settings
   - **Verification:** Verify rule status in the configuration

### False Positives

**Symptoms:**
- Excessive irrelevant alerts
- Alerts triggered by normal activity
- High alert noise

**Possible Causes and Solutions:**

1. **Overly Sensitive Rules**
   - **Issue:** Alert thresholds too low
   - **Solution:** Adjust rule thresholds based on environment
   - **Verification:** Monitor alert frequency after adjustments

2. **Incomplete Baseline**
   - **Issue:** System lacks proper baseline of normal activity
   - **Solution:** Allow system to establish proper baselines
   - **Verification:** Check baseline data completeness

3. **Missing Contextual Information**
   - **Issue:** Rules lack context to distinguish normal from abnormal
   - **Solution:** Enhance rules with contextual conditions
   - **Verification:** Test enhanced rules with known scenarios

### Alert Notification Failures

**Symptoms:**
- Alerts generated but notifications not sent
- Delayed notifications
- Notifications sent to wrong recipients

**Possible Causes and Solutions:**

1. **Notification Configuration**
   - **Issue:** Incorrect notification settings
   - **Solution:** Verify notification configuration
   - **Verification:** Test notification delivery

2. **Email/SMS Gateway Issues**
   - **Issue:** Problems with notification delivery services
   - **Solution:** Check email/SMS gateway functionality
   - **Verification:** Test gateway connectivity

3. **Rate Limiting**
   - **Issue:** Notification rate limiting active
   - **Solution:** Adjust rate limiting or prioritize notifications
   - **Verification:** Check for rate limiting messages in logs

## Integration Issues

### SIEM Integration Problems

**Symptoms:**
- Data not flowing to SIEM
- Incomplete data in SIEM
- Format issues in SIEM data

**Possible Causes and Solutions:**

1. **Connection Configuration**
   - **Issue:** Incorrect connection parameters
   - **Solution:** Verify connection settings
   - **Verification:** Test connection with diagnostic tools

2. **Authentication Issues**
   - **Issue:** Invalid credentials or expired tokens
   - **Solution:** Update authentication credentials
   - **Verification:** Check authentication logs

3. **Data Format Mismatch**
   - **Issue:** Data format not compatible with SIEM
   - **Solution:** Adjust data formatting to match SIEM requirements
   - **Verification:** Validate data format with SIEM documentation

### Ticketing System Integration Issues

**Symptoms:**
- Tickets not being created
- Incomplete ticket information
- Duplicate tickets

**Possible Causes and Solutions:**

1. **API Configuration**
   - **Issue:** Incorrect API settings
   - **Solution:** Verify API configuration
   - **Verification:** Test API connectivity

2. **Mapping Issues**
   - **Issue:** Field mapping between systems incorrect
   - **Solution:** Update field mappings
   - **Verification:** Compare field values between systems

3. **Rate Limiting or Throttling**
   - **Issue:** Ticketing system limiting API calls
   - **Solution:** Implement request throttling or batching
   - **Verification:** Check for rate limiting errors

### API Integration Problems

**Symptoms:**
- API calls failing
- Authentication errors
- Unexpected API responses

**Possible Causes and Solutions:**

1. **API Version Mismatch**
   - **Issue:** Using incompatible API version
   - **Solution:** Update API calls to match current version
   - **Verification:** Check API documentation for version requirements

2. **Authentication Issues**
   - **Issue:** Invalid or expired API credentials
   - **Solution:** Update API authentication
   - **Verification:** Test authentication with simple API call

3. **Request Format Issues**
   - **Issue:** Malformed API requests
   - **Solution:** Correct request format according to API documentation
- **Verification:** Validate request format with API specification

## Testing and Import Path Issues (Pytest)

### ModuleNotFoundError: No module named 'app'

**Symptoms:**
- Running `pytest` fails with `ModuleNotFoundError: No module named 'app'` in tests importing from `ml/app`

**Cause:**
- The test runner’s `PYTHONPATH` does not include the `ml/app` directory, so imports like `from app.core.config import ...` fail.

**Solutions:**
- Quick (PowerShell, session only):
  - `set PYTHONPATH=%CD%\ml\app` (for current session)
  - Or persist: `setx PYTHONPATH "%CD%\ml\app"` then restart the shell
- Project-level (recommended):
  - Ensure `pytest.ini` contains:
    - `[pytest]`
    - `pythonpath = ml/app`
  - Run tests with `pytest -c pytest.ini`

**Verification:**
- Re-run `pytest`; imports of modules under `ml/app` should succeed.

**Notes:**
- If you previously referenced top-level `models/` for artifacts, use `artifacts/` after the rename.

## Machine Learning Issues

### Model Performance Degradation

**Symptoms:**
- Increasing false positives/negatives
- Declining detection accuracy
- Unexpected model behavior

**Possible Causes and Solutions:**

1. **Data Drift**
   - **Issue:** Production data differs from training data
   - **Solution:** Retrain model with current data
   - **Verification:** Compare data distributions between training and production

2. **Insufficient Training**
   - **Issue:** Model not trained on enough diverse data
   - **Solution:** Enhance training dataset
   - **Verification:** Evaluate model performance on diverse test cases

3. **Environmental Changes**
   - **Issue:** Changes in environment affecting model assumptions
   - **Solution:** Update model to account for new patterns
   - **Verification:** Analyze environmental changes and their impact

### Model Training Failures

**Symptoms:**
- Training jobs fail to complete
- Model validation errors
- Poor model metrics after training

**Possible Causes and Solutions:**

1. **Data Quality Issues**
   - **Issue:** Training data contains errors or inconsistencies
   - **Solution:** Clean and validate training data
   - **Verification:** Run data quality checks

2. **Resource Limitations**
   - **Issue:** Insufficient resources for training
   - **Solution:** Increase resources allocated to training
   - **Verification:** Monitor resource usage during training

3. **Algorithm Configuration**
   - **Issue:** Suboptimal algorithm parameters
   - **Solution:** Tune hyperparameters
   - **Verification:** Compare performance with different parameters

## Database Issues

### Database Performance Problems

**Symptoms:**
- Slow query responses
- Database timeouts
- High database load

**Possible Causes and Solutions:**

1. **Missing Indexes**
   - **Issue:** Queries running without proper indexes
   - **Solution:** Add appropriate indexes
   - **Verification:** Check query execution plans

2. **Query Optimization**
   - **Issue:** Inefficient queries
   - **Solution:** Optimize query structure
   - **Verification:** Compare performance before and after optimization

3. **Resource Constraints**
   - **Issue:** Database server resource limitations
   - **Solution:** Increase database server resources
   - **Verification:** Monitor resource utilization

4. **Connection Pool Issues**
   - **Issue:** Connection pool misconfiguration
   - **Solution:** Optimize connection pool settings
   - **Verification:** Monitor connection usage patterns

### Database Corruption

**Symptoms:**
- Database errors
- Inconsistent query results
- Service failures related to database

**Possible Causes and Solutions:**

1. **Storage Issues**
   - **Issue:** Underlying storage problems
   - **Solution:** Check and repair storage
   - **Verification:** Run storage diagnostics

2. **Unexpected Shutdowns**
   - **Issue:** Database not properly shut down
   - **Solution:** Run database recovery procedures
   - **Verification:** Check database logs for recovery status

3. **Concurrent Write Issues**
   - **Issue:** Conflicting write operations
   - **Solution:** Review transaction isolation levels
   - **Verification:** Check for deadlock or conflict errors

## User Interface Issues

### Display Problems

**Symptoms:**
- UI elements misaligned or missing
- Charts not rendering correctly
- Visual glitches

**Possible Causes and Solutions:**

1. **Browser Compatibility**
   - **Issue:** Browser not fully compatible
   - **Solution:** Use recommended browser version
   - **Verification:** Test in different browsers

2. **CSS/JavaScript Errors**
   - **Issue:** Frontend code errors
   - **Solution:** Check browser console for errors
   - **Verification:** Debug using browser developer tools

3. **Caching Issues**
   - **Issue:** Outdated cached resources
   - **Solution:** Clear browser cache
   - **Verification:** Test with cache disabled

### Functionality Issues

**Symptoms:**
- Buttons or controls not working
- Forms not submitting
- Interactive elements unresponsive

**Possible Causes and Solutions:**

1. **JavaScript Errors**
   - **Issue:** JavaScript runtime errors
   - **Solution:** Debug JavaScript issues
   - **Verification:** Check browser console for errors

2. **API Communication**
   - **Issue:** Frontend can't communicate with backend API
   - **Solution:** Verify API connectivity
   - **Verification:** Monitor network requests in browser

3. **Permission Issues**
   - **Issue:** User lacks permissions for actions
   - **Solution:** Verify user permissions
   - **Verification:** Check access control logs

## Logging and Monitoring Issues

### Missing Logs

**Symptoms:**
- Expected logs not appearing
- Gaps in log timeline
- Incomplete logging information

**Possible Causes and Solutions:**

1. **Log Level Configuration**
   - **Issue:** Log level set too high
   - **Solution:** Adjust log level settings
   - **Verification:** Check log configuration

2. **Log Storage Issues**
   - **Issue:** Log storage problems
   - **Solution:** Verify log storage functionality
   - **Verification:** Check log storage capacity and permissions

3. **Log Rotation Issues**
   - **Issue:** Logs being rotated or purged unexpectedly
   - **Solution:** Review log rotation settings
   - **Verification:** Check log rotation configuration

### Monitoring Alert Issues

**Symptoms:**
- System health alerts not triggering
- Monitoring dashboards showing incorrect data
- Monitoring service unresponsive

**Possible Causes and Solutions:**

1. **Monitoring Configuration**
   - **Issue:** Incorrect monitoring settings
   - **Solution:** Verify monitoring configuration
   - **Verification:** Test monitoring alerts

2. **Metric Collection Issues**
   - **Issue:** Metrics not being collected properly
   - **Solution:** Check metric collection services
   - **Verification:** Validate raw metric data

3. **Alert Threshold Configuration**
   - **Issue:** Inappropriate alert thresholds
   - **Solution:** Adjust alert thresholds
   - **Verification:** Test with known conditions

## Advanced Troubleshooting

### Diagnostic Tools

1. **Log Analysis**
   - Use the platform's log explorer to search for error patterns
   - Correlate logs across different components
   - Look for timestamps around when issues occurred

2. **Health Checks**
   - Run built-in health check commands
   - Verify all services are running properly
   - Check resource utilization

3. **Database Diagnostics**
   - Run database consistency checks
   - Check for long-running queries
   - Verify database connections

4. **Network Diagnostics**
   - Test connectivity between components
   - Verify DNS resolution
   - Check for network latency issues

### Collecting Diagnostic Information

When contacting support, collect the following information:

1. **System Information**
   - Platform version
   - Deployment type (on-premises, cloud, hybrid)
   - System specifications

2. **Logs**
   - Relevant service logs
   - Error messages
   - System logs

3. **Configuration**
   - Configuration files (with sensitive information redacted)
   - Recent configuration changes

4. **Issue Details**
   - Exact steps to reproduce
   - Timing of the issue
   - Frequency of occurrence
   - Impact and severity

### Using Support Mode

The platform includes a support mode that can be enabled for advanced troubleshooting:

1. **Enabling Support Mode**
   ```bash
   securityai-cli support enable --duration=24h
   ```

2. **Generating Support Bundle**
   ```bash
   securityai-cli support bundle --output=/path/to/output
   ```

3. **Sharing with Support**
   - Upload the generated bundle to the support portal
   - Include the support ticket number

4. **Disabling Support Mode**
   ```bash
   securityai-cli support disable
   ```

## Common Error Messages

### API Errors

| Error Code | Message | Possible Cause | Solution |
|-----------|---------|----------------|----------|
| 401 | Unauthorized | Invalid API credentials | Verify API key or authentication token |
| 403 | Forbidden | Insufficient permissions | Check user/API key permissions |
| 404 | Not Found | Resource doesn't exist | Verify resource ID or path |
| 429 | Too Many Requests | Rate limiting active | Reduce request frequency or implement backoff |
| 500 | Internal Server Error | Server-side issue | Check server logs for details |
| 503 | Service Unavailable | Service down or overloaded | Check service status and resources |

### Installation Errors

| Error | Possible Cause | Solution |
|-------|----------------|----------|
| "Failed to pull image" | Network or registry issues | Check network connectivity and registry access |
| "Insufficient disk space" | Not enough storage | Free up disk space or add storage |
| "Port already in use" | Port conflict | Change port configuration or stop conflicting service |
| "Database connection failed" | Database not accessible | Verify database connection parameters and status |

### Runtime Errors

| Error | Possible Cause | Solution |
|-------|----------------|----------|
| "Out of memory" | Insufficient memory | Increase memory allocation or optimize usage |
| "Connection timeout" | Network latency or service down | Check network and service status |
| "Certificate expired" | SSL/TLS certificate expired | Renew certificates |
| "Queue overflow" | Processing backlog | Increase processing capacity or reduce input rate |

## Contacting Support

If you're unable to resolve an issue using this guide, contact the SecurityAI Platform support team:

1. **Support Portal**
   - URL: https://support.securityai-platform.example.com
   - Create a new ticket with detailed issue description

2. **Email Support**
   - Address: support@securityai-platform.example.com
   - Include system information and issue details

3. **Phone Support**
   - Premium support customers: +1-888-555-0123
   - Available 24/7 for critical issues

4. **Community Forums**
   - URL: https://community.securityai-platform.example.com
   - Search for similar issues or post new questions

## Appendix

### Log Locations

| Component | Log Location |
|-----------|-------------|
| Frontend | `/var/log/securityai/frontend/` |
| API Server | `/var/log/securityai/api/` |
| ML Pipeline | `/var/log/securityai/ml/` |
| Database | `/var/log/securityai/database/` |
| Agents | `/var/log/securityai/agent/` |

### Configuration File Locations

| Component | Configuration Location |
|-----------|------------------------|
| Main Configuration | `/etc/securityai/config.yaml` |
| API Configuration | `/etc/securityai/api/config.yaml` |
| ML Configuration | `/etc/securityai/ml/config.yaml` |
| Database Configuration | `/etc/securityai/database/config.yaml` |
| Agent Configuration | `/etc/securityai/agent/config.yaml` |

### Diagnostic Commands

| Purpose | Command |
|---------|--------|
| Check Service Status | `securityai-cli service status` |
| Verify Database Connection | `securityai-cli db test-connection` |
| Test API Connectivity | `securityai-cli api test` |
| Check Agent Status | `securityai-cli agent list --status` |
| Validate Configuration | `securityai-cli config validate` |
| View System Health | `securityai-cli health` |