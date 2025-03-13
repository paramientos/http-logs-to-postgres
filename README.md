# HTTP Log to PostgreSQL Connector - Installation and Configuration Guide

This guide explains the installation and configuration of a Go application that streams HTTP access logs in a custom format directly to a PostgreSQL database in real-time.

## 1. Nginx Setup and Log Format

First, you need to configure your Nginx server to use the custom log format:

### Nginx Log Format Configuration

1. Open your Nginx configuration file (`/etc/nginx/nginx.conf` or `/etc/nginx/conf.d/default.conf`):

```bash
sudo nano /etc/nginx/nginx.conf
```

2. Add the custom log format inside the `http` block:

```nginx
http {
    # ... other configurations ...
    
    log_format detailed_log '[$time_local] $remote_addr:$remote_port -> $server_addr:$server_port '
                            '$request_method "$request_uri" "$http_referer" '
                            'Status: $status Bytes: $body_bytes_sent '
                            'UA: "$http_user_agent" '
                            'RT: $request_time '
                            'Forwarded IP: $http_x_forwarded_for';
    
    # ... other configurations ...
}
```

3. Apply this log format to your virtual hosts in the `server` block:

```nginx
server {
    # ... other configurations ...
    
    access_log /var/log/nginx/access.log detailed_log;
    
    # ... other configurations ...
}
```

4. Test and restart Nginx:

```bash
sudo nginx -t
sudo systemctl restart nginx
```

## 2. PostgreSQL Setup

Set up PostgreSQL database and user for storing logs:

```bash
# Connect to PostgreSQL as postgres user
sudo -u postgres psql

# Create database and user
CREATE DATABASE logs;
CREATE USER loguser WITH ENCRYPTED PASSWORD 'your_secure_password';
GRANT ALL PRIVILEGES ON DATABASE logs TO loguser;

# Connect to the logs database
\c logs

# The application will create the necessary tables automatically
# Exit PostgreSQL
\q
```

## 3. Go Application Setup

### Prerequisites

1. Install Go (1.16 or later):

```bash
sudo apt update
sudo apt install golang-go
```

2. Install Git:

```bash
sudo apt install git
```

### Application Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/nginx-logs-to-postgres.git
cd nginx-logs-to-postgres
```

2. Initialize Go modules (if not already set up):

```bash
go mod init github.com/yourusername/nginx-logs-to-postgres
go mod tidy
```

3. Install the required Go package:

```bash
go get github.com/lib/pq
```

4. Build the application:

```bash
go build -o log-processor
```

### First Run with Table Creation

Run the application with the `-createtable` flag to create the required database tables:

```bash
./log-processor -log=/var/log/nginx/access.log -dbname=logs -dbuser=loguser -dbpassword='your_secure_password' -createtable
```

## 4. Systemd Service Setup (for running as a service)

Create a systemd service to ensure the application runs continuously:

1. Create a service file:

```bash
sudo nano /etc/systemd/system/log-processor.service
```

2. Add the following content:

```ini
[Unit]
Description=Nginx Logs to PostgreSQL Processor
After=network.target postgresql.service nginx.service

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/path/to/nginx-logs-to-postgres
ExecStart=/path/to/nginx-logs-to-postgres/log-processor -log=/var/log/nginx/access.log -dbname=logs -dbuser=loguser -dbpassword='your_secure_password' -interval=1
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

3. Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable log-processor.service
sudo systemctl start log-processor.service
```

4. Check service status:

```bash
sudo systemctl status log-processor.service
```

## 5. Log Rotation Configuration

To ensure the application handles log rotation properly, configure logrotate:

1. Edit the Nginx logrotate configuration:

```bash
sudo nano /etc/logrotate.d/nginx
```

2. Ensure it includes:

```
/var/log/nginx/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        [ -s /run/nginx.pid ] && kill -USR1 `cat /run/nginx.pid`
    endscript
}
```

## 6. Application Configuration Parameters

The log processor supports various command-line parameters:

- `-log`: Path to the log file (required)
- `-dbhost`: PostgreSQL server address (default: localhost)
- `-dbport`: PostgreSQL port number (default: 5432)
- `-dbname`: PostgreSQL database name (default: logs)
- `-dbuser`: PostgreSQL username (default: postgres)
- `-dbpassword`: PostgreSQL password
- `-createtable`: Create database tables if they don't exist
- `-interval`: Log file check interval in seconds (default: 1)
- `-batchsize`: Number of log lines to process in a batch (default: 100)
- `-reset`: Reset processing state and start from beginning
- `-forcereset`: Force reset offset in each cycle (for testing)
- `-debug`: Show detailed debug logs

## 7. Troubleshooting

### Common Issues and Solutions

1. **Application not processing new logs:**
   ```bash
   # Reset the processing state
   ./log-processor -log=/var/log/nginx/access.log -reset
   ```

2. **Database connection issues:**
   ```bash
   # Test database connection
   psql -h localhost -U loguser -d logs -W
   ```

3. **Permission issues:**
   ```bash
   # Ensure the application has read access to log files
   sudo usermod -a -G adm www-data
   sudo chmod 640 /var/log/nginx/access.log
   ```

4. **Log format not matching:**
   Check if the log format in Nginx matches the expected format by the parser. You may need to adjust the regular expressions in the `parseLogLine` function.

5. **Service not starting:**
   ```bash
   # Check service logs
   sudo journalctl -u log-processor.service
   ```

### Monitoring

Monitor the application logs:

```bash
sudo journalctl -u log-processor.service -f
```

Query processed logs in PostgreSQL:

```bash
psql -U loguser -d logs -c "SELECT COUNT(*) FROM http_access_logs;"
psql -U loguser -d logs -c "SELECT * FROM http_access_logs ORDER BY timestamp DESC LIMIT 10;"
```

## 8. Database Schema

The application creates two tables:

1. `http_access_logs`: Stores the processed log entries
2. `log_processing_state`: Tracks processing state (offset, line number, etc.)

You can query these tables for custom reports or monitoring.

## 9. Updates and Maintenance

To update the application:

```bash
cd /path/to/nginx-logs-to-postgres
git pull
go build -o log-processor
sudo systemctl restart log-processor.service
```

This setup provides a robust solution for streaming Nginx logs to PostgreSQL in real-time, with automatic handling of log rotation and error recovery.
