package main

import (
	"bufio"
	"database/sql"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	_ "github.com/lib/pq"
)

// LogEntry stores information parsed from HTTP access log
type LogEntry struct {
	Timestamp    time.Time
	ClientIP     string
	ClientPort   string
	ServerIP     string
	ServerPort   string
	Method       string
	Path         string
	Referer      string
	StatusCode   string
	BytesSent    string
	UserAgent    string
	ResponseTime string
	ForwardedIP  string
	PromotionID  string
}

// Function that counts file lines and returns the count at once
func countFileLines(filePath string) (int64, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return 0, err
	}
	defer file.Close()

	var lineCount int64 = 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lineCount++
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	return lineCount, nil
}

func main() {
	// Definition of command line parameters
	var (
		logFile        = flag.String("log", "", "Log file path (required)")
		dbHost         = flag.String("dbhost", "localhost", "PostgreSQL server address")
		dbPort         = flag.Int("dbport", 5432, "PostgreSQL port number")
		dbName         = flag.String("dbname", "logs", "PostgreSQL database name")
		dbUser         = flag.String("dbuser", "postgres", "PostgreSQL username")
		dbPassword     = flag.String("dbpassword", "", "PostgreSQL password")
		createTable    = flag.Bool("createtable", false, "Create database tables")
		stateDir       = flag.String("statedir", "./state", "Directory to save processing state")
		checkInterval  = flag.Int("interval", 1, "Log file check interval (seconds)")
		batchSize      = flag.Int("batchsize", 100, "Number of log lines to process in one batch")
		resetState     = flag.Bool("reset", false, "Reset state information and start from the beginning")
		forceReset     = flag.Bool("forcereset", false, "Reset offset in each cycle (for testing)")
		_          = flag.Bool("debug", false, "Show detailed debug logs")
	)
	flag.Parse()

	// Check log file parameter
	if *logFile == "" {
		log.Fatal("Log file path not specified. Use the -log parameter.")
	}

	// Create state directory (if it doesn't exist)
	if err := os.MkdirAll(*stateDir, 0755); err != nil {
		log.Fatalf("Failed to create state directory: %v", err)
	}

	// PostgreSQL connection information
	connStr := fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=disable",
		*dbHost, *dbPort, *dbName, *dbUser, *dbPassword)

	// Connect to the database
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Error connecting to database: %v", err)
	}
	defer db.Close()

	// Test the connection
	if err := db.Ping(); err != nil {
		log.Fatalf("Database connection test failed: %v", err)
	}
	log.Println("Successfully connected to PostgreSQL database")

	// Create tables (if requested)
	if *createTable {
		createLogTable(db)
		createStateTable(db)
	}
	
	// Check if log file exists
	if _, err := os.Stat(*logFile); os.IsNotExist(err) {
		log.Printf("Specified log file does not exist: %s. Will wait until file is created.", *logFile)
	}

	// Main processing loop
	logFilename := filepath.Base(*logFile)

	// Read state information
	lastOffset, lastLine, lastInode, lastSize := readState(db, logFilename)
	log.Printf("Last processed position: offset=%d, line=%d, inode=%d, size=%d", 
		lastOffset, lastLine, lastInode, lastSize)
	
	// State reset option for debugging
	if *resetState {
		log.Println("Resetting state information...")
		lastOffset = 0
		lastLine = 0
		// Update inode and size information
		fileInfo, err := os.Stat(*logFile)
		if err == nil {
			lastSize = fileInfo.Size()
			if stat, ok := fileInfo.Sys().(*syscall.Stat_t); ok {
				lastInode = stat.Ino
			}
		}
		updateState(db, logFilename, lastOffset, lastLine, lastInode, lastSize)
		log.Println("State information reset!")
	}
	
	// Variables to track file change information
	var lastProcessTime time.Time = time.Now()
	var stuckCounter int = 0
	
	for {
		// Check file information
		fileInfo, err := os.Stat(*logFile)
		if err != nil {
			log.Printf("Error getting file information: %v", err)
			time.Sleep(time.Duration(*checkInterval) * time.Second)
			continue
		}
		
		currentSize := fileInfo.Size()
		
		// Get file inode (on Linux systems)
		var currentInode uint64
		if stat, ok := fileInfo.Sys().(*syscall.Stat_t); ok {
			currentInode = stat.Ino
		}
		
		// Check if file has grown
		if currentSize > lastSize {
			log.Printf("File has grown. Previous size: %d, New size: %d, Difference: %d bytes", 
				lastSize, currentSize, currentSize-lastSize)
				
			if lastOffset >= currentSize {
				log.Printf("ERROR: Last offset (%d) is greater than or equal to file size (%d). Resetting offset to fix the relationship.", 
					lastOffset, currentSize)
				lastOffset = 0
				updateState(db, logFilename, lastOffset, lastLine, lastInode, currentSize)
			}
			
			// Check if there is unprocessed data
			if lastOffset == lastSize && lastSize < currentSize {
				log.Printf("Detected new unprocessed data: offset=%d, old size=%d, new size=%d", 
					lastOffset, lastSize, currentSize)
				// Offset has not been updated, continue with current value
			}
			
			// Check file line count every X minutes
			if time.Now().Minute()%10 == 0 && time.Now().Second() < 5 {
				// This operation can be slow, so don't do it often
				totalLines, err := countFileLines(*logFile)
				if err == nil && totalLines > lastLine {
					log.Printf("File check: Total line count = %d, Last processed line = %d, Difference = %d lines", 
						totalLines, lastLine, totalLines-lastLine)
				}
			}
		}
		
		// Logrotate check - if inode changed or file size decreased
		if (lastInode > 0 && currentInode != lastInode) || 
		   (lastSize > 0 && currentSize < lastOffset) {
			log.Printf("File has changed (logrotate) - restarting. Previous inode: %d, New inode: %d, Previous size: %d, New size: %d", 
				lastInode, currentInode, lastSize, currentSize)
			lastOffset = 0
			lastLine = 0
			lastInode = currentInode
			lastSize = currentSize
			
			// Update database
			updateState(db, logFilename, lastOffset, lastLine, lastInode, lastSize)
		}
		
		// RESET parameter check
		if *forceReset || lastOffset >= currentSize {
			log.Printf("Resetting offset: Current offset=%d, File size=%d", lastOffset, currentSize)
			lastOffset = 0
			// Update database
			updateState(db, logFilename, lastOffset, lastLine, lastInode, currentSize)
		}
		
		// Process log file
		processed := processLogFile(db, *logFile, lastOffset, lastLine, *batchSize)
		if processed > 0 {
			log.Printf("Number of lines processed: %d", processed)
			stuckCounter = 0 // Progress made, reset counter
			lastProcessTime = time.Now()
			
			// Get new state information
			lastOffset, lastLine, lastInode, lastSize = readState(db, logFilename)
		} else {
			// File may have grown but content couldn't be processed, check offset
			fileInfo, _ := os.Stat(*logFile)
			if fileInfo.Size() > lastSize && lastOffset == lastSize {
				log.Printf("WARNING: File has grown (%d → %d) but offset is not updating, will reopen the file.", 
					lastSize, fileInfo.Size())
				
				// Check difference between last known size and current size
				diff := fileInfo.Size() - lastSize
				if diff > 0 {
					stuckCounter++
					
					// Try to force process the file (for offset issues)
					if stuckCounter > 3 {
						log.Printf("WARNING: Progress issue detected, updating offset: %d -> %d", 
							lastOffset, lastSize)
						lastOffset = lastSize // Use last known size as offset
						updateState(db, logFilename, lastOffset, lastLine, lastInode, fileInfo.Size())
						stuckCounter = 0
					}
				}
			} else {
				// File hasn't changed, normal state
				log.Printf("No new lines processed. Current state: offset=%d, line=%d, file size=%d", 
					lastOffset, lastLine, fileInfo.Size())
				
				// If no progress for more than 5 minutes and file is growing
				timeSinceLastProcess := time.Since(lastProcessTime)
				if timeSinceLastProcess > 5*time.Minute && fileInfo.Size() > lastSize {
					log.Printf("WARNING: No progress for %s, will continue from last known value.", 
						timeSinceLastProcess.String())
					lastOffset = lastSize // Use last known size as offset
					updateState(db, logFilename, lastOffset, lastLine, lastInode, fileInfo.Size())
				}
			}
		}

		// Check at specified intervals
		time.Sleep(time.Duration(*checkInterval) * time.Second)
	}
}

// createLogTable creates the log table in PostgreSQL
func createLogTable(db *sql.DB) {
	query := `
	CREATE TABLE IF NOT EXISTS http_access_logs (
		id SERIAL PRIMARY KEY,
		timestamp TIMESTAMP,
		client_ip VARCHAR(45),
		client_port VARCHAR(10),
		server_ip VARCHAR(45),
		server_port VARCHAR(10),
		method VARCHAR(10),
		path TEXT,
		referer TEXT,
		status_code VARCHAR(10),
		bytes_sent VARCHAR(20),
		user_agent TEXT,
		response_time VARCHAR(20),
		forwarded_ip VARCHAR(45),
		promotion_id VARCHAR(255),
		received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`

	_, err := db.Exec(query)
	if err != nil {
		log.Fatalf("Error creating log table: %v", err)
	}
	log.Println("HTTP access logs table successfully created or already exists.")
}

// createStateTable creates the state table in PostgreSQL
func createStateTable(db *sql.DB) {
	query := `
	CREATE TABLE IF NOT EXISTS log_processing_state (
		filename VARCHAR(255) PRIMARY KEY,
		last_offset BIGINT,
		last_line BIGINT,
		last_inode BIGINT,
		file_size BIGINT,
		last_processed TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`

	_, err := db.Exec(query)
	if err != nil {
		log.Fatalf("Error creating state table: %v", err)
	}
	log.Println("Log processing state table successfully created or already exists.")
}

// readState reads the last processed position from the database
func readState(db *sql.DB, filename string) (int64, int64, uint64, int64) {
	var offset, line, inode, fileSize int64

	query := `
	SELECT last_offset, last_line, last_inode, file_size FROM log_processing_state 
	WHERE filename = $1
	`

	err := db.QueryRow(query, filename).Scan(&offset, &line, &inode, &fileSize)
	if err != nil {
		if err == sql.ErrNoRows {
			// Create new record if none exists
			_, err = db.Exec(`
				INSERT INTO log_processing_state (filename, last_offset, last_line, last_inode, file_size)
				VALUES ($1, 0, 0, 0, 0)
			`, filename)
			if err != nil {
				log.Printf("Error creating state record: %v", err)
			}
			return 0, 0, 0, 0
		}
		log.Printf("Error reading state information: %v", err)
		return 0, 0, 0, 0
	}

	return offset, line, uint64(inode), fileSize
}

// updateState updates the last processed position in the database
func updateState(db *sql.DB, filename string, offset, line int64, inode uint64, fileSize int64) {
	// Check for inconsistency
	if offset > fileSize {
		log.Printf("WARNING: Offset to be saved (%d) is larger than file size (%d). Correcting value.", 
			offset, fileSize)
		offset = 0
	}
	
	query := `
	UPDATE log_processing_state 
	SET last_offset = $2, last_line = $3, last_inode = $4, file_size = $5, last_processed = CURRENT_TIMESTAMP
	WHERE filename = $1
	`

	_, err := db.Exec(query, filename, offset, line, inode, fileSize)
	if err != nil {
		log.Printf("Error updating state information: %v", err)
	}
}

// processLogFile processes the log file and continues from where it left off
// Returns the total number of lines processed
func processLogFile(db *sql.DB, filePath string, lastOffset, lastLine int64, batchSize int) int64 {
	// Open log file
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Could not open log file: %v", err)
		return 0
	}
	defer file.Close()

	// Get file information
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		log.Printf("Could not get file information: %v", err)
		return 0
	}
	
	// Log the states
	log.Printf("Processing starting - Last offset: %d, Last line: %d, File size: %d", 
		lastOffset, lastLine, fileInfo.Size())

	// Check offset and file size
	if lastOffset > fileInfo.Size() {
		log.Printf("ERROR: Offset (%d) is larger than file size (%d), resetting", 
			lastOffset, fileInfo.Size())
		lastOffset = 0
	}
	
	// Check if there is new content
	if lastOffset == fileInfo.Size() {
		log.Printf("No new content in file. Offset and file size are equal: %d", lastOffset)
		return 0
	}

	// Go to last processed position (offset)
	if lastOffset > 0 {
		_, err = file.Seek(lastOffset, io.SeekStart)
		if err != nil {
			log.Printf("Could not go to specified position in file: %v", err)
			// Return to beginning of file
			file.Seek(0, io.SeekStart)
			lastOffset = 0
			lastLine = 0
		}
	}

	// Start transaction
	tx, err := db.Begin()
	if err != nil {
		log.Printf("Error starting transaction: %v", err)
		return 0
	}
	defer tx.Rollback()

	// Create prepared statement
	stmt, err := tx.Prepare(`
	INSERT INTO http_access_logs (
		timestamp, client_ip, client_port, server_ip, server_port,
		method, path, referer, status_code, bytes_sent,
		user_agent, response_time, forwarded_ip, promotion_id
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`)
	if err != nil {
		log.Printf("Error creating prepared statement: %v", err)
		return 0
	}
	defer stmt.Close()

	// Read logs line by line
	scanner := bufio.NewScanner(file)
	
	// Increase buffer size for large files
	const maxScanTokenSize = 1024 * 1024 // 1MB
	buf := make([]byte, maxScanTokenSize)
	scanner.Buffer(buf, maxScanTokenSize)
	
	var currentLine, processedLines int64
	currentLine = lastLine
	
	// Process each line
	for scanner.Scan() {
		currentLine++
		
		// Debug
		if currentLine == 1 || currentLine%50000 == 0 {
			log.Printf("Processing line: %d", currentLine)
		}
		
		line := scanner.Text()
		if entry, ok := parseLogLine(line); ok {
			// Add log entry to database
			_, err := stmt.Exec(
				entry.Timestamp,
				entry.ClientIP,
				entry.ClientPort,
				entry.ServerIP,
				entry.ServerPort,
				entry.Method,
				entry.Path,
				entry.Referer,
				entry.StatusCode,
				entry.BytesSent,
				entry.UserAgent,
				entry.ResponseTime,
				entry.ForwardedIP,
				entry.PromotionID,
			)
			
			if err != nil {
				log.Printf("Error adding log record: %v", err)
				// Continue despite error
			} else {
				processedLines++
			}
		}
		
		// Update state at regular intervals or when batch limit is reached
		if processedLines > 0 && processedLines%int64(batchSize) == 0 {
			// Get current file position
			currentOffset, err := file.Seek(0, io.SeekCurrent)
			if err != nil {
				log.Printf("Error getting file position: %v", err)
				currentOffset = 0
			}
			
			// Save intermediate state
			if err := tx.Commit(); err != nil {
				log.Printf("Error committing transaction: %v", err)
				return processedLines
			}
			
			// Get file inode and size
			fileInfo, _ := os.Stat(filePath)
			var inode uint64
			if stat, ok := fileInfo.Sys().(*syscall.Stat_t); ok {
				inode = stat.Ino
			}
			
			// Update state information
			updateState(db, filepath.Base(filePath), currentOffset, currentLine, inode, fileInfo.Size())
			log.Printf("Intermediate state saved: offset=%d, line=%d", currentOffset, currentLine)
			
			// Start new transaction
			tx, err = db.Begin()
			if err != nil {
				log.Printf("Error starting new transaction: %v", err)
				return processedLines
			}
			
			// Create new prepared statement
			stmt, err = tx.Prepare(`
			INSERT INTO http_access_logs (
				timestamp, client_ip, client_port, server_ip, server_port,
				method, path, referer, status_code, bytes_sent,
				user_agent, response_time, forwarded_ip, promotion_id
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
			`)
			if err != nil {
				log.Printf("Error creating new prepared statement: %v", err)
				return processedLines
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Error reading log file: %v", err)
	}

	// Complete final operations
	if processedLines > 0 {
		// Get current file position
		currentOffset, err := file.Seek(0, io.SeekCurrent)
		if err != nil {
			log.Printf("Error getting file position: %v", err)
			currentOffset = 0
		}
		
		if err := tx.Commit(); err != nil {
			log.Printf("Error committing final transaction: %v", err)
			return processedLines
		}
		
		// Get file inode and size
		fileInfo, _ := os.Stat(filePath)
		var inode uint64
		if stat, ok := fileInfo.Sys().(*syscall.Stat_t); ok {
			inode = stat.Ino
		}
		
		// Update state information
		updateState(db, filepath.Base(filePath), currentOffset, currentLine, inode, fileInfo.Size())
		log.Printf("Final state saved: offset=%d, line=%d", currentOffset, currentLine)
	} else {
		// If there's a change in the file but no lines were processed, update the offset
		if fileInfo.Size() > lastOffset {
			log.Printf("There is data to process in the file but no lines were read. Offset will be updated: %d -> %d", 
				lastOffset, fileInfo.Size())
			
			// Get file inode and size
			var inode uint64
			if stat, ok := fileInfo.Sys().(*syscall.Stat_t); ok {
				inode = stat.Ino
			}
			
			// Set offset equal to file size
			updateState(db, filepath.Base(filePath), fileInfo.Size(), currentLine, inode, fileInfo.Size())
		}
	}

	return processedLines
}

// parseLogLine parses a log line and converts it to a LogEntry structure
func parseLogLine(line string) (LogEntry, bool) {
	var entry LogEntry

	// Regex patterns
	timestampPattern := `\[([^\]]+)\]`
	ipPortPattern := `(\d+\.\d+\.\d+\.\d+):(\d+) -> (\d+\.\d+\.\d+\.\d+):(\d+)`
	methodPathPattern := `(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) "([^"]*)"` 
	refererPattern := `"([^"]*)"` 
	statusBytesPattern := `Status: (\d+) Bytes: (\d+)`
	uaPattern := `UA: "([^"]*)"` 
	rtPattern := `RT: ([\d\.]+)`
	forwardedIPPattern := `Forwarded IP: ([\d\.]+)`
	promotionPattern := `promotion=([^&"\s]+)`

	// Parse timestamp
	tsMatches := regexp.MustCompile(timestampPattern).FindStringSubmatch(line)
	if len(tsMatches) >= 2 {
		ts, err := time.Parse("02/Jan/2006:15:04:05 -0700", tsMatches[1])
		if err == nil {
			entry.Timestamp = ts
		}
	}

	// IP addresses and ports
	ipMatches := regexp.MustCompile(ipPortPattern).FindStringSubmatch(line)
	if len(ipMatches) >= 5 {
		entry.ClientIP = ipMatches[1]
		entry.ClientPort = ipMatches[2]
		entry.ServerIP = ipMatches[3]
		entry.ServerPort = ipMatches[4]
	}

	// Method and Path
	methodMatches := regexp.MustCompile(methodPathPattern).FindStringSubmatch(line)
	if len(methodMatches) >= 3 {
		entry.Method = methodMatches[1]
		entry.Path = methodMatches[2]
		
		// Extract promotion ID from URL
		promotionMatches := regexp.MustCompile(promotionPattern).FindStringSubmatch(entry.Path)
		if len(promotionMatches) >= 2 {
			entry.PromotionID = promotionMatches[1]
		}
	}

	// Referer - content in quotes after method and path
	parts := strings.Split(line, methodPathPattern)
	if len(parts) >= 2 {
		refererMatches := regexp.MustCompile(refererPattern).FindStringSubmatch(parts[1])
		if len(refererMatches) >= 2 {
			entry.Referer = refererMatches[1]
		}
	}

	// Status and Bytes
	statusMatches := regexp.MustCompile(statusBytesPattern).FindStringSubmatch(line)
	if len(statusMatches) >= 3 {
		entry.StatusCode = statusMatches[1]
		entry.BytesSent = statusMatches[2]
	}

	// User Agent
	uaMatches := regexp.MustCompile(uaPattern).FindStringSubmatch(line)
	if len(uaMatches) >= 2 {
		entry.UserAgent = uaMatches[1]
	}

	// Response Time
	rtMatches := regexp.MustCompile(rtPattern).FindStringSubmatch(line)
	if len(rtMatches) >= 2 {
		entry.ResponseTime = rtMatches[1]
	}

	// Forwarded IP
	fwdMatches := regexp.MustCompile(forwardedIPPattern).FindStringSubmatch(line)
	if len(fwdMatches) >= 2 {
		entry.ForwardedIP = fwdMatches[1]
	}

	// Check if required fields are filled
	if entry.ClientIP != "" && entry.Method != "" && entry.Path != "" {
		return entry, true
	}
	
	log.Printf("Unparseable log line: %s", line)
	return LogEntry{}, false
}
