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

// LogEntry, HTTP erişim logundan ayrıştırılan bilgileri tutar
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

// Tek seferde dosya satır sayısını hesaplayıp veren fonksiyon
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
	// Komut satırı parametrelerinin tanımlanması
	var (
		logFile        = flag.String("log", "", "Log dosyası yolu (zorunlu)")
		dbHost         = flag.String("dbhost", "localhost", "PostgreSQL sunucu adresi")
		dbPort         = flag.Int("dbport", 5432, "PostgreSQL port numarası")
		dbName         = flag.String("dbname", "logs", "PostgreSQL veritabanı adı")
		dbUser         = flag.String("dbuser", "postgres", "PostgreSQL kullanıcı adı")
		dbPassword     = flag.String("dbpassword", "", "PostgreSQL şifresi")
		createTable    = flag.Bool("createtable", false, "Veritabanı tablolarını oluştur")
		stateDir       = flag.String("statedir", "./state", "İşleme durumunun kaydedileceği dizin")
		checkInterval  = flag.Int("interval", 1, "Log dosyasını kontrol etme aralığı (saniye)")
		batchSize      = flag.Int("batchsize", 100, "Bir seferde işlenecek log satırı sayısı")
		resetState     = flag.Bool("reset", false, "Durum bilgisini sıfırla ve baştan başla")
		forceReset     = flag.Bool("forcereset", false, "Her döngüde offseti sıfırla (test için)")
		debug          = flag.Bool("debug", false, "Detaylı debug loglarını göster")
	)
	flag.Parse()

	// Log dosyası parametresi kontrolü
	if *logFile == "" {
		log.Fatal("Log dosyası yolu belirtilmedi. -log parametresini kullanın.")
	}

	// Durum dizinini oluştur (yoksa)
	if err := os.MkdirAll(*stateDir, 0755); err != nil {
		log.Fatalf("Durum dizini oluşturulamadı: %v", err)
	}

	// PostgreSQL bağlantı bilgisi
	connStr := fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=disable",
		*dbHost, *dbPort, *dbName, *dbUser, *dbPassword)

	// Veritabanına bağlan
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatalf("Veritabanına bağlanırken hata: %v", err)
	}
	defer db.Close()

	// Bağlantıyı test et
	if err := db.Ping(); err != nil {
		log.Fatalf("Veritabanı bağlantı testi başarısız: %v", err)
	}
	log.Println("PostgreSQL veritabanına başarıyla bağlandı")

	// Tabloları oluştur (istenirse)
	if *createTable {
		createLogTable(db)
		createStateTable(db)
	}
	
	// Log dosyası mevcut mu kontrol et
	if _, err := os.Stat(*logFile); os.IsNotExist(err) {
		log.Printf("Belirtilen log dosyası mevcut değil: %s. Dosya oluşana kadar beklenecek.", *logFile)
	}

	// Ana işleme döngüsü
	logFilename := filepath.Base(*logFile)

	// Durum bilgisini oku
	lastOffset, lastLine, lastInode, lastSize := readState(db, logFilename)
	log.Printf("Son işlenen konum: offset=%d, satır=%d, inode=%d, boyut=%d", 
		lastOffset, lastLine, lastInode, lastSize)
	
	// Debug için durum resetleme seçeneği
	if *resetState {
		log.Println("Durum bilgisi resetleniyor...")
		lastOffset = 0
		lastLine = 0
		// Inode ve boyut bilgilerini güncelle
		fileInfo, err := os.Stat(*logFile)
		if err == nil {
			lastSize = fileInfo.Size()
			if stat, ok := fileInfo.Sys().(*syscall.Stat_t); ok {
				lastInode = stat.Ino
			}
		}
		updateState(db, logFilename, lastOffset, lastLine, lastInode, lastSize)
		log.Println("Durum bilgisi resetlendi!")
	}
	
	// Dosya değişim bilgilerini izlemek için değişkenler
	var lastProcessTime time.Time = time.Now()
	var stuckCounter int = 0
	
	for {
		// Dosya bilgilerini kontrol et
		fileInfo, err := os.Stat(*logFile)
		if err != nil {
			log.Printf("Dosya bilgileri alınırken hata: %v", err)
			time.Sleep(time.Duration(*checkInterval) * time.Second)
			continue
		}
		
		currentSize := fileInfo.Size()
		
		// Dosya inode'unu al (Linux sistemlerde)
		var currentInode uint64
		if stat, ok := fileInfo.Sys().(*syscall.Stat_t); ok {
			currentInode = stat.Ino
		}
		
		// Dosya büyümüş mü kontrol et
		if currentSize > lastSize {
			log.Printf("Dosya büyümüş. Önceki boyut: %d, Yeni boyut: %d, Fark: %d byte", 
				lastSize, currentSize, currentSize-lastSize)
				
			if lastOffset >= currentSize {
				log.Printf("HATA: Son offset (%d) dosya boyutundan (%d) büyük veya eşit. İlişkiyi düzeltmek için offseti sıfırlıyorum.", 
					lastOffset, currentSize)
				lastOffset = 0
				updateState(db, logFilename, lastOffset, lastLine, lastInode, currentSize)
			}
			
			// İşlenmeyen veri var mı kontrol et
			if lastOffset == lastSize && lastSize < currentSize {
				log.Printf("İşlenmemiş yeni veri tespit edildi: offset=%d, eski boyut=%d, yeni boyut=%d", 
					lastOffset, lastSize, currentSize)
				// Offset güncellenmemiş, mevcut değerle devam et
			}
			
			// Her X dakikada bir dosya satır sayısını kontrol et
			if time.Now().Minute()%10 == 0 && time.Now().Second() < 5 {
				// Bu işlem yavaş olabilir, bu yüzden sık sık yapma
				totalLines, err := countFileLines(*logFile)
				if err == nil && totalLines > lastLine {
					log.Printf("Dosya kontrol: Toplam satır sayısı = %d, Son işlenen satır = %d, Fark = %d satır", 
						totalLines, lastLine, totalLines-lastLine)
				}
			}
		}
		
		// Logrotate kontrolü - inode değiştiyse veya dosya küçüldüyse
		if (lastInode > 0 && currentInode != lastInode) || 
		   (lastSize > 0 && currentSize < lastOffset) {
			log.Printf("Dosya değişmiş (logrotate) - yeniden başlanıyor. Önceki inode: %d, Yeni inode: %d, Önceki boyut: %d, Yeni boyut: %d", 
				lastInode, currentInode, lastSize, currentSize)
			lastOffset = 0
			lastLine = 0
			lastInode = currentInode
			lastSize = currentSize
			
			// Veritabanını güncelle
			updateState(db, logFilename, lastOffset, lastLine, lastInode, lastSize)
		}
		
		// RESET parametre kontrolü
		if *forceReset || lastOffset >= currentSize {
			log.Printf("Offset sıfırlanıyor: Mevcut offset=%d, Dosya boyutu=%d", lastOffset, currentSize)
			lastOffset = 0
			// Veritabanını güncelle
			updateState(db, logFilename, lastOffset, lastLine, lastInode, currentSize)
		}
		
		// Log dosyasını işle
		processed := processLogFile(db, *logFile, lastOffset, lastLine, *batchSize)
		if processed > 0 {
			log.Printf("İşlenen satır sayısı: %d", processed)
			stuckCounter = 0 // İlerleme var, counter'ı sıfırla
			lastProcessTime = time.Now()
			
			// Yeni durum bilgisini al
			lastOffset, lastLine, lastInode, lastSize = readState(db, logFilename)
		} else {
			// Dosya büyümüş ama içerik işlenememiş olabilir, offseti kontrol et
			fileInfo, _ := os.Stat(*logFile)
			if fileInfo.Size() > lastSize && lastOffset == lastSize {
				log.Printf("UYARI: Dosya büyümüş (%d → %d) ancak offset güncellenmiyor, dosyayı yeniden açacağım.", 
					lastSize, fileInfo.Size())
				
				// Son bilinen boyut ile şu anki boyut farkını kontrol et
				diff := fileInfo.Size() - lastSize
				if diff > 0 {
					stuckCounter++
					
					// Dosyayı zorla işlemeyi dene (offset sorunlarında)
					if stuckCounter > 3 {
						log.Printf("UYARI: İlerleme sorunu tespit edildi, offset güncelleniyor: %d -> %d", 
							lastOffset, lastSize)
						lastOffset = lastSize // Son bilinen boyutu offset olarak kullan
						updateState(db, logFilename, lastOffset, lastLine, lastInode, fileInfo.Size())
						stuckCounter = 0
					}
				}
			} else {
				// Dosya değişmemiş, normal durum
				log.Printf("Yeni satır işlenmedi. Şu an ki durum: offset=%d, satır=%d, dosya boyutu=%d", 
					lastOffset, lastLine, fileInfo.Size())
				
				// 5 dakikadan uzun süredir ilerleme yoksa ve dosya büyüyorsa
				timeSinceLastProcess := time.Since(lastProcessTime)
				if timeSinceLastProcess > 5*time.Minute && fileInfo.Size() > lastSize {
					log.Printf("UYARI: %s süredir ilerleme yok, offseti son bilinen değerden devam ettireceğim.", 
						timeSinceLastProcess.String())
					lastOffset = lastSize // Son bilinen boyutu offset olarak kullan
					updateState(db, logFilename, lastOffset, lastLine, lastInode, fileInfo.Size())
				}
			}
		}

		// Belirli aralıklarla kontrol et
		time.Sleep(time.Duration(*checkInterval) * time.Second)
	}
}

// createLogTable PostgreSQL'de log tablosunu oluşturur
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
		log.Fatalf("Log tablosu oluşturma hatası: %v", err)
	}
	log.Println("HTTP erişim logları tablosu başarıyla oluşturuldu veya zaten mevcut.")
}

// createStateTable PostgreSQL'de durum tablosunu oluşturur
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
		log.Fatalf("Durum tablosu oluşturma hatası: %v", err)
	}
	log.Println("Log işleme durum tablosu başarıyla oluşturuldu veya zaten mevcut.")
}

// readState son işlenen konumu veritabanından okur
func readState(db *sql.DB, filename string) (int64, int64, uint64, int64) {
	var offset, line, inode, fileSize int64

	query := `
	SELECT last_offset, last_line, last_inode, file_size FROM log_processing_state 
	WHERE filename = $1
	`

	err := db.QueryRow(query, filename).Scan(&offset, &line, &inode, &fileSize)
	if err != nil {
		if err == sql.ErrNoRows {
			// Kayıt yoksa yeni oluştur
			_, err = db.Exec(`
				INSERT INTO log_processing_state (filename, last_offset, last_line, last_inode, file_size)
				VALUES ($1, 0, 0, 0, 0)
			`, filename)
			if err != nil {
				log.Printf("Durum kaydı oluşturulurken hata: %v", err)
			}
			return 0, 0, 0, 0
		}
		log.Printf("Durum bilgisi okunurken hata: %v", err)
		return 0, 0, 0, 0
	}

	return offset, line, uint64(inode), fileSize
}

// updateState son işlenen konumu veritabanında günceller
func updateState(db *sql.DB, filename string, offset, line int64, inode uint64, fileSize int64) {
	// Tutarsızlık kontrolü
	if offset > fileSize {
		log.Printf("UYARI: Kaydetmeye çalışılan offset (%d) dosya boyutundan (%d) büyük. Değer düzeltiliyor.", 
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
		log.Printf("Durum bilgisi güncellenirken hata: %v", err)
	}
}

// processLogFile log dosyasını işler ve kaldığı yerden devam eder
// Geriye işlenen toplam satır sayısını döndürür
func processLogFile(db *sql.DB, filePath string, lastOffset, lastLine int64, batchSize int) int64 {
	// Log dosyasını aç
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Log dosyası açılamadı: %v", err)
		return 0
	}
	defer file.Close()

	// Dosya bilgilerini al
	fileInfo, err := os.Stat(filePath)
	if err != nil {
		log.Printf("Dosya bilgileri alınamadı: %v", err)
		return 0
	}
	
	// Durumları logla
	log.Printf("İşlem başlıyor - Son offset: %d, Son satır: %d, Dosya boyutu: %d", 
		lastOffset, lastLine, fileInfo.Size())

	// Offset ve dosya boyutu kontrolü
	if lastOffset > fileInfo.Size() {
		log.Printf("HATA: Offset (%d) dosya boyutundan (%d) büyük, sıfırlanıyor", 
			lastOffset, fileInfo.Size())
		lastOffset = 0
	}
	
	// Yeni içerik var mı kontrol et
	if lastOffset == fileInfo.Size() {
		log.Printf("Dosyada yeni içerik yok. Offset ve dosya boyutu eşit: %d", lastOffset)
		return 0
	}

	// Son işlenen konuma git (offset)
	if lastOffset > 0 {
		_, err = file.Seek(lastOffset, io.SeekStart)
		if err != nil {
			log.Printf("Dosyada belirtilen konuma gidilemedi: %v", err)
			// Dosya başına dön
			file.Seek(0, io.SeekStart)
			lastOffset = 0
			lastLine = 0
		}
	}

	// Transaction başlat
	tx, err := db.Begin()
	if err != nil {
		log.Printf("Transaction başlatılırken hata: %v", err)
		return 0
	}
	defer tx.Rollback()

	// Prepared statement oluştur
	stmt, err := tx.Prepare(`
	INSERT INTO http_access_logs (
		timestamp, client_ip, client_port, server_ip, server_port,
		method, path, referer, status_code, bytes_sent,
		user_agent, response_time, forwarded_ip, promotion_id
	) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
	`)
	if err != nil {
		log.Printf("Prepared statement oluşturulurken hata: %v", err)
		return 0
	}
	defer stmt.Close()

	// Logları satır satır oku
	scanner := bufio.NewScanner(file)
	
	// Büyük dosyalar için tampon boyutunu artır
	const maxScanTokenSize = 1024 * 1024 // 1MB
	buf := make([]byte, maxScanTokenSize)
	scanner.Buffer(buf, maxScanTokenSize)
	
	var currentLine, processedLines int64
	currentLine = lastLine
	
	// Her bir satırı işle
	for scanner.Scan() {
		currentLine++
		
		// Debug
		if currentLine == 1 || currentLine%50000 == 0 {
			log.Printf("Satır işleniyor: %d", currentLine)
		}
		
		line := scanner.Text()
		if entry, ok := parseLogLine(line); ok {
			// Log girdisini veritabanına ekle
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
				log.Printf("Log kaydı eklenirken hata: %v", err)
				// Hataya rağmen devam et
			} else {
				processedLines++
			}
		}
		
		// Belirli aralıklarla veya batch limitine ulaşınca durumu güncelle
		if processedLines > 0 && processedLines%int64(batchSize) == 0 {
			// Şu anki dosya konumunu al
			currentOffset, err := file.Seek(0, io.SeekCurrent)
			if err != nil {
				log.Printf("Dosya pozisyonu alınırken hata: %v", err)
				currentOffset = 0
			}
			
			// Ara durumu kaydet
			if err := tx.Commit(); err != nil {
				log.Printf("Transaction commit edilirken hata: %v", err)
				return processedLines
			}
			
			// Dosya inode ve boyutunu al
			fileInfo, _ := os.Stat(filePath)
			var inode uint64
			if stat, ok := fileInfo.Sys().(*syscall.Stat_t); ok {
				inode = stat.Ino
			}
			
			// Durum bilgisini güncelle
			updateState(db, filepath.Base(filePath), currentOffset, currentLine, inode, fileInfo.Size())
			log.Printf("Ara durum kaydedildi: offset=%d, satır=%d", currentOffset, currentLine)
			
			// Yeni transaction başlat
			tx, err = db.Begin()
			if err != nil {
				log.Printf("Yeni transaction başlatılırken hata: %v", err)
				return processedLines
			}
			
			// Yeni prepared statement oluştur
			stmt, err = tx.Prepare(`
			INSERT INTO http_access_logs (
				timestamp, client_ip, client_port, server_ip, server_port,
				method, path, referer, status_code, bytes_sent,
				user_agent, response_time, forwarded_ip, promotion_id
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
			`)
			if err != nil {
				log.Printf("Yeni prepared statement oluşturulurken hata: %v", err)
				return processedLines
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Log dosyası okuma hatası: %v", err)
	}

	// Son işlemleri tamamla
	if processedLines > 0 {
		// Şu anki dosya konumunu al
		currentOffset, err := file.Seek(0, io.SeekCurrent)
		if err != nil {
			log.Printf("Dosya pozisyonu alınırken hata: %v", err)
			currentOffset = 0
		}
		
		if err := tx.Commit(); err != nil {
			log.Printf("Son transaction commit edilirken hata: %v", err)
			return processedLines
		}
		
		// Dosya inode ve boyutunu al
		fileInfo, _ := os.Stat(filePath)
		var inode uint64
		if stat, ok := fileInfo.Sys().(*syscall.Stat_t); ok {
			inode = stat.Ino
		}
		
		// Durum bilgisini güncelle
		updateState(db, filepath.Base(filePath), currentOffset, currentLine, inode, fileInfo.Size())
		log.Printf("Son durum kaydedildi: offset=%d, satır=%d", currentOffset, currentLine)
	} else {
		// Dosyada bir değişiklik varsa ama satır işlenmediyse, offseti güncelle
		if fileInfo.Size() > lastOffset {
			log.Printf("Dosyada işlenecek veri var ancak satır okunamadı. Offset güncellenecek: %d -> %d", 
				lastOffset, fileInfo.Size())
			
			// Dosya inode ve boyutunu al
			var inode uint64
			if stat, ok := fileInfo.Sys().(*syscall.Stat_t); ok {
				inode = stat.Ino
			}
			
			// Offseti dosya boyutuna eşitle
			updateState(db, filepath.Base(filePath), fileInfo.Size(), currentLine, inode, fileInfo.Size())
		}
	}

	return processedLines
}

// parseLogLine bir log satırını ayrıştırarak LogEntry yapısına dönüştürür
func parseLogLine(line string) (LogEntry, bool) {
	var entry LogEntry

	// Regex desenleri
	timestampPattern := `\[([^\]]+)\]`
	ipPortPattern := `(\d+\.\d+\.\d+\.\d+):(\d+) -> (\d+\.\d+\.\d+\.\d+):(\d+)`
	methodPathPattern := `(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) "([^"]*)"` 
	refererPattern := `"([^"]*)"` 
	statusBytesPattern := `Status: (\d+) Bytes: (\d+)`
	uaPattern := `UA: "([^"]*)"` 
	rtPattern := `RT: ([\d\.]+)`
	forwardedIPPattern := `Forwarded IP: ([\d\.]+)`
	promotionPattern := `promotion=([^&"\s]+)`

	// Timestamp ayrıştırma
	tsMatches := regexp.MustCompile(timestampPattern).FindStringSubmatch(line)
	if len(tsMatches) >= 2 {
		ts, err := time.Parse("02/Jan/2006:15:04:05 -0700", tsMatches[1])
		if err == nil {
			entry.Timestamp = ts
		}
	}

	// IP adresleri ve portlar
	ipMatches := regexp.MustCompile(ipPortPattern).FindStringSubmatch(line)
	if len(ipMatches) >= 5 {
		entry.ClientIP = ipMatches[1]
		entry.ClientPort = ipMatches[2]
		entry.ServerIP = ipMatches[3]
		entry.ServerPort = ipMatches[4]
	}

	// Method ve Path
	methodMatches := regexp.MustCompile(methodPathPattern).FindStringSubmatch(line)
	if len(methodMatches) >= 3 {
		entry.Method = methodMatches[1]
		entry.Path = methodMatches[2]
		
		// URL'den promotion ID'yi çıkar
		promotionMatches := regexp.MustCompile(promotionPattern).FindStringSubmatch(entry.Path)
		if len(promotionMatches) >= 2 {
			entry.PromotionID = promotionMatches[1]
		}
	}

	// Referer - method ve path'ten sonraki tırnak içindeki içerik
	parts := strings.Split(line, methodPathPattern)
	if len(parts) >= 2 {
		refererMatches := regexp.MustCompile(refererPattern).FindStringSubmatch(parts[1])
		if len(refererMatches) >= 2 {
			entry.Referer = refererMatches[1]
		}
	}

	// Status ve Bytes
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

	// Gerekli alanların dolu olup olmadığını kontrol et
	if entry.ClientIP != "" && entry.Method != "" && entry.Path != "" {
		return entry, true
	}
	
	log.Printf("Ayrıştırılamayan log satırı: %s", line)
	return LogEntry{}, false
}
