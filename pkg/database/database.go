package database

import (
	"log"
	"sync"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// DB is the global database handle for the application.
var DB *gorm.DB

var (
	initOnce sync.Once
	initErr  error
)

// Project represents a scaffolded service project.
type Project struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	Name         string    `json:"name"`
	Description  string    `json:"description"`
	GitHubRepo   string    `json:"github_repo"`
	TemplateType string    `json:"template_type"`
	CreatedAt    time.Time `json:"created_at"`
}

// InfrastructureResource represents an infrastructure resource requested for a project.
type InfrastructureResource struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	ProjectID    uint      `json:"project_id"`
	ResourceName string    `json:"resource_name"`
	Type         string    `json:"type"`   // e.g., RDS
	Size         string    `json:"size"`   // Small, Medium, Large
	Status       string    `json:"status"` // Requested, Provisioning, Available, Error
	CreatedAt    time.Time `json:"created_at"`
}

// MonitoredDomain represents a domain monitored by the certificate scanner.
type MonitoredDomain struct {
	gorm.Model                     // 嵌入此项会自动添加 ID, CreatedAt, UpdatedAt, DeletedAt
	DomainName           string    `gorm:"uniqueIndex" json:"domain_name"`
	LastExpiryDate       time.Time `json:"last_expiry_date"`
	Registrar            string    `json:"registrar"`
	Status               string    `json:"status"`
	SSLExpiry            time.Time `json:"ssl_expiry"`
	SSLStatus            string    `json:"ssl_status"`
	LastCheckTime        time.Time `json:"last_check_time"`
	AutoRenew            bool      `json:"auto_renew" gorm:"default:true"` // 续费提醒开关
	LastNotificationSent time.Time `json:"last_notification_sent" gorm:"column:last_notification_sent"`
	IsLive               bool      `json:"is_live" gorm:"default:false"`
	StatusCode           int       `json:"status_code" gorm:"default:0"`
	LastStatusCode       int       `json:"last_status_code" gorm:"default:0"` // Last HTTP status code received
	ResponseTime         int       `json:"response_time" gorm:"default:0"`    // Response time in milliseconds
}

// User represents an authenticated platform user.
type User struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	Username  string    `gorm:"uniqueIndex" json:"username"`
	Password  string    `json:"-"` // Hashed password, never exposed in JSON responses.
	Role      string    `json:"role"`
	Status    string    `gorm:"default:'pending'" json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// NotificationConfig stores webhook configuration for notification platforms
type NotificationConfig struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	WebhookURL string    `json:"webhook_url" gorm:"column:webhook_url"`
	SecretKey  string    `json:"secret_key" gorm:"column:secret_key"`
	Platform   string    `json:"platform"` // e.g., DingTalk, Feishu, Slack
	IsActive   bool      `json:"is_active" gorm:"default:true"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// MessageTemplate stores notification message templates for different events
// Also known as NotificationTemplate with fields: Type (Name/EventName), Content (TemplateText)
type MessageTemplate struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	EventName     string    `json:"event_name" gorm:"uniqueIndex"` // e.g., "SSL_EXPIRED", "SITE_DOWN"
	TitleTemplate string    `json:"title_template" gorm:"column:title_template"`
	BodyTemplate  string    `json:"body_template" gorm:"column:body_template"`
	Name          string    `json:"name" gorm:"column:name"`                   // Type: "SiteDown", "SSLExpired"
	TemplateText  string    `json:"template_text" gorm:"column:template_text"` // Content: Template text for Telegram
	Template      string    `gorm:"type:text" json:"template"`                 // Alias for TemplateText (backward compatibility)
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// NotifyConfig stores Telegram bot configuration for notifications
// Also known as TelegramConfig with fields: BotToken (TGToken), ChatID (TGChatID), IsEnabled (IsActive)
type NotifyConfig struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	TGToken   string    `json:"tg_token" gorm:"column:tg_token"`     // Telegram bot token (BotToken)
	TGChatID  string    `json:"tg_chat_id" gorm:"column:tg_chat_id"` // Telegram chat ID (ChatID)
	IsActive  bool      `json:"is_active" gorm:"default:true"`       // IsEnabled flag
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TelegramConfig stores Telegram bot configuration for notifications (backward compatibility alias)
type TelegramConfig struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	BotToken  string    `gorm:"uniqueIndex" json:"bot_token"`
	ChatID    string    `json:"chat_id"`
	Enabled   bool      `gorm:"default:true" json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Init initializes the global SQLite database connection and runs migrations.
// It is safe to call Init multiple times; initialization will only happen once.
func Init() error {
	initOnce.Do(func() {
		db, err := gorm.Open(sqlite.Open("zenstack.db"), &gorm.Config{})
		if err != nil {
			initErr = err
			return
		}

		// Perform automatic schema migration for core models.
		if err := db.AutoMigrate(
			&Project{},
			&InfrastructureResource{},
			&MonitoredDomain{},
			&User{},
			&NotificationConfig{},
			&MessageTemplate{},
			&NotifyConfig{},
			&TelegramConfig{}, // Backward compatibility
		); err != nil {
			initErr = err
			return
		}

		// Ensure admin user is always active for development
		if err := db.Exec("UPDATE users SET status = 'active' WHERE username = 'admin'").Error; err != nil {
			// Log but don't fail initialization if admin doesn't exist yet
			log.Printf("warning: could not update admin status: %v", err)
		} else {
			log.Println("admin user status ensured to be active")
		}

		// Seed default message templates
		seedMessageTemplates(db)

		DB = db
		log.Println("database initialized and migrations applied")
	})

	return initErr
}

// seedMessageTemplates seeds default message templates if they don't exist
func seedMessageTemplates(db *gorm.DB) {
	// Seed SiteDown template
	var siteDownTemplate MessageTemplate
	if err := db.Where("name = ? OR event_name = ?", "SiteDown", "SITE_DOWN").First(&siteDownTemplate).Error; err != nil {
		// Template doesn't exist, create it
		siteDownTemplate = MessageTemplate{
			Name:          "SiteDown",
			EventName:     "SITE_DOWN",
			TemplateText:  "🚨 告警：站点 {{domain}} 无法访问！状态码：{{status}}",
			TitleTemplate: "Site Down Alert",
			BodyTemplate:  "Site {{domain}} is down. Status code: {{status_code}}",
		}
		if err := db.Create(&siteDownTemplate).Error; err != nil {
			log.Printf("warning: failed to create SiteDown template: %v", err)
		} else {
			log.Println("SiteDown message template seeded")
		}
	}

	// Seed SSLExpired template
	var sslExpiredTemplate MessageTemplate
	if err := db.Where("name = ? OR event_name = ?", "SSLExpired", "SSL_CRITICAL").First(&sslExpiredTemplate).Error; err != nil {
		// Template doesn't exist, create it
		sslExpiredTemplate = MessageTemplate{
			Name:          "SSLExpired",
			EventName:     "SSL_CRITICAL",
			TemplateText:  "🔒 证书预警：域名 {{domain}} 的 SSL 证书将在 {{days}} 天后过期。",
			TitleTemplate: "SSL Certificate Warning",
			BodyTemplate:  "SSL certificate for {{domain}} will expire in {{days_remaining}} days.",
		}
		if err := db.Create(&sslExpiredTemplate).Error; err != nil {
			log.Printf("warning: failed to create SSLExpired template: %v", err)
		} else {
			log.Println("SSLExpired message template seeded")
		}
	}
}
