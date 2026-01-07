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
	ID          uint      `gorm:"primaryKey" json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	GitHubRepo  string    `json:"github_repo"`
	TemplateType string   `json:"template_type"`
	CreatedAt   time.Time `json:"created_at"`
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
	ID             uint      `gorm:"primaryKey" json:"id"`
	DomainName     string    `json:"domain_name"`
	LastExpiryDate time.Time `json:"last_expiry_date"`
	Registrar      string    `json:"registrar"`
	Status         string    `json:"status"`
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

		DB = db
		log.Println("database initialized and migrations applied")
	})

	return initErr
}

