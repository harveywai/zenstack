package database

import (
	"errors"
	"log"

	"github.com/harveywai/zenstack/pkg/auth"
)

var (
	// ErrDatabaseNotInitialized is returned when database operations are attempted before initialization.
	ErrDatabaseNotInitialized = errors.New("database not initialized")
)

// SeedAdmin creates a default admin user if no users exist, and ensures
// the admin user's status is always set to "active" to prevent lockout during development.
func SeedAdmin() error {
	if DB == nil {
		return ErrDatabaseNotInitialized
	}

	var count int64
	if err := DB.Model(&User{}).Count(&count).Error; err != nil {
		return err
	}

	// If no users exist, create the default admin user.
	if count == 0 {
		hashed, err := auth.HashPassword("zenstack2026")
		if err != nil {
			return err
		}

		admin := User{
			Username: "admin",
			Password: hashed,
			Role:     "admin",
			Status:   "active", // Explicitly set status to active
		}

		if err := DB.Create(&admin).Error; err != nil {
			return err
		}

		log.Println("Default admin user 'admin' created with password 'zenstack2026'")
	}

	// Ensure admin user status is always active (prevents lockout during development).
	if err := DB.Model(&User{}).Where("username = ?", "admin").Update("status", "active").Error; err != nil {
		// Log but don't fail if admin doesn't exist yet (will be created on next run)
		log.Printf("warning: could not ensure admin status is active: %v", err)
	} else {
		log.Println("Admin user status ensured to be active")
	}

	return nil
}
