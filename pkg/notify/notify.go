package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/harveywai/zenstack/pkg/database"
)

// formatMessage replaces placeholders in a template string with actual values from the data map.
// Placeholders are in the format {{key}} and will be replaced with the corresponding value from data.
// Example: formatMessage("Domain {{domain}} expires on {{expiry}}", map[string]string{"domain": "example.com", "expiry": "2024-01-01"})
// Returns: "Domain example.com expires on 2024-01-01"
func formatMessage(template string, data map[string]string) string {
	if template == "" {
		return ""
	}

	result := template
	// Match placeholders like {{key}} or {{ key }}
	re := regexp.MustCompile(`\{\{\s*(\w+)\s*\}\}`)

	result = re.ReplaceAllStringFunc(result, func(match string) string {
		// Extract the key from {{key}}
		keyMatch := re.FindStringSubmatch(match)
		if len(keyMatch) < 2 {
			return match
		}
		key := strings.TrimSpace(keyMatch[1])

		// Replace with value from data map, or keep original if not found
		if value, ok := data[key]; ok {
			return value
		}
		return match
	})

	return result
}

// NotificationPayload represents the JSON payload sent to webhooks
type NotificationPayload struct {
	Title  string                 `json:"title"`
	Body   string                 `json:"body"`
	Event  string                 `json:"event"`
	Domain string                 `json:"domain"`
	Time   string                 `json:"time"`
	Extra  map[string]interface{} `json:"extra,omitempty"`
}

// SendNotification sends a notification to all active webhook configurations for a given event.
// It retrieves the message template for the event, formats it with the provided data,
// and sends POST requests to all active notification configs.
func SendNotification(eventName string, domain database.MonitoredDomain, extraData map[string]string) error {
	if database.DB == nil {
		return fmt.Errorf("database not initialized")
	}

	// Get message template for this event
	var template database.MessageTemplate
	if err := database.DB.Where("event_name = ?", eventName).First(&template).Error; err != nil {
		log.Printf("No template found for event %s, skipping notification", eventName)
		return fmt.Errorf("no template found for event: %s", eventName)
	}

	// Prepare data map for template formatting
	data := make(map[string]string)
	data["domain"] = domain.DomainName
	data["expiry"] = domain.SSLExpiry.Format("2006-01-02 15:04:05")
	data["expiry_date"] = domain.SSLExpiry.Format("2006-01-02")
	data["days_remaining"] = fmt.Sprintf("%d", int(time.Until(domain.SSLExpiry).Hours()/24))
	data["ssl_status"] = domain.SSLStatus
	data["registrar"] = domain.Registrar
	data["status"] = domain.Status

	// Add any extra data
	for k, v := range extraData {
		data[k] = v
	}

	// Format title and body templates
	title := formatMessage(template.TitleTemplate, data)
	body := formatMessage(template.BodyTemplate, data)

	// Format Telegram template text if available
	telegramText := formatMessage(template.TemplateText, data)
	if telegramText == "" {
		// Fallback to body template if TemplateText is empty
		telegramText = body
	}

	// Get all active notification configs (webhooks)
	var configs []database.NotificationConfig
	if err := database.DB.Where("is_active = ?", true).Find(&configs).Error; err != nil {
		log.Printf("Error fetching notification configs: %v", err)
		return err
	}

	// Get all active Telegram notification configs
	var telegramConfigs []database.NotifyConfig
	if err := database.DB.Where("is_active = ?", true).Find(&telegramConfigs).Error; err != nil {
		log.Printf("Error fetching Telegram notification configs: %v", err)
		// Don't return error, just log it
	}

	// Prepare webhook payload
	payload := NotificationPayload{
		Title:  title,
		Body:   body,
		Event:  eventName,
		Domain: domain.DomainName,
		Time:   time.Now().Format(time.RFC3339),
		Extra: map[string]interface{}{
			"ssl_expiry":     domain.SSLExpiry.Format(time.RFC3339),
			"ssl_status":     domain.SSLStatus,
			"days_remaining": int(time.Until(domain.SSLExpiry).Hours() / 24),
			"registrar":      domain.Registrar,
		},
	}

	// Send to all active webhooks
	successCount := 0
	for _, config := range configs {
		if err := sendWebhook(config, payload); err != nil {
			log.Printf("Failed to send notification to %s (%s): %v", config.Platform, config.WebhookURL, err)
		} else {
			successCount++
			log.Printf("Successfully sent notification to %s for domain %s", config.Platform, domain.DomainName)
		}
	}

	// Send to all active Telegram bots
	for _, tgConfig := range telegramConfigs {
		if err := SendTelegramMessage(tgConfig.TGToken, tgConfig.TGChatID, telegramText); err != nil {
			log.Printf("Failed to send Telegram notification (chat_id: %s): %v", tgConfig.TGChatID, err)
		} else {
			successCount++
			log.Printf("Successfully sent Telegram notification for domain %s", domain.DomainName)
		}
	}

	if successCount == 0 {
		return fmt.Errorf("failed to send notification to any channel")
	}

	return nil
}

// sendWebhook sends a POST request to a specific webhook URL with the notification payload
func sendWebhook(config database.NotificationConfig, payload NotificationPayload) error {
	// Marshal payload to JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequest("POST", config.WebhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	if config.SecretKey != "" {
		// Add secret key as Authorization header or custom header based on platform
		switch strings.ToLower(config.Platform) {
		case "slack":
			// Slack uses Bearer token
			req.Header.Set("Authorization", "Bearer "+config.SecretKey)
		case "dingtalk", "feishu":
			// DingTalk and Feishu might use custom headers
			req.Header.Set("X-Secret-Key", config.SecretKey)
		default:
			// Generic webhook - use Authorization header
			req.Header.Set("Authorization", "Bearer "+config.SecretKey)
		}
	}

	// Send request with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status code %d", resp.StatusCode)
	}

	return nil
}

// sendTGMessage sends a message to Telegram using the Bot API
// It uses http.Post to send a POST request to https://api.telegram.org/bot<token>/sendMessage
// Parameters: chat_id and text
// This is the internal implementation function
func sendTGMessage(token string, chatID string, content string) error {
	if token == "" || chatID == "" {
		return fmt.Errorf("telegram token and chat_id are required")
	}

	if content == "" {
		return fmt.Errorf("message content cannot be empty")
	}

	// Construct the API URL
	apiURL := fmt.Sprintf("https://api.telegram.org/bot%s/sendMessage", token)

	// Prepare the request payload
	payload := map[string]string{
		"chat_id": chatID,
		"text":    content,
	}

	// Marshal payload to JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Create HTTP request with POST method
	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Send request with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Read response body for error details
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Check status code
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Try to parse error response from Telegram API
		var errorResp struct {
			OK          bool   `json:"ok"`
			ErrorCode   int    `json:"error_code,omitempty"`
			Description string `json:"description,omitempty"`
		}
		if err := json.Unmarshal(bodyBytes, &errorResp); err == nil {
			return fmt.Errorf("telegram API error: %s (code: %d)", errorResp.Description, errorResp.ErrorCode)
		}
		return fmt.Errorf("telegram API returned status code %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Verify response is OK
	var response struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal(bodyBytes, &response); err == nil {
		if !response.OK {
			return fmt.Errorf("telegram API returned ok=false")
		}
	}

	return nil
}

// SendTelegramMessage is an exported alias for sendTGMessage
// It uses http.Post to send a POST request to https://api.telegram.org/bot<token>/sendMessage
// Parameters: chat_id and text
// This function is exported so it can be called directly from other packages
func SendTelegramMessage(token string, chatID string, content string) error {
	return sendTGMessage(token, chatID, content)
}

// ParseTemplate is a simple string replacement function that replaces placeholders like {{domain}} with actual values
// This is an alias for formatMessage for backward compatibility and clarity
func ParseTemplate(template string, data map[string]string) string {
	return formatMessage(template, data)
}

// SendTelegramAlert sends a message to Telegram using the active configuration from the database
// It automatically reads the Telegram bot token and chat ID from the database
// This is the main function for sending Telegram alerts
func SendTelegramAlert(message string) error {
	if message == "" {
		return fmt.Errorf("message cannot be empty")
	}

	// Get active Telegram config from database
	var config database.NotifyConfig
	if err := database.DB.Where("is_active = ?", true).First(&config).Error; err != nil {
		return fmt.Errorf("no active Telegram configuration found: %w", err)
	}

	// Send message using the active configuration
	return sendTGMessage(config.TGToken, config.TGChatID, message)
}

// NotifyTelegram is an alias for SendTelegramAlert (backward compatibility)
func NotifyTelegram(message string) error {
	return SendTelegramAlert(message)
}

// sendTG is a simplified function that sends a message to Telegram
// It automatically reads the Telegram bot token and chat ID from the database
// This is a convenience wrapper around SendTelegramAlert
func sendTG(message string) error {
	return SendTelegramAlert(message)
}

// SendTG is the exported version of sendTG for use in other packages
func SendTG(message string) error {
	return sendTG(message)
}
