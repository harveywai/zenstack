package scaffolder

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/template"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing/object"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/google/go-github/v60/github"
	"github.com/harveywai/zenstack/pkg/database"
	"golang.org/x/oauth2"
)

// ServiceConfig holds the configuration used to scaffold a new service.
type ServiceConfig struct {
	ProjectName string
	Description string
	GitHubToken string
}

// CreateService scaffolds a new Go/Gin service from a local template and pushes it to GitHub.
// It performs the following steps:
//   1. Copies the local template directory to a temporary folder.
//   2. Applies text templates to selected files (README.md, go.mod, main.go).
//   3. Creates a new public GitHub repository using the provided GitHub token.
//   4. Initializes a local git repository and pushes the code to the new GitHub repository.
func CreateService(ctx context.Context, cfg ServiceConfig) (string, error) {
	if cfg.ProjectName == "" {
		return "", fmt.Errorf("project name is required")
	}
	if cfg.GitHubToken == "" {
		return "", fmt.Errorf("github token is required")
	}

	// Source template directory inside this repository.
	templateDir := filepath.Join("templates", "go-gin-starter")

	// Create a temporary directory for the new project.
	tmpDir, err := os.MkdirTemp("", "zenstack-"+cfg.ProjectName+"-")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	// Copy all files from templateDir into tmpDir.
	if err := copyDir(templateDir, tmpDir); err != nil {
		return "", fmt.Errorf("failed to copy template directory: %w", err)
	}

	// Apply templates to key files.
	if err := applyTemplates(tmpDir, cfg); err != nil {
		return "", fmt.Errorf("failed to apply templates: %w", err)
	}

	// Create GitHub repository.
	repo, err := createGitHubRepo(ctx, cfg)
	if err != nil {
		return "", fmt.Errorf("failed to create GitHub repository: %w", err)
	}

	// Initialize git repository in tmpDir and push contents.
	if err := initAndPushGitRepo(tmpDir, cfg, repo.GetCloneURL()); err != nil {
		return "", fmt.Errorf("failed to initialize and push git repository: %w", err)
	}

	// Persist project metadata in the database.
	project := database.Project{
		Name:         cfg.ProjectName,
		Description:  cfg.Description,
		GitHubRepo:   repo.GetHTMLURL(),
		TemplateType: "go-gin-starter",
	}
	if database.DB != nil {
		if err := database.DB.Create(&project).Error; err != nil {
			// Log the error but do not fail the scaffolding operation.
			fmt.Printf("failed to persist project in database: %v\n", err)
		}
	}

	return repo.GetHTMLURL(), nil
}

// copyDir recursively copies src directory contents into dst directory.
// It preserves the relative directory structure.
func copyDir(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)

		if info.IsDir() {
			// Ensure target directory exists.
			return os.MkdirAll(target, 0o755)
		}

		// Copy regular file.
		return copyFile(path, target)
	})
}

// copyFile copies a single file from src to dst.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}

	return out.Close()
}

// applyTemplates processes selected files in the target directory using Go text/template.
func applyTemplates(root string, cfg ServiceConfig) error {
	data := map[string]any{
		"ProjectName": cfg.ProjectName,
		"Description": cfg.Description,
	}

	// Files to process as templates relative to root.
	templateFiles := []string{
		"README.md",
		"go.mod",
		filepath.Join("cmd", "server", "main.go"),
	}

	for _, rel := range templateFiles {
		full := filepath.Join(root, rel)
		if _, err := os.Stat(full); err != nil {
			// If file does not exist in template, skip silently.
			continue
		}

		content, err := os.ReadFile(full)
		if err != nil {
			return fmt.Errorf("failed to read template file %s: %w", full, err)
		}

		tmpl, err := template.New(filepath.Base(rel)).Parse(string(content))
		if err != nil {
			return fmt.Errorf("failed to parse template %s: %w", full, err)
		}

		f, err := os.Create(full)
		if err != nil {
			return fmt.Errorf("failed to open file for writing %s: %w", full, err)
		}

		if err := tmpl.Execute(f, data); err != nil {
			_ = f.Close()
			return fmt.Errorf("failed to execute template for %s: %w", full, err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("failed to close file %s: %w", full, err)
		}
	}

	return nil
}

// createGitHubRepo uses the GitHub API to create a new public repository.
func createGitHubRepo(ctx context.Context, cfg ServiceConfig) (*github.Repository, error) {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: cfg.GitHubToken},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	repo := &github.Repository{
		Name:        github.String(cfg.ProjectName),
		Description: github.String(cfg.Description),
		Private:     github.Bool(false),
	}

	created, _, err := client.Repositories.Create(ctx, "", repo)
	if err != nil {
		return nil, err
	}

	return created, nil
}

// initAndPushGitRepo initializes a git repository in the given directory and pushes it to the remote URL.
func initAndPushGitRepo(dir string, cfg ServiceConfig, remoteURL string) error {
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		return fmt.Errorf("failed to init git repo: %w", err)
	}

	w, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get worktree: %w", err)
	}

	// Add all files.
	if err := w.AddWithOptions(&git.AddOptions{All: true}); err != nil {
		return fmt.Errorf("failed to add files: %w", err)
	}

	// Commit with a simple message.
	_, err = w.Commit("Initial commit from ZenStack scaffolder", &git.CommitOptions{
		Author: &object.Signature{
			Name:  "ZenStack Scaffolder",
			Email: "noreply@example.com",
			When:  time.Now(),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to commit: %w", err)
	}

	// Configure remote "origin".
	if _, err := repo.CreateRemote(&config.RemoteConfig{
		Name: "origin",
		URLs: []string{remoteURL},
	}); err != nil {
		return fmt.Errorf("failed to create remote: %w", err)
	}

	// Use HTTPS with personal access token for authentication.
	auth := &githttp.BasicAuth{
		Username: "github-token",    // Username is not important for PAT auth, but cannot be empty.
		Password: cfg.GitHubToken,   // Token is passed as the password.
	}

	if err := repo.Push(&git.PushOptions{
		RemoteName: "origin",
		Auth:       auth,
	}); err != nil {
		return fmt.Errorf("failed to push to remote: %w", err)
	}

	return nil
}

