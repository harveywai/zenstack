package infra

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/harveywai/zenstack/pkg/database"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// DatabaseResource represents a database instance to be provisioned.
type DatabaseResource struct {
	Name   string `json:"name"`
	Engine string `json:"engine"` // Postgres or MySQL
	Size   string `json:"size"`   // Small, Medium, Large
	Status string `json:"status"`
}

// SizeOption describes a predefined T-shirt size for database resources.
type SizeOption struct {
	Name  string `json:"name"`
	VCPU  int    `json:"vcpu"`
	RAMGB int    `json:"ram_gb"`
}

// DatabaseSizeOptions defines the available T-shirt sizes for databases.
var DatabaseSizeOptions = []SizeOption{
	{
		Name:  "Small",
		VCPU:  1,
		RAMGB: 2,
	},
	{
		Name:  "Medium",
		VCPU:  2,
		RAMGB: 4,
	},
	{
		Name:  "Large",
		VCPU:  4,
		RAMGB: 8,
	},
}

// FindSizeOption returns the SizeOption matching the given name (case-insensitive).
// If there is no match, false is returned.
func FindSizeOption(name string) (SizeOption, bool) {
	for _, opt := range DatabaseSizeOptions {
		if strings.EqualFold(opt.Name, name) {
			return opt, true
		}
	}
	return SizeOption{}, false
}

// ResourceStatus represents a simplified, human-readable status for a managed resource.
type ResourceStatus struct {
	State string `json:"state"` // Available, Provisioning, Error, Unknown
	Color string `json:"color"` // green, yellow, red, grey
}

// managedResourceGVR defines the Crossplane managed resource type to query.
// Update this to match your actual Crossplane CRD (group, version, resource).
var managedResourceGVR = schema.GroupVersionResource{
	Group:    "database.example.org",
	Version:  "v1alpha1",
	Resource: "postgresqlinstances",
}

// GetResourceStatus queries the Kubernetes cluster for a Crossplane managed resource associated
// with the given projectName and maps its status.conditions to a human-readable state.
//
// Mapping:
//   Synced=True && Ready=True -> Available (green)
//   Ready=False                -> Provisioning (yellow)
//   Else                       -> Error (red)
//
// If the resource cannot be found or the cluster cannot be reached, the function returns
// a status of Unknown (grey) instead of failing.
func GetResourceStatus(projectName string) (ResourceStatus, error) {
	if projectName == "" {
		return ResourceStatus{State: "Unknown", Color: "grey"}, nil
	}

	cfg, err := loadKubeConfig()
	if err != nil {
		// Do not fail hard if the cluster is not reachable.
		return ResourceStatus{State: "Unknown", Color: "grey"}, nil
	}

	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return ResourceStatus{State: "Unknown", Color: "grey"}, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Assume the managed resource is cluster-scoped and named after the project.
	res, err := dyn.Resource(managedResourceGVR).Get(ctx, projectName, metav1.GetOptions{})
	if err != nil {
		// Resource not found or other error; treat as Unknown.
		return ResourceStatus{State: "Unknown", Color: "grey"}, nil
	}

	status := res.Object["status"]
	statusMap, ok := status.(map[string]any)
	if !ok {
		return ResourceStatus{State: "Unknown", Color: "grey"}, nil
	}

	rawConds, ok := statusMap["conditions"].([]any)
	if !ok {
		return ResourceStatus{State: "Unknown", Color: "grey"}, nil
	}

	var syncedTrue, readyTrue, readyFalse bool

	for _, c := range rawConds {
		cond, ok := c.(map[string]any)
		if !ok {
			continue
		}
		t, _ := cond["type"].(string)
		s, _ := cond["status"].(string)

		switch t {
		case "Synced":
			if strings.EqualFold(s, "True") {
				syncedTrue = true
			}
		case "Ready":
			if strings.EqualFold(s, "True") {
				readyTrue = true
			}
			if strings.EqualFold(s, "False") {
				readyFalse = true
			}
		}
	}

	switch {
	case syncedTrue && readyTrue:
		return ResourceStatus{State: "Available", Color: "green"}, nil
	case readyFalse:
		return ResourceStatus{State: "Provisioning", Color: "yellow"}, nil
	default:
		return ResourceStatus{State: "Error", Color: "red"}, nil
	}
}

// loadKubeConfig attempts to load in-cluster configuration, falling back to KUBECONFIG or default kubeconfig path.
func loadKubeConfig() (*rest.Config, error) {
	// Try in-cluster config first.
	if cfg, err := rest.InClusterConfig(); err == nil {
		return cfg, nil
	}

	// Fall back to KUBECONFIG or default kubeconfig path.
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		kubeconfig = home + "/.kube/config"
	}

	return clientcmd.BuildConfigFromFlags("", kubeconfig)
}

// RecordInfrastructureRequest stores a new infrastructure resource record for the given request.
// If the corresponding project exists in the database, its ID will be associated with the resource.
// This function is best-effort and does not return an error if persistence fails.
func RecordInfrastructureRequest(name, engine, size string) {
	if database.DB == nil {
		return
	}

	var project database.Project
	if err := database.DB.Where("name = ?", name).First(&project).Error; err != nil {
		// Project may not exist yet; still record the resource with ProjectID=0.
	}

	res := database.InfrastructureResource{
		ProjectID:    project.ID,
		ResourceName: name,
		Type:         engine,
		Size:         size,
		Status:       "Requested",
	}

	_ = database.DB.Create(&res).Error
}

