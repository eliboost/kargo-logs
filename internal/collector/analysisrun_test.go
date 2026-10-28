package collector

import (
	"context"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
	"gitlab.pnet.ch/middleware/kargo/kargo-analysisrun-logs/internal/store"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

func TestBuildRestConfig_DefaultsExecInteractiveModeToNever(t *testing.T) {
	t.Parallel()

	cfg, err := buildRestConfig(clusterConfig{
		Server: "https://example.com",
		Config: clusterConnectionConfig{
			ExecProviderConfig: &execProviderConfig{
				Command:    "credential-plugin",
				APIVersion: "client.authentication.k8s.io/v1",
			},
		},
	})
	if err != nil {
		t.Fatalf("buildRestConfig() returned error: %v", err)
	}

	if got := cfg.ExecProvider.InteractiveMode; got != clientcmdapi.NeverExecInteractiveMode {
		t.Fatalf("expected interactive mode %q, got %q", clientcmdapi.NeverExecInteractiveMode, got)
	}
}

func TestBuildRestConfig_UsesConfiguredExecInteractiveMode(t *testing.T) {
	t.Parallel()

	cfg, err := buildRestConfig(clusterConfig{
		Server: "https://example.com",
		Config: clusterConnectionConfig{
			ExecProviderConfig: &execProviderConfig{
				Command:         "credential-plugin",
				APIVersion:      "client.authentication.k8s.io/v1",
				InteractiveMode: string(clientcmdapi.IfAvailableExecInteractiveMode),
			},
		},
	})
	if err != nil {
		t.Fatalf("buildRestConfig() returned error: %v", err)
	}

	if got := cfg.ExecProvider.InteractiveMode; got != clientcmdapi.IfAvailableExecInteractiveMode {
		t.Fatalf("expected interactive mode %q, got %q", clientcmdapi.IfAvailableExecInteractiveMode, got)
	}
}

func TestBuildRestConfig_RejectsInvalidExecInteractiveMode(t *testing.T) {
	t.Parallel()

	_, err := buildRestConfig(clusterConfig{
		Server: "https://example.com",
		Config: clusterConnectionConfig{
			ExecProviderConfig: &execProviderConfig{
				Command:         "credential-plugin",
				APIVersion:      "client.authentication.k8s.io/v1",
				InteractiveMode: "invalid-mode",
			},
		},
	})
	if err == nil {
		t.Fatal("expected buildRestConfig() to fail for invalid interactive mode")
	}

	if !strings.Contains(err.Error(), "invalid execProviderConfig.interactiveMode") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestIndexAnalysisRunByName(t *testing.T) {
	t.Parallel()

	got, err := indexAnalysisRunByName(&v1alpha1.AnalysisRun{
		ObjectMeta: metav1.ObjectMeta{
			Name: "analysisrun-1",
		},
	})
	if err != nil {
		t.Fatalf("indexAnalysisRunByName() returned error: %v", err)
	}

	want := []string{"analysisrun-1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected index %v, got %v", want, got)
	}
}

func TestIndexAnalysisRunByNamespacedName(t *testing.T) {
	t.Parallel()

	got, err := indexAnalysisRunByNamespacedName(&v1alpha1.AnalysisRun{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "kube-kargo",
			Name:      "analysisrun-1",
		},
	})
	if err != nil {
		t.Fatalf("indexAnalysisRunByNamespacedName() returned error: %v", err)
	}

	want := []string{"kube-kargo/analysisrun-1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected index %v, got %v", want, got)
	}
}

func TestIndexAnalysisRunByName_RejectsInvalidObject(t *testing.T) {
	t.Parallel()

	_, err := indexAnalysisRunByName("invalid")
	if err == nil {
		t.Fatal("expected indexAnalysisRunByName() to return an error for invalid object")
	}
}

func TestCollectContainerLogs_SkipsNonJobMetrics(t *testing.T) {
	t.Parallel()

	st, err := store.NewLocalDisk(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalDisk() returned error: %v", err)
	}

	c := &Collector{store: st, activeStreams: make(map[string]struct{})}

	// AnalysisRun with only a non-job metric – no files should be created.
	ar := &v1alpha1.AnalysisRun{
		ObjectMeta: metav1.ObjectMeta{Namespace: "kube-kargo", Name: "analysisrun-1"},
		Spec: v1alpha1.AnalysisRunSpec{
			Metrics: []v1alpha1.Metric{
				{Name: "prometheus-check"}, // no Job provider
			},
		},
		Status: v1alpha1.AnalysisRunStatus{
			MetricResults: []v1alpha1.MetricResult{
				{Name: "prometheus-check"},
			},
		},
	}

	// startContainerLogStreams with a nil kubeClient is safe because no job
	// metrics are present – the code returns before any API call is made.
	c.startContainerLogStreams(context.Background(), slog.Default(), nil, ar)

	key := store.Key{
		Namespace:   "kube-kargo",
		AnalysisRun: "analysisrun-1",
		JobName:     analysisRunEventJobName,
		Container:   analysisRunEventContainerName,
	}

	exists, err := st.Exists(context.Background(), key)
	if err != nil {
		t.Fatalf("Exists() returned error: %v", err)
	}

	if exists {
		t.Fatal("expected no log file to be created for a non-job metric")
	}
}

func TestCollectContainerLogs_SkipsMetricsWithoutMeasurements(t *testing.T) {
	t.Parallel()

	st, err := store.NewLocalDisk(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalDisk() returned error: %v", err)
	}

	c := &Collector{store: st, activeStreams: make(map[string]struct{})}

	ar := &v1alpha1.AnalysisRun{
		ObjectMeta: metav1.ObjectMeta{Namespace: "kube-kargo", Name: "analysisrun-2"},
		Spec: v1alpha1.AnalysisRunSpec{
			Metrics: []v1alpha1.Metric{
				{
					Name: "job-check",
					Provider: v1alpha1.MetricProvider{
						Job: &v1alpha1.JobMetric{},
					},
				},
			},
		},
		Status: v1alpha1.AnalysisRunStatus{
			// MetricResults has the metric but with no measurements → no job-name metadata.
			MetricResults: []v1alpha1.MetricResult{
				{Name: "job-check", Measurements: nil},
			},
		},
	}

	c.startContainerLogStreams(context.Background(), slog.Default(), nil, ar)

	key := store.Key{
		Namespace:   "kube-kargo",
		AnalysisRun: "analysisrun-2",
		JobName:     "job-check",
		Container:   analysisRunEventContainerName,
	}

	exists, err := st.Exists(context.Background(), key)
	if err != nil {
		t.Fatalf("Exists() returned error: %v", err)
	}

	if exists {
		t.Fatal("expected no log file to be created when there are no measurements")
	}
}
