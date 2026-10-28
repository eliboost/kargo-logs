package collector

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsclientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"gitlab.pnet.ch/middleware/kargo/kargo-analysisrun-logs/internal/store"
)

func TestCollector_ReconcilesClusterSecrets(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS is not set")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	testEnv := &envtest.Environment{}
	cfg, err := testEnv.Start()
	if err != nil {
		t.Fatalf("start envtest: %v", err)
	}
	defer func() {
		if stopErr := testEnv.Stop(); stopErr != nil {
			t.Fatalf("stop envtest: %v", stopErr)
		}
	}()

	if err := installAnalysisRunCRD(ctx, cfg); err != nil {
		t.Fatalf("install analysisrun CRD: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatalf("create kubernetes client: %v", err)
	}

	const namespace = "kube-kargo"
	if _, err := clientset.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{Name: namespace},
	}, metav1.CreateOptions{}); err != nil {
		t.Fatalf("create namespace: %v", err)
	}

	st, err := store.NewLocalDisk(t.TempDir())
	if err != nil {
		t.Fatalf("create local store: %v", err)
	}

	collector, err := NewWithConfig(cfg, namespace, st)
	if err != nil {
		t.Fatalf("create collector: %v", err)
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- collector.Start(ctx)
	}()

	secretClient := clientset.CoreV1().Secrets(namespace)
	secret, err := secretClient.Create(ctx, mustClusterSecret(t, namespace, "cluster-one", cfg, "v1"), metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("create cluster secret: %v", err)
	}

	secretKey := namespace + "/" + secret.Name
	waitForWatchers(t, collector, 1)
	initialFingerprint := watcherFingerprint(t, collector, secretKey)

	updated := secret.DeepCopy()
	updated.Data["config"] = mustConfigJSON(t, cfg, "v2")
	if _, err := secretClient.Update(ctx, updated, metav1.UpdateOptions{}); err != nil {
		t.Fatalf("update cluster secret: %v", err)
	}

	waitForWatcherFingerprintChange(t, collector, secretKey, initialFingerprint)

	if err := secretClient.Delete(ctx, secret.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatalf("delete cluster secret: %v", err)
	}
	waitForWatchers(t, collector, 0)

	cancel()
	select {
	case runErr := <-errCh:
		if runErr != nil {
			t.Fatalf("collector exited with error: %v", runErr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("collector did not stop after cancellation")
	}
}

func mustClusterSecret(t *testing.T, namespace, name string, cfg *rest.Config, marker string) *corev1.Secret {
	t.Helper()

	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: namespace,
			Name:      name,
			Annotations: map[string]string{
				clusterSecretTypeAnnotation: clusterSecretTypeValue,
			},
		},
		Data: map[string][]byte{
			"name":   []byte(name),
			"server": []byte(cfg.Host),
			"config": mustConfigJSON(t, cfg, marker),
		},
	}
}

func mustConfigJSON(t *testing.T, cfg *rest.Config, marker string) []byte {
	payload := map[string]any{
		"username": marker,
		"tlsClientConfig": map[string]any{
			"insecure": false,
			"caData":   base64.StdEncoding.EncodeToString(cfg.TLSClientConfig.CAData),
			"certData": base64.StdEncoding.EncodeToString(cfg.TLSClientConfig.CertData),
			"keyData":  base64.StdEncoding.EncodeToString(cfg.TLSClientConfig.KeyData),
		},
	}

	out, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal secret config: %v", err)
	}
	return out
}

func waitForWatchers(t *testing.T, collector *Collector, expected int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		collector.mu.Lock()
		count := len(collector.watchers)
		collector.mu.Unlock()
		if count == expected {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("watcher count did not reach %d", expected)
}

func watcherFingerprint(t *testing.T, collector *Collector, watcherKey string) string {
	t.Helper()
	collector.mu.Lock()
	defer collector.mu.Unlock()
	watcher, ok := collector.watchers[watcherKey]
	if !ok {
		t.Fatalf("watcher %q not found", watcherKey)
	}
	return watcher.fingerprint
}

func waitForWatcherFingerprintChange(t *testing.T, collector *Collector, watcherKey, initialFingerprint string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		collector.mu.Lock()
		watcher, ok := collector.watchers[watcherKey]
		collector.mu.Unlock()
		if ok && watcher.fingerprint != initialFingerprint {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("watcher %q fingerprint did not change", watcherKey)
}

func installAnalysisRunCRD(ctx context.Context, cfg *rest.Config) error {
	client, err := apiextensionsclientset.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("build apiextensions client: %w", err)
	}

	crd := &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "analysisruns.argoproj.io",
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: "argoproj.io",
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Plural:   "analysisruns",
				Singular: "analysisrun",
				Kind:     "AnalysisRun",
				ListKind: "AnalysisRunList",
			},
			Scope: apiextensionsv1.NamespaceScoped,
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
				{
					Name:    "v1alpha1",
					Served:  true,
					Storage: true,
					Schema: &apiextensionsv1.CustomResourceValidation{
						OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
							Type:                   "object",
							XPreserveUnknownFields: new(true),
						},
					},
				},
			},
		},
	}

	if _, err := client.ApiextensionsV1().CustomResourceDefinitions().Create(ctx, crd, metav1.CreateOptions{}); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create analysisrun CRD: %w", err)
	}

	return wait.PollUntilContextTimeout(ctx, 100*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
		current, err := client.ApiextensionsV1().CustomResourceDefinitions().Get(ctx, crd.Name, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		for _, cond := range current.Status.Conditions {
			if cond.Type == apiextensionsv1.Established && cond.Status == apiextensionsv1.ConditionTrue {
				return true, nil
			}
		}
		return false, nil
	})
}

//go:fix inline
func boolPtr(v bool) *bool {
	return new(v)
}
