// Package collector implements the analysis run collector that watches for Argo Rollouts AnalysisRun resources across multiple clusters and collects their logs.
package collector

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"sync"
	"time"

	"github.com/argoproj/argo-rollouts/pkg/apis/rollouts/v1alpha1"
	"github.com/argoproj/argo-rollouts/pkg/client/clientset/versioned"
	"github.com/argoproj/argo-rollouts/pkg/client/informers/externalversions"
	"gitlab.pnet.ch/middleware/kargo/kargo-analysisrun-logs/internal/logger"
	"gitlab.pnet.ch/middleware/kargo/kargo-analysisrun-logs/internal/store"
	authenticationv1 "k8s.io/api/authentication/v1"
	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8sinformers "k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc" //side-effect: registers OIDC auth provider for client-go
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

//nolint:gosec // ignore G101: Potential hardcoded credentials
const clusterSecretTypeAnnotation = "argocd.postfinance.ch/secret-type"
const clusterSecretTypeValue = "cluster"

const (
	analysisRunByNameIndex           = "analysisrunByName"
	analysisRunByNamespacedNameIndex = "analysisrunByNamespacedName"
	analysisRunEventJobName          = "analysisrun"
	analysisRunEventContainerName    = "container"
)

// clusterWatcher holds the per-cluster runtime state so it can be torn down
// independently when the backing cluster secret changes or is deleted.
type clusterWatcher struct {
	cancel      context.CancelFunc
	factory     externalversions.SharedInformerFactory
	fingerprint string
	clusterName string
}

// Collector is responsible for watching cluster secrets and starting/stopping per-cluster watchers for AnalysisRun resources.
type Collector struct {
	store    *store.LocalDisk
	informer cache.SharedIndexInformer

	mu       sync.Mutex
	watchers map[string]*clusterWatcher

	streamsMu     sync.Mutex
	activeStreams map[string]struct{} // key: "namespace/podName/containerName"
}

// New creates a new Collector instance that watches for cluster secrets in the specified namespace and uses the provided store for log storage.
func New(secretNamespace string, st *store.LocalDisk) (*Collector, error) {
	if secretNamespace == "" {
		return nil, errors.New("secret namespace is required")
	}

	cfg, err := rest.InClusterConfig()
	if err != nil {
		if !errors.Is(err, rest.ErrNotInCluster) {
			return nil, fmt.Errorf("build in-cluster kubernetes config: %w", err)
		}

		cfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			clientcmd.NewDefaultClientConfigLoadingRules(),
			&clientcmd.ConfigOverrides{},
		).ClientConfig()
		if err != nil {
			return nil, fmt.Errorf("build kubernetes config: %w", err)
		}
	}

	return NewWithConfig(cfg, secretNamespace, st)
}

// NewWithConfig creates a new Collector instance using the provided Kubernetes REST config, watching for cluster secrets in the specified namespace and using the provided store for log storage.
func NewWithConfig(cfg *rest.Config, secretNamespace string, st *store.LocalDisk) (*Collector, error) {
	if cfg == nil {
		return nil, errors.New("kubernetes config is required")
	}

	if secretNamespace == "" {
		return nil, errors.New("secret namespace is required")
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build management kubernetes client: %w", err)
	}

	factory := k8sinformers.NewSharedInformerFactoryWithOptions(
		clientset,
		30*time.Second,
		k8sinformers.WithNamespace(secretNamespace),
	)

	l := logger.Get(context.Background())
	l.Info("creating collector", "secretNamespace", secretNamespace)

	return &Collector{
		store:         st,
		informer:      factory.Core().V1().Secrets().Informer(),
		watchers:      make(map[string]*clusterWatcher),
		activeStreams: make(map[string]struct{}),
	}, nil
}

// Start starts the analysis run collector.
func (c *Collector) Start(ctx context.Context) error {
	l := logger.Get(ctx)
	l.Info("collector started")

	if _, err := c.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			c.handleSecretAddOrUpdate(ctx, obj)
		},
		UpdateFunc: func(_, newObj any) {
			c.handleSecretAddOrUpdate(ctx, newObj)
		},
		DeleteFunc: func(obj any) {
			c.handleSecretDelete(ctx, obj)
		},
	}); err != nil {
		return fmt.Errorf("register secret informer handlers: %w", err)
	}

	go c.informer.Run(ctx.Done())

	if !cache.WaitForCacheSync(ctx.Done(), c.informer.HasSynced) {
		return errors.New("secret informer cache failed to sync")
	}

	l.Info("cluster secret informer cache synced")

	<-ctx.Done()
	c.stopAllWatchers()

	return nil
}

func (c *Collector) handleSecretAddOrUpdate(ctx context.Context, obj any) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		return
	}

	secretKey := secret.Namespace + "/" + secret.Name

	if !isClusterSecret(secret) {
		logger.Get(ctx).Debug("ignoring non-cluster secret", slog.String("secret", secretKey))
		c.removeWatcher(ctx, secretKey)

		return
	}

	clusterCfg, err := clusterConfigFromSecret(secret)
	if err != nil {
		logger.Get(ctx).Error("failed to parse cluster secret", slog.String("secret", secretKey), logger.Error(err))
		c.removeWatcher(ctx, secretKey)

		return
	}

	fingerprint := clusterSecretFingerprint(secret)

	c.mu.Lock()
	existing, found := c.watchers[secretKey]
	c.mu.Unlock()

	if found && existing.fingerprint == fingerprint {
		logger.Get(ctx).Debug("cluster watcher already up-to-date", slog.String("secret", secretKey), slog.String("cluster", clusterCfg.Name))
		return
	}

	if found {
		logger.Get(ctx).Debug("cluster secret changed, restarting watcher", slog.String("secret", secretKey), slog.String("cluster", clusterCfg.Name))
		c.removeWatcher(ctx, secretKey)
	}

	if err := c.startCluster(ctx, secretKey, clusterCfg, fingerprint); err != nil {
		logger.Get(ctx).Error(
			"failed to start cluster watcher",
			slog.String("secret", secretKey),
			slog.String("cluster", clusterCfg.Name),
			logger.Error(err),
		)
	}
}

func (c *Collector) handleSecretDelete(ctx context.Context, obj any) {
	secret, ok := obj.(*corev1.Secret)
	if !ok {
		tomb, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}

		secret, ok = tomb.Obj.(*corev1.Secret)
		if !ok {
			return
		}
	}

	secretKey := secret.Namespace + "/" + secret.Name
	c.removeWatcher(ctx, secretKey)
}

func (c *Collector) startCluster(ctx context.Context, watcherKey string, cluster clusterConfig, fingerprint string) error {
	l := logger.Get(ctx).With("cluster", cluster.Name, "watcher", watcherKey)
	authMode := detectAuthMode(cluster.Config)

	l.Debug(
		"starting analysisrun watcher",
		slog.String("server", cluster.Server),
		slog.String("authMode", authMode),
		slog.Bool("hasCAData", cluster.Config.TLSClientConfig.CAData != ""),
		slog.Bool("hasCertData", cluster.Config.TLSClientConfig.CertData != ""),
		slog.Bool("hasKeyData", cluster.Config.TLSClientConfig.KeyData != ""),
		slog.Bool("insecureTLS", cluster.Config.TLSClientConfig.Insecure),
	)

	cfg, err := buildRestConfig(cluster)
	if err != nil {
		return fmt.Errorf("build rest config: %w", err)
	}

	rolloutsClient, err := versioned.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("create rollouts client: %w", err)
	}

	kubeClient, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return fmt.Errorf("create kubernetes client: %w", err)
	}

	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	c.logAnalysisRunStartupAccess(checkCtx, l, kubeClient)
	cancel()

	factory := externalversions.NewSharedInformerFactory(rolloutsClient, 30*time.Second)

	// Create the cluster-scoped context before registering event handlers so
	// that streaming goroutines are cancelled when the cluster watcher stops.
	clusterCtx, cancel := context.WithCancel(ctx)

	informer := factory.Argoproj().V1alpha1().AnalysisRuns().Informer()
	if err := informer.AddIndexers(cache.Indexers{
		analysisRunByNameIndex:           indexAnalysisRunByName,
		analysisRunByNamespacedNameIndex: indexAnalysisRunByNamespacedName,
	}); err != nil {
		cancel()
		return fmt.Errorf("register analysisrun informer indexers: %w", err)
	}

	if err := informer.SetWatchErrorHandler(func(_ *cache.Reflector, watchErr error) {
		if isAuthzError(watchErr) {
			l.Error(
				"analysisrun informer list/watch unauthorized",
				slog.String("server", cluster.Server),
				slog.String("authMode", authMode),
				logger.Error(watchErr),
			)

			return
		}

		l.Warn(
			"analysisrun informer list/watch failed",
			slog.String("server", cluster.Server),
			slog.String("authMode", authMode),
			logger.Error(watchErr),
		)
	}); err != nil {
		cancel()
		return fmt.Errorf("register analysisrun informer watch error handler: %w", err)
	}

	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			c.handleAnalysisRunAdd(clusterCtx, l, kubeClient, obj)
		},
		UpdateFunc: func(_, newObj any) {
			c.handleAnalysisRunUpdate(clusterCtx, l, kubeClient, newObj)
		},
		DeleteFunc: func(obj any) {
			c.handleAnalysisRunDelete(l, obj)
		},
	}); err != nil {
		cancel()
		return fmt.Errorf("register analysisrun informer handlers: %w", err)
	}

	factory.Start(clusterCtx.Done())

	synced := factory.WaitForCacheSync(clusterCtx.Done())
	for typ, ok := range synced {
		if !ok {
			cancel()
			return fmt.Errorf("cache failed to sync for %v", typ)
		}
	}

	c.mu.Lock()
	c.watchers[watcherKey] = &clusterWatcher{
		cancel:      cancel,
		factory:     factory,
		fingerprint: fingerprint,
		clusterName: cluster.Name,
	}
	c.mu.Unlock()

	l.Info("analysisrun informer cache synced")

	return nil
}

func (c *Collector) handleAnalysisRunAdd(ctx context.Context, l *slog.Logger, kubeClient *kubernetes.Clientset, obj any) {
	ar, ok := obj.(*v1alpha1.AnalysisRun)
	if !ok {
		return
	}

	l.Debug("analysisrun added", slog.String("namespace", ar.Namespace), slog.String("analysisRun", ar.Name))

	c.startContainerLogStreams(ctx, l, kubeClient, ar)
}

func (c *Collector) handleAnalysisRunUpdate(ctx context.Context, l *slog.Logger, kubeClient *kubernetes.Clientset, obj any) {
	ar, ok := obj.(*v1alpha1.AnalysisRun)
	if !ok {
		return
	}

	l.Debug("analysisrun updated", slog.String("namespace", ar.Namespace), slog.String("analysisRun", ar.Name),
		slog.String("phase", string(ar.Status.Phase)))

	c.startContainerLogStreams(ctx, l, kubeClient, ar)
}

func (c *Collector) handleAnalysisRunDelete(l *slog.Logger, obj any) {
	ar, ok := obj.(*v1alpha1.AnalysisRun)
	if !ok {
		tomb, ok := obj.(cache.DeletedFinalStateUnknown)
		if !ok {
			return
		}

		ar, ok = tomb.Obj.(*v1alpha1.AnalysisRun)
		if !ok {
			return
		}
	}

	l.Debug("analysisrun deleted", slog.String("namespace", ar.Namespace), slog.String("analysisRun", ar.Name))
}

func (c *Collector) removeWatcher(ctx context.Context, watcherKey string) {
	c.mu.Lock()

	watcher, ok := c.watchers[watcherKey]
	if ok {
		delete(c.watchers, watcherKey)
	}
	c.mu.Unlock()

	if !ok {
		return
	}

	logger.Get(ctx).Info("stopping cluster watcher", "watcher", watcherKey, "cluster", watcher.clusterName)
	watcher.cancel()
}

func (c *Collector) stopAllWatchers() {
	c.mu.Lock()

	watchers := make(map[string]*clusterWatcher, len(c.watchers))
	maps.Copy(watchers, c.watchers)

	c.watchers = make(map[string]*clusterWatcher)
	c.mu.Unlock()

	for _, watcher := range watchers {
		watcher.cancel()
	}
}

type clusterConfig struct {
	Name   string
	Server string
	Config clusterConnectionConfig
}

type clusterConnectionConfig struct {
	BearerToken        string              `json:"bearerToken"`
	Username           string              `json:"username"`
	Password           string              `json:"password"`
	TLSClientConfig    tlsClientConfig     `json:"tlsClientConfig"`
	ExecProviderConfig *execProviderConfig `json:"execProviderConfig"`
}

type tlsClientConfig struct {
	Insecure   bool   `json:"insecure"`
	ServerName string `json:"serverName"`
	CAData     string `json:"caData"`
	CertData   string `json:"certData"`
	KeyData    string `json:"keyData"`
}

type execProviderConfig struct {
	Command            string       `json:"command"`
	Args               []string     `json:"args"`
	Env                []execEnvVar `json:"env"`
	APIVersion         string       `json:"apiVersion"`
	InstallHint        string       `json:"installHint"`
	ProvideClusterInfo bool         `json:"provideClusterInfo"`
	InteractiveMode    string       `json:"interactiveMode"`
}

type execEnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func isClusterSecret(secret *corev1.Secret) bool {
	return secret.Annotations[clusterSecretTypeAnnotation] == clusterSecretTypeValue
}

func clusterSecretFingerprint(secret *corev1.Secret) string {
	hash := sha256.New()
	hash.Write(secret.Data["name"])
	hash.Write(secret.Data["server"])
	hash.Write(secret.Data["config"])

	return hex.EncodeToString(hash.Sum(nil))
}

func clusterConfigFromSecret(secret *corev1.Secret) (clusterConfig, error) {
	name := string(secret.Data["name"])
	server := string(secret.Data["server"])

	if name == "" {
		return clusterConfig{}, errors.New("missing data.name")
	}

	if server == "" {
		return clusterConfig{}, errors.New("missing data.server")
	}

	rawConfig := secret.Data["config"]
	if len(rawConfig) == 0 {
		return clusterConfig{}, errors.New("missing data.config")
	}

	var cfg clusterConnectionConfig
	if err := json.Unmarshal(rawConfig, &cfg); err != nil {
		return clusterConfig{}, fmt.Errorf("unmarshal data.config: %w", err)
	}

	return clusterConfig{
		Name:   name,
		Server: server,
		Config: cfg,
	}, nil
}

func buildRestConfig(cluster clusterConfig) (*rest.Config, error) {
	if cluster.Server == "" {
		return nil, errors.New("cluster server is empty")
	}

	restConfig := &rest.Config{
		Host: cluster.Server,
		TLSClientConfig: rest.TLSClientConfig{
			Insecure:   cluster.Config.TLSClientConfig.Insecure,
			ServerName: cluster.Config.TLSClientConfig.ServerName,
			CAData:     maybeDecodeBase64(cluster.Config.TLSClientConfig.CAData),
			CertData:   maybeDecodeBase64(cluster.Config.TLSClientConfig.CertData),
			KeyData:    maybeDecodeBase64(cluster.Config.TLSClientConfig.KeyData),
		},
		BearerToken: cluster.Config.BearerToken,
		Username:    cluster.Config.Username,
		Password:    cluster.Config.Password,
	}

	if execCfg := cluster.Config.ExecProviderConfig; execCfg != nil {
		interactiveMode, err := normalizeExecInteractiveMode(execCfg.InteractiveMode)
		if err != nil {
			return nil, err
		}

		restConfig.ExecProvider = &clientcmdapi.ExecConfig{
			Command:            execCfg.Command,
			Args:               execCfg.Args,
			APIVersion:         execCfg.APIVersion,
			InstallHint:        execCfg.InstallHint,
			ProvideClusterInfo: execCfg.ProvideClusterInfo,
			InteractiveMode:    interactiveMode,
		}

		for _, envVar := range execCfg.Env {
			restConfig.ExecProvider.Env = append(restConfig.ExecProvider.Env, clientcmdapi.ExecEnvVar{
				Name:  envVar.Name,
				Value: envVar.Value,
			})
		}
	}

	return restConfig, nil
}

func normalizeExecInteractiveMode(mode string) (clientcmdapi.ExecInteractiveMode, error) {
	if mode == "" {
		return clientcmdapi.NeverExecInteractiveMode, nil
	}

	interactiveMode := clientcmdapi.ExecInteractiveMode(mode)
	switch interactiveMode {
	case clientcmdapi.NeverExecInteractiveMode, clientcmdapi.IfAvailableExecInteractiveMode, clientcmdapi.AlwaysExecInteractiveMode:
		return interactiveMode, nil
	default:
		return "", fmt.Errorf("invalid execProviderConfig.interactiveMode %q", mode)
	}
}

func maybeDecodeBase64(value string) []byte {
	if value == "" {
		return nil
	}

	decoded, err := base64.StdEncoding.DecodeString(value)
	if err == nil {
		return decoded
	}

	return []byte(value)
}

func detectAuthMode(cfg clusterConnectionConfig) string {
	switch {
	case cfg.ExecProviderConfig != nil:
		return "exec"
	case cfg.BearerToken != "":
		return "bearerToken"
	case cfg.Username != "" || cfg.Password != "":
		return "basicAuth"
	default:
		return "none"
	}
}

func indexAnalysisRunByName(obj any) ([]string, error) {
	ar, ok := obj.(*v1alpha1.AnalysisRun)
	if !ok {
		return nil, fmt.Errorf("index by name: expected *v1alpha1.AnalysisRun, got %T", obj)
	}

	if ar.Name == "" {
		return nil, errors.New("index by name: analysisrun name is empty")
	}

	return []string{ar.Name}, nil
}

func indexAnalysisRunByNamespacedName(obj any) ([]string, error) {
	ar, ok := obj.(*v1alpha1.AnalysisRun)
	if !ok {
		return nil, fmt.Errorf("index by namespaced name: expected *v1alpha1.AnalysisRun, got %T", obj)
	}

	if ar.Namespace == "" {
		return nil, errors.New("index by namespaced name: analysisrun namespace is empty")
	}

	if ar.Name == "" {
		return nil, errors.New("index by namespaced name: analysisrun name is empty")
	}

	return []string{ar.Namespace + "/" + ar.Name}, nil
}

// startContainerLogStreams inspects the AnalysisRun's job-provider metrics,
// resolves actual Kubernetes Job names from measurement metadata ("job-name"
// key), lists pods for each job, and starts a background goroutine per pod that
// has not yet been streamed.  Goroutines are bound to ctx so they stop when the
// cluster watcher is torn down.
func (c *Collector) startContainerLogStreams(ctx context.Context, l *slog.Logger, kubeClient *kubernetes.Clientset, ar *v1alpha1.AnalysisRun) {
	if ar == nil {
		return
	}

	metricActualJobs := metricJobNames(ar)

	for _, metric := range ar.Spec.Metrics {
		if metric.Provider.Job == nil {
			continue
		}

		actualJobs, ok := metricActualJobs[metric.Name]
		if !ok {
			continue
		}

		specJobName := metric.Provider.Job.Metadata.Name
		if specJobName == "" {
			specJobName = metric.Name
		}

		containerName := analysisRunEventContainerName
		if len(metric.Provider.Job.Spec.Template.Spec.Containers) > 0 {
			containerName = metric.Provider.Job.Spec.Template.Spec.Containers[0].Name
		}

		storeKey := store.Key{
			Namespace:   ar.Namespace,
			AnalysisRun: ar.Name,
			JobName:     specJobName,
			Container:   containerName,
		}

		for actualJobName := range actualJobs {
			c.startJobLogStreams(ctx, l, kubeClient, ar.Namespace, actualJobName, containerName, storeKey)
		}
	}
}

// metricJobNames builds a map from metric name to the set of actual Kubernetes
// Job names found in that metric's measurement metadata.
func metricJobNames(ar *v1alpha1.AnalysisRun) map[string]map[string]struct{} {
	result := make(map[string]map[string]struct{})

	for _, metricResult := range ar.Status.MetricResults {
		for _, m := range metricResult.Measurements {
			jobName := m.Metadata["job-name"]
			if jobName == "" {
				continue
			}

			if result[metricResult.Name] == nil {
				result[metricResult.Name] = make(map[string]struct{})
			}

			result[metricResult.Name][jobName] = struct{}{}
		}
	}

	return result
}

// startJobLogStreams lists pods for actualJobName and starts a streaming
// goroutine for each pod not already being streamed.
func (c *Collector) startJobLogStreams(ctx context.Context, l *slog.Logger, kubeClient *kubernetes.Clientset, namespace, actualJobName, containerName string, storeKey store.Key) {
	pods, err := kubeClient.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "job-name=" + actualJobName,
	})
	if err != nil {
		if ctx.Err() == nil {
			l.Warn("failed to list pods for job", slog.String("job", actualJobName), logger.Error(err))
		}

		return
	}

	for i := range pods.Items {
		pod := &pods.Items[i]
		streamKey := namespace + "/" + pod.Name + "/" + containerName

		c.streamsMu.Lock()

		_, alreadyStreaming := c.activeStreams[streamKey]
		if !alreadyStreaming {
			c.activeStreams[streamKey] = struct{}{}
		}
		c.streamsMu.Unlock()

		if alreadyStreaming {
			continue
		}

		go c.streamPodLogs(ctx, l, kubeClient, namespace, pod.Name, containerName, storeKey, streamKey)
	}
}

// streamPodLogs opens a streaming (followed) log connection to a single pod
// container and copies the output into the store.  It removes its entry from
// activeStreams when done so a new stream can be started if needed.
func (c *Collector) streamPodLogs(ctx context.Context, l *slog.Logger, kubeClient *kubernetes.Clientset, namespace, podName, containerName string, storeKey store.Key, streamKey string) {
	defer func() {
		c.streamsMu.Lock()
		delete(c.activeStreams, streamKey)
		c.streamsMu.Unlock()
	}()

	l.Debug("starting pod log stream", slog.String("pod", podName), slog.String("container", containerName))

	req := kubeClient.CoreV1().Pods(namespace).GetLogs(podName, &corev1.PodLogOptions{
		Container: containerName,
		Follow:    true,
	})

	stream, err := req.Stream(ctx)
	if err != nil {
		if ctx.Err() == nil {
			l.Warn("failed to open pod log stream",
				slog.String("pod", podName),
				slog.String("container", containerName),
				logger.Error(err),
			)
		}

		return
	}
	defer stream.Close()

	writer, err := c.store.Writer(ctx, storeKey)
	if err != nil {
		l.Warn("failed to open store writer",
			slog.String("pod", podName),
			slog.String("container", containerName),
			logger.Error(err),
		)

		return
	}
	defer writer.Close()

	if _, err := io.Copy(writer, stream); err != nil && ctx.Err() == nil {
		l.Warn("error copying pod logs",
			slog.String("pod", podName),
			slog.String("container", containerName),
			logger.Error(err),
		)
	}

	l.Debug("pod log stream ended", slog.String("pod", podName), slog.String("container", containerName))
}

func isAuthzError(err error) bool {
	return k8serrors.IsUnauthorized(err) || k8serrors.IsForbidden(err)
}

func (c *Collector) logAnalysisRunStartupAccess(ctx context.Context, l *slog.Logger, kubeClient *kubernetes.Clientset) {
	review, err := kubeClient.AuthenticationV1().SelfSubjectReviews().Create(
		ctx,
		&authenticationv1.SelfSubjectReview{},
		metav1.CreateOptions{},
	)
	if err != nil {
		l.Warn("analysisrun startup identity check failed", logger.Error(err))
	} else {
		l.Debug(
			"analysisrun startup identity resolved",
			slog.String("username", review.Status.UserInfo.Username),
			slog.String("uid", review.Status.UserInfo.UID),
			slog.Any("groups", review.Status.UserInfo.Groups),
		)
	}

	for _, verb := range []string{"list", "watch"} {
		accessReview, err := kubeClient.AuthorizationV1().SelfSubjectAccessReviews().Create(
			ctx,
			&authorizationv1.SelfSubjectAccessReview{
				Spec: authorizationv1.SelfSubjectAccessReviewSpec{
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Group:    "argoproj.io",
						Resource: "analysisruns",
						Verb:     verb,
					},
				},
			},
			metav1.CreateOptions{},
		)
		if err != nil {
			l.Warn("analysisrun startup access check failed", slog.String("verb", verb), logger.Error(err))
			continue
		}

		if accessReview.Status.Allowed {
			l.Debug("analysisrun startup access allowed", slog.String("verb", verb), slog.String("reason", accessReview.Status.Reason))
			continue
		}

		l.Warn(
			"analysisrun startup access denied",
			slog.String("verb", verb),
			slog.String("reason", accessReview.Status.Reason),
			slog.String("evaluationError", accessReview.Status.EvaluationError),
		)
	}
}
