# pilot_discover分析

其中 Server 为 pilot-discovery 的主服务，包含了三个比较重要的组件：

- Config Controller：从不同来源接收流量控制和路由规则等 Istio 的配置，并响应各类事件。•Service Controller：从不同注册中心同步服务及实例，并响应各类事件。•EnvoyXdsServer：核心的 xDS 协议推送服务，根据上面组件的数据生成 xDS 协议并下发。

- Config Controller 比较核心的就是对接 Kubernetes，从 kube-apiserver 中 Watch 集群中的 VirtualService、ServiceEntry、DestinationRules 等配置信息，有变化则生成 PushRequest 推送至 EnvoyXdsServer 中的推送队列。除此之外，还支持对接 MCP(Mesh Configuration Protocol) 协议的 gRPC Server，如 Nacos 的 MCP 服务等，只需要在 meshconfig 中配置 configSources 即可。最后一种是基于内存的 Config Controller 实现，通过 Watch 一个文件目录，加载目录中的 yaml 文件生成配置数据，主要用来测试。

- Service Controller 目前原生支持 Kubernetes 和 Consul，注册在这些注册中心中的服务可以无痛接入 Mesh，另外一种比较特殊，就是 ServiceEntryStore，它本质是储存在 Config Controller 中的 Istio 配置数据，但它描述的却是集群外部的服务信息，详情可阅读文档 ServiceEntry[2]，Istio 通过它将集群外部，如部署在虚拟机中的服务、非 Kubernetes 的原生服务同步到 Istio 中，纳入网格统一进行流量控制和路由，所以 ServiceEntryStore 也可以视为一种注册中心。还有一种就是 Mock Service Registry，主要用来测试。

## 主程序
```diff
func main() {
	log.EnableKlogWithCobra()
	rootCmd := app.NewRootCommand()
	if err := rootCmd.Execute(); err != nil {
		log.Error(err)
		os.Exit(-1)
	}
}
```
- rootCmd命令
```diff
// NewRootCommand returns the root cobra command of pilot-discovery.
func NewRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:          "pilot-discovery",
		Short:        "Istio Pilot.",
		Long:         "Istio Pilot provides fleet-wide traffic management capabilities in the Istio Service Mesh.",
		SilenceUsage: true,
		PreRunE: func(c *cobra.Command, args []string) error {
			cmd.AddFlags(c)
			return nil
		},
	}

	discoveryCmd := newDiscoveryCommand()
	addFlags(discoveryCmd)
	rootCmd.AddCommand(discoveryCmd)
	rootCmd.AddCommand(version.CobraCommand())
	rootCmd.AddCommand(collateral.CobraCommand(rootCmd, &doc.GenManHeader{
		Title:   "Istio Pilot Discovery",
		Section: "pilot-discovery CLI",
		Manual:  "Istio Pilot Discovery",
	}))
	rootCmd.AddCommand(requestCmd)

	return rootCmd
}

func newDiscoveryCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "discovery",
		Short: "Start Istio proxy discovery service.",
		Args:  cobra.ExactArgs(0),
		PreRunE: func(c *cobra.Command, args []string) error {
			log.Configure(loggingOptions)
			validateFlags(serverArgs)
			serverArgs.Complete()
			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			cmd.PrintFlags(c.Flags())

			// Create the stop channel for all of the servers.
			stop := make(chan struct{})

			// Create the server for the discovery service.
			discoveryServer, err := bootstrap.NewServer(serverArgs)

			// Start the server
			discoveryServer.Start(stop); err != nil {

			cmd.WaitSignal(stop)
			// Wait until we shut down. In theory this could block forever; in practice we will get
			// forcibly shut down after 30s in Kubernetes.
			discoveryServer.WaitUntilCompletion()
			return nil
		},
	}
}
```

## Discover 命令
```diff
		RunE: func(c *cobra.Command, args []string) error {
			cmd.PrintFlags(c.Flags())

			// Create the stop channel for all of the servers.
			stop := make(chan struct{})

			// Create the server for the discovery service.
			discoveryServer, err := bootstrap.NewServer(serverArgs)

			// Start the server
			discoveryServer.Start(stop); err != nil {

			cmd.WaitSignal(stop)
			// Wait until we shut down. In theory this could block forever; in practice we will get
			// forcibly shut down after 30s in Kubernetes.
			discoveryServer.WaitUntilCompletion()
			return nil
		},
```

- bootstrap.NewServer
```diff
type Server struct {
  XDSServer *xds.DiscoveryServer  // Xds 服务
  environment *model.Environment  // Pilot 环境所需的 API 集合
  kubeClient kubelib.Client // kube的几种clients: restclient,clientset,dynamicclient,discoverclient
  kubeRegistry *kubecontroller.Controller   // 处理 Kubernetes 主集群的注册中心
  multicluster *kubecontroller.Multicluster // 处理 Kubernetes 多个集群的注册中心
  configController  model.ConfigStoreCache  // 统一处理配置数据（如 VirtualService 等) 的 Controller
  ConfigStores      []model.ConfigStoreCache // 不同配置信息的缓存器，提供 Get、List、Create 等方法
  serviceEntryStore *serviceentry.ServiceEntryStore // 单独处理 ServiceEntry 的 Controller
  fileWatcher filewatcher.FileWatcher // 文件监听器，主要 watch meshconfig 和 networks 配置文件等
  startFuncs []startFunc // 保存了上述所有服务的启动函数，便于在 Start() 方法中批量启动及管理
...
}

// NewServer creates a new Server instance based on the provided arguments.
func NewServer(args *PilotArgs, initFuncs ...func(*Server)) (*Server, error) {
	e := &model.Environment{
		PushContext:  model.NewPushContext(),
		DomainSuffix: args.RegistryOptions.KubeOptions.DomainSuffix,
	}
	e.SetLedger(buildLedger(args.RegistryOptions))

	ac := aggregate.NewController(aggregate.Options{
		MeshHolder: e,
	})
	e.ServiceDiscovery = ac

	s := &Server{
		clusterID:               getClusterID(args),
		environment:             e,
		fileWatcher:             filewatcher.NewWatcher(),
		httpMux:                 http.NewServeMux(),
		monitoringMux:           http.NewServeMux(),
		readinessProbes:         make(map[string]readinessProbe),
		workloadTrustBundle:     tb.NewTrustBundle(nil),
		server:                  server.New(),
		shutdownDuration:        args.ShutdownDuration,
		internalStop:            make(chan struct{}),
		istiodCertBundleWatcher: keycertbundle.NewWatcher(),
	}
	// Apply custom initialization functions.
	for _, fn := range initFuncs {
		fn(s)
	}
	// Initialize workload Trust Bundle before XDS Server
	e.TrustBundle = s.workloadTrustBundle
	s.XDSServer = xds.NewDiscoveryServer(e, args.Plugins, args.PodName, args.Namespace, args.RegistryOptions.KubeOptions.ClusterAliases)

	prometheus.EnableHandlingTimeHistogram()

	// Apply the arguments to the configuration.
	if err := s.initKubeClient(args); err != nil {
		return nil, fmt.Errorf("error initializing kube client: %v", err)
	}

	// used for both initKubeRegistry and initClusterRegistries
	args.RegistryOptions.KubeOptions.EndpointMode = kubecontroller.DetectEndpointMode(s.kubeClient)

	s.initMeshConfiguration(args, s.fileWatcher)
	spiffe.SetTrustDomain(s.environment.Mesh().GetTrustDomain())

	s.initMeshNetworks(args, s.fileWatcher)
	s.initMeshHandlers()
	s.environment.Init()

	// Options based on the current 'defaults' in istio.
	caOpts := &caOptions{
		TrustDomain:      s.environment.Mesh().TrustDomain,
		Namespace:        args.Namespace,
		ExternalCAType:   ra.CaExternalType(externalCaType),
		CertSignerDomain: features.CertSignerDomain,
	}

	if caOpts.ExternalCAType == ra.ExtCAK8s {
		// Older environment variable preserved for backward compatibility
		caOpts.ExternalCASigner = k8sSigner
	}
	// CA signing certificate must be created first if needed.
	if err := s.maybeCreateCA(caOpts); err != nil {
		return nil, err
	}

	if err := s.initControllers(args); err != nil {
		return nil, err
	}

	s.XDSServer.InitGenerators(e, args.Namespace)

	// Initialize workloadTrustBundle after CA has been initialized
	if err := s.initWorkloadTrustBundle(args); err != nil {
		return nil, err
	}

	// Parse and validate Istiod Address.
	istiodHost, _, err := e.GetDiscoveryAddress()
	if err != nil {
		return nil, err
	}

	// Create Istiod certs and setup watches.
	if err := s.initIstiodCerts(args, string(istiodHost)); err != nil {
		return nil, err
	}

	// Secure gRPC Server must be initialized after CA is created as may use a Citadel generated cert.
	if err := s.initSecureDiscoveryService(args); err != nil {
		return nil, fmt.Errorf("error initializing secure gRPC Listener: %v", err)
	}

	var wh *inject.Webhook
	// common https server for webhooks (e.g. injection, validation)
	if s.kubeClient != nil {
		s.initSecureWebhookServer(args)
		wh, err = s.initSidecarInjector(args)
		if err != nil {
			return nil, fmt.Errorf("error initializing sidecar injector: %v", err)
		}
		if err := s.initConfigValidation(args); err != nil {
			return nil, fmt.Errorf("error initializing config validator: %v", err)
		}
	}

	whc := func() map[string]string {
		if wh != nil {
			return wh.Config.Templates
		}
		return map[string]string{}
	}

	// Used for readiness, monitoring and debug handlers.
	if err := s.initIstiodAdminServer(args, whc); err != nil {
		return nil, fmt.Errorf("error initializing debug server: %v", err)
	}
	// This should be called only after controllers are initialized.
	s.initRegistryEventHandlers()

	s.initDiscoveryService(args)

	s.initSDSServer()

	// Notice that the order of authenticators matters, since at runtime
	// authenticators are activated sequentially and the first successful attempt
	// is used as the authentication result.
	authenticators := []security.Authenticator{
		&authenticate.ClientCertAuthenticator{},
	}
	if args.JwtRule != "" {
		jwtAuthn, err := initOIDC(args, s.environment.Mesh().TrustDomain)
		if err != nil {
			return nil, fmt.Errorf("error initializing OIDC: %v", err)
		}
		if jwtAuthn == nil {
			return nil, fmt.Errorf("JWT authenticator is nil")
		}
		authenticators = append(authenticators, jwtAuthn)
	}
	// The k8s JWT authenticator requires the multicluster registry to be initialized,
	// so we build it later.
	authenticators = append(authenticators,
		kubeauth.NewKubeJWTAuthenticator(s.environment.Watcher, s.kubeClient, s.clusterID, s.multiclusterController.GetRemoteKubeClient, features.JwtPolicy))
	if features.XDSAuth {
		s.XDSServer.Authenticators = authenticators
	}
	caOpts.Authenticators = authenticators

	// Start CA or RA server. This should be called after CA and Istiod certs have been created.
	s.startCA(caOpts)

	// TODO: don't run this if galley is started, one ctlz is enough
	if args.CtrlZOptions != nil {
		_, _ = ctrlz.Run(args.CtrlZOptions, nil)
	}

	// This must be last, otherwise we will not know which informers to register
	if s.kubeClient != nil {
		s.addStartFunc(func(stop <-chan struct{}) error {
			s.kubeClient.RunAndWait(stop)
			return nil
		})
	}

	s.addReadinessProbe("discovery", func() (bool, error) {
		return s.XDSServer.IsServerReady(), nil
	})

	return s, nil
}
```
