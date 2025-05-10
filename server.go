package grco

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"github.com/x3a-tech/configo"
	"github.com/x3a-tech/logit-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/reflection"
	"net"
	"os"
)

type Server interface {
	Start(ctx context.Context) error
	Stop(ctx context.Context)
}

type ServiceRegisterFunc func(s grpc.ServiceRegistrar, srv any)

// server управляет экземпляром gRPC сервера.
type server struct {
	cfg        *configo.GrpcServer
	logger     logit.Logger
	grpcServer *grpc.Server
	listener   net.Listener
	regFunc    ServiceRegisterFunc
}

// ClientParams содержит параметры для создания нового server.
type ServerParams struct {
	Config       *configo.GrpcServer
	Logger       logit.Logger
	RegisterFunc ServiceRegisterFunc
}

// New создает новый экземпляр server.
func NewServer(params ServerParams) (*server, error) {
	if params.Config == nil {
		return nil, errors.New("grpcserver: config is required")
	}
	if params.Logger == nil {
		// Если логгер не предоставлен, можно использовать стандартный log.Printf или no-op логгер.
		// Для примера, здесь требуется логгер.
		return nil, errors.New("grpcserver: logger is required")
	}
	if params.RegisterFunc == nil {
		// Можно сделать опциональным и выводить предупреждение, если сервисы не будут зарегистрированы.
		params.Logger.Warn(context.Background(), "grpcserver: New - RegisterFunc is nil, no user services will be registered unless provided later.")
	}

	return &server{
		cfg:     params.Config,
		logger:  params.Logger,
		regFunc: params.RegisterFunc,
	}, nil
}

// Start инициализирует и запускает gRPC сервер. Этот метод блокирующий.
func (s *server) Start(ctx context.Context) error {
	const op = "grpcserver.Start"
	l := s.logger // Используем короткое имя для логгера в методе

	l.Info(ctx, fmt.Sprintf("%s: configuring gRPC server...", op))

	var opts []grpc.ServerOption

	// 1. Конфигурация TLS
	if s.cfg.EnableTLS {
		l.Info(ctx, fmt.Sprintf("%s: TLS enabled", op))
		if s.cfg.CertFile == "" || s.cfg.KeyFile == "" {
			err := fmt.Errorf("%s: CertFile and KeyFile are required when TLS is enabled", op)
			l.Error(ctx, err) // Используем Error(ctx, error) как в вашем примере GServ
			return err
		}

		serverCert, err := tls.LoadX509KeyPair(s.cfg.CertFile, s.cfg.KeyFile)
		if err != nil {
			loadErr := fmt.Errorf("%s: failed to load server cert/key pair from '%s' and '%s': %w", op, s.cfg.CertFile, s.cfg.KeyFile, err)
			l.Error(ctx, loadErr)
			return loadErr
		}
		l.Info(ctx, fmt.Sprintf("%s: server certificate and key loaded from '%s' and '%s'", op, s.cfg.CertFile, s.cfg.KeyFile))

		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{serverCert},
			MinVersion:   tls.VersionTLS12, // Рекомендуется для безопасности
		}

		if s.cfg.ClientCAFile != "" { // mTLS
			l.Info(ctx, fmt.Sprintf("%s: mTLS enabled, loading ClientCAFile: %s", op, s.cfg.ClientCAFile))
			caCert, errRead := os.ReadFile(s.cfg.ClientCAFile)
			if errRead != nil {
				readErr := fmt.Errorf("%s: failed to read client CA cert file '%s': %w", op, s.cfg.ClientCAFile, errRead)
				l.Error(ctx, readErr)
				return readErr
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				appendErr := fmt.Errorf("%s: failed to append client CA certs to pool from '%s'", op, s.cfg.ClientCAFile)
				l.Error(ctx, appendErr)
				return appendErr
			}
			tlsConfig.ClientCAs = caCertPool
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert // Принудительный mTLS
			l.Info(ctx, fmt.Sprintf("%s: mTLS credentials configured", op))
		} else {
			l.Info(ctx, fmt.Sprintf("%s: server-side TLS (no mTLS) configured", op))
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	} else {
		l.Info(ctx, fmt.Sprintf("%s: TLS disabled, using insecure connection", op))
	}

	// 2. KeepAlive параметры сервера (KASP)
	kasp := keepalive.ServerParameters{
		MaxConnectionIdle:     s.cfg.KeepAliveMaxConnectionIdle,
		MaxConnectionAge:      s.cfg.KeepAliveMaxConnectionAge,
		MaxConnectionAgeGrace: s.cfg.KeepAliveMaxConnectionAgeGrace,
		Time:                  s.cfg.KeepAliveServerTime,
		Timeout:               s.cfg.KeepAliveServerTimeout,
	}
	opts = append(opts, grpc.KeepaliveParams(kasp))
	l.Info(ctx, fmt.Sprintf("%s: KASP configured: MaxConnectionIdle=%v, MaxConnectionAge=%v, MaxConnectionAgeGrace=%v, Time=%v, Timeout=%v",
		op, kasp.MaxConnectionIdle, kasp.MaxConnectionAge, kasp.MaxConnectionAgeGrace, kasp.Time, kasp.Timeout))

	// 3. Политика принудительного KeepAlive (KAEP)
	kaep := keepalive.EnforcementPolicy{
		MinTime:             s.cfg.KeepAliveEnforcementPolicyMinTime,
		PermitWithoutStream: s.cfg.KeepAliveEnforcementPolicyPermitWithoutStream,
	}
	opts = append(opts, grpc.KeepaliveEnforcementPolicy(kaep))
	l.Info(ctx, fmt.Sprintf("%s: KAEP configured: MinTime=%v, PermitWithoutStream=%t",
		op, kaep.MinTime, kaep.PermitWithoutStream))

	// 4. Лимиты размеров сообщений
	if s.cfg.MaxReceiveMessageSize > 0 {
		opts = append(opts, grpc.MaxRecvMsgSize(s.cfg.MaxReceiveMessageSize))
		l.Info(ctx, fmt.Sprintf("%s: MaxRecvMsgSize set to %d bytes", op, s.cfg.MaxReceiveMessageSize))
	}
	if s.cfg.MaxSendMessageSize > 0 {
		opts = append(opts, grpc.MaxSendMsgSize(s.cfg.MaxSendMessageSize))
		l.Info(ctx, fmt.Sprintf("%s: MaxSendMsgSize set to %d bytes", op, s.cfg.MaxSendMessageSize))
	}

	// 5. Лимиты потоков и параллелизма
	if s.cfg.MaxConcurrentStreams > 0 {
		opts = append(opts, grpc.MaxConcurrentStreams(s.cfg.MaxConcurrentStreams))
		l.Info(ctx, fmt.Sprintf("%s: MaxConcurrentStreams set to %d", op, s.cfg.MaxConcurrentStreams))
	}
	// grpc-go не имеет прямых опций для InitialWindowSize и InitialConnWindowSize как ServerOption на момент написания (они обычно для клиента или transport specific).
	// Однако, grpc.InitialWindowSize и grpc.InitialConnWindowSize существуют как DialOption для клиента и ServerOption для HTTP/2 transport settings.
	// Для сервера, эти параметры управляются через grpc.WriteBufferSize, grpc.ReadBufferSize и косвенно через настройки HTTP/2 транспорта, если они вынесены.
	// Если же вы хотите установить их через ServerOption, то это может потребовать более глубокой настройки транспорта,
	// или они могут быть автоматически выведены из других параметров.
	// В стандартных ServerOption их нет. Для `InitialWindowSize` и `InitialConnWindowSize` на сервере:
	// эти параметры обычно устанавливаются через `keepalive.ServerParameters` для управляющих фреймов или через настройки транспорта HTTP/2.
	// `grpc.InitialWindowSize` и `grpc.InitialConnWindowSize` являются `ServerOption`, которые влияют на настройки транспорта.
	if s.cfg.InitialWindowSize > 0 {
		opts = append(opts, grpc.InitialWindowSize(s.cfg.InitialWindowSize))
		l.Info(ctx, fmt.Sprintf("%s: InitialWindowSize set to %d", op, s.cfg.InitialWindowSize))
	}
	if s.cfg.InitialConnWindowSize > 0 {
		opts = append(opts, grpc.InitialConnWindowSize(s.cfg.InitialConnWindowSize))
		l.Info(ctx, fmt.Sprintf("%s: InitialConnWindowSize set to %d", op, s.cfg.InitialConnWindowSize))
	}

	// 6. Размеры буферов
	if s.cfg.ReadBufferSize > 0 {
		opts = append(opts, grpc.ReadBufferSize(s.cfg.ReadBufferSize))
		l.Info(ctx, fmt.Sprintf("%s: ReadBufferSize set to %d bytes", op, s.cfg.ReadBufferSize))
	}
	if s.cfg.WriteBufferSize > 0 {
		opts = append(opts, grpc.WriteBufferSize(s.cfg.WriteBufferSize))
		l.Info(ctx, fmt.Sprintf("%s: WriteBufferSize set to %d bytes", op, s.cfg.WriteBufferSize))
	}

	// 7. Таймаут на установку соединения
	if s.cfg.ConnectionTimeout > 0 {
		opts = append(opts, grpc.ConnectionTimeout(s.cfg.ConnectionTimeout))
		l.Info(ctx, fmt.Sprintf("%s: ConnectionTimeout set to %v", op, s.cfg.ConnectionTimeout))
	}

	// Создание gRPC сервера
	s.grpcServer = grpc.NewServer(opts...)
	l.Info(ctx, fmt.Sprintf("%s: grpc.NewServer created with configured options", op))

	// Регистрация стандартных сервисов
	if s.cfg.EnableHealthCheckService {
		healthServer := health.NewServer()
		// Вы можете установить статус для конкретных сервисов, если это необходимо.
		// healthServer.SetServingStatus("your.service.v1.YourService", grpc_health_v1.HealthCheckResponse_SERVING)
		// Пустая строка "" используется для общего состояния сервера.
		healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)
		grpc_health_v1.RegisterHealthServer(s.grpcServer, healthServer)
		l.Info(ctx, fmt.Sprintf("%s: health check service registered and set to SERVING", op))
	}
	if s.cfg.EnableReflectionService {
		reflection.Register(s.grpcServer)
		l.Info(ctx, fmt.Sprintf("%s: reflection service registered", op))
	}

	// Регистрация пользовательских сервисов
	if s.regFunc != nil {
		s.regFunc(s.grpcServer, s)
		l.Info(ctx, fmt.Sprintf("%s: user-defined services registered via RegisterFunc", op))
	} else {
		l.Warn(ctx, fmt.Sprintf("%s: no user-defined services registered (RegisterFunc was nil)", op))
	}

	// Создание слушателя (listener)
	listenAddr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)
	var errListen error
	s.listener, errListen = net.Listen("tcp", listenAddr)
	if errListen != nil {
		listenErr := fmt.Errorf("%s: failed to listen on %s: %w", op, listenAddr, errListen)
		l.Error(ctx, listenErr)
		return listenErr
	}
	actualListenAddr := s.listener.Addr().String()
	l.Info(ctx, fmt.Sprintf("%s: gRPC server listening on %s", op, actualListenAddr))

	// Запуск сервера (блокирующий вызов)
	l.Info(ctx, fmt.Sprintf("%s: starting blocking grpcServer.Serve() on %s...", op, actualListenAddr))
	if err := s.grpcServer.Serve(s.listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		serveErr := fmt.Errorf("%s: grpcServer.Serve() failed: %w", op, err)
		l.Error(ctx, serveErr)
		return serveErr
	}

	l.Info(ctx, fmt.Sprintf("%s: grpcServer.Serve() finished (server stopped)", op))
	return nil
}

// Stop выполняет "вежливое" завершение работы gRPC сервера.
func (s *server) Stop(ctx context.Context) {
	const op = "grpcserver.Stop"
	l := s.logger

	l.Info(ctx, fmt.Sprintf("%s: stopping gRPC server...", op))

	if s.grpcServer == nil {
		l.Info(ctx, fmt.Sprintf("%s: server was not started or already stopped", op))
		return
	}

	// Используем предоставленный контекст для общего таймаута остановки,
	// но также уважаем GracefulShutdownTimeout для GracefulStop.
	gracefulStopCtx, cancelGracefulStop := context.WithTimeout(context.Background(), s.cfg.GracefulShutdownTimeout)
	defer cancelGracefulStop()

	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		l.Info(ctx, fmt.Sprintf("%s: initiating GracefulStop()...", op))
		s.grpcServer.GracefulStop() // Ожидает завершения активных RPC
		l.Info(ctx, fmt.Sprintf("%s: GracefulStop() completed", op))
	}()

	select {
	case <-stopped:
		l.Info(ctx, fmt.Sprintf("%s: server gracefully stopped", op))
	case <-gracefulStopCtx.Done(): // Таймаут для GracefulStop
		l.Warn(ctx, fmt.Sprintf("%s: graceful shutdown timed out after %v. Forcing stop...", op, s.cfg.GracefulShutdownTimeout))
		s.grpcServer.Stop() // Принудительная остановка
		l.Info(ctx, fmt.Sprintf("%s: server forcefully stopped after timeout", op))
	case <-ctx.Done(): // Если основной контекст Stop отменен
		l.Warn(ctx, fmt.Sprintf("%s: stop context cancelled. Forcing stop... (Error: %v)", op, ctx.Err()))
		s.grpcServer.Stop() // Принудительная остановка
		l.Info(ctx, fmt.Sprintf("%s: server forcefully stopped due to context cancellation", op))
	}

	// Закрытие слушателя не всегда необходимо здесь, т.к. Serve() должен освободить его при остановке.
	// Но если Stop() вызывается до Serve(), или для дополнительной гарантии:
	if s.listener != nil {
		l.Info(ctx, fmt.Sprintf("%s: closing listener %s", op, s.listener.Addr().String()))
		if err := s.listener.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			l.Errorf(ctx, "%s: error closing listener: %v", op, err)
		}
	}

	l.Info(ctx, fmt.Sprintf("%s: gRPC server shutdown process complete", op))
}

// GetGRPCServer возвращает базовый *grpc.Server экземпляр.
// Используйте с осторожностью, если ServerManager управляет его жизненным циклом.
func (s *server) GetGRPCServer() *grpc.Server {
	return s.grpcServer
}
