package grco

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/x3a-tech/configo"
	"go.uber.org/zap"
	"google.golang.org/grpc/connectivity"
	"os"
	"time"

	"github.com/x3a-tech/logit-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

type Client[T any] interface {
	Connect(ctx context.Context) error
	Close() error
	GetConnection() *grpc.ClientConn
	Native() T
}

type client[T any] struct {
	conn          *grpc.ClientConn
	cfg           *configo.GrpcClient
	reconnectChan chan struct{}
	nativeFunc    func(cc grpc.ClientConnInterface) T
	native        T
	logger        logit.Logger
}

type ClientParams[T any] struct {
	Cfg        *configo.GrpcClient
	Logger     logit.Logger
	NativeFunc func(cc grpc.ClientConnInterface) T
}

func NewClient[T any](params *ClientParams[T]) Client[T] {
	return &client[T]{
		cfg:        params.Cfg,
		logger:     params.Logger,
		nativeFunc: params.NativeFunc,
	}
}

// Connect устанавливает соединение с gRPC сервером, используя предоставленную конфигурацию.
// Реализует логику повторных попыток подключения.
// Connect устанавливает соединение с gRPC сервером, используя предоставленную конфигурацию.
// Реализует логику повторных попыток подключения.
func (c *client[T]) Connect(ctx context.Context) error {
	const op = "gcli.client.Connect"
	ctx = c.logger.NewOpCtx(ctx, op)

	target := fmt.Sprintf("%s:%d", c.cfg.Host, c.cfg.Port)
	c.logger.Infof(ctx, "Попытка подключения к %s", target)

	dialOpts, err := c.buildDialOptions(ctx)
	if err != nil {
		c.logger.Errorf(ctx, "Ошибка при сборке опций подключения: %v", err)
		return fmt.Errorf("%s: ошибка сборки опций: %w", op, err)
	}

	currentBackoff := c.cfg.ConnectInitialBackoff
	var lastErr error

	for attempt := 0; attempt < c.cfg.ConnectMaxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			c.logger.Warnf(ctx, "Контекст отменен, прерывание попыток подключения: %v", ctx.Err())
			if lastErr != nil {
				return fmt.Errorf("%s: подключение отменено после %d попыток, последняя ошибка: %w (контекст: %v)", op, attempt, lastErr, ctx.Err())
			}
			return fmt.Errorf("%s: подключение отменено (контекст: %v)", op, ctx.Err())
		default:
		}

		c.logger.Infof(ctx, "Попытка подключения #%d/%d к %s...", attempt+1, c.cfg.ConnectMaxAttempts, target)

		dialCtx, cancelDial := context.WithTimeout(ctx, c.cfg.DialTimeout)
		conn, errDial := grpc.DialContext(dialCtx, target, dialOpts...)
		cancelDial()

		if errDial == nil { // Используем errDial
			c.conn = conn
			c.native = c.nativeFunc(c.conn)
			c.logger.Infof(ctx, "Успешное подключение к %s", target)

			c.reconnectChan = make(chan struct{})
			go c.monitorConnection(ctx)

			go func(connCtx context.Context) {
				ticker := time.NewTicker(time.Second * 10)
				defer ticker.Stop()
				for {
					select {
					case <-connCtx.Done(): // Используем connCtx
						c.logger.Info(connCtx, "Мониторинг соединения (тикер) остановлен из-за отмены контекста.")
						return
					case <-ticker.C:
						c.checkConnection(connCtx)
					}
				}
			}(ctx)

			return nil
		}

		lastErr = errDial // Используем errDial
		c.logger.Warnf(ctx, "Попытка #%d/%d не удалась: %v. Следующая попытка через %v", attempt+1, c.cfg.ConnectMaxAttempts, errDial, currentBackoff)

		if attempt < c.cfg.ConnectMaxAttempts-1 {
			select {
			case <-time.After(currentBackoff):
				currentBackoff = time.Duration(float64(currentBackoff) * c.cfg.ConnectBackoffMultiplier)
				if currentBackoff > c.cfg.ConnectMaxBackoff {
					currentBackoff = c.cfg.ConnectMaxBackoff
				}
			case <-ctx.Done():
				c.logger.Warnf(ctx, "Контекст отменен во время ожидания backoff: %v", ctx.Err())
				return fmt.Errorf("%s: подключение отменено во время backoff после %d попыток, последняя ошибка: %w (контекст: %v)", op, attempt+1, lastErr, ctx.Err())
			}
		}
	}

	c.logger.Errorf(ctx, "Не удалось подключиться к %s после %d попыток. Последняя ошибка: %v", target, c.cfg.ConnectMaxAttempts, lastErr)
	return fmt.Errorf("%s: не удалось подключиться к %s после %d попыток: %w", op, target, c.cfg.ConnectMaxAttempts, lastErr)
}

func (c *client[T]) buildDialOptions(ctx context.Context) ([]grpc.DialOption, error) {
	const op = "gcli.client.buildDialOptions"
	var dialOpts []grpc.DialOption

	// 1. TLS
	if c.cfg.EnableTLS {
		c.logger.Info(ctx, "TLS включен.")
		tlsConfig := &tls.Config{
			InsecureSkipVerify: false,                    // Важно! Обычно false для продакшена
			ServerName:         c.cfg.ServerNameOverride, // Используется, если указано, иначе будет использоваться host из target
		}

		if c.cfg.CACertFile != "" {
			caCert, err := os.ReadFile(c.cfg.CACertFile)
			if err != nil {
				c.logger.Errorf(ctx, "Не удалось прочитать CA сертификат %s: %v", c.cfg.CACertFile, err)
				return nil, fmt.Errorf("%s: чтение CA сертификата: %w", op, err)
			}
			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				c.logger.Errorf(ctx, "Не удалось добавить CA сертификат в пул из %s", c.cfg.CACertFile)
				return nil, fmt.Errorf("%s: добавление CA сертификата в пул", op)
			}
			tlsConfig.RootCAs = caCertPool
			c.logger.Infof(ctx, "CA сертификат %s загружен.", c.cfg.CACertFile)
		}

		if c.cfg.ClientCertFile != "" && c.cfg.ClientKeyFile != "" {
			clientCert, err := tls.LoadX509KeyPair(c.cfg.ClientCertFile, c.cfg.ClientKeyFile)
			if err != nil {
				c.logger.Errorf(ctx, "Не удалось загрузить пару клиентского сертификата/ключа (%s, %s): %v", c.cfg.ClientCertFile, c.cfg.ClientKeyFile, err)
				return nil, fmt.Errorf("%s: загрузка клиентского сертификата: %w", op, err)
			}
			tlsConfig.Certificates = []tls.Certificate{clientCert}
			c.logger.Infof(ctx, "Клиентский сертификат %s и ключ %s загружены для mTLS.", c.cfg.ClientCertFile, c.cfg.ClientKeyFile)
		}
		// Если ServerNameOverride не задан и Host из cfg это не IP, то он будет использован как ServerName по умолчанию.
		// Если Host это IP, то ServerNameOverride может быть необходим, если сертификат выдан на доменное имя.
		if tlsConfig.ServerName == "" && c.cfg.Host != "" { // Дополнительно можно проверять, является ли Host IP-адресом
			// tlsConfig.ServerName = c.cfg.Host // grpc/credentials/tls.go делает это автоматически, если ServerName пуст
		}

		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		c.logger.Info(ctx, "TLS отключен, используется небезопасное соединение.")
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	// 2. KeepAlive
	kap := keepalive.ClientParameters{
		Time:                c.cfg.KeepAliveTime,
		Timeout:             c.cfg.KeepAliveTimeout,
		PermitWithoutStream: c.cfg.PermitWithoutStream,
	}
	dialOpts = append(dialOpts, grpc.WithKeepaliveParams(kap))
	c.logger.Infof(ctx, "KeepAlive параметры: Time=%v, Timeout=%v, PermitWithoutStream=%t", kap.Time, kap.Timeout, kap.PermitWithoutStream)

	// 3. Размеры сообщений
	if c.cfg.MaxRecvMsgSize > 0 {
		dialOpts = append(dialOpts, grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(c.cfg.MaxRecvMsgSize)))
		c.logger.Infof(ctx, "MaxRecvMsgSize установлен: %d байт", c.cfg.MaxRecvMsgSize)
	}
	if c.cfg.MaxSendMsgSize > 0 {
		dialOpts = append(dialOpts, grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(c.cfg.MaxSendMsgSize)))
		c.logger.Infof(ctx, "MaxSendMsgSize установлен: %d байт", c.cfg.MaxSendMsgSize)
	}

	// 4. User Agent
	if c.cfg.UserAgent != "" {
		dialOpts = append(dialOpts, grpc.WithUserAgent(c.cfg.UserAgent))
		c.logger.Infof(ctx, "UserAgent установлен: %s", c.cfg.UserAgent)
	}

	// TODO: Добавить Interceptors, если они передаются через конфигурацию или программно
	// dialOpts = append(dialOpts, grpc.WithChainUnaryInterceptor(unaryInterceptors...))
	// dialOpts = append(dialOpts, grpc.WithChainStreamInterceptor(streamInterceptors...))

	return dialOpts, nil
}

// Close закрывает соединение с gRPC сервером.
func (c *client[T]) Close() error {
	const op = "gcli.client.Close"
	if c.conn != nil {
		c.logger.Info(context.Background(), op+": Закрытие gRPC соединения.")
		return c.conn.Close()
	}
	c.logger.Info(context.Background(), op+": Соединение не было установлено или уже закрыто.")
	return nil
}

// GetConnection возвращает активное gRPC соединение.
func (c *client[T]) GetConnection() *grpc.ClientConn {
	return c.conn
}

func (c *client[T]) Native() T {
	return c.native
}

func (c *client[T]) monitorConnection(ctx context.Context) {
	const op = "gcli.client.monitorConnection"
	baseReconnectDelay := time.Second * 5 // Начальная задержка перед повторной попыткой после неудачного reconnect
	maxReconnectDelay := time.Minute * 5  // Максимальная задержка
	currentReconnectDelay := baseReconnectDelay

	for {
		select {
		case <-ctx.Done():
			c.logger.Info(ctx, op+": Мониторинг остановлен из-за отмены контекста.")
			return
		case <-c.reconnectChan:
			c.logger.Warn(ctx, op+": Обнаружен разрыв соединения или сигнал к переподключению. Попытка переподключения...")
			reconnectOpCtx, cancelReconnectOp := context.WithTimeout(ctx, c.cfg.DialTimeout*time.Duration(c.cfg.ConnectMaxAttempts+1)) // Примерный таймаут

			err := c.reconnect(reconnectOpCtx) // Используем новый контекст для операции
			cancelReconnectOp()                // Важно отменить контекст операции

			if err != nil {
				c.logger.Errorf(ctx, op+": Не удалось переподключиться после всех попыток: %v. Следующая попытка через %v", err, currentReconnectDelay)

				select {
				case <-time.After(currentReconnectDelay):
					currentReconnectDelay *= 2
					if currentReconnectDelay > maxReconnectDelay {
						currentReconnectDelay = maxReconnectDelay
					}
				case <-ctx.Done():
					c.logger.Info(ctx, op+": Ожидание перед повторным переподключением прервано отменой контекста.")
					return
				}
			} else {
				c.logger.Info(ctx, op+": Успешное переподключение.")
				currentReconnectDelay = baseReconnectDelay // Сбрасываем задержку после успешного переподключения
			}
		}
	}
}

func (c *client[T]) reconnect(ctx context.Context) error {
	if err := c.Close(); err != nil {
		c.logger.Warn(ctx, "Ошибка при закрытии старого соединения:", zap.Error(err))
	}
	return c.Connect(ctx)
}

func (c *client[T]) checkConnection(ctx context.Context) { // Добавлен параметр ctx
	if c.conn == nil || c.conn.GetState() == connectivity.TransientFailure || c.conn.GetState() == connectivity.Shutdown {
		c.logger.Warn(ctx, "checkConnection: Обнаружено состояние TransientFailure или Shutdown.") // Логируем с контекстом
		select {
		case c.reconnectChan <- struct{}{}:
			c.logger.Info(ctx, "checkConnection: Сигнал на переподключение отправлен.")
		default:
			c.logger.Info(ctx, "checkConnection: Сигнал на переподключение уже был отправлен ранее или канал заблокирован.")
		}
	}
}
