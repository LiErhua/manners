/*
Package manners provides a wrapper for a standard net/http server that
ensures all active HTTP client have completed their current request
before the server shuts down.

It can be used a drop-in replacement for the standard http package,
or can wrap a pre-configured Server.

eg.

	http.Handle("/hello", func(w http.ResponseWriter, r *http.Request) {
	  w.Write([]byte("Hello\n"))
	})

	log.Fatal(manners.ListenAndServe(":8080", nil))

or for a customized server:

	s := manners.NewWithServer(&http.Server{
		Addr:           ":8080",
		Handler:        myHandler,
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	})
	log.Fatal(s.ListenAndServe())

The server will shut down cleanly when the Close() method is called:

	go func() {
		sigchan := make(chan os.Signal, 1)
		signal.Notify(sigchan, os.Interrupt, os.Kill)
		<-sigchan
		log.Info("Shutting down...")
		manners.Close()
	}()

	http.Handle("/hello", myHandler)
	log.Fatal(manners.ListenAndServe(":8080", nil))
*/
package manners

import (
	"crypto/tls"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
)

// A GracefulServer maintains a WaitGroup that counts how many in-flight
// requests the server is handling. When it receives a shutdown signal,
// it stops accepting new requests but does not actually shut down until
// all in-flight requests terminate.
//
// GracefulServer embeds the underlying net/http.Server making its non-override
// methods and properties avaiable.
//
// It must be initialized by calling NewWithServer.
type GracefulServer struct {
	*http.Server

	shutdown         chan bool
	shutdownFinished chan bool
	wg               waitGroup
	routinesCount    int

	lcsmu       sync.RWMutex
	connections map[net.Conn]bool

	up chan net.Listener // Only used by test code.
}

// NewServer creates a new GracefulServer.
func NewServer() *GracefulServer {
	return NewWithServer(new(http.Server))
}

// NewWithServer wraps an existing http.Server object and returns a
// GracefulServer that supports all of the original Server operations.
func NewWithServer(s *http.Server) *GracefulServer {
	return &GracefulServer{
		Server:           s,
		shutdown:         make(chan bool),
		shutdownFinished: make(chan bool, 1),
		wg:               new(sync.WaitGroup),
		routinesCount:    0,
		connections:      make(map[net.Conn]bool),
	}
}

// Close stops the server from accepting new requets and begins shutting down.
// It returns true if it's the first time Close is called.
func (s *GracefulServer) Close() bool {
	return <-s.shutdown
}

// BlockingClose is similar to Close, except that it blocks until the last
// connection has been closed.
func (s *GracefulServer) BlockingClose() bool {
	result := s.Close()
	<-s.shutdownFinished
	return result
}

// ListenAndServe provides a graceful equivalent of net/http.Serve.ListenAndServe.
func (s *GracefulServer) ListenAndServe() error {
	addr := s.Addr
	if addr == "" {
		addr = ":http"
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	return s.Serve(listener)
}

// ListenAndServeTLS provides a graceful equivalent of net/http.Serve.ListenAndServeTLS.
func (s *GracefulServer) ListenAndServeTLS(certFile, keyFile string) error {
	// direct lift from net/http/server.go
	addr := s.Addr
	if addr == "" {
		addr = ":https"
	}
	config := &tls.Config{}
	if s.TLSConfig != nil {
		*config = *s.TLSConfig
	}
	if config.NextProtos == nil {
		config.NextProtos = []string{"http/1.1"}
	}

	var err error
	config.Certificates = make([]tls.Certificate, 1)
	config.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return err
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	return s.Serve(tls.NewListener(ln, config))
}

// Serve provides a graceful equivalent net/http.Server.Serve.
func (s *GracefulServer) Serve(listener net.Listener) error {
	// Wrap the server HTTP handler into graceful one, that will close kept
	// alive connections if a new request is received after shutdown.
	gracefulHandler := newGracefulHandler(s.Server.Handler)
	s.Server.Handler = gracefulHandler

	// Start a goroutine that waits for a shutdown signal and will stop the
	// listener when it receives the signal. That in turn will result in
	// unblocking of the http.Serve call.
	go func() {
		s.shutdown <- true
		close(s.shutdown)
		gracefulHandler.Close()
		s.Server.SetKeepAlivesEnabled(false)  // 将 Keep alive 关掉
		listener.Close()   // 在这里先关掉 listener, 不接受外来请求了
	}()

	originalConnState := s.Server.ConnState

	// s.ConnState is invoked by the net/http.Server every time a connection
	// changes state. It keeps track of each connection's state over time,
	// enabling manners to handle persisted connections correctly.
	// server 里每次连接状态的变更都会调用一次 s.ConnState, 是用来追踪每一个连接的状态的
	// s.Connstate 是一个函数，因此我们相当于覆写一下这个函数的实现
	// ConnState specifies an optional callback function that is
	// called when a client connection changes state. See the
	// ConnState type and associated constants for details.
	// ConnState func(net.Conn, ConnState)
	s.ConnState = func(conn net.Conn, newState http.ConnState) {
		s.lcsmu.RLock()   // lcsmu 是个读写锁，给这个对象加一个读锁
		protected := s.connections[conn]   // 给 gracefulServer 加锁，为了防止 s.connections 这个 map 并发读
		s.lcsmu.RUnlock()

		switch newState {

		case http.StateNew:
			// New connection -> StateNew  // 建立的新的连接，这个 hook 函数就会调用，传入的 state 就是 StateNew
			protected = true
			s.StartRoutine()

		case http.StateActive:
			// (StateNew, StateIdle) -> StateActive   // 一个连接，StateActive 会从状态 StateNew 或者 StateIdle 变过来
			if gracefulHandler.IsClosed() {  // 如果 gracefulHandler 状态已经处于关闭状态，那么关闭这个 conn, 不再变为活跃状态
				conn.Close()
				break
			}

			if !protected {  // 如果这个连接 protected 是假，需要置为真
				protected = true
				s.StartRoutine()   // 先加锁，然后 waitGroup 加一，然后 routinesCount 加一
			}

		default:
			// (StateNew, StateActive) -> (StateIdle, StateClosed, StateHiJacked)  // 其他状态的变更时
			if protected {  // 如果这个 conn 已经被变为 protected 过，那就 waitGroup done 一次，然后 routinesCount 减一
				s.FinishRoutine()
				protected = false
			}
			// 如果没有被 protected 过，其他状态的变更是不处理的
		}

		s.lcsmu.Lock()   // 加锁，因为要开始对 s.connections 这个 map 进行修改了，防止并发写导致问题
		if newState == http.StateClosed || newState == http.StateHijacked {
			delete(s.connections, conn)
		} else {
			s.connections[conn] = protected
		}
		s.lcsmu.Unlock()

		if originalConnState != nil {  // 如果原始的 ConnState 函数不为空，那么执行一下它
			originalConnState(conn, newState)
		}
	}

	// A hook to allow the server to notify others when it is ready to receive
	// requests; only used by tests.
	if s.up != nil {
		s.up <- listener
	}

	err := s.Server.Serve(listener)
	// An error returned on shutdown is not worth reporting.
	if err != nil && gracefulHandler.IsClosed() {
		err = nil
	}

	// Wait for pending requests to complete regardless the Serve result.
	s.wg.Wait()
	s.shutdownFinished <- true
	return err
}

// StartRoutine increments the server's WaitGroup. Use this if a web request
// starts more goroutines and these goroutines are not guaranteed to finish
// before the request.
func (s *GracefulServer) StartRoutine() {
	s.lcsmu.Lock()
	defer s.lcsmu.Unlock()
	s.wg.Add(1)
	s.routinesCount++
}

// FinishRoutine decrements the server's WaitGroup. Use this to complement
// StartRoutine().
func (s *GracefulServer) FinishRoutine() {
	s.lcsmu.Lock()
	defer s.lcsmu.Unlock()
	s.wg.Done()
	s.routinesCount--
}

// RoutinesCount returns the number of currently running routines
func (s *GracefulServer) RoutinesCount() int {
	s.lcsmu.RLock()
	defer s.lcsmu.RUnlock()
	return s.routinesCount
}

// gracefulHandler is used by GracefulServer to prevent calling ServeHTTP on
// to be closed kept-alive connections during the server shutdown.
// gracefulHandler 目的是为了在服务被关闭的过程中，阻止在 keep-alive 的连接上继续调用 ServeHTTP
type gracefulHandler struct {
	closed  int32 // accessed atomically.    // 需要被原子操作的，标志被关闭状态的表示
	wrapped http.Handler                     // 包含的 net/http 的 Handler
}

func newGracefulHandler(wrapped http.Handler) *gracefulHandler {
	return &gracefulHandler{
		wrapped: wrapped,
	}
}

func (gh *gracefulHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if atomic.LoadInt32(&gh.closed) == 0 {
		gh.wrapped.ServeHTTP(w, r)
		return
	}
	r.Body.Close() // 如果已经是 closed 状态了，这个 connection 也处于被关闭的边缘，因此我们不用具体处理它的逻辑，直接关掉就好了
	// Server is shutting down at this moment, and the connection that this
	// handler is being called on is about to be closed. So we do not need to
	// actually execute the handler logic.
}

func (gh *gracefulHandler) Close() {
	atomic.StoreInt32(&gh.closed, 1)
}

func (gh *gracefulHandler) IsClosed() bool {
	return atomic.LoadInt32(&gh.closed) == 1
}
