package authz

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"

	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authzv1 "github.com/grafana/authlib/authz/proto/v1"
	"github.com/grafana/authlib/cache"
	"github.com/grafana/authlib/claims"
)

var (
	ErrMissingConfig  = errors.New("missing config")
	ErrMissingStackID = status.Errorf(codes.InvalidArgument, "missing stack ID")
	ErrMissingAction  = status.Errorf(codes.InvalidArgument, "missing action")
	ErrMissingCaller  = status.Errorf(codes.Unauthenticated, "missing caller")
	ErrMissingSubject = status.Errorf(codes.Unauthenticated, "missing subject")
	ErrReadPermission = status.Errorf(codes.PermissionDenied, "read permission failed")
)

type CheckRequest struct {
	Caller     claims.AuthInfo
	StackID    int64
	Action     string
	Resource   *Resource
	Contextual []Resource
}

type MultiTenantClient interface {
	Check(ctx context.Context, req *CheckRequest) (bool, error)
}

type MultiTenantClientConfig struct {
	// RemoteAddress is the address of the authz service. It should be in the format "host:port".
	RemoteAddress string

	// accessTokenAuthEnabled is a flag to enable access token authentication.
	// If disabled, no service authentication will be performed. Defaults to true.
	accessTokenAuthEnabled bool
}

var _ MultiTenantClient = (*LegacyClientImpl)(nil)

type LegacyClientOption func(*LegacyClientImpl)

type LegacyClientImpl struct {
	authCfg      *MultiTenantClientConfig
	clientV1     authzv1.AuthzServiceClient
	cache        cache.Cache
	grpcConn     grpc.ClientConnInterface
	grpcOptions  []grpc.DialOption
	namespaceFmt claims.NamespaceFormatter
	tracer       trace.Tracer
}

type tracerProvider struct {
	trace.TracerProvider
	tracer trace.Tracer
}

func (tp *tracerProvider) Tracer(name string, options ...trace.TracerOption) trace.Tracer {
	return tp.tracer
}

// -----
// Options
// -----

func WithCacheLCOption(cache cache.Cache) LegacyClientOption {
	return func(c *LegacyClientImpl) {
		c.cache = cache
	}
}

// WithGrpcDialOptionsLCOption sets the gRPC dial options for client connection setup.
// Useful for adding client interceptors. These options are ignored if WithGrpcConnection is used.
func WithGrpcDialOptionsLCOption(opts ...grpc.DialOption) LegacyClientOption {
	return func(c *LegacyClientImpl) {
		c.grpcOptions = opts
	}
}

// WithGrpcConnectionLCOption sets the gRPC client connection directly.
// Useful for running the client in the same process as the authorization service.
func WithGrpcConnectionLCOption(conn grpc.ClientConnInterface) LegacyClientOption {
	return func(c *LegacyClientImpl) {
		c.grpcConn = conn
	}
}

func WithTracerLCOption(tracer trace.Tracer) LegacyClientOption {
	return func(c *LegacyClientImpl) {
		c.tracer = tracer
	}
}

func WithNamespaceFormatterLCOption(fmt claims.NamespaceFormatter) LegacyClientOption {
	return func(c *LegacyClientImpl) {
		c.namespaceFmt = fmt
	}
}

// WithDisableAccessTokenLCOption is an option to disable access token authorization.
// Warning: Using this option means there won't be any service authorization.
func WithDisableAccessTokenLCOption() LegacyClientOption {
	return func(c *LegacyClientImpl) {
		c.authCfg.accessTokenAuthEnabled = false
	}
}

// -----
// Initialization
// -----

func NewLegacyClient(cfg *MultiTenantClientConfig, opts ...LegacyClientOption) (*LegacyClientImpl, error) {
	if cfg == nil {
		return nil, ErrMissingConfig
	}
	cfg.accessTokenAuthEnabled = true

	client := &LegacyClientImpl{authCfg: cfg}

	// Apply options
	for _, opt := range opts {
		opt(client)
	}

	// Instantiate the cache
	if client.cache == nil {
		client.cache = cache.NewLocalCache(cache.Config{
			Expiry:          cache.DefaultExpiration,
			CleanupInterval: 1 * cache.DefaultExpiration,
		})
	}

	if client.tracer == nil {
		client.tracer = noop.Tracer{}
	}

	// Instantiate the client
	if client.grpcConn == nil {
		if cfg.RemoteAddress == "" {
			return nil, fmt.Errorf("missing remote address: %w", ErrMissingConfig)
		}

		tp := tracerProvider{tracer: client.tracer}
		grpcOpts := client.grpcOptions
		grpcOpts = append(grpcOpts, grpc.WithStatsHandler(otelgrpc.NewClientHandler(otelgrpc.WithTracerProvider(&tp))))

		conn, err := grpc.NewClient(cfg.RemoteAddress, grpcOpts...)
		if err != nil {
			return nil, err
		}
		client.grpcConn = conn
	}
	client.clientV1 = authzv1.NewAuthzServiceClient(client.grpcConn)

	if client.namespaceFmt == nil {
		client.namespaceFmt = claims.CloudNamespaceFormatter
	}

	return client, nil
}

// -----
// Implementation
// -----

func (r *CheckRequest) Validate(accessTokenEnabled bool) error {
	if r.StackID <= 0 {
		return ErrMissingStackID
	}
	if r.Action == "" {
		return ErrMissingAction
	}
	accessClaims := r.Caller.GetAccess()
	if accessTokenEnabled && (accessClaims == nil || accessClaims.IsNil()) {
		return ErrMissingCaller
	}
	idClaims := r.Caller.GetIdentity()
	if idClaims != nil && !idClaims.IsNil() && idClaims.Subject() == "" {
		return ErrMissingSubject
	}
	return nil
}

func (c *LegacyClientImpl) Check(ctx context.Context, req *CheckRequest) (bool, error) {
	ctx, span := c.tracer.Start(ctx, "LegacyClientImpl.Check")
	defer span.End()

	if err := req.Validate(c.authCfg.accessTokenAuthEnabled); err != nil {
		span.RecordError(err)
		return false, err
	}

	if !c.validateNamespace(req.Caller, req.StackID) {
		return false, nil
	}

	accessClaims := req.Caller.GetAccess()
	identityClaims := req.Caller.GetIdentity()

	if c.authCfg.accessTokenAuthEnabled && accessClaims != nil && !accessClaims.IsNil() {
		span.SetAttributes(attribute.String("service", accessClaims.Subject()))
	}
	span.SetAttributes(attribute.Int64("stack_id", req.StackID))
	span.SetAttributes(attribute.String("action", req.Action))
	if req.Resource != nil {
		span.SetAttributes(attribute.String("resource", req.Resource.Scope()))
		span.SetAttributes(attribute.Int("contextual", len(req.Contextual)))
	}
	span.SetAttributes(attribute.Bool("with_user", identityClaims != nil && !identityClaims.IsNil()))

	// No user => check on the service permissions
	if identityClaims == nil || identityClaims.IsNil() {
		// access token check is disabled => we can skip the authz service
		if !c.authCfg.accessTokenAuthEnabled {
			return true, nil
		}

		if accessClaims == nil || accessClaims.IsNil() {
			return false, ErrMissingCaller
		}

		perms := accessClaims.Permissions()
		for _, p := range perms {
			if p == req.Action {
				return true, nil
			}
		}
		return false, nil
	}

	span.SetAttributes(attribute.String("subject", identityClaims.Subject()))

	// Only check the service permissions if the access token check is enabled
	if c.authCfg.accessTokenAuthEnabled {
		if accessClaims == nil || accessClaims.IsNil() {
			return false, ErrMissingCaller
		}

		// Make sure the service is allowed to perform the requested action
		serviceIsAllowedAction := false
		for _, p := range accessClaims.DelegatedPermissions() {
			if p == req.Action {
				serviceIsAllowedAction = true
				break
			}
		}
		if !serviceIsAllowedAction {
			return false, nil
		}
	}

	res, err := c.retrievePermissions(ctx, req.StackID, identityClaims.Subject(), req.Action)
	if err != nil {
		span.RecordError(err)
		return false, err
	}

	// No permissions found
	if !res.Found {
		return false, nil
	}

	// Action check only
	if req.Resource == nil {
		return true, nil
	}

	// Check if the user has access to any of the requested resources
	return res.Check(append(req.Contextual, *req.Resource)...), nil
}

func (c *LegacyClientImpl) validateNamespace(caller claims.AuthInfo, stackID int64) bool {
	expectedNamespace := c.namespaceFmt(stackID)

	// Check both AccessToken and IDToken (if present) for namespace match
	accessClaims := caller.GetAccess()
	accessTokenMatch := !c.authCfg.accessTokenAuthEnabled ||
		(accessClaims != nil && !accessClaims.IsNil() && claims.NamespaceMatches(accessClaims, expectedNamespace))

	idClaims := caller.GetIdentity()
	idTokenMatch := idClaims == nil || idClaims.IsNil() || claims.NamespaceMatches(idClaims, expectedNamespace)

	return accessTokenMatch && idTokenMatch
}

func (c *LegacyClientImpl) retrievePermissions(ctx context.Context, stackID int64, subject, action string) (*controller, error) {
	ctx, span := c.tracer.Start(ctx, "LegacyClientImpl.retrievePermissions")
	defer span.End()

	span.SetAttributes(attribute.Int64("stack_id", stackID))

	// Check the cache
	key := controllerCacheKey(stackID, subject, action)
	ctrl, err := c.getCachedController(ctx, key)
	if err == nil || !errors.Is(err, cache.ErrNotFound) {
		return ctrl, err
	}

	// Instantiate a new context for the request
	outCtx := newOutgoingContext(ctx)

	readReq := &authzv1.ReadRequest{
		StackId: stackID,
		Action:  action,
		Subject: subject,
	}

	// Query the authz service
	resp, err := c.clientV1.Read(outCtx, readReq)
	if err != nil {
		return nil, ErrReadPermission
	}

	res := newController(resp)

	// Cache the result
	err = c.cacheController(ctx, key, res)
	return res, err
}

// newOutgoingContext creates a new context that will be canceled when the input context is canceled.
func newOutgoingContext(ctx context.Context) context.Context {
	outCtx, cancel := context.WithCancel(context.Background())

	// Propagate the span into the new context
	spanContext := trace.SpanContextFromContext(ctx)
	if spanContext.IsValid() {
		outCtx = trace.ContextWithSpanContext(outCtx, spanContext)
	}

	go func() {
		select {
		case <-ctx.Done():
			cancel()
		case <-outCtx.Done():
			// exit
		}
	}()

	return outCtx
}

// -----
// RESULT
// -----

type controller struct {
	// Whether the requested action was found in the users' permissions
	Found bool
	// All the scopes the user has access to for the requested action
	Scopes map[string]bool
	// Wildcard per kinds
	Wildcard map[string]bool
}

func newController(resp *authzv1.ReadResponse) *controller {
	if resp == nil || !resp.Found {
		return &controller{Found: false}
	}

	res := &controller{
		Found:    true,
		Scopes:   make(map[string]bool, len(resp.Data)),
		Wildcard: make(map[string]bool, 2),
	}
	for _, o := range resp.Data {
		kind, _, id := splitScope(o.Object)
		if id == "*" {
			res.Wildcard[kind] = true
		} else {
			res.Scopes[o.Object] = true
		}
	}
	return res
}

func (r *controller) Check(resources ...Resource) bool {
	// the user has no permissions
	if !r.Found {
		return false
	}

	// it's an action check only
	if len(resources) == 0 {
		return true
	}

	// the user has no permissions
	if len(r.Scopes) == 0 && len(r.Wildcard) == 0 {
		return false
	}

	// the user has access to all resources
	if r.Wildcard["*"] {
		return true
	}

	// the user has access to the requested resources
	for _, res := range resources {
		if r.Wildcard[res.Kind] || r.Scopes[res.Scope()] {
			return true
		}
	}
	return false
}

// -----
// CACHE
// -----

func controllerCacheKey(stackID int64, subject, action string) string {
	return fmt.Sprintf("read-%d-%s-%s", stackID, subject, action)
}

func (c *LegacyClientImpl) cacheController(ctx context.Context, key string, ctrl *controller) error {
	ctx, span := c.tracer.Start(ctx, "LegacyClientImpl.cacheController")
	defer span.End()

	if ctrl == nil {
		return nil
	}

	buf := bytes.Buffer{}
	err := gob.NewEncoder(&buf).Encode(*ctrl)
	if err != nil {
		return err
	}

	// Cache with default expiry
	return c.cache.Set(ctx, key, buf.Bytes(), cache.DefaultExpiration)
}

func (c *LegacyClientImpl) getCachedController(ctx context.Context, key string) (*controller, error) {
	ctx, span := c.tracer.Start(ctx, "LegacyClientImpl.getCachedController")
	defer span.End()

	data, err := c.cache.Get(ctx, key)
	if err != nil {
		return nil, err
	}

	var ctrl controller
	err = gob.NewDecoder(bytes.NewReader(data)).Decode(&ctrl)
	if err != nil {
		return nil, err
	}
	return &ctrl, nil
}
