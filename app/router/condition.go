package router

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/strmatcher"
	"github.com/xtls/xray-core/features/routing"
)

type Condition interface {
	Apply(ctx routing.Context) bool
}

type ConditionChan []Condition

func NewConditionChan() *ConditionChan {
	var condChan ConditionChan = make([]Condition, 0, 8)
	return &condChan
}

func (v *ConditionChan) Add(cond Condition) *ConditionChan {
	*v = append(*v, cond)
	return v
}

// Apply applies all conditions registered in this chan.
func (v *ConditionChan) Apply(ctx routing.Context) bool {
	for _, cond := range *v {
		if !cond.Apply(ctx) {
			return false
		}
	}
	return true
}

func (v *ConditionChan) Len() int {
	return len(*v)
}

var matcherTypeMap = map[Domain_Type]strmatcher.Type{
	Domain_Plain:  strmatcher.Substr,
	Domain_Regex:  strmatcher.Regex,
	Domain_Domain: strmatcher.Domain,
	Domain_Full:   strmatcher.Full,
}

type DomainMatcher struct {
	Matchers strmatcher.IndexMatcher
}

func SerializeDomainMatcher(domains []*Domain, w io.Writer) error {

	g := strmatcher.NewMphMatcherGroup()
	for _, d := range domains {
		matcherType, f := matcherTypeMap[d.Type]
		if !f {
			continue
		}

		_, err := g.AddPattern(d.Value, matcherType)
		if err != nil {
			return err
		}
	}
	g.Build()
	// serialize
	return g.Serialize(w)
}

func NewDomainMatcherFromBuffer(data []byte) (*strmatcher.MphMatcherGroup, error) {
	matcher, err := strmatcher.NewMphMatcherGroupFromBuffer(data)
	if err != nil {
		return nil, err
	}
	return matcher, nil
}

func NewMphMatcherGroup(domains []*Domain) (*DomainMatcher, error) {
	g := strmatcher.NewMphMatcherGroup()
	for i, d := range domains {
		domains[i] = nil
		matcherType, f := matcherTypeMap[d.Type]
		if !f {
			errors.LogError(context.Background(), "ignore unsupported domain type ", d.Type, " of rule ", d.Value)
			continue
		}
		_, err := g.AddPattern(d.Value, matcherType)
		if err != nil {
			errors.LogErrorInner(context.Background(), err, "ignore domain rule ", d.Type, " ", d.Value)
			continue
		}
	}
	g.Build()
	return &DomainMatcher{
		Matchers: g,
	}, nil
}

func (m *DomainMatcher) ApplyDomain(domain string) bool {
	return len(m.Matchers.Match(strings.ToLower(domain))) > 0
}

// Apply implements Condition.
func (m *DomainMatcher) Apply(ctx routing.Context) bool {
	domain := ctx.GetTargetDomain()
	if len(domain) == 0 {
		return false
	}
	return m.ApplyDomain(domain)
}

type MatcherAsType byte

const (
	MatcherAsType_Local MatcherAsType = iota
	MatcherAsType_Source
	MatcherAsType_Target
	MatcherAsType_VlessRoute // for port
)

type IPMatcher struct {
	matcher GeoIPMatcher
	asType  MatcherAsType
}

func NewIPMatcher(geoips []*GeoIP, asType MatcherAsType) (*IPMatcher, error) {
	matcher, err := BuildOptimizedGeoIPMatcher(geoips...)
	if err != nil {
		return nil, err
	}
	return &IPMatcher{matcher: matcher, asType: asType}, nil
}

// Apply implements Condition.
func (m *IPMatcher) Apply(ctx routing.Context) bool {
	var ips []net.IP

	switch m.asType {
	case MatcherAsType_Local:
		ips = ctx.GetLocalIPs()
	case MatcherAsType_Source:
		ips = ctx.GetSourceIPs()
	case MatcherAsType_Target:
		ips = ctx.GetTargetIPs()
	default:
		errors.LogWarning(context.Background(), "IPMatcher: unknown asType ", m.asType, ", returning no match")
		return false
	}

	return m.matcher.AnyMatch(ips)
}

type PortMatcher struct {
	port   net.MemoryPortList
	asType MatcherAsType
}

// NewPortMatcher create a new port matcher that can match source or local or destination port
func NewPortMatcher(list *net.PortList, asType MatcherAsType) *PortMatcher {
	return &PortMatcher{
		port:   net.PortListFromProto(list),
		asType: asType,
	}
}

// Apply implements Condition.
func (v *PortMatcher) Apply(ctx routing.Context) bool {
	switch v.asType {
	case MatcherAsType_Local:
		return v.port.Contains(ctx.GetLocalPort())
	case MatcherAsType_Source:
		return v.port.Contains(ctx.GetSourcePort())
	case MatcherAsType_Target:
		return v.port.Contains(ctx.GetTargetPort())
	case MatcherAsType_VlessRoute:
		return v.port.Contains(ctx.GetVlessRoute())
	default:
		errors.LogWarning(context.Background(), "PortMatcher: unknown asType ", v.asType, ", returning no match")
		return false
	}
}

type NetworkMatcher struct {
	list [8]bool
}

func NewNetworkMatcher(network []net.Network) NetworkMatcher {
	var matcher NetworkMatcher
	for _, n := range network {
		matcher.list[int(n)] = true
	}
	return matcher
}

// Apply implements Condition.
func (v NetworkMatcher) Apply(ctx routing.Context) bool {
	return v.list[int(ctx.GetNetwork())]
}

type UserMatcher struct {
	user    []string
	pattern []*regexp.Regexp
}

func NewUserMatcher(users []string) *UserMatcher {
	usersCopy := make([]string, 0, len(users))
	patternsCopy := make([]*regexp.Regexp, 0, len(users))
	for _, user := range users {
		if len(user) > 0 {
			if len(user) > 7 && strings.HasPrefix(user, "regexp:") {
				if re, err := regexp.Compile(user[7:]); err == nil {
					patternsCopy = append(patternsCopy, re)
				}
				// Items of users slice with an invalid regexp syntax are ignored.
				continue
			}
			usersCopy = append(usersCopy, user)
		}
	}
	return &UserMatcher{
		user:    usersCopy,
		pattern: patternsCopy,
	}
}

// Apply implements Condition.
func (v *UserMatcher) Apply(ctx routing.Context) bool {
	user := ctx.GetUser()
	if len(user) == 0 {
		return false
	}
	for _, u := range v.user {
		if u == user {
			return true
		}
	}
	for _, re := range v.pattern {
		if re.MatchString(user) {
			return true
		}
	}
	return false
}

type InboundTagMatcher struct {
	tags []string
}

func NewInboundTagMatcher(tags []string) *InboundTagMatcher {
	tagsCopy := make([]string, 0, len(tags))
	for _, tag := range tags {
		if len(tag) > 0 {
			tagsCopy = append(tagsCopy, tag)
		}
	}
	return &InboundTagMatcher{
		tags: tagsCopy,
	}
}

// Apply implements Condition.
func (v *InboundTagMatcher) Apply(ctx routing.Context) bool {
	tag := ctx.GetInboundTag()
	if len(tag) == 0 {
		return false
	}
	for _, t := range v.tags {
		if t == tag {
			return true
		}
	}
	return false
}

type ProtocolMatcher struct {
	protocols []string
}

func NewProtocolMatcher(protocols []string) *ProtocolMatcher {
	pCopy := make([]string, 0, len(protocols))

	for _, p := range protocols {
		if len(p) > 0 {
			pCopy = append(pCopy, p)
		}
	}

	return &ProtocolMatcher{
		protocols: pCopy,
	}
}

// Apply implements Condition.
func (m *ProtocolMatcher) Apply(ctx routing.Context) bool {
	protocol := ctx.GetProtocol()
	if len(protocol) == 0 {
		return false
	}
	for _, p := range m.protocols {
		if strings.HasPrefix(protocol, p) {
			return true
		}
	}
	return false
}

type AttributeMatcher struct {
	configuredKeys map[string]*regexp.Regexp
}

// Match implements attributes matching.
func (m *AttributeMatcher) Match(attrs map[string]string) bool {
	// Most attribute keys are already normalized; only build a folded-key view
	// on demand when an exact lookup misses.
	var foldedHeaders map[string]string
	for key, regex := range m.configuredKeys {
		a, ok := attrs[key]
		if !ok {
			if foldedHeaders == nil {
				foldedHeaders = make(map[string]string, len(attrs))
				for headerKey, value := range attrs {
					foldedHeaders[strings.ToLower(headerKey)] = value
				}
			}
			a, ok = foldedHeaders[key]
		}
		if !ok || !regex.MatchString(a) {
			return false
		}
	}
	return true
}

// Apply implements Condition.
func (m *AttributeMatcher) Apply(ctx routing.Context) bool {
	attributes := ctx.GetAttributes()
	if attributes == nil {
		return false
	}
	return m.Match(attributes)
}

type ProcessNameMatcher struct {
	ProcessNames  []string
	AbsPaths      []string
	Folders       []string
	MatchXraySelf bool

	cacheMu sync.Mutex
	cache   [processLookupCacheSize]processLookupEntry
}

const (
	processLookupCacheSize = 256
	processLookupCacheTTL  = 2 * time.Second
)

type processLookupKey struct {
	network net.Network
	port    net.Port
	ip      [16]byte
	ipLen   uint8
}

type processLookupEntry struct {
	key       processLookupKey
	expiresAt int64
	pid       int
	name      string
	absPath   string
	valid     bool
}

var findProcess = net.FindProcess

func makeProcessLookupKey(network net.Network, ip net.IP, port net.Port) (processLookupKey, bool) {
	var key processLookupKey
	key.network = network
	key.port = port
	if ip4 := ip.To4(); ip4 != nil {
		key.ipLen = 4
		copy(key.ip[:], ip4)
		return key, true
	}
	if ip16 := ip.To16(); ip16 != nil {
		key.ipLen = 16
		copy(key.ip[:], ip16)
		return key, true
	}
	return processLookupKey{}, false
}

func processLookupCacheIndex(key processLookupKey) int {
	h := uint32(key.network)<<24 ^ uint32(key.port)<<8 ^ uint32(key.ipLen)
	for i := 0; i < int(key.ipLen); i++ {
		h ^= uint32(key.ip[i])
		h *= 16777619
	}
	return int(h % processLookupCacheSize)
}

func (m *ProcessNameMatcher) loadProcessCache(key processLookupKey, now int64) (int, string, string, bool) {
	idx := processLookupCacheIndex(key)
	m.cacheMu.Lock()
	defer m.cacheMu.Unlock()

	entry := m.cache[idx]
	if !entry.valid || entry.key != key {
		return 0, "", "", false
	}
	if entry.expiresAt <= now {
		m.cache[idx] = processLookupEntry{}
		return 0, "", "", false
	}
	return entry.pid, entry.name, entry.absPath, true
}

func (m *ProcessNameMatcher) storeProcessCache(key processLookupKey, pid int, name, absPath string, now int64) {
	idx := processLookupCacheIndex(key)
	m.cacheMu.Lock()
	m.cache[idx] = processLookupEntry{
		key:       key,
		expiresAt: now + int64(processLookupCacheTTL),
		pid:       pid,
		name:      name,
		absPath:   absPath,
		valid:     true,
	}
	m.cacheMu.Unlock()
}

func (m *ProcessNameMatcher) matches(pid int, name, absPath string) bool {
	if m.MatchXraySelf && pid == os.Getpid() {
		return true
	}
	if slices.Contains(m.ProcessNames, name) {
		return true
	}
	if slices.Contains(m.AbsPaths, absPath) {
		return true
	}
	for _, f := range m.Folders {
		if strings.HasPrefix(absPath, f) {
			return true
		}
	}
	return false
}

func NewProcessNameMatcher(names []string) *ProcessNameMatcher {
	processNames := []string{}
	folders := []string{}
	absPaths := []string{}
	matchXraySelf := false
	for _, name := range names {
		if name == "self/" {
			matchXraySelf = true
			continue
		}
		// replace xray/ with self executable path
		if name == "xray/" {
			xrayPath, err := os.Executable()
			if err != nil {
				errors.LogError(context.Background(), "Failed to get xray executable path: ", err)
				continue
			}
			name = xrayPath
		}
		name := filepath.ToSlash(name)
		// /usr/bin/
		if strings.HasSuffix(name, "/") {
			folders = append(folders, name)
			continue
		}
		// /usr/bin/curl
		if strings.Contains(name, "/") {
			absPaths = append(absPaths, name)
			continue
		}
		// curl.exe or curl
		processNames = append(processNames, strings.TrimSuffix(name, ".exe"))
	}
	return &ProcessNameMatcher{
		ProcessNames:  processNames,
		AbsPaths:      absPaths,
		Folders:       folders,
		MatchXraySelf: matchXraySelf,
	}
}

func (m *ProcessNameMatcher) Apply(ctx routing.Context) bool {
	sourceIPs := ctx.GetSourceIPs()
	if len(sourceIPs) == 0 {
		return false
	}
	sourceIP := sourceIPs[0]
	sourcePort := ctx.GetSourcePort()
	network := ctx.GetNetwork()

	address := net.IPAddress(sourceIP)
	if address == nil {
		return false
	}

	var src net.Destination
	switch ctx.GetNetwork() {
	case net.Network_TCP:
		src = net.TCPDestination(address, sourcePort)
	case net.Network_UDP:
		src = net.UDPDestination(address, sourcePort)
	default:
		return false
	}

	key, ok := makeProcessLookupKey(network, sourceIP, sourcePort)
	if !ok {
		return false
	}

	now := time.Now().UnixNano()
	if pid, name, absPath, hit := m.loadProcessCache(key, now); hit {
		return m.matches(pid, name, absPath)
	}

	pid, name, absPath, err := findProcess(src)
	if err != nil {
		if err != net.ErrNotLocal {
			errors.LogError(context.Background(), "Unables to find local process name: ", err)
		}
		return false
	}

	m.storeProcessCache(key, pid, name, absPath, now)
	return m.matches(pid, name, absPath)
}
