package splithttp

import (
	"context"
	"io"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport/internet/browser_dialer"
	"github.com/xtls/xray-core/transport/internet/websocket"
)

// BrowserDialerClient implements splithttp.DialerClient in terms of browser dialer
type BrowserDialerClient struct {
	transportConfig *Config
}

func (c *BrowserDialerClient) IsClosed() bool {
	return false // Browser dialer does not track connection state
}

func (c *BrowserDialerClient) OpenStream(ctx context.Context, url string, _ string, body io.Reader, uploadOnly bool) (io.ReadCloser, net.Addr, net.Addr, error) {
	if body != nil {
		return nil, nil, nil, errors.New("bidirectional streaming for browser dialer not implemented yet")
	}

	header := c.transportConfig.GetRequestHeader()
	length := int(c.transportConfig.GetNormalizedXPaddingBytes().rand())
	config := XPaddingConfig{Length: length}

	if c.transportConfig.XPaddingObfsMode {
		config.Placement = XPaddingPlacement{
			Placement: c.transportConfig.XPaddingPlacement,
			Key:       c.transportConfig.XPaddingKey,
			Header:    c.transportConfig.XPaddingHeader,
			RawURL:    url,
		}
		config.Method = PaddingMethod(c.transportConfig.XPaddingMethod)
	} else {
		config.Placement = XPaddingPlacement{
			Placement: PlacementQueryInHeader,
			Key:       "x_padding",
			Header:    "Referer",
			RawURL:    url,
		}
	}

	c.transportConfig.ApplyXPaddingToHeader(header, config)

	conn, err := browser_dialer.DialGet(url, header)
	dummyAddr := &net.IPAddr{}
	if err != nil {
		return nil, dummyAddr, dummyAddr, err
	}

	return websocket.NewConnection(conn, dummyAddr, nil, 0), conn.RemoteAddr(), conn.LocalAddr(), nil
}

// maxBrowserPostBytes is the maximum body size for browser dialer POST requests.
// This prevents memory exhaustion from oversized request bodies.
const maxBrowserPostBytes = 32 * 1024 * 1024 // 32 MiB

func (c *BrowserDialerClient) PostPacket(ctx context.Context, url string, _ string, _ string, body io.Reader, contentLength int64) error {
	bytes, err := io.ReadAll(io.LimitReader(body, maxBrowserPostBytes+1))
	if err != nil {
		return err
	}
	if int64(len(bytes)) > maxBrowserPostBytes {
		return errors.New("browser dialer: POST body exceeds maximum size")
	}

	header := c.transportConfig.GetRequestHeader()
	length := int(c.transportConfig.GetNormalizedXPaddingBytes().rand())
	config := XPaddingConfig{Length: length}

	if c.transportConfig.XPaddingObfsMode {
		config.Placement = XPaddingPlacement{
			Placement: c.transportConfig.XPaddingPlacement,
			Key:       c.transportConfig.XPaddingKey,
			Header:    c.transportConfig.XPaddingHeader,
			RawURL:    url,
		}
		config.Method = PaddingMethod(c.transportConfig.XPaddingMethod)
	} else {
		config.Placement = XPaddingPlacement{
			Placement: PlacementQueryInHeader,
			Key:       "x_padding",
			Header:    "Referer",
			RawURL:    url,
		}
	}

	c.transportConfig.ApplyXPaddingToHeader(header, config)

	err = browser_dialer.DialPost(url, header, bytes)
	if err != nil {
		return err
	}

	return nil
}
