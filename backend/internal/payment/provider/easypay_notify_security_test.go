package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// 回归测试：易支付回调伪造入账（issue #7881 / #7875）。
//
// 攻击链是「下单签名复用 + return_url 注入 trade_status」，落到本包的关键点是
// VerifyNotification 只验签、不校验参数集合，导致攻击者自洽构造的表单能被接受。

func newEasyPayNotifyTestProvider(t *testing.T, extra map[string]string) *EasyPay {
	t.Helper()

	cfg := map[string]string{
		"pid":       "1001",
		"pkey":      "test_secret_key",
		"apiBase":   "https://pay.example.com",
		"notifyUrl": "https://site.example.com/api/v1/payment/webhook/easypay",
		"returnUrl": "https://site.example.com/payment/result",
	}
	for k, v := range extra {
		cfg[k] = v
	}
	p, err := NewEasyPay("test-instance", cfg)
	if err != nil {
		t.Fatalf("NewEasyPay: %v", err)
	}
	return p
}

func notifyBody(params map[string]string) string {
	values := url.Values{}
	for k, v := range params {
		values.Set(k, v)
	}
	return values.Encode()
}

func standardNotifyParams() map[string]string {
	return map[string]string{
		"pid":          "1001",
		"trade_no":     "T-100",
		"out_trade_no": "O-100",
		"type":         "usdt",
		"name":         "余额充值",
		"money":        "100.00",
		"trade_status": tradeStatusSuccess,
	}
}

func TestEasyPayVerifyNotificationAcceptsStandardParams(t *testing.T) {
	t.Parallel()

	p := newEasyPayNotifyTestProvider(t, nil)
	params := standardNotifyParams()
	params["sign"] = easyPaySign(params, "test_secret_key")
	params["sign_type"] = signTypeMD5

	note, err := p.VerifyNotification(context.Background(), notifyBody(params), nil)
	if err != nil {
		t.Fatalf("legit notify must be accepted, got %v", err)
	}
	if note.OrderID != "O-100" || note.TradeNo != "T-100" || note.Amount != 100 {
		t.Fatalf("unexpected notification: %+v", note)
	}
}

func TestEasyPayVerifyNotificationRejectsUnexpectedParam(t *testing.T) {
	t.Parallel()

	p := newEasyPayNotifyTestProvider(t, nil)
	// 攻击者能算出「自洽」的签名（签名基础串包含被注入的 return_url），
	// 但字段集合多出白名单外的 return_url —— 必须拒绝。
	params := standardNotifyParams()
	params["money"] = "2000.00"
	params["return_url"] = "https://site.example.com/payment/result?trade_status=TRADE_SUCCESS"
	params["sign"] = easyPaySign(params, "test_secret_key")

	if _, err := p.VerifyNotification(context.Background(), notifyBody(params), nil); err == nil ||
		!strings.Contains(err.Error(), "unexpected notify param") {
		t.Fatalf("forged notify must be rejected, got err=%v", err)
	}
}

func TestEasyPayVerifyNotificationRejectsEmptyUnexpectedParam(t *testing.T) {
	t.Parallel()

	p := newEasyPayNotifyTestProvider(t, nil)
	// 空值同样要拒：空值虽被签名串忽略，但它说明表单不是上游原样发出的。
	params := standardNotifyParams()
	params["device"] = ""
	params["sign"] = easyPaySign(params, "test_secret_key")

	if _, err := p.VerifyNotification(context.Background(), notifyBody(params), nil); err == nil ||
		!strings.Contains(err.Error(), "unexpected notify param") {
		t.Fatalf("empty unexpected param must be rejected, got err=%v", err)
	}
}

func TestEasyPayVerifyNotificationRejectsDuplicateParam(t *testing.T) {
	t.Parallel()

	p := newEasyPayNotifyTestProvider(t, nil)
	params := standardNotifyParams()
	params["sign"] = easyPaySign(params, "test_secret_key")
	// 重复字段意味着「解析取一个值、验签用另一个值」的错位，必须拒绝。
	body := notifyBody(params) + "&money=9999.00"

	if _, err := p.VerifyNotification(context.Background(), body, nil); err == nil ||
		!strings.Contains(err.Error(), "duplicate notify param") {
		t.Fatalf("duplicate param must be rejected, got err=%v", err)
	}
}

// --- 入账前向上游查单核实 ---

func newUpstreamVerifyServer(t *testing.T, response string, wantCalled *bool) *httptest.Server {
	t.Helper()

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wantCalled != nil {
			*wantCalled = true
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(response))
	}))
}

func signedNotifyParams() map[string]string {
	params := standardNotifyParams()
	params["sign"] = easyPaySign(params, "test_secret_key")
	return params
}

func TestEasyPayVerifyNotificationUpstreamVerifyOffSkipsQuery(t *testing.T) {
	t.Parallel()

	called := false
	srv := newUpstreamVerifyServer(t, `{"status_code":400,"message":"order not found"}`, &called)
	defer srv.Close()

	p := newEasyPayNotifyTestProvider(t, map[string]string{"upstreamVerifyURL": srv.URL})
	if _, err := p.VerifyNotification(context.Background(), notifyBody(signedNotifyParams()), nil); err != nil {
		t.Fatalf("off 模式不应查单、不应拦截: %v", err)
	}
	if called {
		t.Fatal("off 模式不应发起查单请求")
	}
}

func TestEasyPayVerifyNotificationUpstreamVerifyEnforceRejectsUnknownOrder(t *testing.T) {
	t.Parallel()

	srv := newUpstreamVerifyServer(t, `{"status_code":400,"message":"order not found"}`, nil)
	defer srv.Close()

	p := newEasyPayNotifyTestProvider(t, map[string]string{
		"upstreamVerifyMode": "enforce",
		"upstreamVerifyURL":  srv.URL,
	})
	if _, err := p.VerifyNotification(context.Background(), notifyBody(signedNotifyParams()), nil); err == nil ||
		!strings.Contains(err.Error(), "upstream order verify failed") {
		t.Fatalf("enforce 模式下上游查无此单必须拒绝入账, got err=%v", err)
	}
}

func TestEasyPayVerifyNotificationUpstreamVerifyDryRunDoesNotBlock(t *testing.T) {
	t.Parallel()

	srv := newUpstreamVerifyServer(t, `{"status_code":400,"message":"order not found"}`, nil)
	defer srv.Close()

	p := newEasyPayNotifyTestProvider(t, map[string]string{
		"upstreamVerifyMode": "dry_run",
		"upstreamVerifyURL":  srv.URL,
	})
	if _, err := p.VerifyNotification(context.Background(), notifyBody(signedNotifyParams()), nil); err != nil {
		t.Fatalf("dry_run 只记录不拦截, got err=%v", err)
	}
}

func TestEasyPayVerifyNotificationUpstreamVerifyRejectsAmountMismatch(t *testing.T) {
	t.Parallel()

	srv := newUpstreamVerifyServer(t,
		`{"status_code":200,"data":{"order_id":"O-100","trade_id":"T-100","money":"2000","status":2}}`, nil)
	defer srv.Close()

	p := newEasyPayNotifyTestProvider(t, map[string]string{
		"upstreamVerifyMode": "enforce",
		"upstreamVerifyURL":  srv.URL,
	})
	if _, err := p.VerifyNotification(context.Background(), notifyBody(signedNotifyParams()), nil); err == nil ||
		!strings.Contains(err.Error(), "amount mismatch") {
		t.Fatalf("金额不一致必须拒绝, got err=%v", err)
	}
}

func TestEasyPayVerifyNotificationUpstreamVerifyAcceptsPaidOrder(t *testing.T) {
	t.Parallel()

	srv := newUpstreamVerifyServer(t,
		`{"status_code":200,"data":{"order_id":"O-100","trade_id":"T-100","money":"100","status":2}}`, nil)
	defer srv.Close()

	p := newEasyPayNotifyTestProvider(t, map[string]string{
		"upstreamVerifyMode": "enforce",
		"upstreamVerifyURL":  srv.URL,
	})
	notification, err := p.VerifyNotification(context.Background(), notifyBody(signedNotifyParams()), nil)
	if err != nil {
		t.Fatalf("真实已支付订单必须通过: %v", err)
	}
	if notification == nil || notification.OrderID != "O-100" {
		t.Fatalf("unexpected notification: %+v", notification)
	}
}

func TestEasyPayVerifyNotificationAllowsConfiguredExtraParam(t *testing.T) {
	t.Parallel()

	// 逃生通道：确属上游网关的额外字段可在实例配置里显式放行。
	p := newEasyPayNotifyTestProvider(t, map[string]string{"notifyAllowExtraParams": "device, channel"})
	params := standardNotifyParams()
	params["device"] = "mobile"
	params["sign"] = easyPaySign(params, "test_secret_key")

	if _, err := p.VerifyNotification(context.Background(), notifyBody(params), nil); err != nil {
		t.Fatalf("configured extra param must be accepted, got %v", err)
	}
}
