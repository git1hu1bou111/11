package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/payment"
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

// Regression tests for the EasyPay forged-callback vulnerability
// (Wei-Shaw/sub2api issue #7875).
//
// Attack recap: the order-creation signature (visible to the payer in the
// submit.php popup URL) signs return_url among other fields, and the sign
// base string concatenates values unescaped. A client-supplied return_url
// ending in "&trade_status=TRADE_SUCCESS" therefore produced a signature
// that was byte-identical to a payment-success notification's signature
// once the callback decoded return_url partially and promoted the smuggled
// pair to a top-level parameter. Merchant-key rotation could not help
// because the attacker never needed the key.
//
// Fixes covered here:
//  1. service.CanonicalizeReturnURL drops client-supplied query parameters
//     (see payment_resume_service_test.go).
//  2. VerifyNotification rejects any parameter outside the genuine async
//     notify set, so smuggled order-creation fields (return_url et al.)
//     fail closed even if a signed value smuggles a fake pair.

// easyPayPoCProvider returns a provider with a fixed test credential set.
func easyPayPoCProvider() *EasyPay {
	return &EasyPay{config: map[string]string{
		"pid":       "1000",
		"pkey":      "MERCHANT_SECRET_KEY",
		"apiBase":   "https://pay.example.com",
		"notifyUrl": "https://site.example.com/api/v1/payment/webhook/easypay",
		"returnUrl": "https://site.example.com/payment/result",
	}}
}

// TestEasyPayNotifyRejectsForgedSignReuseCallback is the exact PoC payload
// that was accepted before the fix: the order's own submit.php signature
// replayed with trade_status smuggled out of the return_url value.
func TestEasyPayNotifyRejectsForgedSignReuseCallback(t *testing.T) {
	t.Parallel()
	e := easyPayPoCProvider()

	// Order creation (popup mode): return_url carries the smuggled pair as
	// its last sorted inner query key, exactly as buildPaymentReturnURL
	// would have produced before CanonicalizeReturnURL stripped user query.
	returnURL := "https://site.example.com/payment/result?order_id=99&out_trade_no=ORDER123&status=success&trade_status=TRADE_SUCCESS"
	createParams := map[string]string{
		"pid":          "1000",
		"type":         "alipay",
		"out_trade_no": "ORDER123",
		"notify_url":   e.config["notifyUrl"],
		"return_url":   returnURL,
		"name":         "balance recharge",
		"money":        "650.00",
	}
	sign := easyPaySign(createParams, e.config["pkey"])

	// Forged callback: return_url encoded only up to status=success, then a
	// raw &trade_status=TRADE_SUCCESS promotes it to a top-level parameter.
	prefix := "https://site.example.com/payment/result?order_id=99&out_trade_no=ORDER123&status=success"
	cb := url.Values{}
	cb.Set("pid", "1000")
	cb.Set("type", "alipay")
	cb.Set("out_trade_no", "ORDER123")
	cb.Set("notify_url", e.config["notifyUrl"])
	cb.Set("name", "balance recharge")
	cb.Set("money", "650.00")
	cb.Set("return_url", prefix)
	rawCallback := cb.Encode() + "&trade_status=TRADE_SUCCESS" + "&sign=" + sign + "&sign_type=MD5"

	if _, err := e.VerifyNotification(context.Background(), rawCallback, nil); err == nil {
		t.Fatal("forged sign-reuse callback must be rejected")
	}
}

// TestEasyPayNotifyRejectsOrderURLReplay covers the milder variant where the
// attacker replays the complete signed pay URL unchanged: return_url itself
// is not a legitimate notify parameter and must also be rejected.
func TestEasyPayNotifyRejectsOrderURLReplay(t *testing.T) {
	t.Parallel()
	e := easyPayPoCProvider()

	createParams := map[string]string{
		"pid":          "1000",
		"type":         "alipay",
		"out_trade_no": "ORDER123",
		"notify_url":   e.config["notifyUrl"],
		"return_url":   "https://site.example.com/payment/result",
		"name":         "balance recharge",
		"money":        "650.00",
	}
	createParams["sign"] = easyPaySign(createParams, e.config["pkey"])
	createParams["sign_type"] = signTypeMD5
	q := url.Values{}
	for k, v := range createParams {
		q.Set(k, v)
	}

	if _, err := e.VerifyNotification(context.Background(), q.Encode(), nil); err == nil {
		t.Fatal("replayed order URL must be rejected")
	}
}

// TestEasyPayNotifyAcceptsGenuineCallback locks in the legitimate notify
// contract: the canonical parameter set with a valid signature succeeds.
func TestEasyPayNotifyAcceptsGenuineCallback(t *testing.T) {
	t.Parallel()
	e := easyPayPoCProvider()

	params := map[string]string{
		"pid":          "1000",
		"trade_no":     "2026100622001400000001",
		"out_trade_no": "ORDER123",
		"type":         "alipay",
		"name":         "balance recharge",
		"money":        "650.00",
		"trade_status": tradeStatusSuccess,
	}
	sign := easyPaySign(params, e.config["pkey"])
	params["sign"] = sign
	params["sign_type"] = signTypeMD5
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}

	n, err := e.VerifyNotification(context.Background(), q.Encode(), nil)
	if err != nil {
		t.Fatalf("genuine callback rejected: %v", err)
	}
	if n.Status != payment.ProviderStatusSuccess {
		t.Fatalf("status = %v, want success", n.Status)
	}
	if n.OrderID != "ORDER123" || n.TradeNo != "2026100622001400000001" || n.Amount != 650.00 {
		t.Fatalf("unexpected notification: %+v", n)
	}
}

// TestEasyPayNotifyRejectsUnknownParam ensures any parameter outside the
// canonical notify set fails closed, including empty-valued ones that the
// signer itself would skip.
func TestEasyPayNotifyRejectsUnknownParam(t *testing.T) {
	t.Parallel()
	e := easyPayPoCProvider()

	params := map[string]string{
		"pid":          "1000",
		"trade_no":     "T1",
		"out_trade_no": "ORDER123",
		"type":         "alipay",
		"name":         "balance recharge",
		"money":        "650.00",
		"trade_status": tradeStatusSuccess,
	}
	sign := easyPaySign(params, e.config["pkey"])
	q := url.Values{}
	for k, v := range params {
		q.Set(k, v)
	}
	q.Set("sign", sign)
	q.Set("sign_type", signTypeMD5)
	q.Set("device", "") // empty value: invisible to the signer, still rejected

	if _, err := e.VerifyNotification(context.Background(), q.Encode(), nil); err == nil {
		t.Fatal("callback with unknown param must be rejected")
	}
}
