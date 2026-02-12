package sumsub

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"passstore/cre_go/internal/config"
)

type ReviewDecision string

const (
	DecisionGreen   ReviewDecision = "GREEN"
	DecisionRed     ReviewDecision = "RED"
	DecisionPending ReviewDecision = "PENDING"
)

type Client struct {
	baseURL        string
	appToken       string
	secretKey      string
	sdkTokenPath   string
	statusPathTmpl string
	httpClient     *http.Client
}

func New(cfg config.Config) *Client {
	return &Client{
		baseURL:        cfg.SumsubBaseURL,
		appToken:       cfg.SumsubAppToken,
		secretKey:      cfg.SumsubSecretKey,
		sdkTokenPath:   cfg.SumsubSDKTokenPath,
		statusPathTmpl: cfg.SumsubStatusPathTmpl,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

func (c *Client) GenerateSDKToken(ctx context.Context, userID, levelName string, ttlSeconds int) (string, error) {
	body := map[string]interface{}{
		"userId":    userID,
		"levelName": levelName,
		"ttlInSecs": ttlSeconds,
	}

	resp, err := c.request(ctx, http.MethodPost, c.sdkTokenPath, body)
	if err != nil {
		return "", err
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(resp, &decoded); err != nil {
		return "", err
	}

	token, _ := decoded["token"].(string)
	if token == "" {
		return "", fmt.Errorf("sumsub token response has no token field: %s", string(resp))
	}

	return token, nil
}

func (c *Client) GetReviewDecisionByUserID(ctx context.Context, userID string) (ReviewDecision, error) {
	path := strings.ReplaceAll(c.statusPathTmpl, "{userId}", url.QueryEscape(userID))
	resp, err := c.request(ctx, http.MethodGet, path, nil)
	if err != nil {
		if isApplicantNotFoundError(err) {
			return DecisionPending, nil
		}
		return DecisionPending, err
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(resp, &decoded); err != nil {
		return DecisionPending, err
	}

	reviewStatus := extractString(decoded, []string{"review", "reviewStatus"})
	if reviewStatus == "" {
		reviewStatus = extractString(decoded, []string{"reviewStatus"})
	}
	if reviewStatus == "" {
		reviewStatus = extractString(decoded, []string{"reviewResult", "reviewAnswer"})
	}
	if reviewStatus == "" {
		reviewStatus = extractString(decoded, []string{"inspectionStatus"})
	}

	return normalizeDecision(reviewStatus), nil
}

func isApplicantNotFoundError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "failed (404)") && strings.Contains(msg, "applicant not found")
}

func (c *Client) request(ctx context.Context, method, path string, body map[string]interface{}) ([]byte, error) {
	bodyBytes := []byte{}
	if body != nil {
		var err error
		bodyBytes, err = json.Marshal(body)
		if err != nil {
			return nil, err
		}
	}

	ts := fmt.Sprintf("%d", time.Now().Unix())
	sig := signature(c.secretKey, ts, method, path, string(bodyBytes))

	fullURL := strings.TrimRight(c.baseURL, "/") + path
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}

	req.Header.Set("X-App-Token", c.appToken)
	req.Header.Set("X-App-Access-Ts", ts)
	req.Header.Set("X-App-Access-Sig", sig)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	res, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	respBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return nil, fmt.Errorf("sumsub %s %s failed (%d): %s", method, path, res.StatusCode, string(respBytes))
	}

	return respBytes, nil
}

func signature(secretKey, ts, method, path, body string) string {
	payload := ts + strings.ToUpper(method) + path + body
	h := hmac.New(sha256.New, []byte(secretKey))
	_, _ = h.Write([]byte(payload))
	return hex.EncodeToString(h.Sum(nil))
}

func normalizeDecision(raw string) ReviewDecision {
	normalized := strings.ToUpper(raw)

	if strings.Contains(normalized, "GREEN") || strings.Contains(normalized, "APPROVED") || strings.Contains(normalized, "COMPLETED") {
		return DecisionGreen
	}
	if strings.Contains(normalized, "RED") || strings.Contains(normalized, "REJECTED") || strings.Contains(normalized, "DECLINED") {
		return DecisionRed
	}

	return DecisionPending
}

func extractString(data map[string]interface{}, path []string) string {
	var cur interface{} = data
	for _, segment := range path {
		obj, ok := cur.(map[string]interface{})
		if !ok {
			return ""
		}
		cur, ok = obj[segment]
		if !ok {
			return ""
		}
	}
	v, _ := cur.(string)
	return v
}
