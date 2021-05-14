/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:39:03
 * @Last Modified: U2, 2018-07-14 16:39:03
 */

package models

import "time"

type HitInfo struct {
	TypeID    int64 // 1: CCPolicy  2:GroupPolicy
	PolicyID  int64
	VulnName  string
	Action    PolicyAction
	ClientID  string // for CC/Attack Client ID
	TargetURL string // for CAPTCHA redirect
	BlockTime int64
}

type CaptchaContext struct {
	CaptchaId string
	ClientID  string
}

type OAuthState struct {
	CallbackURL string
	UserID      string
	AccessToken string
}

// AccessStat record access statistics
type AccessStat struct {
	AppID      int64  `json:"app_id"`
	URLPath    string `json:"url_path"`
	StatDate   string `json:"stat_date"` // Format("20060102")
	Delta      int64  `json:"delta"`
	UpdateTime int64  `json:"update_time"` // Used for expired cleanup
}

type RefererStat struct {
	AppID      int64  `json:"app_id"`
	Host       string `json:"host"`
	URL        string `json:"url"`
	ClientID   string `json:"client_id"`
	Delta      int64  `json:"delta"`
	UpdateTime int64  `json:"update_time"` // Used for expired cleanup
}

// PopularContent i.e. top visited URL Path
type PopularContent struct {
	AppID   int64  `json:"app_id"`
	URLPath string `json:"url_path"`
	Amount  int64  `json:"amount"`
}

// InternalErrorInfo i.e. 502 or server offline
type InternalErrorInfo struct {
	Description string `json:"description"`
}

// GateHealth give basic information
type GateHealth struct {
	StartTime   int64   `json:"start_time"`
	CurrentTime int64   `json:"cur_time"`
	Version     string  `json:"version"`
	CPUPercent  float64 `json:"cpu_percent"`
	CPULoad1    float64 `json:"cpu_load1"`
	CPULoad5    float64 `json:"cpu_load5"`
	CPULoad15   float64 `json:"cpu_load15"`
	MemUsed     uint64  `json:"mem_used"`
	MemTotal    uint64  `json:"mem_total"`
	DiskUsed    uint64  `json:"disk_used"`
	DiskTotal   uint64  `json:"disk_total"`
	TimeZone    string  `json:"time_zone"`
	TimeOffset  int     `json:"time_offset"`
	ConCurrency int64   `json:"concurrency"`
}

// RefererHost ...
type RefererHost struct {
	Host string `json:"host"`
	PV   int64  `json:"PV"`
	UV   int64  `json:"UV"`
}

// RefererURL ...
type RefererURL struct {
	URL string `json:"url"`
	PV  int64  `json:"PV"`
	UV  int64  `json:"UV"`
}

// ShieldInfo used for 5-second shield page
type ShieldInfo struct {
	Callback string
}

// SMTPSetting shared with all nodes
type SMTPSetting struct {
	SMTPEnabled  bool   `json:"smtp_enabled"`
	SMTPServer   string `json:"smtp_server"`
	SMTPPort     string `json:"smtp_port"`
	SMTPAccount  string `json:"smtp_account"`
	SMTPPassword string `json:"smtp_password"`
	// AdminEmails used as recipients for replica nodes which can not access to database
	// Seperated by ;
	AdminEmails string `json:"admin_emails"`
}

// PrimarySetting used for admin configuration and primary node only
type PrimarySetting struct {
    // AuthenticatorEnabled for janusec-admin 2-factor authentication, v1.2.2
    AuthenticatorEnabled bool `json:"authenticator_enabled"`

	// AuthEnabled for SSO Authentication
	AuthEnabled bool `json:"auth_enabled"`

	// AuthProvider such as wxwork, dingtalk, feishu, lark, ldap, cas2
	AuthProvider string `json:"auth_provider"`

	// WebSSHEnabled for Web-based SSH
	WebSSHEnabled bool `json:"webssh_enabled"`

	// WAFLogDays for WAF logs
	WAFLogDays int64 `json:"waf_log_days"`

	// CCLogDays for CC logs
	CCLogDays int64 `json:"cc_log_days"`

	// AccessLogDays for log files
	AccessLogDays int64 `json:"access_log_days"`

	// Search engines, for 5-second shield
	SkipSEEnabled bool   `json:"skip_se_enabled"`
	SearchEngines string `json:"search_engines"`

	// SMTP
	SMTP *SMTPSetting `json:"smtp"`
}

// NodeShareSetting for sync to replica nodes, v1.2.0
type NodeShareSetting struct {
	// BackendLastModified is the timestamp for latest change of applications, certificates
	BackendLastModified int64 `json:"backend_last_modified"`

	// FirewallLastModified is the timestamp for latest change of WAF/CC rules
	FirewallLastModified int64 `json:"firewall_last_modified"`

	// SyncDuration for replica nodes to check update
	// SyncDuration = "sync_seconds" * time.Second
	SyncInterval time.Duration `json:"sync_interval"`

	// SearchEnginesPattern for bypass the 5-second shield
	SkipSEEnabled        bool   `json:"skip_se_enabled"`
	SearchEnginesPattern string `json:"search_engines_pattern"`

	// AuthConfig for authentication
	AuthConfig *OAuthConfig `json:"auth_config"`

	// SMTP
	SMTP *SMTPSetting `json:"smtp"`
}

// SMTPTestRequest for SMTP test
type SMTPTestRequest struct {
	Action string          `json:"action"`
	Object *SMTPSetting    `json:"object"`
}
