/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:34:51
 * @Last Modified: U2, 2018-07-14 16:34:51
 */

package firewall

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"janusec/data"
	"janusec/models"
	"janusec/usermgmt"
	"janusec/utils"

	"golang.org/x/time/rate"
)

type GroupPoliciesRateLimiter struct {
	limiterMap map[string]*rate.Limiter
	mu         sync.Mutex
}

func NewGroupPoliciesRateLimiter() *GroupPoliciesRateLimiter {
	return &GroupPoliciesRateLimiter{
		limiterMap: make(map[string]*rate.Limiter),
	}
}

func (l *GroupPoliciesRateLimiter) Allowed(clientID string, intervalMilliSeconds float64, maxCount int64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	limiter, ok := l.limiterMap[clientID]
	if !ok {
		// 计算qps
		limit := float64(maxCount) / (intervalMilliSeconds / 1000.0)
		limiter = rate.NewLimiter(rate.Limit(limit), int(maxCount))
		l.limiterMap[clientID] = limiter
	}
	return limiter.Allow()
}

var (
	groupPolicies            = []*models.GroupPolicy{}
	groupPoliciesRateLimiter = NewGroupPoliciesRateLimiter()
)

// InitGroupPolicy ...
func InitGroupPolicy() {
	var dbGroupPolicies []*models.GroupPolicy
	if data.IsPrimary {
		err := data.DAL.CreateTableIfNotExistsGroupPolicy()
		if err != nil {
			utils.DebugPrintln("CreateTableIfNotExistsGroupPolicy error", err)
		}
		err = data.DAL.CreateTableIfNotExistCheckItems()
		if err != nil {
			utils.DebugPrintln("CreateTableIfNotExistCheckItems error", err)
		}
		existRegexPolicy := data.DAL.ExistsGroupPolicy()
		if !existRegexPolicy {
			/*
				err := data.DAL.SetIDSeqStartWith("group_policies", 10101)
				if err != nil {
					utils.DebugPrintln("InitGroupPolicy SetIDSeqStartWith error", err)
				}
			*/
			curTime := time.Now().Unix()
			groupPolicyID, err := data.DAL.InsertGroupPolicy(models.GroupPolicy{
				Description: "Code Leakage",
				VulnID:      100,
				HitValue:    int64(models.ChkPointURLPath),
				Action:      models.Action_Block_100,
				IsEnabled:   true,
				CcStatus:    false,
				UpdateTime:  curTime,
			})
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertGroupPolicy", err)
			}
			_, err = data.DAL.InsertCheckItem(models.ChkPointURLPath, models.OperationRegexMatch, "", `(?i)/\.(git|svn)/`, groupPolicyID)
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertCheckItem", err)
			}

			// r.Form get nil when query use % instead for %25, so check it in url query
			groupPolicyID, err = data.DAL.InsertGroupPolicy(models.GroupPolicy{
				Description: "SQL Injection with Search",
				VulnID:      200,
				HitValue:    int64(models.ChkPointURLQuery),
				Action:      models.Action_Block_100,
				IsEnabled:   true,
				CcStatus:    false,
				UpdateTime:  curTime,
			})
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertGroupPolicy", err)
			}
			_, err = data.DAL.InsertCheckItem(models.ChkPointURLQuery, models.OperationRegexMatch, "", `(?i)%\s+(and|or|procedure)\s+`, groupPolicyID)
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertCheckItem", err)
			}

			// Multiple Sentences SQL Injection  ;\s*(declare|use|drop|create|exec)\s
			groupPolicyID, err = data.DAL.InsertGroupPolicy(models.GroupPolicy{
				Description: "SQL Injection with Multiple Sentences",
				VulnID:      200,
				HitValue:    int64(models.ChkPointURLQuery),
				Action:      models.Action_Block_100,
				IsEnabled:   true,
				CcStatus:    false,
				UpdateTime:  curTime,
			})
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertGroupPolicy", err)
			}
			_, err = data.DAL.InsertCheckItem(models.ChkPointURLQuery, models.OperationRegexMatch, "", `(?i);\s*(declare|use|drop|create|exec)\s`, groupPolicyID)
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertCheckItem", err)
			}

			//  SQL Injection Function
			groupPolicyID, err = data.DAL.InsertGroupPolicy(models.GroupPolicy{
				Description: "Basic SQL Injection Functions",
				VulnID:      200,
				HitValue:    int64(models.ChkPointURLQuery),
				Action:      models.Action_Block_100,
				IsEnabled:   true,
				CcStatus:    false,
				UpdateTime:  curTime,
			})
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertGroupPolicy", err)
			}
			_, err = data.DAL.InsertCheckItem(models.ChkPointURLQuery, models.OperationRegexMatch, "", `(?i)(updatexml|extractvalue|ascii|ord|char|chr|count|concat|rand|floor|substr|length|len|user|database|benchmark|analyse)\s?\(`, groupPolicyID)
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertCheckItem", err)
			}

			//  SQL Injection Case When
			groupPolicyID, err = data.DAL.InsertGroupPolicy(models.GroupPolicy{
				Description: "Basic SQL Injection Case When",
				VulnID:      200,
				HitValue:    int64(models.ChkPointURLQuery),
				Action:      models.Action_Block_100,
				IsEnabled:   true,
				CcStatus:    false,
				UpdateTime:  curTime,
			})
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertGroupPolicy", err)
			}
			_, err = data.DAL.InsertCheckItem(models.ChkPointURLQuery, models.OperationRegexMatch, "", `(?i)\(case\s+when\s+[\w\p{L}]+=[\w\p{L}]+\s+then\s+`, groupPolicyID)
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertCheckItem", err)
			}

			groupPolicyID, err = data.DAL.InsertGroupPolicy(models.GroupPolicy{
				Description: "Basic SQL Injection Attempt",
				VulnID:      200,
				HitValue:    int64(models.ChkPointGetPostValue),
				Action:      models.Action_Block_100,
				IsEnabled:   true,
				CcStatus:    false,
				UpdateTime:  curTime,
			})
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertGroupPolicy", err)
			}
			_, err = data.DAL.InsertCheckItem(models.ChkPointGetPostValue, models.OperationRegexMatch, "", `(?i)\s+(and|or|procedure)\s+[\w\p{L}]+=[\w\p{L}]+(\s|$|--|#)`, groupPolicyID)
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertCheckItem", err)
			}

			groupPolicyID, err = data.DAL.InsertGroupPolicy(models.GroupPolicy{
				Description: "Basic SQL Injection Attempt 2",
				VulnID:      200,
				HitValue:    int64(models.ChkPointGetPostValue),
				Action:      models.Action_Block_100,
				IsEnabled:   true,
				CcStatus:    false,
				UpdateTime:  curTime,
			})
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertGroupPolicy", err)
			}
			_, err = data.DAL.InsertCheckItem(models.ChkPointGetPostValue, models.OperationRegexMatch, "", `(?i)\s+(and|or|rlike)\s+(select|case)\s+`, groupPolicyID)
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertCheckItem", err)
			}

			groupPolicyID, err = data.DAL.InsertGroupPolicy(models.GroupPolicy{
				Description: "Basic SQL Injection Attempt 3",
				VulnID:      200,
				HitValue:    int64(models.ChkPointGetPostValue),
				Action:      models.Action_Block_100,
				IsEnabled:   true,
				CcStatus:    false,
				UpdateTime:  curTime,
			})
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertGroupPolicy", err)
			}
			_, err = data.DAL.InsertCheckItem(models.ChkPointGetPostValue, models.OperationRegexMatch, "", `(?i)\s+(and|or|rlike)\s+(if|updatexml)\(`, groupPolicyID)
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertCheckItem", err)
			}

			groupPolicyID, err = data.DAL.InsertGroupPolicy(models.GroupPolicy{
				Description: "Basic SQL Injection Comment",
				VulnID:      200,
				CheckItems:  nil,
				HitValue:    int64(models.ChkPointGetPostValue),
				Action:      models.Action_Block_100,
				IsEnabled:   true,
				CcStatus:    false,
				UpdateTime:  curTime,
			})
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertGroupPolicy", err)
			}
			_, err = data.DAL.InsertCheckItem(models.ChkPointGetPostValue, models.OperationRegexMatch, "", `(?i)/\*(!|\x00)`, groupPolicyID)
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertCheckItem", err)
			}

			groupPolicyID, err = data.DAL.InsertGroupPolicy(models.GroupPolicy{
				Description: "Union SQL Injection",
				VulnID:      200,
				CheckItems:  nil,
				HitValue:    int64(models.ChkPointURLPath),
				Action:      models.Action_Block_100,
				IsEnabled:   true,
				CcStatus:    false,
				UpdateTime:  curTime,
			})
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertGroupPolicy", err)
			}
			_, err = data.DAL.InsertCheckItem(models.ChkPointGetPostValue, models.OperationRegexMatch, "", `(?i)union[\s/\*]+select`, groupPolicyID)
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertCheckItem", err)
			}

			groupPolicyID, err = data.DAL.InsertGroupPolicy(models.GroupPolicy{
				Description: "Command Injection",
				VulnID:      210,
				HitValue:    int64(models.ChkPointGetPostValue),
				Action:      models.Action_Block_100,
				IsEnabled:   true,
				CcStatus:    false,
				UpdateTime:  curTime,
			})
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertGroupPolicy", err)
			}
			_, err = data.DAL.InsertCheckItem(models.ChkPointGetPostValue, models.OperationRegexMatch, "", `(^|\&\s*|\|\s*|\;\s*)(pwd|ls|ll|whoami|net\s+user)$`, groupPolicyID)
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertCheckItem", err)
			}

			groupPolicyID, err = data.DAL.InsertGroupPolicy(models.GroupPolicy{
				Description: "Web Shell",
				VulnID:      500,
				HitValue:    int64(models.ChkPointGetPostValue),
				Action:      models.Action_Block_100,
				IsEnabled:   true,
				CcStatus:    false,
				UpdateTime:  curTime,
			})
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertGroupPolicy", err)
			}
			_, err = data.DAL.InsertCheckItem(models.ChkPointGetPostValue, models.OperationRegexMatch, "", `(?i)(eval|system|exec|execute|passthru|shell_exec|phpinfo)\(`, groupPolicyID)
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertCheckItem", err)
			}

			groupPolicyID, err = data.DAL.InsertGroupPolicy(models.GroupPolicy{
				Description: "Upload",
				VulnID:      510,
				HitValue:    int64(models.ChkPointUploadFileExt),
				Action:      models.Action_Block_100,
				IsEnabled:   true,
				CcStatus:    false,
				UpdateTime:  curTime,
			})
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertGroupPolicy", err)
			}
			_, err = data.DAL.InsertCheckItem(models.ChkPointUploadFileExt, models.OperationRegexMatch, "", `(?i)\.(php|jsp|aspx|asp|exe|asa)`, groupPolicyID)
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertCheckItem", err)
			}

			// XSS Tags
			groupPolicyID, err = data.DAL.InsertGroupPolicy(models.GroupPolicy{
				Description: "Basic XSS Tags",
				VulnID:      300,
				HitValue:    int64(models.ChkPointURLQuery),
				Action:      models.Action_Block_100,
				IsEnabled:   true,
				CcStatus:    false,
				UpdateTime:  curTime,
			})
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertGroupPolicy", err)
			}
			_, err = data.DAL.InsertCheckItem(models.ChkPointURLQuery, models.OperationRegexMatch, "", `(?i)<(script|iframe)`, groupPolicyID)
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertCheckItem", err)
			}

			// XSS Functions
			groupPolicyID, err = data.DAL.InsertGroupPolicy(models.GroupPolicy{
				Description: "Basic XSS Functions",
				VulnID:      300,
				CheckItems:  nil,
				HitValue:    int64(models.ChkPointURLQuery),
				Action:      models.Action_Block_100,
				IsEnabled:   true,
				CcStatus:    false,
				UpdateTime:  curTime,
			})
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertGroupPolicy", err)
			}
			_, err = data.DAL.InsertCheckItem(models.ChkPointURLQuery, models.OperationRegexMatch, "", `(?i)(alert|eval|prompt)\(`, groupPolicyID)
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertCheckItem", err)
			}

			// XSS Event
			groupPolicyID, err = data.DAL.InsertGroupPolicy(models.GroupPolicy{
				Description: "Basic XSS Event",
				VulnID:      300,
				HitValue:    int64(models.ChkPointURLQuery),
				Action:      models.Action_Block_100,
				IsEnabled:   true,
				CcStatus:    false,
				UpdateTime:  curTime,
			})
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertGroupPolicy", err)
			}
			_, err = data.DAL.InsertCheckItem(models.ChkPointURLQuery, models.OperationRegexMatch, "", `(?i)(onmouseover|onerror|onload|onclick)\s*=`, groupPolicyID)
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertCheckItem", err)
			}

			// Path Traversal
			groupPolicyID, err = data.DAL.InsertGroupPolicy(models.GroupPolicy{
				Description: "Basic Path Traversal",
				VulnID:      400,
				CheckItems:  nil,
				HitValue:    int64(models.ChkPointURLQuery),
				Action:      models.Action_Block_100,
				IsEnabled:   true,
				CcStatus:    false,
				UpdateTime:  curTime,
			})
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertGroupPolicy", err)
			}
			_, err = data.DAL.InsertCheckItem(models.ChkPointURLQuery, models.OperationRegexMatch, "", `\.\./\.\./|/etc/passwd$`, groupPolicyID)
			if err != nil {
				utils.DebugPrintln("InitGroupPolicy InsertCheckItem", err)
			}

		}
		// Load Policies
		dbGroupPolicies = data.DAL.SelectGroupPolicies()
		for _, dbGroupPolicy := range dbGroupPolicies {
			user, _ := usermgmt.GetAppUserByID(dbGroupPolicy.UserID)
			groupPolicy := &models.GroupPolicy{
				ID:                   dbGroupPolicy.ID,
				Description:          dbGroupPolicy.Description,
				AppID:                dbGroupPolicy.AppID,
				VulnID:               dbGroupPolicy.VulnID,
				CheckItems:           []*models.CheckItem{},
				HitValue:             dbGroupPolicy.HitValue,
				Action:               dbGroupPolicy.Action,
				IsEnabled:            dbGroupPolicy.IsEnabled,
				CcStatus:             dbGroupPolicy.CcStatus,
				IntervalMilliSeconds: dbGroupPolicy.IntervalMilliSeconds,
				MaxCount:             dbGroupPolicy.MaxCount,
				BlockSeconds:         dbGroupPolicy.BlockSeconds,
				StatByURL:            dbGroupPolicy.StatByURL,
				StatByUserAgent:      dbGroupPolicy.StatByUserAgent,
				StatByCookie:         dbGroupPolicy.StatByCookie,
				User:                 user,
				UpdateTime:           dbGroupPolicy.UpdateTime,
			}
			groupPolicies = append(groupPolicies, groupPolicy)
		}
	} else {
		groupPolicies = RPCSelectGroupPolicies()
	}
}

// GetGroupPolicies ...
func GetGroupPolicies() ([]*models.GroupPolicy, error) {
	return groupPolicies, nil
}

// GetGroupPolicyByID ...
func GetGroupPolicyByID(id int64) (*models.GroupPolicy, error) {
	for _, groupPolicy := range groupPolicies {
		if groupPolicy.ID == id {
			return groupPolicy, nil
		}
	}
	return nil, errors.New("not found")
}

// GetGroupPolicyIndex ...
func GetGroupPolicyIndex(id int64) int {
	for i := 0; i < len(groupPolicies); i++ {
		if groupPolicies[i].ID == id {
			return i
		}
	}
	return -1
}

// DeleteGroupPolicyByID ...
func DeleteGroupPolicyByID(id int64, clientIP string, authUser *models.AuthUser) error {
	if !authUser.IsSuperAdmin {
		return errors.New("only super administrators can perform this operation")
	}
	groupPolicy, err := GetGroupPolicyByID(id)
	if err != nil {
		return err
	}
	err = DeleteCheckItemsByGroupPolicy(groupPolicy)
	if err != nil {
		utils.DebugPrintln("DeleteCheckItemsByGroupPolicy error", err)
	}
	err = data.DAL.DeleteGroupPolicyByID(id)
	if err != nil {
		utils.DebugPrintln("DeleteGroupPolicyByID error", err)
	}
	i := GetGroupPolicyIndex(id)
	groupPolicies = append(groupPolicies[:i], groupPolicies[i+1:]...)
	go utils.OperationLog(clientIP, authUser.Username, "Delete Group Policy", strconv.FormatInt(id, 10))
	data.UpdateFirewallLastModified()
	return nil
}

// UpdateGroupPolicy ...
func UpdateGroupPolicy(r *http.Request, clientIP string, authUser *models.AuthUser) (*models.GroupPolicy, error) {
	if !authUser.IsSuperAdmin {
		return nil, errors.New("only super administrators can perform this operation")
	}
	var groupPolicyRequest models.APIGroupPolicyRequest
	err := json.NewDecoder(r.Body).Decode(&groupPolicyRequest)
	if err != nil {
		utils.DebugPrintln("UpdateGroupPolicy Decode", err)
		return nil, errors.New("decode body error")
	}
	defer r.Body.Close()
	curGroupPolicy := groupPolicyRequest.Object
	if curGroupPolicy == nil {
		return nil, errors.New("updateGroupPolicy parse body null")
	}
	curGroupPolicy.UpdateTime = time.Now().Unix()
	checkItems := curGroupPolicy.CheckItems
	curGroupPolicy.HitValue = 0
	for _, checkItem := range checkItems {
		checkItem.GroupPolicy = curGroupPolicy
		curGroupPolicy.HitValue += int64(checkItem.CheckPoint)
	}
	curGroupPolicy.UserID = authUser.UserID
	curTime := time.Now().Unix()
	if curGroupPolicy.ID == 0 {
		newID, err := data.DAL.InsertGroupPolicy(models.GroupPolicy{
			Description:          curGroupPolicy.Description,
			AppID:                curGroupPolicy.AppID,
			VulnID:               curGroupPolicy.VulnID,
			HitValue:             curGroupPolicy.HitValue,
			Action:               curGroupPolicy.Action,
			IsEnabled:            curGroupPolicy.IsEnabled,
			CcStatus:             curGroupPolicy.CcStatus,
			IntervalMilliSeconds: curGroupPolicy.IntervalMilliSeconds,
			MaxCount:             curGroupPolicy.MaxCount,
			BlockSeconds:         curGroupPolicy.BlockSeconds,
			StatByURL:            curGroupPolicy.StatByURL,
			StatByUserAgent:      curGroupPolicy.StatByUserAgent,
			StatByCookie:         curGroupPolicy.StatByCookie,
			UserID:               curGroupPolicy.UserID,
			UpdateTime:           curTime,
		})
		if err != nil {
			utils.DebugPrintln("UpdateGroupPolicy InsertGroupPolicy", err)
		}
		curGroupPolicy.ID = newID
		groupPolicies = append(groupPolicies, curGroupPolicy)
		err = UpdateCheckItems(curGroupPolicy, checkItems)
		if err != nil {
			utils.DebugPrintln("UpdateGroupPolicy UpdateCheckItems error", err)
		}
		go utils.OperationLog(clientIP, authUser.Username, "Add Group Policy", curGroupPolicy.Description)
	} else {
		groupPolicy, err := GetGroupPolicyByID(curGroupPolicy.ID)
		groupPolicy.Description = curGroupPolicy.Description
		groupPolicy.AppID = curGroupPolicy.AppID
		groupPolicy.VulnID = curGroupPolicy.VulnID
		groupPolicy.HitValue = curGroupPolicy.HitValue
		groupPolicy.Action = curGroupPolicy.Action
		groupPolicy.IsEnabled = curGroupPolicy.IsEnabled
		groupPolicy.CcStatus = curGroupPolicy.CcStatus
		groupPolicy.IntervalMilliSeconds = curGroupPolicy.IntervalMilliSeconds
		groupPolicy.MaxCount = curGroupPolicy.MaxCount
		groupPolicy.BlockSeconds = curGroupPolicy.BlockSeconds
		groupPolicy.StatByURL = curGroupPolicy.StatByURL
		groupPolicy.StatByUserAgent = curGroupPolicy.StatByUserAgent
		groupPolicy.StatByCookie = curGroupPolicy.StatByCookie
		groupPolicy.UserID = curGroupPolicy.UserID
		groupPolicy.UpdateTime = curTime
		if err != nil {
			utils.DebugPrintln("UpdateGroupPolicy GetGroupPolicyByID", err)
		}
		_ = data.DAL.UpdateGroupPolicy(*groupPolicy)
		if err != nil {
			utils.DebugPrintln("UpdateGroupPolicy UpdateGroupPolicy", err)
		}
		err = UpdateCheckItems(groupPolicy, checkItems)
		if err != nil {
			utils.DebugPrintln("UpdateGroupPolicy UpdateCheckItems error", err)
		}
		go utils.OperationLog(clientIP, authUser.Username, "Update Group Policy", curGroupPolicy.Description)
	}
	return curGroupPolicy, nil
}

// IsMatchGroupPolicy ...
func IsMatchGroupPolicy(hitValueMap *sync.Map, appID int64, value string, checkPoint models.ChkPoint, headerKey string, needDecode bool) (bool, *models.GroupPolicy) {
	if len(value) == 0 && checkPoint != models.ChkPointReferer {
		// Exclude referer, because some cases require that Referer exists, such as CSRF detection
		return false, nil
	}
	checkItemsMap, ok := checkPointCheckItemsMap.Load(checkPoint)
	if !ok {
		return false, nil
	}
	//fmt.Println("IsMatchGroupPolicy checkpoint:", check_point)
	checkItems := checkItemsMap.([]*models.CheckItem)
	if needDecode {
		value = UnEscapeRawValue(value)
	}
	for _, checkItem := range checkItems {
		groupPolicy := checkItem.GroupPolicy
		if !groupPolicy.IsEnabled {
			continue
		}
		if groupPolicy.AppID == 0 || groupPolicy.AppID == appID {
			if len(checkItem.KeyName) > 0 && (checkItem.KeyName != headerKey) {
				continue
			}
			hit := false
			var err error
			switch checkItem.Operation {
			case models.OperationRegexMatch:
				hit, err = regexp.MatchString(checkItem.RegexPolicy, value)
				if err != nil {
					utils.DebugPrintln("IsMatchGroupPolicy MatchString", err)
				}
			case models.OperationEqualsStringCaseInsensitive:
				if strings.EqualFold(checkItem.RegexPolicy, value) {
					hit = true
				}
			case models.OperationGreaterThanInteger:
				policyValue, err := strconv.ParseInt(checkItem.RegexPolicy, 10, 64)
				if err != nil {
					utils.DebugPrintln("IsMatchGroupPolicy ParseInt", err)
				}
				checkValue, err := strconv.ParseInt(value, 10, 64)
				if err != nil {
					utils.DebugPrintln("IsMatchGroupPolicy ParseInt", err)
				}
				if checkValue > policyValue {
					hit = true
				}
			case models.OperationEqualsInteger:
				policyValue, err := strconv.ParseInt(checkItem.RegexPolicy, 10, 64)
				if err != nil {
					utils.DebugPrintln("IsMatchGroupPolicy ParseInt", err)
				}
				checkValue, err := strconv.ParseInt(value, 10, 64)
				if err != nil {
					utils.DebugPrintln("IsMatchGroupPolicy ParseInt", err)
				}
				if checkValue == policyValue {
					hit = true
				}
			case models.OperationLengthGreaterThanInteger:
				policyValue, err := strconv.ParseInt(checkItem.RegexPolicy, 10, 64)
				if err != nil {
					utils.DebugPrintln("IsMatchGroupPolicy ParseInt", err)
				}
				if (int64(len(value)) > policyValue) && (policyValue > 0) {
					hit = true
				}
			case models.OperationRegexNotMatch:
				notHit, err := regexp.MatchString(checkItem.RegexPolicy, value)
				hit = !notHit
				if err != nil {
					utils.DebugPrintln("IsMatchGroupPolicy NotMatchString", err)
				}
			}
			if hit {
				hitValueInterface, _ := hitValueMap.LoadOrStore(groupPolicy.ID, int64(0))
				hitValue := hitValueInterface.(int64)
				hitValue += int64(checkItem.CheckPoint)
				if hitValue == groupPolicy.HitValue {
					return hit, groupPolicy
				}
				hitValueMap.Store(groupPolicy.ID, hitValue)
			}
		}
	}
	return false, nil
}

// IsMatchGroupPolicyRateLimit 是否匹配到频率限制 return iscc clientID needlog
func IsMatchGroupPolicyRateLimit(r *http.Request, policy *models.GroupPolicy, srcIP string) (bool, string, bool) {
	if !policy.CcStatus || policy.Action == models.Action_Pass_400 {
		return false, "", false
	}
	// 构建访问唯一标识
	preHashContent := srcIP + fmt.Sprint(policy.ID)
	if policy.StatByURL {
		preHashContent += r.URL.Path
	}
	if policy.StatByUserAgent {
		ua := r.Header.Get("User-Agent")
		preHashContent += ua
	}
	if policy.StatByCookie {
		cookie := r.Header.Get("Cookie")
		preHashContent += cookie
	}
	clientID := data.SHA256Hash(preHashContent)
	allowed := groupPoliciesRateLimiter.Allowed(clientID, policy.IntervalMilliSeconds, policy.MaxCount)
	if allowed {
		return false, "", false
	}
	return true, clientID, true
}

// PreProcessString ...
func PreProcessString(value string) string {
	value2 := strings.Replace(value, `'`, ``, -1)
	value2 = strings.Replace(value2, `"`, ``, -1)
	value2 = strings.Replace(value2, `+`, ` `, -1)
	value2 = strings.Replace(value2, `/**/`, ` `, -1)
	return value2
}

// IsMatch ...
func IsMatch(pattern string, str string) (bool, error) {
	return regexp.MatchString(pattern, str)
}

// TestRegex ...
func TestRegex(body []byte) (*models.RegexMatch, error) {
	var rpcRegexTestRequest models.APIRegexMatchRequest
	if err := json.Unmarshal(body, &rpcRegexTestRequest); err != nil {
		utils.DebugPrintln("UpdateRegexTestPolicy", err)
		return nil, err
	}
	regexTest := rpcRegexTestRequest.Object
	if regexTest.PreProcess {
		regexTest.Payload = UnEscapeRawValue(regexTest.Payload)
	}
	var err error
	regexTest.Matched, err = IsMatch(regexTest.Pattern, regexTest.Payload)
	return regexTest, err
}
