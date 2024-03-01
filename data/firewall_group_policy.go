/*
 * @Copyright Reserved By Janusec (https://www.janusec.com/).
 * @Author: U2
 * @Date: 2018-07-14 16:31:06
 * @Last Modified: U2, 2018-07-14 16:31:06
 */

package data

import (
	"janusec/models"
	"janusec/utils"
)

const (
	sqlCreateTableIfNotExistsGroupPolicy = `CREATE TABLE IF NOT EXISTS "group_policies"
(
    "id"                    bigserial primary key,
    "description"           VARCHAR(256) NOT NULL DEFAULT '',
    "app_id"                bigint,
    "vuln_id"               bigint,
    "hit_value"             bigint,
    "action"                bigint,
    "is_enabled"            boolean,
    cc_status               boolean,
    "interval_milliseconds" double precision,
    "max_count"             bigint,
    "block_seconds"         double precision,
    "stat_by_url"           boolean,
    "stat_by_ua"            boolean,
    "stat_by_cookie"        boolean,
    "user_id"               bigint,
    "update_time"           bigint
)`
	sqlExistsGroupPolicy   = `SELECT COALESCE((SELECT 1 FROM "group_policies" limit 1),0)`
	sqlSelectGroupPolicies = `SELECT "id",
       "description",
       "app_id",
       "vuln_id",
       "hit_value",
       "action",
       "is_enabled",
       "cc_status",
       "interval_milliseconds",
       "max_count",
       "block_seconds",
       "stat_by_url",
       "stat_by_ua",
       "stat_by_cookie",
       "user_id",
       "update_time"
FROM "group_policies"`
	sqlSelectGroupPoliciesByAppID = `SELECT "id","description","vuln_id","hit_value","action","is_enabled","cc_status","interval_milliseconds","max_count","block_seconds","stat_by_url","stat_by_ua","stat_by_cookie","user_id","update_time" FROM "group_policies" WHERE "app_id"=$1`
	sqlInsertGroupPolicy          = `INSERT INTO "group_policies"("id", "description", "app_id", "vuln_id", "hit_value", "action", "is_enabled", "cc_status",
                             "interval_milliseconds", "max_count", "block_seconds", "stat_by_url", "stat_by_ua",
                             "stat_by_cookie", "user_id", "update_time")
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,$10,$11,$12,$13,$14,$15,$16) RETURNING "id"`
	sqlUpdateGroupPolicy     = `UPDATE "group_policies" SET "description"=$1,"app_id"=$2,"vuln_id"=$3,"hit_value"=$4,"action"=$5,"is_enabled"=$6,"user_id"=$7,"update_time"=$8 WHERE "id"=$9`
	sqlDeleteGroupPolicyByID = `DELETE FROM "group_policies" WHERE "id"=$1`
)

// CreateTableIfNotExistsGroupPolicy ...
func (dal *MyDAL) CreateTableIfNotExistsGroupPolicy() error {
	_, err := dal.db.Exec(sqlCreateTableIfNotExistsGroupPolicy)
	if err != nil {
		utils.DebugPrintln("CreateTableIfNotExistsGroupPolicy", err)
	}
	return err
}

// DeleteGroupPolicyByID ...
func (dal *MyDAL) DeleteGroupPolicyByID(id int64) error {
	_, err := dal.db.Exec(sqlDeleteGroupPolicyByID, id)
	if err != nil {
		utils.DebugPrintln("DeleteGroupPolicyByID", err)
	}
	return err
}

// UpdateGroupPolicy ...
func (dal *MyDAL) UpdateGroupPolicy(model models.GroupPolicy) error {
	stmt, _ := dal.db.Prepare(sqlUpdateGroupPolicy)
	defer stmt.Close()
	_, err := stmt.Exec(model.Description, model.AppID, model.VulnID, model.HitValue, model.Action, model.IsEnabled, model.UserID, model.UpdateTime, model.ID)
	if err != nil {
		utils.DebugPrintln("UpdateGroupPolicy", err)
	}
	return err
}

// SelectGroupPolicies ...
func (dal *MyDAL) SelectGroupPolicies() []*models.GroupPolicy {
	var groupPolicies []*models.GroupPolicy
	rows, err := dal.db.Query(sqlSelectGroupPolicies)
	if err != nil {
		utils.DebugPrintln("SelectGroupPolicies", err)
	}
	defer rows.Close()
	for rows.Next() {
		groupPolicy := &models.GroupPolicy{}
		err = rows.Scan(&groupPolicy.ID, &groupPolicy.Description, &groupPolicy.AppID, &groupPolicy.VulnID,
			&groupPolicy.HitValue, &groupPolicy.Action, &groupPolicy.IsEnabled,
			&groupPolicy.CcStatus, &groupPolicy.IntervalMilliSeconds, &groupPolicy.MaxCount, &groupPolicy.BlockSeconds,
			&groupPolicy.StatByURL, &groupPolicy.StatByUserAgent, &groupPolicy.StatByCookie,
			&groupPolicy.UserID, &groupPolicy.UpdateTime)
		if err != nil {
			utils.DebugPrintln("SelectGroupPolicies Scan", err)
		}
		groupPolicies = append(groupPolicies, groupPolicy)
	}
	return groupPolicies
}

// SelectGroupPoliciesByAppID ...
func (dal *MyDAL) SelectGroupPoliciesByAppID(appID int64) ([]*models.GroupPolicy, error) {
	var groupPolicies []*models.GroupPolicy
	rows, err := dal.db.Query(sqlSelectGroupPoliciesByAppID, appID)
	if err != nil {
		utils.DebugPrintln("SelectGroupPoliciesByAppID", err)
	}
	defer rows.Close()
	for rows.Next() {
		groupPolicy := &models.GroupPolicy{}
		groupPolicy.AppID = appID
		err = rows.Scan(&groupPolicy.ID, &groupPolicy.Description, &groupPolicy.VulnID,
			&groupPolicy.HitValue, &groupPolicy.Action, &groupPolicy.IsEnabled,
			&groupPolicy.CcStatus, &groupPolicy.IntervalMilliSeconds, &groupPolicy.MaxCount, &groupPolicy.BlockSeconds,
			&groupPolicy.StatByURL, &groupPolicy.StatByUserAgent, &groupPolicy.StatByCookie,
			&groupPolicy.UserID, &groupPolicy.UpdateTime)
		if err != nil {
			utils.DebugPrintln("SelectGroupPoliciesByAppID Scan", err)
			return groupPolicies, err
		}
		groupPolicies = append(groupPolicies, groupPolicy)
	}
	return groupPolicies, err
}

// InsertGroupPolicy ...
func (dal *MyDAL) InsertGroupPolicy(model models.GroupPolicy) (newID int64, err error) {
	stmt, err := dal.db.Prepare(sqlInsertGroupPolicy)
	if err != nil {
		utils.DebugPrintln("InsertGroupPolicy Prepare", err)
	}
	defer stmt.Close()
	id := utils.GenSnowflakeID()
	err = stmt.QueryRow(id, model.Description, model.AppID, model.VulnID, model.HitValue, model.Action, model.IsEnabled,
		model.CcStatus, model.IntervalMilliSeconds, model.MaxCount, model.BlockSeconds, model.StatByURL, model.StatByUserAgent, model.StatByCookie, model.UserID, model.UpdateTime).Scan(&newID)
	if err != nil {
		utils.DebugPrintln("InsertGroupPolicy Scan", err)
	}
	return newID, err
}

// ExistsGroupPolicy ...
func (dal *MyDAL) ExistsGroupPolicy() bool {
	var exist int
	err := dal.db.QueryRow(sqlExistsGroupPolicy).Scan(&exist)
	if err != nil {
		utils.DebugPrintln("ExistsGroupPolicy", err)
	}
	return exist != 0
}
