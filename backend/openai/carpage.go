package openai

import (
	"backend/modules/chatgpt/model"
	"bytes"
	"encoding/json"
	"github.com/gogf/gf/v2/os/gctx"
	"time"

	"github.com/cool-team-official/cool-admin-go/cool"
	baseservice "github.com/cool-team-official/cool-admin-go/modules/base/service"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/text/gstr"
)

func ActiveByCode(r *ghttp.Request) {
	reqJson, err := r.GetJson()
	if err != nil {
		r.Response.WriteJson(g.Map{
			"message": "Unable to parse request body.",
		})
		return
	}
	code := reqJson.Get("code").Int()
	token, err := GetAccessToken(r, []string{"/api/CharacterRedemptionCode/activeVIPByRedemptionCode"})
	if err != nil {
		r.Response.WriteJson(g.Map{
			"code":    401,
			"message": "Unauthorized",
		})
		return
	}
	headerMap := map[string]string{
		"Authorization": token,
	}
	argMap := g.Map{
		"code": code,
	}
	jsonBytes, err := json.Marshal(argMap)
	if err != nil {
		r.Response.WriteJson(g.Map{
			"message": "Unable to parse code",
		})
		return
	}
	ctx := gctx.GetInitCtx()
	zyx_gateway_url := g.Cfg().MustGetWithEnv(ctx, "ZYX_GATEWAY").String()
	result, err := DoPost(zyx_gateway_url+"/user-resource-server/api/CharacterRedemptionCode/activeVIPByRedemptionCode", bytes.NewBuffer(jsonBytes), headerMap)
	if err != nil || result == nil || !result.IsSuccess {
		errorMessage := "授权服务连接失败"
		if result != nil {
			errorMessage = result.Message
		}
		r.Response.WriteJson(g.Map{
			"message": errorMessage,
		})
		return
	}

	r.Response.WriteJson(g.Map{
		"code":    200,
		"message": "激活成功",
	})
}

// 分页返回车辆列表
func CarPage(r *ghttp.Request) {
	// ctx := r.GetCtx()
	oauthUserInfo := GetZyxOnlineUser(r)
	if oauthUserInfo == nil {
		r.Response.WriteJson(g.Map{
			"code":    401,
			"message": "Unauthorized",
		})
		return
	}
	roleCode := oauthUserInfo.CurrentRole.RoleCode
	roleMark := oauthUserInfo.CurrentRole.Mark
	accountBalance := oauthUserInfo.AccountBalance
	roleExpireTime := oauthUserInfo.CurrentRole.ExpireTime
	var leastTime int64
	if roleExpireTime == "" {
		leastTime = ParseTime("2025-05-27 17:37:00").Sub(time.Now()).Milliseconds()
	} else {
		leastTime = ParseTime(roleExpireTime).Sub(time.Now()).Milliseconds()
	}
	invitationCode := oauthUserInfo.InvitationCode
	oauthUserId := GenState(oauthUserInfo.ID)
	reqJson, err := r.GetJson()
	if err != nil {
		r.Response.WriteJson(g.Map{
			"detail": "Unable to parse request body.",
		})
		return
	}
	page := reqJson.Get("page").Int()
	size := reqJson.Get("size").Int()
	if page == 0 {
		page = 1
	}
	if size == 0 {
		size = 10
	}
	// .Limit(size).Offset((page - 1) * size).AllAndCount(false)
	record, count, err := cool.DBM(model.NewChatgptSession()).Fields("carID", "status", "isPlus").OrderDesc("sort").OrderAsc("id").Page(page, size).AllAndCount(false)
	if err != nil {
		r.Response.WriteJson(g.Map{
			"detail": err.Error(),
		})
		return
	}
	notice := baseservice.NewBaseSysParamService().HtmlByKey("notice")
	// 去除 <html><body> </body></html>
	notice = gstr.Replace(notice, "<html><body>", "", -1)
	notice = gstr.Replace(notice, "</body></html>", "", -1)
	// 如果 notice 为 keyName notfound
	if notice == "keyName notfound" {
		notice = "暂无公告"
	}
	r.Response.WriteJson(g.Map{
		"code":     1000,
		"messages": "success",
		"data": g.Map{
			"list": record,
			"pagination": g.Map{
				"page":  page,
				"size":  size,
				"total": count,
			},
			"oauthUserId":    oauthUserId,
			"roleCode":       roleCode,
			"roleMark":       roleMark,
			"roleExpireTime": roleExpireTime,
			"accountBalance": accountBalance,
			"invitationCode": invitationCode,
			"leastTime":      leastTime,
		},
		"notice": notice,
	})
}
