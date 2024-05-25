package openai

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gctx"
	uuid2 "github.com/google/uuid"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

type GetAccessTokenArg struct {
	AuthorizeCode string   `json:"authorizeCode"` // 授权码
	ClientID      string   `json:"clientId"`      // 客户端id
	ClientSecret  string   `json:"clientSecret"`  // 客户端密码
	GrantType     string   `json:"grantType"`     // 响应类别（access_code,client_security）
	RedirectURI   string   `json:"redirectUri"`   // 重定向地址
	Scopes        []string `json:"scopes"`        // 授权范围
	State         string   `json:"state"`         // 客户端状态码
	Nonce         string   `json:"nonce"`         // 安全随机码
	JWT           string   `json:"jwt"`           // JWT
	Device        string   `json:"device"`        // 设备信息
}
type RoleModel struct {
	ID                    string `json:"id"`       // 注意这里id和roleCode重复了，通常一个字段只有一个名称，需要确认哪个是正确的
	RoleCode              string `json:"roleCode"` // 同上
	RoleName              string `json:"roleName"`
	Mark                  int    `json:"mark"`
	PermissionFollowRoles int    `json:"permissionFollowRoles"`
	PermissionLevel       int    `json:"permissionLevel"`
	ExpireTime            string `json:"expireTime"`
}

type GroupModel struct {
	ID          string `json:"id"`
	GroupCode   string `json:"groupCode"`
	GroupName   string `json:"groupName"`
	Description string `json:"description"`
}
type IDToken struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	LoginName   string      `json:"loginName"`
	CurrentRole RoleModel   `json:"currentRole"`
	Roles       []RoleModel `json:"roles"`
	Group       GroupModel  `json:"group"`
	PictureURL  string      `json:"pictureURL"`
	Device      string      `json:"device"`
	Fingerprint string      `json:"fingerprint"`
	ExpireTime  string      `json:"expireTime"`
}
type TokenVO struct {
	OpenID       string `json:"openid"`
	AccessToken  string `json:"accessToken"`
	RefreshToken string `json:"refreshToken"`
}

// ResultVO represents a generic response structure.
type ResultVO struct {
	Code      int         `json:"code" description:"HTTP status code"`
	Data      interface{} `json:"data" description:"Data value"`
	Message   string      `json:"message" description:"Error information"`
	IsSuccess bool        `json:"isSuccess" description:"Indicates if the response is successful"`
}
type RefreshToken struct {
	ClientID        string   `json:"clientID"`
	LoginName       string   `json:"loginName"`
	GroupID         string   `json:"groupID"`
	ExpireTime      string   `json:"expireTime"`
	AuthorizeScopes []string `json:"authorizeScopes"`
	Fingerprint     string   `json:"fingerprint"`
}

// AccessToken 结构体对应于Java中的AccessToken类
type AccessToken struct {
	ClientID        string   `json:"clientID"`
	LoginName       string   `json:"loginName"`
	GroupID         string   `json:"groupID"`
	ExpireTime      string   `json:"expireTime"`
	AuthorizeScopes []string `json:"authorizeScopes"` // Go中没有Set类型，但可以用切片（slice）来近似表示
	Fingerprint     string   `json:"fingerprint"`
	Device          string   `json:"device"`
	CurrentRoleCode string   `json:"currentRoleCode"`
}

type AuthenticatedUser struct {
	IDToken
	RefreshToken string `json:"refreshToken"`
	AccessToken  string `json:"accessToken"`
	IdToken      string `json:"idToken"`
}

func Authorize(r *ghttp.Request) {
	authorizecode := r.Get("code")
	log.Println("授权码:", authorizecode)
	oauthUrl := AuthorizeUrl()
	var tokenVO *TokenVO
	var err error
	if authorizecode == nil || authorizecode.String() == "" {

		refreshTokenString := r.Cookie.Get("zyx_refresh")

		if refreshTokenString == nil || refreshTokenString.String() == "" {
			//重新认证
			r.Response.RedirectTo(oauthUrl)
		}
		//刷新token
		tokenVO, err = refreshToken(refreshTokenString.String())
		if err != nil {
			//重新认证
			r.Response.RedirectTo(oauthUrl)
		}
	} else {
		//code 换取 token
		tokenVO, err = getTokenByCode(authorizecode.String())
		if err != nil {
			//重新认证
			r.Response.RedirectTo(oauthUrl)
		}
	}
	if tokenVO == nil {
		r.Response.RedirectTo(oauthUrl)
	}
	//验证token签名
	err = validAndCacheTokenVO(tokenVO)
	if err != nil {
		//重新认证
		r.Response.RedirectTo(oauthUrl)
	}
	//保存token
	r.Cookie.Set("zyx_open_id", tokenVO.OpenID)
	r.Cookie.Set("zyx_refresh", tokenVO.RefreshToken)
	r.Response.RedirectTo("/list")

}

func validAndCacheTokenVO(tokenvo *TokenVO) error {
	openId := tokenvo.OpenID
	accessToken := tokenvo.AccessToken
	refreshTokenStr := tokenvo.RefreshToken
	//验证token签名
	ctx := gctx.GetInitCtx()
	publicKey := g.Cfg().MustGetWithEnv(ctx, "ZYX_OAUTH_CLIENT_PUBLIC_KEY").String()
	sm2, err := NewSM2AlgorithmByPublicKey(publicKey)
	if err != nil {
		return err
	}
	idSm2JwtToken, err := InitSM2JWTTokenByToken(openId, &IDToken{}, sm2)
	if err != nil {
		return err
	}

	if parseTime(idSm2JwtToken.Payload.ExpireTime).Before(time.Now()) {
		return errors.New("id token过期")
	}
	accessSm2JwtToken, err := InitSM2JWTTokenByToken(accessToken, &AccessToken{}, sm2)
	if err != nil {
		return err
	}

	if parseTime(accessSm2JwtToken.Payload.ExpireTime).Before(time.Now()) {
		return errors.New("access token过期")
	}
	refreshSm2JwtToken, err := InitSM2JWTTokenByToken(refreshTokenStr, &RefreshToken{}, sm2)
	if err != nil {
		return nil
	}

	if parseTime(refreshSm2JwtToken.Payload.ExpireTime).Before(time.Now()) {
		return errors.New("refresh token过期")
	}
	return nil
}

func AuthorizeUrl() string {
	ctx := gctx.GetInitCtx()
	oauthUrl := g.Cfg().MustGetWithEnv(ctx, "ZYX_OAUTH_AUTHORIZE_URL").String()
	callBackUrl := g.Cfg().MustGetWithEnv(ctx, "ZYX_OAUTH_CALLBACK_URL").String()
	clientId := g.Cfg().MustGetWithEnv(ctx, "ZYX_OAUTH_CLIENT_ID").String()
	if oauthUrl == "" {
		return ""
	}
	oauthUrl = fmt.Sprintf("%s?response_type=client_credentials&client_id=%s&scope=OpenId&redirect_uri=%s&state=%s&nonce=%s",
		oauthUrl,
		clientId,
		callBackUrl,
		randomState(),
		randomState())

	return oauthUrl
}

func getTokenByCode(code string) (*TokenVO, error) {
	ctx := gctx.GetInitCtx()
	oauthUrl := g.Cfg().MustGetWithEnv(ctx, "ZYX_OAUTH_URL").String()
	callBackUrl := g.Cfg().MustGetWithEnv(ctx, "ZYX_OAUTH_CALLBACK_URL").String()
	clientId := g.Cfg().MustGetWithEnv(ctx, "ZYX_OAUTH_CLIENT_ID").String()
	publicKey := g.Cfg().MustGetWithEnv(ctx, "ZYX_OAUTH_CLIENT_PUBLIC_KEY").String()
	Secret := g.Cfg().MustGetWithEnv(ctx, "ZYX_OAUTH_CLIENT_SECRET").String()
	sm2, err := NewSM2AlgorithmByPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	arg := &GetAccessTokenArg{}
	arg.AuthorizeCode = code
	arg.RedirectURI = callBackUrl
	arg.ClientID = clientId
	arg.State = randomState()
	xorState, err := actualState(arg.State)
	if err != nil {
		return nil, err
	}
	preEncStr := Secret + "." + xorState
	arg.ClientSecret = sm2.EncryptString(preEncStr)
	arg.GrantType = "access_code"
	arg.Nonce = randomState()
	arg.Scopes = []string{"OpenId"}
	jsonBytes, err := json.Marshal(arg)
	if err != nil {
		return nil, err
	}
	return doPost(oauthUrl+"/access_token", bytes.NewBuffer(jsonBytes)), nil
}

// RefreshTokenArg 结构体对应于Java中的RefreshTokenArg类
type RefreshTokenArg struct {
	RefreshToken string   `json:"refreshToken" validate:"required"`
	ClientID     string   `json:"客户端id" validate:"required"`
	ClientSecret string   `json:"客户端密码"`
	GrantType    string   `json:"响应类别（access_code,client_security）" validate:"required"`
	RedirectURI  string   `json:"重定向地址"`
	Scopes       []string `json:"授权范围"`
	State        string   `json:"客户端状态码" validate:"required"`
	Nonce        string   `json:"安全随机码" validate:"required"`
	JWT          string   `json:"jwt"`
}

func refreshToken(refreshToken string) (*TokenVO, error) {
	ctx := gctx.GetInitCtx()
	oauthUrl := g.Cfg().MustGetWithEnv(ctx, "ZYX_OAUTH_URL").String()
	callBackUrl := g.Cfg().MustGetWithEnv(ctx, "ZYX_OAUTH_CALLBACK_URL").String()
	clientId := g.Cfg().MustGetWithEnv(ctx, "ZYX_OAUTH_CLIENT_ID").String()
	publicKey := g.Cfg().MustGetWithEnv(ctx, "ZYX_OAUTH_CLIENT_PUBLIC_KEY").String()
	Secret := g.Cfg().MustGetWithEnv(ctx, "ZYX_OAUTH_CLIENT_SECRET").String()
	sm2, err := NewSM2AlgorithmByPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	arg := &RefreshTokenArg{}
	arg.RefreshToken = refreshToken
	arg.ClientID = clientId
	arg.RedirectURI = callBackUrl
	arg.GrantType = "access_code"
	arg.State = randomState()
	xorState, err := actualState(arg.State)
	if err != nil {
		return nil, err
	}
	preEncStr := Secret + "." + xorState
	arg.ClientSecret = sm2.EncryptString(preEncStr)
	arg.Nonce = randomState()
	arg.Scopes = []string{"OpenId"}
	jsonBytes, err := json.Marshal(arg)
	if err != nil {
		return nil, err
	}
	return doPost(oauthUrl+"/refresh_token", bytes.NewBuffer(jsonBytes)), nil

}

func doPost(url string, playLoad io.Reader) *TokenVO {

	req, err := http.NewRequest("POST", url, playLoad)
	if err != nil {
		panic(err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != 200 {
		panic(err)
	}
	oauthResponseStr := string(body)
	var vo ResultVO
	err = json.Unmarshal([]byte(oauthResponseStr), &vo)
	if err != nil || !vo.IsSuccess {
		log.Println(oauthResponseStr)
		panic("oauth响应失败")
	}
	dataByte, err := json.Marshal(vo.Data)
	if err != nil {
		panic(err)
	}
	var tokenVO TokenVO
	err = json.Unmarshal(dataByte, &tokenVO)
	return &tokenVO
}

func randomState() string {
	//uuid_, _ := uuid2.NewRandom() // 使用md5代替UUID，因为Go中没有内置的UUID库
	uuidStr := uuid()
	reverseUUID := reverseString(uuidStr)
	prefix := []byte(uuidStr)
	fix := []byte(reverseUUID)
	for i := range prefix {
		prefix[i] ^= fix[i]
	}
	reverseUUID = string(prefix)
	preEncode := uuidStr + reverseUUID
	return base64.StdEncoding.EncodeToString([]byte(preEncode))
}

func GenState(str string) string {
	reverseUUID := reverseString(str)
	prefix := []byte(str)
	fix := []byte(reverseUUID)
	for i := range prefix {
		prefix[i] ^= fix[i]
	}
	reverseUUID = string(prefix)
	preEncode := str + reverseUUID
	return base64.StdEncoding.EncodeToString([]byte(preEncode))
}

func validState(state string) bool {
	decodeState, err := base64.StdEncoding.DecodeString(state)
	if err != nil {
		return false
	}
	prefix := decodeState[:len(decodeState)/2]
	fix := decodeState[len(decodeState)/2:]
	reverseUUID := reverseString(string(prefix))
	reverseBytes := []byte(reverseUUID)
	for i := range prefix {
		fix[i] ^= reverseBytes[i]
	}
	return string(prefix) == string(fix)
}

func actualState(state string) (string, error) {
	if !validState(state) {
		return "", fmt.Errorf("state非法")
	}
	decodeState, err := base64.StdEncoding.DecodeString(state)
	if err != nil {
		return "", err
	}
	return string(decodeState[:len(decodeState)/2]), nil
}

func uuid() string {
	// 在Go中，可以使用自定义方式生成随机字符串，这里用作示例
	uuidStr, _ := uuid2.NewRandom()
	uuidString := uuidStr.String()
	uuidString = strings.Replace(uuidString, "-", "", -1)
	return uuidString
}

func reverseString(s string) string {
	runes := []rune(s)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}

func GetZyxOnlineUser(r *ghttp.Request) *IDToken {
	ctx := gctx.GetInitCtx()
	openid := r.Cookie.Get("zyx_open_id")
	if openid == nil || openid.String() == "" {
		return nil
	}
	publicKey := g.Cfg().MustGetWithEnv(ctx, "ZYX_OAUTH_CLIENT_PUBLIC_KEY").String()
	sm2, err := NewSM2AlgorithmByPublicKey(publicKey)
	if err != nil {
		return nil
	}
	token, err := InitSM2JWTTokenByToken(openid.String(), &IDToken{}, sm2)
	if err != nil || token == nil || token.Payload == nil {
		return nil
	}

	if parseTime(token.Payload.ExpireTime).Before(time.Now()) {
		return nil
	}
	return token.Payload
}

func parseTime(timeStr string) time.Time {
	layout := "2006-01-02 15:04:05.999"
	// 解析日期时间字符串
	expireTime, err := time.Parse(layout, timeStr)
	if err != nil {
		panic(err)
	}
	return expireTime
}
