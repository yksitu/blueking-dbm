package handler

import (
	"encoding/json"
	"io/ioutil"
	"log/slog"
	"strings"

	"dbm-services/common/go-pubpkg/errno"
	"dbm-services/mysql/priv-service/service"

	"github.com/gin-gonic/gin"
)

// CloneInstancePrivDryRun 克隆实例权限预检查
func (m *PrivService) CloneInstancePrivDryRun(c *gin.Context) {
	slog.Info("do  CloneInstancePrivDryRun!")

	var input service.CloneInstancePrivParaList

	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		slog.Error("msg", err)
		SendResponse(c, errno.ErrBind, err)
		return
	}

	if err = json.Unmarshal(body, &input); err != nil {
		slog.Error("msg", err)
		SendResponse(c, errno.ErrBind, err)
		return
	}

	err = input.CloneInstancePrivDryRun()
	SendResponse(c, err, nil)
	return
}

// CloneInstancePriv 克隆实例权限
func (m *PrivService) CloneInstancePriv(c *gin.Context) {
	slog.Info("do  CloneInstancePriv!")

	var input service.CloneInstancePrivPara
	ticket := strings.TrimPrefix(c.FullPath(), "/priv/")

	body, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		slog.Error("msg", err)
		SendResponse(c, errno.ErrBind, err)
		return
	}

	if err = json.Unmarshal(body, &input); err != nil {
		slog.Error("msg", err)
		SendResponse(c, errno.ErrBind, err)
		return
	}

	err = input.CloneInstancePriv(string(body), ticket)
	SendResponse(c, err, nil)
	return
}
