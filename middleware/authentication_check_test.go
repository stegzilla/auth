package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/todanni/auth/models"
	"github.com/todanni/auth/test"
	"github.com/todanni/auth/token"
)

type AuthenticationCheckTestSuite struct {
	suite.Suite
	key jwk.Key
}

func dummyHandler(w http.ResponseWriter, r *http.Request) {}

func (s *AuthenticationCheckTestSuite) SetupSuite() {
	s.key = test.ServePublicKey()
}

func (s *AuthenticationCheckTestSuite) Test_AuthenticationCheck_Bad_NoCookie401() {
	handler := NewAuthenticationCheck(dummyHandler)

	rw := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)

	handler.ServeHTTP(rw, req)

	require.Equal(s.T(), rw.Code, 401)
	require.Equal(s.T(), rw.Body.String(), "unauthorised\n")
}

func (s *AuthenticationCheckTestSuite) Test_AuthenticationCheck_Bad_InvalidToken403() {
	handler := NewAuthenticationCheck(dummyHandler)

	rw := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	cookie := &http.Cookie{
		Name:   "todanni-access-token",
		Value:  "token",
		MaxAge: 300,
	}
	req.AddCookie(cookie)

	handler.ServeHTTP(rw, req)

	require.Equal(s.T(), rw.Code, 403)
	require.Equal(s.T(), rw.Body.String(), "invalid token\n")
}

func (s *AuthenticationCheckTestSuite) Test_AuthenticationCheck_Good() {
	user := models.UserInfo{
		UserID:     1,
		Email:      "test@test.com",
		ProfilePic: "",
	}
	dashboards := make([]models.Dashboard, 0)
	projects := make([]models.Project, 0)

	todanniToken := token.New()
	todanniToken.SetUserInfo(user).
		SetProjectsPermissions(projects).
		SetDashboardPermissions(dashboards)

	signedToken, err := todanniToken.SignedToken(s.key)
	require.NoError(s.T(), err)

	handler := NewAuthenticationCheck(func(w http.ResponseWriter, r *http.Request) {
		accessToken := r.Context().Value(AccessTokenContextKey).(*token.ToDanniToken)
		require.NotNil(s.T(), accessToken)
		userInfo, err := accessToken.GetUserInfo()
		require.NoError(s.T(), err)
		if userInfo.UserID != user.UserID {
			s.T().Errorf("user info incorrect, expected %v but got %v", user.UserID, userInfo.UserID)
		}
	})

	rw := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/", nil)
	cookie := &http.Cookie{
		Name:   "todanni-access-token",
		Value:  signedToken,
		MaxAge: 300,
	}
	req.AddCookie(cookie)

	handler.ServeHTTP(rw, req)

	require.Equal(s.T(), rw.Code, 200)
}

func TestAuthenticationCheckTestSuite(t *testing.T) {
	suite.Run(t, new(AuthenticationCheckTestSuite))
}
