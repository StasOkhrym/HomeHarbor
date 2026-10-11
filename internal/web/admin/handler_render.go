package admin

import "net/http"

func (s *Handler) renderAdmin(w http.ResponseWriter, status int, model Page) {
	RenderPage(w, status, model, s.logger)
}
