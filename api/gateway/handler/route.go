package handler

func (h Handler) Route() {
	h.e.POST("/jobs", h.create)
	h.e.GET("/jobs/:id", h.get)
}
