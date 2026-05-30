package handler

type apiResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
	Data    any    `json:"data,omitempty"`
	Error   string `json:"error,omitempty"`
}

func ok(message string, data any) apiResponse {
	return apiResponse{Success: true, Message: message, Data: data}
}

func errResp(message string) apiResponse {
	return apiResponse{Success: false, Error: message}
}
