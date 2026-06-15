package handler

type registerRequest struct {
	Name     string `json:"name"     binding:"required,min=1,max=100"`
	Email    string `json:"email"    binding:"required,email,max=254"`
	Password string `json:"password" binding:"required,min=8,max=128"`
}

type loginRequest struct {
	Email    string `json:"email"    binding:"required,email,max=254"`
	Password string `json:"password" binding:"required,min=8,max=128"`
	TOTPCode string `json:"totp_code" binding:"omitempty,len=6,numeric"`
}

type verifyEmailQuery struct {
	Token string `form:"token" binding:"required,len=64,hexadecimal"`
}

type forgotPasswordRequest struct {
	Email string `json:"email" binding:"required,email,max=254"`
}

type resetPasswordRequest struct {
	Token       string `json:"token"        binding:"required,len=64,hexadecimal"`
	NewPassword string `json:"new_password" binding:"required,min=8,max=128"`
}

type enableTOTPRequest struct {
	Code string `json:"code" binding:"required,len=6"`
}

type updateProfileRequest struct {
	Name string `json:"name" binding:"required,min=1,max=100"`
	Bio  string `json:"bio"  binding:"omitempty,max=500"`
}
