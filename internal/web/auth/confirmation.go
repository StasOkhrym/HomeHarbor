package auth

func (a *BrowserAuth) SignAction(csrf string, payload []byte) string {
	return a.codec.SignAction(csrf, payload)
}

func (a *BrowserAuth) VerifyAction(csrf string, payload []byte, proof string) bool {
	return a.codec.VerifyAction(csrf, payload, proof)
}
