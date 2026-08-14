package federation

import "errors"

var (
	ErrMalformedBearer     = errors.New("malformed bearer authorization")
	ErrIntrospectionFailed = errors.New("token introspection failed")
	ErrInactiveToken       = errors.New("inactive token")
	ErrEmptySubject        = errors.New("empty subject")
	ErrAudienceMismatch    = errors.New("audience mismatch")
	ErrScopeMissing        = errors.New("required scope missing")
)
