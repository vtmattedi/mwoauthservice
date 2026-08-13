package project

import (
	"context"
	"fmt"
)

type CallbackSecretRecord struct {
	Ciphertext string
	Nonce      string
	KeyVersion int
}

func (s *Service) CallbackSigningSecret(
	ctx context.Context,
	projectID int64,
) ([]byte, error) {
	if projectID <= 0 {
		return nil, ErrNotFound
	}
	if s.cipher == nil {
		return nil, fmt.Errorf(
			"callback secret cipher is unavailable",
		)
	}

	record, err := s.store.GetProjectCallbackSecret(
		ctx,
		projectID,
	)
	if err != nil {
		return nil, err
	}

	plaintext, err := s.cipher.Decrypt(
		record.Ciphertext,
		record.Nonce,
		record.KeyVersion,
	)
	if err != nil {
		return nil, fmt.Errorf(
			"decrypt project callback signing secret: %w",
			err,
		)
	}

	return plaintext, nil
}
