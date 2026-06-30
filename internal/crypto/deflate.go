package crypto

import (
	"bytes"
	"compress/flate"
	"fmt"
	"io"
)

const (
	maxDecompressionRatio = 200
	maxDecompressedSize   = 100 << 20
)

func DeflateCompress(data []byte, level int) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, level)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func DeflateDecompress(data []byte) ([]byte, error) {
	reader := flate.NewReader(bytes.NewReader(data))
	limit := int64(len(data)) * maxDecompressionRatio
	if limit > maxDecompressedSize {
		limit = maxDecompressedSize
	}
	limitedReader := io.LimitReader(reader, limit+1)
	output, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: invalid key or corrupted data")
	}
	if int64(len(output)) > limit {
		return nil, fmt.Errorf("decryption failed: invalid key or corrupted data")
	}
	return output, nil
}
