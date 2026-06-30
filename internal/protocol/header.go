package protocol

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"os"
)

const (
	ModePassword    = 1 << 0
	ModeKeyFile     = 1 << 1
	ModeMultiFactor = 1 << 2
	ModeStream      = 1 << 3
)

type Header struct {
	Version   byte
	Mode      byte
	Salt      []byte
	Nonce     []byte
	Tag       []byte
	OpChain   []byte
	SHA256Dat []byte
}

func (h *Header) EncodeSingle() ([]byte, error) {
	buf := new(bytes.Buffer)
	buf.WriteByte(h.Version)
	buf.WriteByte(h.Mode)
	if h.Mode&ModePassword != 0 || h.Mode&ModeMultiFactor != 0 {
		if len(h.Salt) != 32 {
			return nil, errors.New("salt must be 32 bytes")
		}
		buf.Write(h.Salt)
	}
	if len(h.Nonce) != 12 {
		return nil, errors.New("nonce must be 12 bytes")
	}
	buf.Write(h.Nonce)
	if len(h.Tag) != 16 {
		return nil, errors.New("tag must be 16 bytes")
	}
	buf.Write(h.Tag)
	buf.Write(h.OpChain)
	return buf.Bytes(), nil
}

func DecodeSingle(data []byte) (*Header, int, error) {
	if len(data) < 2 {
		return nil, 0, errors.New("header too short")
	}
	h := &Header{Version: data[0]}
	if h.Version != 0x02 && h.Version != 0x03 {
		return nil, 0, errors.New("unsupported version")
	}
	h.Mode = data[1]
	offset := 2
	if h.Mode&ModePassword != 0 || h.Mode&ModeMultiFactor != 0 {
		if len(data) < offset+32 {
			return nil, 0, errors.New("salt missing")
		}
		h.Salt = make([]byte, 32)
		copy(h.Salt, data[offset:offset+32])
		offset += 32
	}
	if len(data) < offset+12+16 {
		return nil, 0, errors.New("nonce/tag missing")
	}
	h.Nonce = make([]byte, 12)
	copy(h.Nonce, data[offset:offset+12])
	offset += 12
	h.Tag = make([]byte, 16)
	copy(h.Tag, data[offset:offset+16])
	offset += 16

	end := bytes.IndexByte(data[offset:], 0x00)
	if end == -1 {
		return nil, 0, errors.New("opchain terminator not found")
	}
	h.OpChain = make([]byte, end+1)
	copy(h.OpChain, data[offset:offset+end+1])
	offset += end + 1
	return h, offset, nil
}

func (h *Header) EncodeSplit(datPath string) ([]byte, error) {
	f, err := os.Open(datPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return nil, err
	}
	h.SHA256Dat = hasher.Sum(nil)

	buf := new(bytes.Buffer)
	buf.WriteByte(h.Version)
	buf.WriteByte(h.Mode)
	if h.Mode&ModePassword != 0 || h.Mode&ModeMultiFactor != 0 {
		if len(h.Salt) != 32 {
			return nil, errors.New("salt required")
		}
		buf.Write(h.Salt)
	}
	if len(h.Nonce) != 12 {
		return nil, errors.New("nonce required")
	}
	buf.Write(h.Nonce)
	if len(h.Tag) != 16 {
		return nil, errors.New("tag required")
	}
	buf.Write(h.Tag)
	buf.Write(h.OpChain)
	buf.Write(h.SHA256Dat)
	return buf.Bytes(), nil
}

func DecodeSplit(hdrData []byte) (*Header, error) {
	if len(hdrData) < 2 {
		return nil, errors.New("header too short")
	}
	h := &Header{Version: hdrData[0]}
	if h.Version != 0x02 && h.Version != 0x03 {
		return nil, errors.New("unsupported version")
	}
	h.Mode = hdrData[1]
	offset := 2
	if h.Mode&ModePassword != 0 || h.Mode&ModeMultiFactor != 0 {
		if len(hdrData) < offset+32 {
			return nil, errors.New("salt missing")
		}
		h.Salt = make([]byte, 32)
		copy(h.Salt, hdrData[offset:offset+32])
		offset += 32
	}
	if len(hdrData) < offset+12+16 {
		return nil, errors.New("nonce/tag missing")
	}
	h.Nonce = make([]byte, 12)
	copy(h.Nonce, hdrData[offset:offset+12])
	offset += 12
	h.Tag = make([]byte, 16)
	copy(h.Tag, hdrData[offset:offset+16])
	offset += 16

	end := bytes.IndexByte(hdrData[offset:], 0x00)
	if end == -1 {
		return nil, errors.New("opchain terminator not found")
	}
	h.OpChain = make([]byte, end+1)
	copy(h.OpChain, hdrData[offset:offset+end+1])
	offset += end + 1

	if len(hdrData) < offset+32 {
		return nil, errors.New("dat hash missing")
	}
	h.SHA256Dat = make([]byte, 32)
	copy(h.SHA256Dat, hdrData[offset:offset+32])
	return h, nil
}
