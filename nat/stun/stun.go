// Package stun implements a subset of the Session Traversal Utilities
// for NAT (STUN) protocol, described in RFC 5389. Notably absent is
// support for long-term credentials.
package stun

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"net"
)

type Class uint8
type Method uint16

// Possible classes and methods for a STUN packet.
const (
	ClassRequest = iota
	ClassIndication
	ClassSuccess
	ClassError
	MethodBinding = 1
)

// A Packet presents select information about a STUN packet.
type Packet struct {
	Class    Class
	Method   Method
	Tid      [12]byte
	Addr     *net.UDPAddr
	HasMac   bool
	Software string
	UseCandidate bool

	Error     *PacketError
	Alternate *net.UDPAddr
}

func RandomTid() ([]byte, error) {
	ret := make([]byte, 12)
	_, err := io.ReadFull(rand.Reader, ret)
	if err != nil {
		return nil, err
	}
	return ret, nil
}

func InformReady(tid []byte, addr *net.UDPAddr, macKey []byte) ([]byte, error) {
	if len(tid) != 12 {
		panic("Wrong length for tid")
	}
	var hdr header
	hdr.TypeCode = typeCode(ClassIndication, MethodBinding)
	hdr.Magic = magic
	copy(hdr.Tid[:], tid)

	var buf bytes.Buffer
	if addr != nil {
		ip := addr.IP.To4()
		family := 1
		if ip == nil {
			ip = addr.IP
			family++
		}

		binary.Write(&buf, binary.BigEndian, []uint16{
			attrAddress,
			uint16(4 + len(ip)),
			uint16(family),
			uint16(addr.Port)})
		buf.Write(ip)
	}
	return buildPacket(hdr, buf.Bytes(), macKey, false)
}
// BindRequest constructs and returns a Binding Request STUN packet.
//
// tid must be 12 bytes long. If a macKey is provided, the returned
// packet is signed.
func BindRequest(tid []byte, addr *net.UDPAddr, macKey []byte, compat bool, useCandidate bool) ([]byte, error) {
	if len(tid) != 12 {
		panic("Wrong length for tid")
	}
	var hdr header
	hdr.TypeCode = typeCode(ClassRequest, MethodBinding)
	hdr.Magic = magic
	copy(hdr.Tid[:], tid)

	var buf bytes.Buffer
	if useCandidate {
		binary.Write(&buf, binary.BigEndian, []uint16{
			attrUseCandidate,
			uint16(0)})
	}

	if addr != nil {
		ip := addr.IP.To4()
		family := 1
		if ip == nil {
			ip = addr.IP
			family++
		}

		binary.Write(&buf, binary.BigEndian, []uint16{
			attrAddress,
			uint16(4 + len(ip)),
			uint16(family),
			uint16(addr.Port)})
		buf.Write(ip)
	}
	return buildPacket(hdr, buf.Bytes(), macKey, compat)
}

// BindResponse constructs and returns a Binding Success STUN packet.
//
// tid must be 12 bytes long. If a macKey is provided, the returned
// packet is signed.
func BindResponse(tid []byte, addr *net.UDPAddr, macKey []byte, compat bool) ([]byte, error) {
	if len(tid) != 12 {
		panic("Wrong length for tid")
	}
	var hdr header
	hdr.TypeCode = typeCode(ClassSuccess, MethodBinding)
	hdr.Magic = magic
	copy(hdr.Tid[:], tid)

	ip := addr.IP.To4()
	family := 1
	if ip == nil {
		ip = addr.IP
		family++
	}

	var buf bytes.Buffer
	binary.Write(&buf, binary.BigEndian, []uint16{
		attrXorAddress,
		uint16(4 + len(ip)),
		uint16(family),
		uint16(addr.Port ^ magic>>16)})
	buf.Write(ip)

	attrs := buf.Bytes()
	for i := range magicBytes {
		attrs[8+i] ^= magicBytes[i]
	}
	for i := range attrs[12:] {
		attrs[12+i] ^= tid[i]
	}
	return buildPacket(hdr, attrs, macKey, compat)
}

// ParsePacket parses a byte slice as a STUN packet.
//
// If a macKey is provided, only packets correctly signed with that
// key will be accepted. If no macKey is provided, only unsigned
// packets will be accepted.
func ParsePacket(raw []byte, macKey []byte) (*Packet, error) {
	var hdr header
	if err := binary.Read(bytes.NewBuffer(raw[:headerLen]), binary.BigEndian, &hdr); err != nil {
		return nil, err
	}

	// Initial sanity checks: verify initial bits, magic, length and
	// optional fingerprint.
	if hdr.TypeCode&0xC000 != 0 || int(hdr.Length+20) != len(raw) || hdr.Magic != magic {
		return nil, MalformedPacket{}
	}
	if hdr.Length >= fpLen {
		if present, valid := checkFp(raw); present {
			if !valid {
				return nil, MalformedPacket{}
			}
			raw = raw[:len(raw)-fpLen]
		}
	}

	pkt := &Packet{
		Class:  typeCodeClass(hdr.TypeCode),
		Method: typeCodeMethod(hdr.TypeCode),
		Tid:    hdr.Tid,
	}

	attrReader := bytes.NewBuffer(raw[headerLen:])
	var haveXor bool
	for {
		if attrReader.Len() == 0 {
			break
		}

		var ahdr attrHeader
		if err := binary.Read(attrReader, binary.BigEndian, &ahdr); err != nil {
			return nil, err
		}
		if ahdr.Length > 500 || attrReader.Len() < int(ahdr.Length) {
			return nil, MalformedPacket{}
		}
		value := attrReader.Next(int(ahdr.Length))
		if ahdr.Length%4 != 0 {
			attrReader.Next(int(4 - ahdr.Length%4))
		}

		switch ahdr.Type {
		case attrAddress:
			if !haveXor {
				ip, port, err := parseAddress(value)
				if err != nil {
					return nil, err
				}
                                pkt.Addr = &net.UDPAddr{IP:ip, Port:port}
			}
		case attrXorAddress:
			ip, port, err := parseAddress(value)
			if err != nil {
				return nil, err
			}
			for i := range ip {
				ip[i] ^= raw[4+i]
			}
			port ^= int(binary.BigEndian.Uint16(raw[4:]))
                        pkt.Addr = &net.UDPAddr{IP:ip, Port:port}
			haveXor = true
		case attrUseCandidate:
			pkt.UseCandidate = true

		case attrFingerprint:
			return nil, MalformedPacket{}
		case attrIntegrity:
			if len(macKey) == 0 {
				return nil, UnverifiableMac{}
			}
			tocheck := raw[:len(raw)-attrReader.Len()-macLen]
			binary.BigEndian.PutUint16(tocheck[2:4], uint16(len(tocheck)+macLen-headerLen))
			macer := hmac.New(sha1.New, macKey)
			if _, err := macer.Write(tocheck); err != nil {
				return nil, err
			}
			mac := make([]byte, 0, 20)
			mac = macer.Sum(mac)
			if !bytes.Equal(mac, value) {
				return nil, BadMac{}
			}
			pkt.HasMac = true
			return pkt, nil

		case attrErrCode:
			code := uint16(value[2])*100 + uint16(value[3])
			reason := string(value[4:])
			pkt.Error = &PacketError{code, reason}
		case attrUnknownAttrs:
			// Ignored
		case attrSoftware:
			pkt.Software = string(value)
		case attrAlternate:
			ip, port, err := parseAddress(value)
			if err != nil {
				return nil, err
			}
                        pkt.Alternate = &net.UDPAddr{IP:ip, Port:port}

		case attrUsername:
		case attrRealm:
		case attrNonce:
			return nil, errors.New("Unsupported STUN attribute")
		}
	}

	if len(macKey) > 0 {
		return nil, MissingMac{}
	}
	return pkt, nil
}

// A MalformedPacket error is returned by ParsePacket when it
// encounters structural malformations in the STUN packet.
//
// On a network endpoing where STUN coexists with another protocol,
// this error can be used to differentiate STUN and non-STUN traffic.
type MalformedPacket struct{}

func (m MalformedPacket) Error() string {
	return "Malformed STUN packet"
}

// A BadMac error is returned by ParsePacket when a structurally sound
// STUN packet is received with a signature not matching the provided
// macKey.
type BadMac struct{}

func (b BadMac) Error() string {
	return "Incorrect MAC on packet"
}

// A MissingMac error is returned by ParsePacket when it receives a
// valid but unsigned STUN packet where it expected a signed packet.
type MissingMac struct{}

func (m MissingMac) Error() string {
	return "MAC expected but missing"
}

// An UnverifiableMac error is returned by ParsePacket when it
// encounters a valid and signed STUN packet, and no macKey was
// provided.
type UnverifiableMac struct{}

func (u UnverifiableMac) Error() string {
	return "MAC found but no key given"
}

// A PacketError describes an error returned by a STUN server.
type PacketError struct {
	Code   uint16
	Reason string
}

func (p PacketError) Error() string {
	var genericErr string
	switch p.Code {
	case errTryAlternate:
		genericErr = "Try Alternate"
	case errBadRequest:
		genericErr = "Bad Request"
	case errUnauthorized:
		genericErr = "Unauthorized"
	case errUnknownAttribute:
		genericErr = "Unknown Attribute(s)"
	case errStaleNonce:
		genericErr = "Stale Nonce"
	case errServerInternal:
		genericErr = "Internal Server Error"
	default:
		genericErr = fmt.Sprintf("Error %d", p.Code)
	}
	if len(p.Reason) == 0 {
		return genericErr
	}
	return fmt.Sprintf("%s: %s", genericErr, p.Reason)
}

func buildPacket(hdr header, attributes, macKey []byte, compat bool) ([]byte, error) {
	var buf bytes.Buffer

	if len(macKey) > 0 {
		hdr.Length = uint16(len(attributes) + macLen)

		macer := hmac.New(sha1.New, macKey)
		if err := binary.Write(macer, binary.BigEndian, hdr); err != nil {
			return nil, err
		}
		if _, err := macer.Write(attributes); err != nil {
			return nil, err
		}

		if err := binary.Write(&buf, binary.BigEndian, attrHeader{attrIntegrity, 20}); err != nil {
			return nil, err
		}
		attributes = append(attributes, macer.Sum(buf.Bytes())...)
		buf.Reset()
	}
	hdr.Length = uint16(len(attributes))
	if !compat {
		hdr.Length += fpLen
	}
	if err := binary.Write(&buf, binary.BigEndian, hdr); err != nil {
		return nil, err
	}
	buf.Write(attributes)
	if !compat {
		var fp fpAttr
		fp.Type = attrFingerprint
		fp.Length = 4
		fp.Crc = crc32.ChecksumIEEE(buf.Bytes()) ^ 0x5354554e
		if err := binary.Write(&buf, binary.BigEndian, fp); err != nil {
			return nil, err
		}
	}
	return buf.Bytes(), nil
}

func parseAddress(raw []byte) (net.IP, int, error) {
	if len(raw) != 8 && len(raw) != 20 {
		return nil, 0, MalformedPacket{}
	}
	var family int
	switch int(raw[1]) {
	case 1:
		family = 4
	case 2:
		family = 16
	default:
		return nil, 0, MalformedPacket{}
	}
	port := binary.BigEndian.Uint16(raw[2:])
	ip := make([]byte, len(raw[4:]))
	copy(ip, raw[4:])
	if len(ip) != family {
		return nil, 0, MalformedPacket{}
	}
	return net.IP(ip), int(port), nil
}

func checkFp(raw []byte) (present, valid bool) {
	split := len(raw) - fpLen
	var fp fpAttr
	if err := binary.Read(bytes.NewBuffer(raw[split:]), binary.BigEndian, &fp); err != nil {
		return false, false
	}
	if fp.Type != attrFingerprint || fp.Length != 4 {
		return false, false
	}
	if fp.Crc != (crc32.ChecksumIEEE(raw[:split]) ^ 0x5354554e) {
		return true, false
	}
	return true, true
}

func typeCode(class uint8, method uint16) uint16 {
	return method<<2&0xFE00 | uint16(class)&2<<7 | method<<1&0x00E0 | uint16(class)&1<<4 | method&0xF
}

func typeCodeClass(typeCode uint16) Class {
	return Class(typeCode>>4&1 | typeCode>>7&2)
}

func typeCodeMethod(typeCode uint16) Method {
	return Method(typeCode&0xF | typeCode&0xE0>>1 | typeCode&0xFE00>>2)
}

// Parsing structs
type header struct {
	TypeCode uint16
	Length   uint16
	Magic    uint32
	Tid      [12]byte
}

type attrHeader struct {
	Type   uint16
	Length uint16
}

type fpAttr struct {
	attrHeader
	Crc uint32
}

// Constants

const (
	magic     = 0x2112a442
	headerLen = 20
	fpLen     = 8
	macLen    = 24
)

var magicBytes = []byte{0x21, 0x12, 0xa4, 0x42}

const (
	// Comprehension required
	attrAddress      = 0x01 //
	attrUsername     = 0x06 //
	attrIntegrity    = 0x08 //
	attrErrCode      = 0x09 //
	attrUnknownAttrs = 0x0A //
	attrRealm        = 0x14 //
	attrNonce        = 0x15 //
	attrXorAddress   = 0x20 //
	attrUseCandidate = 0x25 //

	// Comprehension optional
	attrSoftware    = 0x8022 //
	attrAlternate   = 0x8023 //
	attrFingerprint = 0x8028 //
)

const (
	errTryAlternate     = 300
	errBadRequest       = 400
	errUnauthorized     = 401
	errUnknownAttribute = 420
	errStaleNonce       = 438
	errServerInternal   = 500
)
