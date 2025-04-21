package attestation

import (
	"errors"
)

type SpdmMeasurementRequestMessage struct {
	SpdmVersion         uint8
	RequestResponseCode uint8
	Param1              uint8
	Param2              uint8
	Nonce               [32]byte
	SlotIDParam         uint8
}

func ParseSpdmMeasurementRequestMessage(data []byte) (*SpdmMeasurementRequestMessage, error) {
	if len(data) < 37 {
		return nil, errors.New("data too short to be a valid SPDM MEASUREMENTS request")
	}

	message := &SpdmMeasurementRequestMessage{
		SpdmVersion:         data[0],
		RequestResponseCode: data[1],
		Param1:              data[2],
		Param2:              data[3],
		Nonce:               [32]byte{},
		SlotIDParam:         data[36],
	}

	copy(message.Nonce[:], data[4:36])

	return message, nil
}

type SpdmMeasurementResponseMessage struct {
	SpdmVersion         uint8
	RequestResponseCode uint8
	Param1              uint8
	Param2              uint8
	NumberOfBlocks      uint8
	MeasurementRecord   []byte
	Nonce               [32]byte
	OpaqueData          []byte
	Signature           []byte
}

func ParseSpdmMeasurementResponseMessage(data []byte, signatureLength int) (*SpdmMeasurementResponseMessage, error) {
	if len(data) < 42+signatureLength {
		return nil, errors.New("data too short to be a valid SPDM MEASUREMENTS response")
	}
	mrRecordLength := int(data[5]) | int(data[6])<<8 | int(data[7])<<16
	opaqueLength := int(data[8+mrRecordLength+32]) | int((data[8+mrRecordLength+32+1]))<<8

	message := &SpdmMeasurementResponseMessage{
		SpdmVersion:         data[0],
		RequestResponseCode: data[1],
		Param1:              data[2],
		Param2:              data[3],
		NumberOfBlocks:      data[4],
		MeasurementRecord:   make([]byte, mrRecordLength),
		Nonce:               [32]byte{},
		OpaqueData:          make([]byte, opaqueLength),
		Signature:           make([]byte, signatureLength),
	}

	copy(message.MeasurementRecord, data[8:8+mrRecordLength])
	copy(message.Nonce[:], data[8+mrRecordLength:40+mrRecordLength])

	copy(message.OpaqueData, data[42+mrRecordLength:42+mrRecordLength+opaqueLength])
	copy(message.Signature, data[42+mrRecordLength+opaqueLength:42+signatureLength+mrRecordLength+opaqueLength])

	return message, nil
}
