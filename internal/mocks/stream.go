// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/seong889/quic-go (interfaces: StreamI)

package mocks

import (
	context "context"
	reflect "reflect"
	time "time"

	gomock "github.com/golang/mock/gomock"
	protocol "github.com/seong889/quic-go/internal/protocol"
	wire "github.com/seong889/quic-go/internal/wire"
)

// MockStreamI is a mock of StreamI interface
type MockStreamI struct {
	ctrl     *gomock.Controller
	recorder *MockStreamIMockRecorder
}

// MockStreamIMockRecorder is the mock recorder for MockStreamI
type MockStreamIMockRecorder struct {
	mock *MockStreamI
}

// NewMockStreamI creates a new mock instance
func NewMockStreamI(ctrl *gomock.Controller) *MockStreamI {
	mock := &MockStreamI{ctrl: ctrl}
	mock.recorder = &MockStreamIMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (_m *MockStreamI) EXPECT() *MockStreamIMockRecorder {
	return _m.recorder
}

// AddStreamFrame mocks base method
func (_m *MockStreamI) AddStreamFrame(_param0 *wire.StreamFrame) error {
	ret := _m.ctrl.Call(_m, "AddStreamFrame", _param0)
	ret0, _ := ret[0].(error)
	return ret0
}

// AddStreamFrame indicates an expected call of AddStreamFrame
func (_mr *MockStreamIMockRecorder) AddStreamFrame(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "AddStreamFrame", reflect.TypeOf((*MockStreamI)(nil).AddStreamFrame), arg0)
}

// Cancel mocks base method
func (_m *MockStreamI) Cancel(_param0 error) {
	_m.ctrl.Call(_m, "Cancel", _param0)
}

// Cancel indicates an expected call of Cancel
func (_mr *MockStreamIMockRecorder) Cancel(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "Cancel", reflect.TypeOf((*MockStreamI)(nil).Cancel), arg0)
}

// Close mocks base method
func (_m *MockStreamI) Close() error {
	ret := _m.ctrl.Call(_m, "Close")
	ret0, _ := ret[0].(error)
	return ret0
}

// Close indicates an expected call of Close
func (_mr *MockStreamIMockRecorder) Close() *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "Close", reflect.TypeOf((*MockStreamI)(nil).Close))
}

// Context mocks base method
func (_m *MockStreamI) Context() context.Context {
	ret := _m.ctrl.Call(_m, "Context")
	ret0, _ := ret[0].(context.Context)
	return ret0
}

// Context indicates an expected call of Context
func (_mr *MockStreamIMockRecorder) Context() *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "Context", reflect.TypeOf((*MockStreamI)(nil).Context))
}

// Finished mocks base method
func (_m *MockStreamI) Finished() bool {
	ret := _m.ctrl.Call(_m, "Finished")
	ret0, _ := ret[0].(bool)
	return ret0
}

// Finished indicates an expected call of Finished
func (_mr *MockStreamIMockRecorder) Finished() *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "Finished", reflect.TypeOf((*MockStreamI)(nil).Finished))
}

// GetDataForWriting mocks base method
func (_m *MockStreamI) GetDataForWriting(_param0 protocol.ByteCount) []byte {
	ret := _m.ctrl.Call(_m, "GetDataForWriting", _param0)
	ret0, _ := ret[0].([]byte)
	return ret0
}

// GetDataForWriting indicates an expected call of GetDataForWriting
func (_mr *MockStreamIMockRecorder) GetDataForWriting(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "GetDataForWriting", reflect.TypeOf((*MockStreamI)(nil).GetDataForWriting), arg0)
}

// GetWindowUpdate mocks base method
func (_m *MockStreamI) GetWindowUpdate() protocol.ByteCount {
	ret := _m.ctrl.Call(_m, "GetWindowUpdate")
	ret0, _ := ret[0].(protocol.ByteCount)
	return ret0
}

// GetWindowUpdate indicates an expected call of GetWindowUpdate
func (_mr *MockStreamIMockRecorder) GetWindowUpdate() *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "GetWindowUpdate", reflect.TypeOf((*MockStreamI)(nil).GetWindowUpdate))
}

// GetWriteOffset mocks base method
func (_m *MockStreamI) GetWriteOffset() protocol.ByteCount {
	ret := _m.ctrl.Call(_m, "GetWriteOffset")
	ret0, _ := ret[0].(protocol.ByteCount)
	return ret0
}

// GetWriteOffset indicates an expected call of GetWriteOffset
func (_mr *MockStreamIMockRecorder) GetWriteOffset() *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "GetWriteOffset", reflect.TypeOf((*MockStreamI)(nil).GetWriteOffset))
}

// IsFlowControlBlocked mocks base method
func (_m *MockStreamI) IsFlowControlBlocked() bool {
	ret := _m.ctrl.Call(_m, "IsFlowControlBlocked")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsFlowControlBlocked indicates an expected call of IsFlowControlBlocked
func (_mr *MockStreamIMockRecorder) IsFlowControlBlocked() *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "IsFlowControlBlocked", reflect.TypeOf((*MockStreamI)(nil).IsFlowControlBlocked))
}

// LenOfDataForWriting mocks base method
func (_m *MockStreamI) LenOfDataForWriting() protocol.ByteCount {
	ret := _m.ctrl.Call(_m, "LenOfDataForWriting")
	ret0, _ := ret[0].(protocol.ByteCount)
	return ret0
}

// LenOfDataForWriting indicates an expected call of LenOfDataForWriting
func (_mr *MockStreamIMockRecorder) LenOfDataForWriting() *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "LenOfDataForWriting", reflect.TypeOf((*MockStreamI)(nil).LenOfDataForWriting))
}

// Read mocks base method
func (_m *MockStreamI) Read(_param0 []byte) (int, error) {
	ret := _m.ctrl.Call(_m, "Read", _param0)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Read indicates an expected call of Read
func (_mr *MockStreamIMockRecorder) Read(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "Read", reflect.TypeOf((*MockStreamI)(nil).Read), arg0)
}

// RegisterRemoteError mocks base method
func (_m *MockStreamI) RegisterRemoteError(_param0 error, _param1 protocol.ByteCount) error {
	ret := _m.ctrl.Call(_m, "RegisterRemoteError", _param0, _param1)
	ret0, _ := ret[0].(error)
	return ret0
}

// RegisterRemoteError indicates an expected call of RegisterRemoteError
func (_mr *MockStreamIMockRecorder) RegisterRemoteError(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "RegisterRemoteError", reflect.TypeOf((*MockStreamI)(nil).RegisterRemoteError), arg0, arg1)
}

// Reset mocks base method
func (_m *MockStreamI) Reset(_param0 error) {
	_m.ctrl.Call(_m, "Reset", _param0)
}

// Reset indicates an expected call of Reset
func (_mr *MockStreamIMockRecorder) Reset(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "Reset", reflect.TypeOf((*MockStreamI)(nil).Reset), arg0)
}

// SentFin mocks base method
func (_m *MockStreamI) SentFin() {
	_m.ctrl.Call(_m, "SentFin")
}

// SentFin indicates an expected call of SentFin
func (_mr *MockStreamIMockRecorder) SentFin() *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "SentFin", reflect.TypeOf((*MockStreamI)(nil).SentFin))
}

// SetDeadline mocks base method
func (_m *MockStreamI) SetDeadline(_param0 time.Time) error {
	ret := _m.ctrl.Call(_m, "SetDeadline", _param0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetDeadline indicates an expected call of SetDeadline
func (_mr *MockStreamIMockRecorder) SetDeadline(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "SetDeadline", reflect.TypeOf((*MockStreamI)(nil).SetDeadline), arg0)
}

// SetReadDeadline mocks base method
func (_m *MockStreamI) SetReadDeadline(_param0 time.Time) error {
	ret := _m.ctrl.Call(_m, "SetReadDeadline", _param0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetReadDeadline indicates an expected call of SetReadDeadline
func (_mr *MockStreamIMockRecorder) SetReadDeadline(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "SetReadDeadline", reflect.TypeOf((*MockStreamI)(nil).SetReadDeadline), arg0)
}

// SetWriteDeadline mocks base method
func (_m *MockStreamI) SetWriteDeadline(_param0 time.Time) error {
	ret := _m.ctrl.Call(_m, "SetWriteDeadline", _param0)
	ret0, _ := ret[0].(error)
	return ret0
}

// SetWriteDeadline indicates an expected call of SetWriteDeadline
func (_mr *MockStreamIMockRecorder) SetWriteDeadline(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "SetWriteDeadline", reflect.TypeOf((*MockStreamI)(nil).SetWriteDeadline), arg0)
}

// ShouldSendFin mocks base method
func (_m *MockStreamI) ShouldSendFin() bool {
	ret := _m.ctrl.Call(_m, "ShouldSendFin")
	ret0, _ := ret[0].(bool)
	return ret0
}

// ShouldSendFin indicates an expected call of ShouldSendFin
func (_mr *MockStreamIMockRecorder) ShouldSendFin() *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "ShouldSendFin", reflect.TypeOf((*MockStreamI)(nil).ShouldSendFin))
}

// StreamID mocks base method
func (_m *MockStreamI) StreamID() protocol.StreamID {
	ret := _m.ctrl.Call(_m, "StreamID")
	ret0, _ := ret[0].(protocol.StreamID)
	return ret0
}

// StreamID indicates an expected call of StreamID
func (_mr *MockStreamIMockRecorder) StreamID() *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "StreamID", reflect.TypeOf((*MockStreamI)(nil).StreamID))
}

// UpdateSendWindow mocks base method
func (_m *MockStreamI) UpdateSendWindow(_param0 protocol.ByteCount) {
	_m.ctrl.Call(_m, "UpdateSendWindow", _param0)
}

// UpdateSendWindow indicates an expected call of UpdateSendWindow
func (_mr *MockStreamIMockRecorder) UpdateSendWindow(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "UpdateSendWindow", reflect.TypeOf((*MockStreamI)(nil).UpdateSendWindow), arg0)
}

// Write mocks base method
func (_m *MockStreamI) Write(_param0 []byte) (int, error) {
	ret := _m.ctrl.Call(_m, "Write", _param0)
	ret0, _ := ret[0].(int)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Write indicates an expected call of Write
func (_mr *MockStreamIMockRecorder) Write(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "Write", reflect.TypeOf((*MockStreamI)(nil).Write), arg0)
}
