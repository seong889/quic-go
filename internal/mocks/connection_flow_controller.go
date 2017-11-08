// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/seong889/quic-go/internal/flowcontrol (interfaces: ConnectionFlowController)

package mocks

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	protocol "github.com/seong889/quic-go/internal/protocol"
)

// MockConnectionFlowController is a mock of ConnectionFlowController interface
type MockConnectionFlowController struct {
	ctrl     *gomock.Controller
	recorder *MockConnectionFlowControllerMockRecorder
}

// MockConnectionFlowControllerMockRecorder is the mock recorder for MockConnectionFlowController
type MockConnectionFlowControllerMockRecorder struct {
	mock *MockConnectionFlowController
}

// NewMockConnectionFlowController creates a new mock instance
func NewMockConnectionFlowController(ctrl *gomock.Controller) *MockConnectionFlowController {
	mock := &MockConnectionFlowController{ctrl: ctrl}
	mock.recorder = &MockConnectionFlowControllerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (_m *MockConnectionFlowController) EXPECT() *MockConnectionFlowControllerMockRecorder {
	return _m.recorder
}

// AddBytesRead mocks base method
func (_m *MockConnectionFlowController) AddBytesRead(_param0 protocol.ByteCount) {
	_m.ctrl.Call(_m, "AddBytesRead", _param0)
}

// AddBytesRead indicates an expected call of AddBytesRead
func (_mr *MockConnectionFlowControllerMockRecorder) AddBytesRead(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "AddBytesRead", reflect.TypeOf((*MockConnectionFlowController)(nil).AddBytesRead), arg0)
}

// AddBytesSent mocks base method
func (_m *MockConnectionFlowController) AddBytesSent(_param0 protocol.ByteCount) {
	_m.ctrl.Call(_m, "AddBytesSent", _param0)
}

// AddBytesSent indicates an expected call of AddBytesSent
func (_mr *MockConnectionFlowControllerMockRecorder) AddBytesSent(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "AddBytesSent", reflect.TypeOf((*MockConnectionFlowController)(nil).AddBytesSent), arg0)
}

// GetWindowUpdate mocks base method
func (_m *MockConnectionFlowController) GetWindowUpdate() protocol.ByteCount {
	ret := _m.ctrl.Call(_m, "GetWindowUpdate")
	ret0, _ := ret[0].(protocol.ByteCount)
	return ret0
}

// GetWindowUpdate indicates an expected call of GetWindowUpdate
func (_mr *MockConnectionFlowControllerMockRecorder) GetWindowUpdate() *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "GetWindowUpdate", reflect.TypeOf((*MockConnectionFlowController)(nil).GetWindowUpdate))
}

// IsBlocked mocks base method
func (_m *MockConnectionFlowController) IsBlocked() bool {
	ret := _m.ctrl.Call(_m, "IsBlocked")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsBlocked indicates an expected call of IsBlocked
func (_mr *MockConnectionFlowControllerMockRecorder) IsBlocked() *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "IsBlocked", reflect.TypeOf((*MockConnectionFlowController)(nil).IsBlocked))
}

// SendWindowSize mocks base method
func (_m *MockConnectionFlowController) SendWindowSize() protocol.ByteCount {
	ret := _m.ctrl.Call(_m, "SendWindowSize")
	ret0, _ := ret[0].(protocol.ByteCount)
	return ret0
}

// SendWindowSize indicates an expected call of SendWindowSize
func (_mr *MockConnectionFlowControllerMockRecorder) SendWindowSize() *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "SendWindowSize", reflect.TypeOf((*MockConnectionFlowController)(nil).SendWindowSize))
}

// UpdateSendWindow mocks base method
func (_m *MockConnectionFlowController) UpdateSendWindow(_param0 protocol.ByteCount) {
	_m.ctrl.Call(_m, "UpdateSendWindow", _param0)
}

// UpdateSendWindow indicates an expected call of UpdateSendWindow
func (_mr *MockConnectionFlowControllerMockRecorder) UpdateSendWindow(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "UpdateSendWindow", reflect.TypeOf((*MockConnectionFlowController)(nil).UpdateSendWindow), arg0)
}
