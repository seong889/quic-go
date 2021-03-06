// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/seong889/quic-go/internal/flowcontrol (interfaces: StreamFlowController)

package mocks

import (
	reflect "reflect"

	gomock "github.com/golang/mock/gomock"
	protocol "github.com/seong889/quic-go/internal/protocol"
)

// MockStreamFlowController is a mock of StreamFlowController interface
type MockStreamFlowController struct {
	ctrl     *gomock.Controller
	recorder *MockStreamFlowControllerMockRecorder
}

// MockStreamFlowControllerMockRecorder is the mock recorder for MockStreamFlowController
type MockStreamFlowControllerMockRecorder struct {
	mock *MockStreamFlowController
}

// NewMockStreamFlowController creates a new mock instance
func NewMockStreamFlowController(ctrl *gomock.Controller) *MockStreamFlowController {
	mock := &MockStreamFlowController{ctrl: ctrl}
	mock.recorder = &MockStreamFlowControllerMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (_m *MockStreamFlowController) EXPECT() *MockStreamFlowControllerMockRecorder {
	return _m.recorder
}

// AddBytesRead mocks base method
func (_m *MockStreamFlowController) AddBytesRead(_param0 protocol.ByteCount) {
	_m.ctrl.Call(_m, "AddBytesRead", _param0)
}

// AddBytesRead indicates an expected call of AddBytesRead
func (_mr *MockStreamFlowControllerMockRecorder) AddBytesRead(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "AddBytesRead", reflect.TypeOf((*MockStreamFlowController)(nil).AddBytesRead), arg0)
}

// AddBytesSent mocks base method
func (_m *MockStreamFlowController) AddBytesSent(_param0 protocol.ByteCount) {
	_m.ctrl.Call(_m, "AddBytesSent", _param0)
}

// AddBytesSent indicates an expected call of AddBytesSent
func (_mr *MockStreamFlowControllerMockRecorder) AddBytesSent(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "AddBytesSent", reflect.TypeOf((*MockStreamFlowController)(nil).AddBytesSent), arg0)
}

// GetWindowUpdate mocks base method
func (_m *MockStreamFlowController) GetWindowUpdate() protocol.ByteCount {
	ret := _m.ctrl.Call(_m, "GetWindowUpdate")
	ret0, _ := ret[0].(protocol.ByteCount)
	return ret0
}

// GetWindowUpdate indicates an expected call of GetWindowUpdate
func (_mr *MockStreamFlowControllerMockRecorder) GetWindowUpdate() *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "GetWindowUpdate", reflect.TypeOf((*MockStreamFlowController)(nil).GetWindowUpdate))
}

// IsBlocked mocks base method
func (_m *MockStreamFlowController) IsBlocked() bool {
	ret := _m.ctrl.Call(_m, "IsBlocked")
	ret0, _ := ret[0].(bool)
	return ret0
}

// IsBlocked indicates an expected call of IsBlocked
func (_mr *MockStreamFlowControllerMockRecorder) IsBlocked() *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "IsBlocked", reflect.TypeOf((*MockStreamFlowController)(nil).IsBlocked))
}

// SendWindowSize mocks base method
func (_m *MockStreamFlowController) SendWindowSize() protocol.ByteCount {
	ret := _m.ctrl.Call(_m, "SendWindowSize")
	ret0, _ := ret[0].(protocol.ByteCount)
	return ret0
}

// SendWindowSize indicates an expected call of SendWindowSize
func (_mr *MockStreamFlowControllerMockRecorder) SendWindowSize() *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "SendWindowSize", reflect.TypeOf((*MockStreamFlowController)(nil).SendWindowSize))
}

// UpdateHighestReceived mocks base method
func (_m *MockStreamFlowController) UpdateHighestReceived(_param0 protocol.ByteCount, _param1 bool) error {
	ret := _m.ctrl.Call(_m, "UpdateHighestReceived", _param0, _param1)
	ret0, _ := ret[0].(error)
	return ret0
}

// UpdateHighestReceived indicates an expected call of UpdateHighestReceived
func (_mr *MockStreamFlowControllerMockRecorder) UpdateHighestReceived(arg0, arg1 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "UpdateHighestReceived", reflect.TypeOf((*MockStreamFlowController)(nil).UpdateHighestReceived), arg0, arg1)
}

// UpdateSendWindow mocks base method
func (_m *MockStreamFlowController) UpdateSendWindow(_param0 protocol.ByteCount) {
	_m.ctrl.Call(_m, "UpdateSendWindow", _param0)
}

// UpdateSendWindow indicates an expected call of UpdateSendWindow
func (_mr *MockStreamFlowControllerMockRecorder) UpdateSendWindow(arg0 interface{}) *gomock.Call {
	return _mr.mock.ctrl.RecordCallWithMethodType(_mr.mock, "UpdateSendWindow", reflect.TypeOf((*MockStreamFlowController)(nil).UpdateSendWindow), arg0)
}
