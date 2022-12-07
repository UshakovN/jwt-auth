package repo

import "fmt"

type Storage interface {
  Put(id string, item any) error
  Get(id string) (any, error)
}

type MockStorage struct {
  data map[string]any
}

func NewMockStorage() *MockStorage {
  return &MockStorage{
    data: map[string]any{},
  }
}

func (s *MockStorage) Put(id string, item any) error {
  if s.data == nil {
    return fmt.Errorf("storage is empty")
  }
  s.data[id] = item
  return nil
}

func (s *MockStorage) Get(id string) (any, error) {
  if s.data == nil {
    return nil, fmt.Errorf("storage is empty")
  }
  return s.data[id], nil
}
