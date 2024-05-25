package openai

import (
	"encoding/json"
	"sort"
)

type sortedMap map[string]interface{}

func (m sortedMap) Keys() []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (m sortedMap) MarshalJSON() ([]byte, error) {
	// 创建一个新的map，保证顺序
	sorted := make(map[string]interface{}, len(m))
	for _, k := range m.Keys() {
		sorted[k] = m[k]
	}
	return json.Marshal(sorted)
}
