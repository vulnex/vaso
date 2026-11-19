package main

// disguiseJSONValue disguises, inside an inline JSON config a variable holds
// (OPENCODE_CONFIG_CONTENT), what was redacted there before — every string
// under a credential-named key (apiKey, headers, environment…) and an
// argv's credentials — with same-shape stand-ins, as in a config file:
// "[redacted]" read as a placeholder, so CFG-002 flagged a plaintext key
// locally and passed remotely. Other strings are redacted as before
// (URL credentials, token-shaped values).
func (c *collector) disguiseJSONValue(v interface{}, key string, secret bool) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, val := range t {
			t[k] = c.disguiseJSONValue(val, k, secret || isSecretJSONKey(k))
		}
		return t
	case []interface{}:
		var argv []string
		index := map[int]int{}
		for i, val := range t {
			if str, ok := val.(string); ok {
				index[len(argv)] = i
				argv = append(argv, str)
			}
		}
		hit := map[int][2]int{}
		for _, h := range judgeArgv(argv) {
			hit[index[h.tok]] = [2]int{h.from, h.to}
		}
		for i, val := range t {
			if sp, ok := hit[i]; ok {
				str := val.(string)
				t[i] = str[:sp[0]] + c.disguiseArgv(str[sp[0]:sp[1]]) + str[sp[1]:]
				continue
			}
			t[i] = c.disguiseJSONValue(val, key, secret)
		}
		return t
	case string:
		if secret {
			if out := c.disguiseKeyed(key, t); out != t || isPlaceholderSecret(t) || isSecretReference(t) {
				return out
			}
			// a value the file rules would leave (too short to judge) still
			// never ships under a credential name: drawn like an argv password
			return c.disguiseArgv(t)
		}
		return redactSecretValues(t)
	}
	return v
}
