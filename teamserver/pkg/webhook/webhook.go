package webhook

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
)

type WebHook struct {
	Discord struct {
		Avatar string
		User   string
		Url    string
	}
}

func StringPtr(str string) *string {
	return &str
}

func BoolPtr(b bool) *bool {
	return &b
}

func NewWebHook() *WebHook {
	return new(WebHook)
}

// safeStr extracts a string from a map with a fallback default.
func safeStr(m map[string]any, key, fallback string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return fallback
}

// safeInt extracts an int from a map with a fallback default.
func safeInt(m map[string]any, key string, fallback int) int {
	if v, ok := m[key]; ok {
		if i, ok := v.(int); ok {
			return i
		}
	}
	return fallback
}

func (w *WebHook) NewAgent(agent map[string]any) error {

	if len(w.Discord.Url) > 0 {
		var (
			payload = new(bytes.Buffer)
			message Message
			embed   Embed
			field   Field
		)

		AgentInfo, ok := agent["Info"].(map[string]any)
		if !ok {
			return fmt.Errorf("webhook: agent Info field is missing or malformed")
		}

		message.AvatarUrl = &w.Discord.Avatar
		message.Username = &w.Discord.User
		message.Embeds = new([]Embed)

		embed.Title = StringPtr("New Agent Initialized")
		embed.Fields = new([]Field)

		field.Name = StringPtr("Agent ID")
		field.Value = StringPtr(safeStr(agent, "NameID", "unknown"))
		field.Inline = BoolPtr(true)
		*embed.Fields = append(*embed.Fields, field)

		field.Name = StringPtr("Username")
		field.Value = StringPtr(safeStr(AgentInfo, "Username", "unknown"))
		field.Inline = BoolPtr(true)
		*embed.Fields = append(*embed.Fields, field)

		field.Name = StringPtr("Hostname")
		field.Value = StringPtr(safeStr(AgentInfo, "Hostname", "unknown"))
		field.Inline = BoolPtr(true)
		*embed.Fields = append(*embed.Fields, field)

		field.Name = StringPtr("Internal IP")
		field.Value = StringPtr(safeStr(AgentInfo, "InternalIP", "unknown"))
		field.Inline = BoolPtr(true)
		*embed.Fields = append(*embed.Fields, field)

		field.Name = StringPtr("Process Path")
		field.Value = StringPtr(safeStr(AgentInfo, "ProcessPath", "unknown"))
		field.Inline = BoolPtr(true)
		*embed.Fields = append(*embed.Fields, field)

		field.Name = StringPtr("Process Name")
		field.Value = StringPtr(safeStr(AgentInfo, "ProcessName", "unknown"))
		field.Inline = BoolPtr(true)
		*embed.Fields = append(*embed.Fields, field)

		field.Name = StringPtr("Process ID")
		field.Value = StringPtr(strconv.Itoa(safeInt(AgentInfo, "ProcessPID", 0)))
		field.Inline = BoolPtr(true)
		*embed.Fields = append(*embed.Fields, field)

		field.Name = StringPtr("Process Arch")
		field.Value = StringPtr(safeStr(AgentInfo, "ProcessArch", "unknown"))
		field.Inline = BoolPtr(true)
		*embed.Fields = append(*embed.Fields, field)

		field.Name = StringPtr("OS Version")
		field.Value = StringPtr(safeStr(AgentInfo, "OSVersion", "unknown"))
		*embed.Fields = append(*embed.Fields, field)

		field.Name = StringPtr("OS Arch")
		field.Value = StringPtr(safeStr(AgentInfo, "OSArch", "unknown"))
		field.Inline = BoolPtr(true)
		*embed.Fields = append(*embed.Fields, field)

		field.Name = StringPtr("First Callback")
		field.Value = StringPtr(safeStr(AgentInfo, "FirstCallIn", "unknown"))
		*embed.Fields = append(*embed.Fields, field)

		*message.Embeds = append(*message.Embeds, embed)

		err := json.NewEncoder(payload).Encode(message)
		if err != nil {
			return err
		}

		resp, err := http.Post(w.Discord.Url, "application/json", payload)
		if err != nil {
			return err
		}

		if resp.StatusCode != 200 && resp.StatusCode != 204 {
			defer resp.Body.Close()

			responseBody, err := io.ReadAll(resp.Body)
			if err != nil {
				return err
			}

			return fmt.Errorf(string(responseBody))
		}

		return nil
	}

	return nil
}

func (w *WebHook) SetDiscord(AvatarUrl, User, Url string) {
	w.Discord.Avatar = AvatarUrl
	w.Discord.User = User
	w.Discord.Url = Url
}
