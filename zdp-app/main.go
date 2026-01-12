package main

import (
	_ "embed"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

//go:embed executables/OTPGenerator.exe
var otpGeneratorExe []byte

//go:embed executables/ZEPSdkInvokeOTP.exe
var zepSdkInvokeOtpExe []byte

//go:embed executables/ZDPObfuscate.exe
var zdpObfuscateExe []byte

const (
	defaultKeyFilePath = `C:\ProgramData\Zscaler\ZDP\Settings\zdp_endpoint_id`
)

var (
	// Styles
	docStyle         = lipgloss.NewStyle().Margin(0, 2)
	cursorStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("208")).Bold(true)
	statusStyle      = lipgloss.NewStyle().Foreground(lipgloss.Color("86"))
	errorStyle       = lipgloss.NewStyle().Foreground(lipgloss.Color("196"))
	successStyle     = lipgloss.NewStyle().Foreground(lipgloss.Color("46"))
	endpointKeyStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("46")) // Green for keys
	endpointValueStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("255")) // White for values
)


type (
	errorMsg                error
	enableTAMsg           struct{}
	verifyTAMsg           struct{ enabled bool }
	disableTAMsg          struct{}
	verifyTADisabledMsg   struct{ disabled bool }
	gotStatusMsg          struct{ status string }
	deobfuscationDoneMsg  struct{ message string }
	tickMsg               time.Time
	gotEndpointDetailsMsg struct{ details map[string]interface{} }
)

type model struct {
	choices          []string
	cursor           int
	selected         string
	state            string // "menu", "processing", "result", "endpoint_details"
	spinner          spinner.Model
	status           string
	antiTamperStatus string
	endpointDetails  map[string]interface{}
}

func initialModel() model {
	s := spinner.New()
	s.Spinner = spinner.MiniDot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))


	return model{
		choices: []string{
			"Enable Anti-tampering",
			"Disable Anti-tampering",
			"Get Endpoint details",
			"De-obfuscate ootb-settings",
			"De-obfuscate zdp-modes",
			"Exit",
		},
		spinner: s,
		state:   "menu",
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(getAntiTamperingStatusCmd, tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	}))
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch m.state {
		case "menu":
			switch msg.String() {
			case "ctrl+c", "q", "esc":
				return m, tea.Quit
			case "up", "k":
				if m.cursor > 0 {
					m.cursor--
				}
			case "down", "j":
				if m.cursor < len(m.choices)-1 {
					m.cursor++
				}
			case "enter", " ":
				m.selected = m.choices[m.cursor]
				
				switch m.selected {
				case "Enable Anti-tampering":
					m.state = "processing"
					m.status = "Attempting to enable anti-tampering..."
					return m, tea.Batch(m.spinner.Tick, enableAntiTampering)
				case "Disable Anti-tampering":
					m.state = "processing"
					m.status = "Attempting to disable anti-tampering..."
					return m, tea.Batch(m.spinner.Tick, disableAntiTampering)
				case "Get Endpoint details":
					m.state = "processing"
					m.status = "Getting endpoint details..."
					return m, tea.Batch(m.spinner.Tick, getEndpointDetailsCmd)
				case "De-obfuscate ootb-settings":
					m.state = "processing"
					m.status = "De-obfuscating ootb-settings..."
					return m, tea.Batch(m.spinner.Tick, deobfuscateOotbSettings)
				case "De-obfuscate zdp-modes":
					m.state = "processing"
					m.status = "De-obfuscating zdp-modes..."
					return m, tea.Batch(m.spinner.Tick, deobfuscateZdpModes)
				case "Exit":
					return m, tea.Quit
				}
			}
		case "result", "endpoint_details":
			m.state = "menu"
			m.cursor = 0
			return m, tea.Batch(getAntiTamperingStatusCmd, tea.Tick(time.Second, func(t time.Time) tea.Msg {
				return tickMsg(t)
			}))
		}
	case tickMsg:
		if m.state == "menu" {
			return m, tea.Batch(getAntiTamperingStatusCmd, tea.Tick(time.Second, func(t time.Time) tea.Msg {
				return tickMsg(t)
			}))
		}
		// If not in menu, do not re-schedule the tick.
		return m, nil

	case enableTAMsg:
		m.status = "Verifying anti-tampering is enabled..."
		return m, tea.Batch(m.spinner.Tick, verifyAntiTampering)
	case verifyTAMsg:
		if msg.enabled {
			m.antiTamperStatus = successStyle.Render("Anti-tampering enabled successfully.")
		} else {
			m.antiTamperStatus = errorStyle.Render("Failed to verify that anti-tampering was enabled.")
		}
		m.state = "menu"
		m.cursor = 0
		return m, tea.Batch(getAntiTamperingStatusCmd, tea.Tick(time.Second, func(t time.Time) tea.Msg {
			return tickMsg(t)
		}))
	case disableTAMsg:
		m.status = "Verifying anti-tampering is disabled..."
		return m, tea.Batch(m.spinner.Tick, verifyAntiTamperingDisabled)
	case verifyTADisabledMsg:
		if msg.disabled {
			m.antiTamperStatus = successStyle.Render("Anti-tampering disabled successfully.")
		} else {
			m.antiTamperStatus = errorStyle.Render("Failed to verify that anti-tampering was disabled.")
		}
		m.state = "menu"
		m.cursor = 0
		return m, tea.Batch(getAntiTamperingStatusCmd, tea.Tick(time.Second, func(t time.Time) tea.Msg {
			return tickMsg(t)
		}))
	case gotStatusMsg:
		if m.state == "menu" {
			statusText := fmt.Sprintf("Anti-tampering Status: %s", msg.status)
			if msg.status == "Enabled" {
				m.antiTamperStatus = successStyle.Render(statusText)
			} else if msg.status == "Disabled" {
				m.antiTamperStatus = errorStyle.Render(statusText)
			} else {
				m.antiTamperStatus = statusText
			}
		}
		return m, nil
	case deobfuscationDoneMsg:
		m.state = "result"
		m.status = successStyle.Render(msg.message)
		return m, nil
	case gotEndpointDetailsMsg:
		m.state = "endpoint_details"
		m.endpointDetails = msg.details
		return m, nil
	case errorMsg:
		m.state = "result"
		m.status = errorStyle.Render(fmt.Sprintf("Error: %v", msg))
		return m, nil
	case spinner.TickMsg:
		if m.state == "processing" {
			var cmd tea.Cmd
			m.spinner, cmd = m.spinner.Update(msg)
			return m, cmd
		}
		return m, nil
	}

	return m, nil
}

func (m model) View() string {
	switch m.state {
	case "processing":
		return docStyle.Render(fmt.Sprintf("%s %s", m.spinner.View(), statusStyle.Render(m.status)))
	case "result":
		return docStyle.Render(fmt.Sprintf("%s\nPress any key to return to the menu.", m.status))
	case "endpoint_details":
		var s strings.Builder
		s.WriteString("Endpoint Details:\n\n")
		for k, v := range m.endpointDetails {
			s.WriteString(fmt.Sprintf("%s: %v\n", endpointKeyStyle.Render(k), endpointValueStyle.Render(fmt.Sprintf("%v", v))))
		}
		s.WriteString("\nPress any key to return to the menu.")
		return docStyle.Render(s.String())
	default: // "menu"
		s := "What do you want to do?\n"
		s += m.antiTamperStatus + "\n\n"
		for i, choice := range m.choices {
			cursor := " "
			if m.cursor == i {
				s += cursorStyle.Render("> " + choice)
			} else {
				s += fmt.Sprintf("%s %s", cursor, choice)
			}
			s += "\n"
		}
		s += "\n(q to quit)\n"
		return docStyle.Render(s)
	}
}

func main() {
	p := tea.NewProgram(initialModel())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Alas, there's been an error: %v", err)
		os.Exit(1)
	}
	fmt.Print("\033[2J") // Clear screen on exit
}

// --- Commands ---

func isZdpServiceRunning() bool {
	cmd := exec.Command("powershell", "-Command", "Get-Service -Name zdpservice")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "Running")
}

func getEndpointDetailsCmd() tea.Msg {
	if !isZdpServiceRunning() {
		return errorMsg(fmt.Errorf("zdpservice is not running. make sure it's running and try again"))
	}
	
	url := "https://127.0.0.1:9861/api/v1.0/get-zdpe-details"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return errorMsg(fmt.Errorf("failed to create network request: %w", err))
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	resp, err := client.Do(req)
	if err != nil {
		// Try http if https fails
		url = "http://127.0.0.1:9861/api/v1.0/get-zdpe-details"
		req, err = http.NewRequest("GET", url, nil)
		if err != nil {
			return errorMsg(fmt.Errorf("failed to create http request for fallback: %w", err))
		}
		client = &http.Client{}
		resp, err = client.Do(req)
		if err != nil {
			return errorMsg(fmt.Errorf("failed to connect to endpoint details service. Is the service running and reachable? Original error: %w", err))
		}
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return errorMsg(fmt.Errorf("failed to read response from endpoint details service: %w", err))
	}

	var details map[string]interface{}
	err = json.Unmarshal(body, &details)
	if err != nil {
		return errorMsg(fmt.Errorf("failed to parse endpoint details response. Invalid JSON format: %w", err))
	}

	return gotEndpointDetailsMsg{details: details}
}


func enableAntiTampering() tea.Msg {
	err := setAntiTamperingMode(true)
	if err != nil {
		return errorMsg(fmt.Errorf("failed to enable anti-tampering: %w", err))
	}
	return enableTAMsg{}
}

func verifyAntiTampering() tea.Msg {
	enabled := false
	for i := 0; i < 10; i++ {
		status, err := getAntiTamperingStatus()
		if err != nil {
			return errorMsg(fmt.Errorf("failed to verify anti-tampering status: %w", err))
		}
		if status == "Enabled" {
			enabled = true
			break
		}
		time.Sleep(1 * time.Second)
	}
	return verifyTAMsg{enabled: enabled}
}

func disableAntiTampering() tea.Msg {
	err := setAntiTamperingMode(false)
	if err != nil {
		return errorMsg(fmt.Errorf("failed to disable anti-tampering: %w", err))
	}
	return disableTAMsg{}
}

func verifyAntiTamperingDisabled() tea.Msg {
	disabled := false
	for i := 0; i < 10; i++ {
		status, err := getAntiTamperingStatus()
		if err != nil {
			return errorMsg(fmt.Errorf("failed to verify anti-tampering status: %w", err))
		}
		if status == "Disabled" {
			disabled = true
			break
		}
		time.Sleep(1 * time.Second)
	}
	return verifyTADisabledMsg{disabled: disabled}
}

func getAntiTamperingStatusCmd() tea.Msg {
	status, err := getAntiTamperingStatus()
	if err != nil {
		return errorMsg(fmt.Errorf("failed to get anti-tampering status: %w", err))
	}
	return gotStatusMsg{status: status}
}

func deobfuscateOotbSettings() tea.Msg {
	filePath := `C:\ProgramData\Zscaler\ZDP\Settings\zdp_endpoint_settings_ootb.json`
	err := runZDPObfuscate(true, defaultKeyFilePath, filePath)
	if err != nil {
		if strings.Contains(err.Error(), "key file read error") {
			return errorMsg(fmt.Errorf("key file read error: Anti-tampering is enabled. Please disable it to de-obfuscate the file"))
		}
		return errorMsg(fmt.Errorf("failed to de-obfuscate ootb-settings: %w", err))
	}
	return deobfuscationDoneMsg{message: fmt.Sprintf("File '%s' de-obfuscated successfully.", filePath)}
}

func deobfuscateZdpModes() tea.Msg {
	filePath := `C:\ProgramData\Zscaler\ZDP\Settings\zdp_modes.json`
	err := runZDPObfuscate(true, defaultKeyFilePath, filePath)
	if err != nil {
		if strings.Contains(err.Error(), "key file read error") {
			return errorMsg(fmt.Errorf("key file read error: Anti-tampering is enabled. Please disable it to de-obfuscate the file"))
		}
		return errorMsg(fmt.Errorf("failed to de-obfuscate zdp-modes: %w", err))
	}
	return deobfuscationDoneMsg{message: fmt.Sprintf("File '%s' de-obfuscated successfully.", filePath)}
}


func runZDPObfuscate(deobfuscate bool, keyPath, filePath string) error {
	var args []string
	if deobfuscate {
		args = append(args, "-d")
	}
	args = append(args, keyPath, filePath)
	_, err := runEmbeddedExe(zdpObfuscateExe, "ZDPObfuscate.exe", args...)
	return err
}

// --- Helper Functions from original code ---

func setAntiTamperingMode(enable bool) error {
	otp, err := getOTP()
	if err != nil {
		return err
	}
	mode := "0"
	if enable {
		mode = "1"
	}
	_, err = runEmbeddedExe(zepSdkInvokeOtpExe, "ZEPSdkInvokeOTP.exe", "SetATModeEx", mode, otp)
	return err
}

func getAntiTamperingStatus() (string, error) {
	output, err := runEmbeddedExe(zepSdkInvokeOtpExe, "ZEPSdkInvokeOTP.exe", "GetATMode")
	if err != nil {
		return "", err
	}
	if strings.Contains(output, "Enabled") {
		return "Enabled", nil
	}
	if strings.Contains(output, "Disabled") {
		return "Disabled", nil
	}
	return "Unknown", nil
}

func getOTP() (string, error) {
	hostname, err := getHostname()
	if err != nil {
		return "", err
	}
	output, err := runEmbeddedExe(otpGeneratorExe, "OTPGenerator.exe", hostname)
	if err != nil {
		return "", fmt.Errorf("failed to generate OTP: %w", err)
	}
	otp := strings.TrimSpace(strings.TrimPrefix(output, "OTP:"))
	if otp == "" {
		return "", fmt.Errorf("OTPGenerator.exe returned empty OTP")
	}
	return otp, nil
}

func getHostname() (string, error) {
	return os.Hostname()
}

func runEmbeddedExe(exeData []byte, exeName string, args ...string) (string, error) {
	tempDir, err := ioutil.TempDir("", "go-app-exec")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer os.RemoveAll(tempDir)

	tempExePath := filepath.Join(tempDir, exeName)
	err = ioutil.WriteFile(tempExePath, exeData, 0755)
	if err != nil {
		return "", fmt.Errorf("failed to write embedded executable to temp file: %w", err)
	}

	cmd := exec.Command(tempExePath, args...)
	outputBytes, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("executable '%s' failed: %w\nOutput: %s", exeName, err, string(outputBytes))
	}
	return string(outputBytes), nil
}