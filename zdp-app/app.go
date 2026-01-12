package main

import (
	"context"
	_ "embed"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
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

// App struct
type App struct {
	ctx context.Context
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// --- Methods callable from frontend ---

func (a *App) IsZdpServiceRunning() bool {
	cmd := exec.Command("powershell", "-Command", "Get-Service -Name zdpservice")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(output), "Running")
}

func (a *App) GetDetailsHttpsCmd() (string, error) {
	url := "https://127.0.0.1:9861/api/v1.0/get-zdpe-details"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create HTTPS request: %w", err)
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   5 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("HTTPS request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read HTTPS response body: %w", err)
	}
	return string(body), nil
}

func (a *App) GetDetailsHttpCmd() (string, error) {
	url := "http://127.0.0.1:9861/api/v1.0/get-zdpe-details"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create HTTP request: %w", err)
	}
	client := &http.Client{
		Timeout: 5 * time.Second,
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read HTTP response body: %w", err)
	}
	return string(body), nil
}

func (a *App) EnableAntiTampering() error {
	return a.setAntiTamperingMode(true)
}

func (a *App) DisableAntiTampering() error {
	return a.setAntiTamperingMode(false)
}

func (a *App) GetAntiTamperingStatus() (string, error) {
	output, err := a.runEmbeddedExe(zepSdkInvokeOtpExe, "ZEPSdkInvokeOTP.exe", "GetATMode")
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

func (a *App) DeobfuscateOotbSettings() (string, error) {
	filePath := `C:\ProgramData\Zscaler\ZDP\Settings\zdp_endpoint_settings_ootb.json`
	err := a.runZDPObfuscate(true, defaultKeyFilePath, filePath)
	if err != nil {
		if strings.Contains(err.Error(), "key file read error") {
			return "", fmt.Errorf("key file read error: Anti-tampering is enabled. Please disable it to de-obfuscate the file")
		}
		return "", fmt.Errorf("failed to de-obfuscate ootb-settings: %w", err)
	}
	return fmt.Sprintf("File '%s' de-obfuscated successfully.", filePath), nil
}

func (a *App) DeobfuscateZdpModes() (string, error) {
	filePath := `C:\ProgramData\Zscaler\ZDP\Settings\zdp_modes.json`
	err := a.runZDPObfuscate(true, defaultKeyFilePath, filePath)
	if err != nil {
		if strings.Contains(err.Error(), "key file read error") {
			return "", fmt.Errorf("key file read error: Anti-tampering is enabled. Please disable it to de-obfuscate the file")
		}
		return "", fmt.Errorf("failed to de-obfuscate zdp-modes: %w", err)
	}
	return fmt.Sprintf("File '%s' de-obfuscated successfully.", filePath), nil
}

// --- Helper Functions ---

func (a *App) runZDPObfuscate(deobfuscate bool, keyPath, filePath string) error {
	var args []string
	if deobfuscate {
		args = append(args, "-d")
	}
	args = append(args, keyPath, filePath)
	_, err := a.runEmbeddedExe(zdpObfuscateExe, "ZDPObfuscate.exe", args...)
	return err
}

func (a *App) setAntiTamperingMode(enable bool) error {
	otp, err := a.getOTP()
	if err != nil {
		return err
	}
	mode := "0"
	if enable {
		mode = "1"
	}
	_, err = a.runEmbeddedExe(zepSdkInvokeOtpExe, "ZEPSdkInvokeOTP.exe", "SetATModeEx", mode, otp)
	return err
}

func (a *App) getOTP() (string, error) {
	hostname, err := a.getHostname()
	if err != nil {
		return "", err
	}
	output, err := a.runEmbeddedExe(otpGeneratorExe, "OTPGenerator.exe", hostname)
	if err != nil {
		return "", fmt.Errorf("failed to generate OTP: %w", err)
	}
	otp := strings.TrimSpace(strings.TrimPrefix(output, "OTP:"))
	if otp == "" {
		return "", fmt.Errorf("OTPGenerator.exe returned empty OTP")
	}
	return otp, nil
}

func (a *App) getHostname() (string, error) {
	return os.Hostname()
}

func (a *App) runEmbeddedExe(exeData []byte, exeName string, args ...string) (string, error) {
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
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	outputBytes, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("executable '%s' failed: %w\nOutput: %s", exeName, err, string(outputBytes))
	}
	return string(outputBytes), nil
}