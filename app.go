package main

import (
	"context"
	_ "embed"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
	"encoding/json"
	"github.com/wailsapp/wails/v2/pkg/runtime"
	"regexp" // Added this import
	"golang.org/x/sys/windows/registry"
)

type WailsJson struct {
	Name string `json:"name"`
}

//go:embed executables/OTPGenerator.exe
var otpGeneratorExe []byte

//go:embed executables/ZEPSdkInvokeOTP.exe
var zepSdkInvokeOtpExe []byte

//go:embed executables/ZDPObfuscate.exe
var zdpObfuscateExe []byte

//go:embed resources/dlp_config_dlp_sdk.json
var dlpConfigDlpSdkJson []byte

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

// GetCurrentLogLevel reads the ZEP global log level from the registry.
func (a *App) GetCurrentLogLevel() (string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Zscaler Inc.\ZEP\Log`, registry.QUERY_VALUE)
	if err != nil {
		if err == registry.ErrNotExist {
			// If the key or value doesn't exist, it's better to return a known default.
			// ZEP default is "info"
			return "info", nil
		}
		return "", fmt.Errorf("failed to open registry key: %w", err)
	}
	defer key.Close()

	logLevel, _, err := key.GetStringValue("GlobalLogLevel")
	if err != nil {
		if err == registry.ErrNotExist {
			// ZEP default is "info"
			return "info", nil
		}
		return "", fmt.Errorf("failed to read registry value: %w", err)
	}

	// The registry might store the value with a different case.
	return strings.ToLower(logLevel), nil
}

// SetLogLevel sets the ZEP global log level in the registry.
func (a *App) SetLogLevel(level string) error {
	// This action requires administrator privileges. The frontend should be aware of this.
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Zscaler Inc.\ZEP\Log`, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("failed to open registry key with write access: %w. Please ensure the application is run with administrator privileges", err)
	}
	defer key.Close()

	err = key.SetStringValue("GlobalLogLevel", level)
	if err != nil {
		return fmt.Errorf("failed to write registry value: %w", err)
	}

	return nil
}

// --- Methods callable from frontend ---

func (a *App) IsZdpServiceRunning() string {
	cmd := exec.Command("powershell", "-Command", "(Get-Service -Name zdpservice -ErrorAction SilentlyContinue).Status")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "Not Installed"
	}
	status := strings.TrimSpace(string(output))
	if status == "" {
		return "Not Installed"
	}
	return status
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
	obfuscated, err := a.IsOotbSettingsObfuscated()
	if err != nil {
		return "", err
	}
	if !obfuscated {
		return "File is already de-obfuscated.", nil
	}

	filePath := `C:\ProgramData\Zscaler\ZDP\Settings\zdp_endpoint_settings_ootb.json`
	err = a.runZDPObfuscate(true, defaultKeyFilePath, filePath)
	if err != nil {
		if strings.Contains(err.Error(), "key file read error") {
			return "", fmt.Errorf("key file read error: Anti-tampering is enabled. Please disable it to de-obfuscate the file")
		}
		return "", fmt.Errorf("failed to de-obfuscate ootb-settings: %w", err)
	}
	return fmt.Sprintf("File '%s' de-obfuscated successfully.", filePath), nil
}

func (a *App) DeobfuscateZdpModes() (string, error) {
	obfuscated, err := a.IsZdpModesObfuscated()
	if err != nil {
		return "", err
	}
	if !obfuscated {
		return "File is already de-obfuscated.", nil
	}

	filePath := `C:\ProgramData\Zscaler\ZDP\Settings\zdp_modes.json`
	err = a.runZDPObfuscate(true, defaultKeyFilePath, filePath)
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

func (a *App) GetVersion() (string, error) {
	wailsJsonFile, err := os.ReadFile("wails.json")
	if err != nil {
		return "", fmt.Errorf("failed to read wails.json: %w", err)
	}

	var wailsJson WailsJson
	err = json.Unmarshal(wailsJsonFile, &wailsJson)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal wails.json: %w", err)
	}

	return wailsJson.Name, nil
}

func (a *App) IsOotbSettingsObfuscated() (bool, error) {
    status := a.IsZdpServiceRunning()
    if status == "Not Installed" {
        return false, nil // ZDP not installed, so can't be obfuscated
    }
	return a.isFileObfuscated(`C:\ProgramData\Zscaler\ZDP\Settings\zdp_endpoint_settings_ootb.json`)
}

func (a *App) IsZdpModesObfuscated() (bool, error) {
    status := a.IsZdpServiceRunning()
    if status == "Not Installed" {
        return false, nil // ZDP not installed, so can't be obfuscated
    }
	return a.isFileObfuscated(`C:\ProgramData\Zscaler\ZDP\Settings\zdp_modes.json`)
}

func (a *App) isFileObfuscated(filePath string) (bool, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	buffer := make([]byte, 4)
	_, err = file.Read(buffer)
	if err != nil {
		return false, fmt.Errorf("failed to read file: %w", err)
	}

	return string(buffer) == "ZDPU", nil
}

type ClassifierOutput struct {
	Command           string `json:"command"`
	Output            string `json:"output"`
	OcrTextPath       string `json:"ocrTextPath"`
	ExtractedTextPath string `json:"extractedTextPath"`
}

var (
	versionDLL               = syscall.NewLazyDLL("version.dll")
	procGetFileVersionInfoSize = versionDLL.NewProc("GetFileVersionInfoSizeW")
	procGetFileVersionInfo     = versionDLL.NewProc("GetFileVersionInfoW")
	procVerQueryValue          = versionDLL.NewProc("VerQueryValueW")
)

type VS_FIXEDFILEINFO struct {
	dwSignature        uint32
	dwStrucVersion     uint32
	dwFileVersionMS    uint32
	dwFileVersionLS    uint32
	dwProductVersionMS uint32
	dwProductVersionLS uint32
	dwFileFlagsMask    uint32
	dwFileFlags        uint32
	dwFileOS           uint32
	dwFileType         uint32
	dwFileSubtype      uint32
	dwFileDateMS       uint32
	dwFileDateLS       uint32
}

type AllVersions struct {
    Zdp string `json:"zdp"`
    Zcc string `json:"zcc"`
    Zep string `json:"zep"`
}

func (a *App) getExeVersion(filePath string) (string, error) {
	filePathPtr, err := syscall.UTF16PtrFromString(filePath)
	if err != nil {
		return "", err
	}

	infoSize, _, err := procGetFileVersionInfoSize.Call(uintptr(unsafe.Pointer(filePathPtr)), 0)
	if infoSize == 0 {
		return "", fmt.Errorf("GetFileVersionInfoSizeW failed: %v", err)
	}

	infoBuf := make([]byte, infoSize)

	ret, _, err := procGetFileVersionInfo.Call(
		uintptr(unsafe.Pointer(filePathPtr)),
		0,
		uintptr(infoSize),
		uintptr(unsafe.Pointer(&infoBuf[0])),
	)
	if ret == 0 {
		return "", fmt.Errorf("GetFileVersionInfoW failed: %v", err)
	}

	var fixedInfo *VS_FIXEDFILEINFO
	var len uint32
	ret, _, err = procVerQueryValue.Call(
		uintptr(unsafe.Pointer(&infoBuf[0])),
		uintptr(unsafe.Pointer(syscall.StringBytePtr(`\`))),
		uintptr(unsafe.Pointer(&fixedInfo)),
		uintptr(unsafe.Pointer(&len)),
	)
	if ret == 0 {
		return "", fmt.Errorf("VerQueryValueW failed: %v", err)
	}

	verMS := fixedInfo.dwProductVersionMS
	verLS := fixedInfo.dwProductVersionLS
	major := (verMS >> 16) & 0xffff
	minor := verMS & 0xffff
	patch := (verLS >> 16) & 0xffff
	build := verLS & 0xffff
    
	return fmt.Sprintf("%d.%d.%d.%d", major, minor, patch, build), nil
}


func (a *App) GetAllVersions() (*AllVersions, error) {
    zdpPath := `C:\Program Files\Zscaler\ZDP\ZDPService.exe`
    zccPath := `C:\Program Files\Zscaler\ZSATray\ZSATray.exe`
    zepPath := `C:\Program Files\Zscaler\ZEP\ZEPService.exe`

    zdpVer, zdpErr := a.getExeVersion(zdpPath)
    if zdpErr != nil {
        zdpVer = "Not Installed"
    }

    zccVer, zccErr := a.getExeVersion(zccPath)
    if zccErr != nil {
        zccVer = "Not Installed"
    }
    
    zepVer, zepErr := a.getExeVersion(zepPath)
    if zepErr != nil {
        zepVer = "Not Installed"
    }

    return &AllVersions{
        Zdp: zdpVer,
        Zcc: zccVer,
        Zep: zepVer,
    }, nil
}


func (a *App) StandaloneClassifier(filePath string, configOption string, configPath string, useOcr bool, useText bool) (*ClassifierOutput, error) {
	classifierPath := `C:\Program Files\Zscaler\ZDP\ZDPClassifier.exe`
	if _, err := os.Stat(classifierPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("classifier executable not found at %s", classifierPath)
	}

	var finalConfigPath string
	switch configOption {
	case "default":
		tempDir, err := ioutil.TempDir("", "zdp-tool-")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp dir: %w", err)
		}
		defer os.RemoveAll(tempDir)

		finalConfigPath = filepath.Join(tempDir, "dlp_config_dlp_sdk.json")
		err = ioutil.WriteFile(finalConfigPath, dlpConfigDlpSdkJson, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to write embedded config to temp file: %w", err)
		}
	case "last_modified":
		configDir := `C:\ProgramData\Zscaler\ZDP\Config`
		latestConfig, err := a.getLatestConfigFile(configDir)
		if err != nil {
			return nil, fmt.Errorf("failed to get latest config file: %w", err)
		}
		finalConfigPath = latestConfig
	case "custom":
		finalConfigPath = configPath
	default:
		return nil, fmt.Errorf("invalid config option: %s", configOption)
	}

	var args []string
	args = append(args, "-config", finalConfigPath, "-file", filePath)
	if useOcr {
		args = append(args, "-ocr")
	}
	if useText {
		args = append(args, "-text")
	}

	cmdString := fmt.Sprintf("%s %s", classifierPath, strings.Join(args, " "))
	cmd := exec.Command(classifierPath, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to run classifier: %w\nOutput: %s", err, string(output))
	}

	var ocrTextPath, extractedTextPath string
	if useOcr {
		ocrTextPath = filePath + ".ocr_text.txt"
	}
	if useText {
		extractedTextPath = filePath + ".extracted_text.txt"
	}

	return &ClassifierOutput{
		Command:           cmdString,
		Output:            string(output),
		OcrTextPath:       ocrTextPath,
		ExtractedTextPath: extractedTextPath,
	}, nil
}

func (a *App) getLatestConfigFile(dir string) (string, error) {
	files, err := ioutil.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("failed to read directory %s: %w", dir, err)
	}

	var latestFile os.FileInfo
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".json") {
			if latestFile == nil || file.ModTime().After(latestFile.ModTime()) {
				latestFile = file
			}
		}
	}

	if latestFile == nil {
		return "", fmt.Errorf("no json files found in %s", dir)
	}

	return filepath.Join(dir, latestFile.Name()), nil
}

func (a *App) SelectFile() (string, error) {
	file, err := runtime.OpenFileDialog(a.ctx, runtime.OpenDialogOptions{
		Title: "Select File",
		Filters: []runtime.FileFilter{
			{
				DisplayName: "All Files (*.*)",
				Pattern:     "*.*",
			},
		},
	})
	if err != nil {
		return "", err
	}
	return file, nil
}

func (a *App) ReadFileContent(path string) (string, error) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read file %s: %w", path, err)
	}
	return string(content), nil
}

func (a *App) ClearZdpLogs() (string, error) {
    status, err := a.GetAntiTamperingStatus()
    if err != nil {
        return "", fmt.Errorf("failed to get anti-tampering status: %w", err)
    }

    if status == "Enabled" {
        return "", fmt.Errorf("anti-tampering is enabled. Please disable it before clearing ZDP logs")
    }

    logFilePath := `C:\ProgramData\Zscaler\ZDP\Logs\zdp_service.log`
    
    // Check if the file exists before attempting to clear.
    // If it doesn't exist, we can treat it as successfully "cleared" (it's already empty).
    _, err = os.Stat(logFilePath)
    if os.IsNotExist(err) {
        return fmt.Sprintf("ZDP logs file %s does not exist (already cleared).", logFilePath), nil
    } else if err != nil {
        return "", fmt.Errorf("failed to check existence of ZDP logs at %s: %w", logFilePath, err)
    }

    err = os.WriteFile(logFilePath, []byte{}, 0644) // Empty byte slice clears content
    if err != nil {
        // More verbose error reporting
        return "", fmt.Errorf("failed to clear ZDP logs at %s: %v. This might be due to file being in use or permissions. Ensure ZDP service is stopped or anti-tampering is truly disabled.", logFilePath, err)
    }

    return fmt.Sprintf("ZDP logs at %s cleared successfully.", logFilePath), nil
}
// GetDlpSdkVersion function (added manually because I kept messing up the replace)
func (a *App) GetDlpSdkVersion() (string, error) {
	status := a.IsZdpServiceRunning()
	if status == "Not Installed" {
		return "Not Installed", nil
	}
	fmt.Println("Attempting to get DLP SDK Version...")
	result, classifierErr := a.StandaloneClassifier("C:\\ProgramData\\Zscaler\\ZDP\\Logs\\zdp_install.log", "default", "", false, false)

	// Check if result is nil first
	if result == nil {
		if classifierErr != nil {
			fmt.Printf("StandaloneClassifier returned nil result with error: %v\n", classifierErr)
			return "Unknown", fmt.Errorf("StandaloneClassifier returned nil result: %w", classifierErr)
		}
		// This case should ideally not happen (nil result without an error)
		fmt.Println("StandaloneClassifier returned nil result without an error. This is unexpected.")
		return "Unknown", fmt.Errorf("StandaloneClassifier returned nil result unexpectedly")
	}
	
	// Proceed with logging and parsing only if result is not nil
	fmt.Printf("Executed Command: %s\n", result.Command)
	fmt.Printf("Classifier Output: %s\n", result.Output)
	if classifierErr != nil {
		fmt.Printf("StandaloneClassifier returned an error (ignored if version found): %v\n", classifierErr)
	}

	// Always attempt to parse the DLP SDK version from the output
	re := regexp.MustCompile(`DLP SDK version: (.*)`)
	match := re.FindStringSubmatch(result.Output)
	
	fmt.Printf("Regex Match Result: %v\n", match)

	if len(match) > 1 {
		version := strings.TrimSpace(match[1])
		fmt.Printf("DLP SDK Version Extracted: %s\n", version)
		return version, nil
	}
	fmt.Println("DLP SDK Version not found in output.")

	// If version is not found and classifier had an error, then return the error
	if classifierErr != nil {
		return "Unknown", fmt.Errorf("DLP SDK version not found in output and classifier failed: %w", classifierErr)
	}

	return "Unknown", nil
}

const ootbSettingsPath = `C:\ProgramData\Zscaler\ZDP\Settings\zdp_endpoint_settings_ootb.json`

func (a *App) getOotbSettings() (map[string]interface{}, error) {
	// This function now assumes the file might need de-obfuscation,
	// which is handled by the calling functions Get/SetSaveMessagesLocallyStatus.
	// It just reads and parses the file.

	// Read file
	content, err := ioutil.ReadFile(ootbSettingsPath)
	if err != nil {
		return nil, fmt.Errorf("could not read ootb settings file: %w", err)
	}

	// Unmarshal JSON
	var settings map[string]interface{}
	err = json.Unmarshal(content, &settings)
	if err != nil {
		return nil, fmt.Errorf("could not unmarshal ootb settings json: %w", err)
	}
	return settings, nil
}

func (a *App) GetSaveMessagesLocallyStatus() (bool, error) {
	// Ensure the file is readable by de-obfuscating if necessary.
	obfuscated, err := a.IsOotbSettingsObfuscated()
	if err != nil {
		// If the file doesn't exist, we can reasonably assume the setting is disabled/default.
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("could not check if ootb settings are obfuscated: %w", err)
	}
	if obfuscated {
		_, err := a.DeobfuscateOotbSettings() // This returns a string message on success, which we ignore here.
		if err != nil {
			return false, fmt.Errorf("failed to de-obfuscate ootb settings to read status: %w", err)
		}
	}

	settings, err := a.getOotbSettings()
	if err != nil {
		// If the file doesn't exist after all checks, return false.
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}

	// Navigate to the "troubleshooting" object
	troubleshooting, ok := settings["troubleshooting"].(map[string]interface{})
	if !ok {
		return false, fmt.Errorf("'troubleshooting' section not found or invalid in ootb settings")
	}

	// Get value
	saveMessages, ok := troubleshooting["save_messages_locally"].(bool)
	if !ok {
		// If the key doesn't exist or is not a boolean, assume false.
		return false, nil
	}

	return saveMessages, nil
}

func (a *App) SetSaveMessagesLocally(enabled bool) (string, error) {
	// Step 1: De-obfuscate ootb settings
	// We run this regardless, as it checks for obfuscation internally and handles anti-tampering errors.
	deobfuscateMsg, err := a.DeobfuscateOotbSettings()
	if err != nil {
		// Don't stop if it's already de-obfuscated, but fail on other errors (like AT enabled)
		if !strings.Contains(err.Error(), "already de-obfuscated") {
			return "", err
		}
	}
	fmt.Println(deobfuscateMsg) // Log the message from de-obfuscation for debugging

	// Step 2: Read, update, and write the setting
	settings, err := a.getOotbSettings()
	if err != nil {
		return "", err // Error reading settings file
	}

	// Navigate to the "troubleshooting" object
	troubleshooting, ok := settings["troubleshooting"].(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("'troubleshooting' section not found or invalid in ootb settings")
	}

	// Update value
	troubleshooting["save_messages_locally"] = enabled

	// Marshal back to JSON with indentation
	updatedContent, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal updated settings: %w", err)
	}

	// Write file
	err = ioutil.WriteFile(ootbSettingsPath, updatedContent, 0644)
	if err != nil {
		return "", fmt.Errorf("failed to write updated ootb settings: %w", err)
	}

	// Step 3: Restart the service
	err = a.RestartZdpService()
	if err != nil {
		// Return a more specific error message to the user
		return "", fmt.Errorf("settings updated, but failed to restart ZDP service: %w. Please try restarting manually", err)
	}

	return fmt.Sprintf("Successfully set 'save_messages_locally' to %v and restarted ZDP service.", enabled), nil
}

func (a *App) StopZdpService() error {
	stopCmd := `
		$service = Get-Service -Name zdpservice -ErrorAction SilentlyContinue
		if ($null -ne $service -and $service.Status -ne 'Stopped') {
			try {
				Stop-Service -Name zdpservice -PassThru | Out-Null
				$service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
			} catch {
				throw "Timeout waiting for ZDP service to stop."
			}
		}
	`
	cmd := exec.Command("powershell", "-Command", stopCmd)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to stop service: %s", string(output))
	}
	return nil
}

func (a *App) StartZdpService() error {
	startCmd := `
		$service = Get-Service -Name zdpservice -ErrorAction SilentlyContinue
		if ($null -ne $service -and $service.Status -ne 'Running') {
			try {
				Start-Service -Name zdpservice -PassThru | Out-Null
				$service.WaitForStatus('Running', [TimeSpan]::FromSeconds(30))
			} catch {
				throw "Timeout waiting for ZDP service to start."
			}
		}
	`
	cmd := exec.Command("powershell", "-Command", startCmd)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("failed to start service: %s", string(output))
	}

	// Final check
	finalCheckCmd := `(Get-Service -Name zdpservice -ErrorAction SilentlyContinue).Status`
	cmd = exec.Command("powershell", "-Command", finalCheckCmd)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if output, err := cmd.CombinedOutput(); err != nil || strings.TrimSpace(string(output)) != "Running" {
		return fmt.Errorf("service did not start correctly. Final status: %s. Error: %v", string(output), err)
	}

	return nil
}

func (a *App) RestartZdpService() error {

	// This command requires administrator privileges.

	err := a.StopZdpService()

	if err != nil {

		return err

	}

	return a.StartZdpService()

}



func (a *App) RegisterDev04(freshStart bool) (string, error) {
	// 1. Disable anti-tampering
	err := a.DisableAntiTampering()
	if err != nil {
		return "", fmt.Errorf("failed to disable anti-tampering: %w", err)
	}

	// 2. de-obfuscate ootb
	deobfuscateMsg, err := a.DeobfuscateOotbSettings()
	if err != nil {
		if !strings.Contains(err.Error(), "already de-obfuscated") {
			return "", err
		}
	}
	fmt.Println(deobfuscateMsg)

	// 3. change the "register_endpoint_dev_url" key and "register_endpoint_dev_apikey" key values
	settings, err := a.getOotbSettings()
	if err != nil {
		return "", err
	}

	troubleshooting, ok := settings["troubleshooting"].(map[string]interface{})
	if !ok {
		// if troubleshooting section doesn't exist, create it
		troubleshooting = make(map[string]interface{})
		settings["troubleshooting"] = troubleshooting
	}

	troubleshooting["register_endpoint_dev_url"] = "https://endpoints.dev04.us-east-1.m3.dataprotection.zsprotect.net/api/1.0/register-endpoint"
	troubleshooting["register_endpoint_dev_apikey"] = "3nNKYWHW449IczYdgBFwc65bBmFx6lWT2WgVWH4d"

	updatedContent, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal updated settings: %w", err)
	}

	err = ioutil.WriteFile(ootbSettingsPath, updatedContent, 0644)
	if err != nil {
		return "", fmt.Errorf("failed to write updated ootb settings: %w", err)
	}

	// 4. if 'fresh start' is checked
	if freshStart {
		err = a.StopZdpService()
		if err != nil {
			return "", fmt.Errorf("failed to stop ZDP service: %w", err)
		}

		zdpPath := `C:\ProgramData\Zscaler\ZDP`
		exceptions := []string{
			`C:\ProgramData\Zscaler\ZDP\Settings\PSI\XEY`,
			`C:\ProgramData\Zscaler\ZDP\Settings\zdp_endpoint_settings_ootb.json`,
			`C:\ProgramData\Zscaler\ZDP\Settings\zdp_endpoint_id`,
			`C:\ProgramData\Zscaler\ZDP\Applications\application_ids.json`,
			`C:\ProgramData\Zscaler\ZDP\Settings\zdp_modes.json`,
		}

		// Create a map for quick lookup
		exceptionMap := make(map[string]bool)
		for _, e := range exceptions {
			exceptionMap[e] = true
		}

		// Get all files and directories to delete
		var filesToDelete []string
		walkErr := filepath.Walk(zdpPath, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			// Skip the root zdpPath itself
			if path == zdpPath {
				return nil
			}

			// check if path is an exception
			if _, ok := exceptionMap[path]; ok {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			// check if path is a parent of an exception
			isParent := false
			for _, e := range exceptions {
				if strings.HasPrefix(e, path) {
					isParent = true
					break
				}
			}

			if isParent {
				return nil
			}

			filesToDelete = append(filesToDelete, path)
			return nil
		})

		if walkErr != nil {
			return "", fmt.Errorf("error walking directory: %w", walkErr)
		}

		// Delete files in reverse order to ensure children are deleted before parents
		for i := len(filesToDelete) - 1; i >= 0; i-- {
			err = os.RemoveAll(filesToDelete[i])
			if err != nil {
				// Log the error but continue trying to delete other files
				fmt.Printf("failed to delete %s: %v\n", filesToDelete[i], err)
			}
		}

		err = a.StartZdpService()
		if err != nil {
			return "", fmt.Errorf("failed to start ZDP service: %w", err)
		}
	} else {
		err = a.RestartZdpService()
		if err != nil {
			return "", fmt.Errorf("failed to restart ZDP service: %w", err)
		}
	}

	return "Successfully registered to Dev04.", nil
}
