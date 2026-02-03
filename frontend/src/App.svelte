<script>
    import { onMount, onDestroy } from 'svelte';
    import {
        IsZdpServiceRunning,
        EnableAntiTampering,
        DisableAntiTampering,
        GetAntiTamperingStatus,
        DeobfuscateOotbSettings,
        DeobfuscateZdpModes,
        IsOotbSettingsObfuscated,
        IsZdpModesObfuscated,
        GetDlpSdkVersion,
        ClearZdpLogs,
        GetCurrentLogLevel,
        SetLogLevel,
        GetSaveMessagesLocallyStatus,
        SetSaveMessagesLocally,
        RegisterDev04
    } from '../wailsjs/go/main/App.js';
    import Footer from './Footer.svelte';
    import StandaloneClassifier from './StandaloneClassifier.svelte';
  
    let antiTamperStatus = '';
    let resultText = '';
    let zdpServiceStatus = '';
    let isOotbSettingsObfuscated = false;
    let isZdpModesObfuscated = false;
    let saveMessagesLocally = false;
    let freshStart = false;
    let currentTab = 'Main';
    let dlpSdkVersion = '';

    const logLevels = ["error", "warning", "info", "debug", "trace"];
    let currentLogLevel = 'info';
  
    let timeoutId = null;
    let intervalId = null;
  
    function clearResultText() {
      resultText = '';
    }
  
    function autoClearResultText(timeout = 10000) {
      console.log(`autoClearResultText called with timeout: ${timeout}`);
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
      timeoutId = setTimeout(() => {
        console.log('autoClearResultText: clearing result text');
        resultText = '';
      }, timeout);
    }
  
    async function checkStatuses() {
      try {
        antiTamperStatus = await GetAntiTamperingStatus();
  	    zdpServiceStatus = await IsZdpServiceRunning();
        isOotbSettingsObfuscated = await IsOotbSettingsObfuscated();
        isZdpModesObfuscated = await IsZdpModesObfuscated();
        saveMessagesLocally = await GetSaveMessagesLocallyStatus();
      } catch (error) {
        resultText = `Error: ${error}`;
        autoClearResultText(1000);
      }
    }
    
    async function handleToggleAntiTampering(event) {
      const isEnabled = event.target.checked;
      clearResultText();
      try {
        if (isEnabled) {
          resultText = 'Enabling anti-tampering...';
          await EnableAntiTampering();
          resultText = 'Anti-tampering enabled successfully.';
        } else {
          resultText = 'Disabling anti-tampering...';
          await DisableAntiTampering();
          resultText = 'Anti-tampering disabled successfully.';
        }
        checkStatuses();
      } catch (error) {
        resultText = `Error: ${error}`;
      }
      autoClearResultText(1000);
    }
  
    async function handleDeobfuscateOotbSettings() {
      clearResultText();
      console.log('handleDeobfuscateOotbSettings: start');
      try {
        resultText = 'De-obfuscating ootb-settings...';
        const result = await DeobfuscateOotbSettings();
        resultText = result;
        console.log(`handleDeobfuscateOotbSettings: success: ${result}`);
        checkStatuses();
      } catch (error) {
        resultText = `Error: ${error}`;
        console.log(`handleDeobfuscateOotbSettings: error: ${error}`);
      }
      autoClearResultText(5000);
    }

    async function handleDeobfuscateZdpModes() {
      clearResultText();
      console.log('handleDeobfuscateZdpModes: start');
      try {
        resultText = 'De-obfuscating zdp-modes...';
        const result = await DeobfuscateZdpModes();
        resultText = result;
        console.log(`handleDeobfuscateZdpModes: success: ${result}`);
        checkStatuses();
      } catch (error) {
        resultText = `Error: ${error}`;
        console.log(`handleDeobfuscateZdpModes: error: ${error}`);
      }
      autoClearResultText(5000);
    }

    async function handleLogLevelChange(event) {
        const newLevel = event.target.value;
        clearResultText();
        resultText = `Setting log level to ${newLevel}...`;
        try {
            await SetLogLevel(newLevel);
            currentLogLevel = newLevel;
            resultText = `Log level successfully set to ${newLevel}.`;
        } catch (error) {
            resultText = `Error setting log level: ${error}`;
        }
        autoClearResultText(5000);
    }

    async function handleToggleSaveMessagesLocally(event) {
        const isEnabled = event.target.checked;
        clearResultText();
        resultText = `Setting 'Save Messages Locally' to ${isEnabled}...`;
        try {
            const result = await SetSaveMessagesLocally(isEnabled);
            resultText = result;
            saveMessagesLocally = isEnabled;
        } catch (error) {
            resultText = `Error: ${error}`;
        }
        autoClearResultText(5000);
    }

    async function handleRegisterDev04() {
      clearResultText();
      console.log('handleRegisterDev04: start');
      try {
        resultText = 'Registering to Dev04...';
        const result = await RegisterDev04(freshStart);
        resultText = result;
        console.log(`handleRegisterDev04: success: ${result}`);
        checkStatuses();
      } catch (error) {
        resultText = `Error: ${error}`;
        console.log(`handleRegisterDev04: error: ${error}`);
      }
      autoClearResultText(5000);
    }

    // New function to handle clearing ZDP logs
    async function handleClearZdpLogs() {
      clearResultText();
      console.log('handleClearZdpLogs: start');
      try {
        resultText = 'Attempting to clear ZDP logs...';
        const result = await ClearZdpLogs();
        resultText = result;
        console.log(`handleClearZdpLogs: success: ${result}`);
        checkStatuses(); // Update statuses in case anti-tampering was checked
      } catch (error) {
        resultText = `Error: ${error}`;
        console.log(`handleClearZdpLogs: error: ${error}`);
      }
      autoClearResultText(5000);
    }
  
    onMount(async () => {
      checkStatuses();
      intervalId = setInterval(checkStatuses, 5000); // Check every 5 seconds
      try {
        dlpSdkVersion = await GetDlpSdkVersion();
      } catch (error) {
        console.error("Failed to get DLP SDK Version:", error);
        dlpSdkVersion = "Error";
      }
      try {
        currentLogLevel = await GetCurrentLogLevel();
      } catch (error) {
        resultText = `Error getting log level: ${error}`;
        autoClearResultText(5000);
      }
      try {
        saveMessagesLocally = await GetSaveMessagesLocallyStatus();
      } catch (error) {
        resultText = `Error getting 'Save Messages Locally' status: ${error}`;
        autoClearResultText(5000);
      }
    });

    onDestroy(() => {
      if (intervalId) {
        clearInterval(intervalId);
      }
    });
  </script>
  
  <main>
    <h1>ZDP Tool</h1>
    <div class="tabs">
      <button on:click={() => currentTab = 'Main'} class:active={currentTab === 'Main'}>Main</button>
      <button on:click={() => currentTab = 'Standalone Classifier'} class:active={currentTab === 'Standalone Classifier'}>Standalone Classifier</button>
    </div>

    {#if currentTab === 'Main'}
      <div class="buttons">
            <div class="toggle-container">
              <label for="anti-tamper-toggle">Anti-tampering</label>
              <label class="switch">
                <input
                  id="anti-tamper-toggle"
                  type="checkbox"
                  checked={antiTamperStatus === 'Enabled'}
                  on:change={handleToggleAntiTampering}
                />
                <span class="slider round"></span>
              </label>
            </div>
            <div class="toggle-container">
              <label for="save-messages-locally-toggle">Save Messages Locally</label>
              <label class="switch">
                <input
                  id="save-messages-locally-toggle"
                  type="checkbox"
                  checked={saveMessagesLocally}
                  on:change={handleToggleSaveMessagesLocally}
                />
                <span class="slider round"></span>
              </label>
            </div>
            <div class="toggle-container">
              <label for="log-level-select">ZEP Log Level</label>
              <select id="log-level-select" class="dropdown" bind:value={currentLogLevel} on:change={handleLogLevelChange}>
                {#each logLevels as level}
                  <option value={level}>{level}</option>
                {/each}
              </select>
            </div>
            <div class="toggle-container">
              <label for="ootb-settings-toggle">De-obfuscate ootb-settings</label>
              <label class="switch">
                <input
                  id="ootb-settings-toggle"
                  type="checkbox"
                  checked={!isOotbSettingsObfuscated}
                  disabled={!isOotbSettingsObfuscated}
                  on:change={handleDeobfuscateOotbSettings}
                />
                <span class="slider round"></span>
              </label>
            </div>
            <div class="toggle-container">
              <label for="zdp-modes-toggle">De-obfuscate zdp-modes</label>
              <label class="switch">
                <input
                  id="zdp-modes-toggle"
                  type="checkbox"
                  checked={!isZdpModesObfuscated}
                  disabled={!isZdpModesObfuscated}
                  on:change={handleDeobfuscateZdpModes}
                />
                <span class="slider round"></span>
              </label>
            </div>
            <button on:click={handleClearZdpLogs}>Clear ZDP Logs</button>
            <div class="toggle-container">
              <label for="fresh-start-toggle">Fresh Start</label>
              <label class="switch">
                <input
                  id="fresh-start-toggle"
                  type="checkbox"
                  bind:checked={freshStart}
                />
                <span class="slider round"></span>
              </label>
            </div>
            <button on:click={handleRegisterDev04}>Register to Dev04</button>
      </div>
      <div class="output">
        <div class="result">
          {resultText}
        </div>
      </div>
    {/if}

    {#if currentTab === 'Standalone Classifier'}
      <StandaloneClassifier />
    {/if}
  </main>
  
  <Footer {antiTamperStatus} {zdpServiceStatus} {dlpSdkVersion} />
  
  <style>
    main {
      padding: 1em;
      display: flex;
      flex-direction: column;
      align-items: center;
      height: 100vh;
    }

    .tabs {
      margin-bottom: 1em;
    }

    .tabs button {
      margin: 0 0.5em;
      padding: 0.5em 1em;
      border: 1px solid #ccc;
      background-color: #f0f0f0;
      cursor: pointer;
    }

    .tabs button.active {
      background-color: #fff;
      border-bottom-color: #fff;
    }
  
    h1 {
      color: #ff3e00;
      text-transform: uppercase;
      font-size: 2em;
      font-weight: 100;
    }
  
    .buttons {
      display: flex;
      flex-direction: column;
      gap: 0.5em;
      width: 100%;
    }
  
    .output {
      margin-top: 1em;
      width: 100%;
    }
  
    .result {
      margin-top: 1em;
    }
  
    .endpoint-details {
      margin-top: 1em;
      text-align: left;
    }
  
      .endpoint-details .header {
        display: flex;
        justify-content: space-between;
        align-items: center;
      }
    
      .toggle-container {
        display: flex;
        justify-content: space-between;
        align-items: center;
        width: 100%;
        margin-bottom: 0.5em;
      }
    
      .switch {
        position: relative;
        display: inline-block;
        width: 50px;
        height: 24px;
      }
    
      .switch input { 
        opacity: 0;
        width: 0;
        height: 0;
      }
    
      .slider {
        position: absolute;
        cursor: pointer;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background-color: #ccc;
        -webkit-transition: .4s;
        transition: .4s;
      }
    
      .slider:before {
        position: absolute;
        content: "";
        height: 16px;
        width: 16px;
        left: 4px;
        bottom: 4px;
        background-color: white;
        -webkit-transition: .4s;
        transition: .4s;
      }

      .dropdown {
        padding: 0.5em;
        border: 1px solid #ccc;
        border-radius: 4px;
        background-color: white;
        width: 100px; /* Or adjust as needed */
      }
    
      input:checked + .slider {
        background-color: #2196F3;
      }
    
      input:focus + .slider {
        box-shadow: 0 0 1px #2196F3;
      }
    
      input:checked + .slider:before {
        -webkit-transform: translateX(26px);
        -ms-transform: translateX(26px);
        transform: translateX(26px);
      }
    
      /* Rounded sliders */
      .slider.round {
        border-radius: 34px;
      }
    
      .slider.round:before {
        border-radius: 50%;
      }
    </style>
