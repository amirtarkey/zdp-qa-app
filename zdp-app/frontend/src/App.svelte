<script>
  import { onMount } from 'svelte';
  import {
    IsZdpServiceRunning,
    GetDetailsHttpsCmd,
    GetDetailsHttpCmd,
    EnableAntiTampering,
    DisableAntiTampering,
    GetAntiTamperingStatus,
    DeobfuscateOotbSettings,
    DeobfuscateZdpModes
  } from '../wailsjs/go/main/App.js';
  import { ClipboardSetText } from '../wailsjs/runtime/runtime.js';

  let antiTamperStatus = '';
  let resultText = '';
  let endpointDetails = null;
  let copyButtonText = 'Copy';

  let timeoutId = null;

  function clearResultText() {
    resultText = '';
    endpointDetails = null;
  }

  function autoClearResultText(timeout = 10000) {
    console.log(`autoClearResultText called with timeout: ${timeout}`);
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
    timeoutId = setTimeout(() => {
      console.log('autoClearResultText: clearing result text');
      resultText = '';
      endpointDetails = null;
    }, timeout);
  }

  async function checkAntiTamperStatus() {
    try {
      antiTamperStatus = await GetAntiTamperingStatus();
    } catch (error) {
      resultText = `Error: ${error}`;
      autoClearResultText(1000);
    }
  }

  async function handleEnableAntiTampering() {
    clearResultText();
    try {
      resultText = 'Enabling anti-tampering...';
      await EnableAntiTampering();
      resultText = 'Anti-tampering enabled successfully.';
      checkAntiTamperStatus();
    } catch (error) {
      resultText = `Error: ${error}`;
    }
    autoClearResultText(1000);
  }

  async function handleDisableAntiTampering() {
    clearResultText();
    try {
      resultText = 'Disabling anti-tampering...';
      await DisableAntiTampering();
      resultText = 'Anti-tampering disabled successfully.';
      checkAntiTamperStatus();
    } catch (error) {
      resultText = `Error: ${error}`;
    }
    autoClearResultText(1000);
  }

  async function handleGetEndpointDetails() {
    clearResultText();
    resultText = 'Getting endpoint details...';
    endpointDetails = null;
    console.log('handleGetEndpointDetails: start');

    try {
      const isRunning = await IsZdpServiceRunning();
      if (!isRunning) {
        resultText = 'ZDP service is not running.';
        autoClearResultText(10000);
        console.log('handleGetEndpointDetails: ZDP service not running');
        return;
      }

      try {
        console.log('handleGetEndpointDetails: trying HTTPS');
        const details = await GetDetailsHttpsCmd();
        endpointDetails = JSON.parse(details);
        resultText = 'Endpoint details retrieved successfully via HTTPS.';
        console.log('handleGetEndpointDetails: HTTPS success');
        autoClearResultText(10000);
      } catch (httpsError) {
        console.log(`handleGetEndpointDetails: HTTPS error: ${httpsError}`);
        resultText = `HTTPS attempt failed: ${httpsError}. Trying HTTP...`;
        try {
          console.log('handleGetEndpointDetails: trying HTTP');
          const details = await GetDetailsHttpCmd();
          endpointDetails = JSON.parse(details);
          resultText = 'Endpoint details retrieved successfully via HTTP.';
          console.log('handleGetEndpointDetails: HTTP success');
          autoClearResultText(10000);
        } catch (httpError) {
          console.log(`handleGetEndpointDetails: HTTP error: ${httpError}`);
          resultText = `HTTP attempt also failed: ${httpError}`;
          autoClearResultText(10000);
        }
      }
    } catch (error) {
      console.log(`handleGetEndpointDetails: unexpected error: ${error}`);
      resultText = `An unexpected error occurred: ${error}`;
      autoClearResultText(10000);
    }
  }

  async function handleDeobfuscateOotbSettings() {
    clearResultText();
    console.log('handleDeobfuscateOotbSettings: start');
    try {
      resultText = 'De-obfuscating ootb-settings...';
      const result = await DeobfuscateOotbSettings();
      resultText = result;
      console.log(`handleDeobfuscateOotbSettings: success: ${result}`);
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
    } catch (error) {
      resultText = `Error: ${error}`;
      console.log(`handleDeobfuscateZdpModes: error: ${error}`);
    }
    autoClearResultText(5000);
  }

  function copyEndpointDetails() {
    if (endpointDetails) {
      ClipboardSetText(JSON.stringify(endpointDetails, null, 2));
      copyButtonText = 'Copied!';
      setTimeout(() => {
        copyButtonText = 'Copy';
      }, 2000);
    }
  }

  onMount(() => {
    checkAntiTamperStatus();
  });
</script>

<main>
  <h1>ZDP Tool</h1>
  <div class="status">
    Anti-tampering status: {antiTamperStatus}
  </div>
  <div class="buttons">
    <button on:click={handleEnableAntiTampering}>Enable Anti-tampering</button>
    <button on:click={handleDisableAntiTampering}>Disable Anti-tampering</button>
    <button on:click={handleGetEndpointDetails}>Get Endpoint Details</button>
    <button on:click={handleDeobfuscateOotbSettings}>De-obfuscate ootb-settings</button>
    <button on:click={handleDeobfuscateZdpModes}>De-obfuscate zdp-modes</button>
  </div>
  <div class="output">
    <div class="result">
      {resultText}
    </div>
    {#if endpointDetails}
      <div class="endpoint-details">
        <div class="header">
          <h2>Endpoint Details</h2>
          <button on:click={copyEndpointDetails}>{copyButtonText}</button>
        </div>
        <pre>{JSON.stringify(endpointDetails, null, 2)}</pre>
      </div>
    {/if}
  </div>
</main>

<style>
  main {
    padding: 1em;
    display: flex;
    flex-direction: column;
    align-items: center;
    height: 100vh;
  }

  h1 {
    color: #ff3e00;
    text-transform: uppercase;
    font-size: 2em;
    font-weight: 100;
  }

  .status {
    margin-bottom: 1em;
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
</style>
