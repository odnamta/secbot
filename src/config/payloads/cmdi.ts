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
  // Windows variants
  { payload: '& timeout /t 5', delay: 5, os: 'windows' },
  { payload: '| timeout /t 5', delay: 5, os: 'windows' },
];

export const CMDI_PAYLOADS_OUTPUT: CmdiOutputPayload[] = [
  { payload: '; echo secbot-cmdi-marker', marker: 'secbot-cmdi-marker', os: 'unix' },
  { payload: '| echo secbot-cmdi-marker', marker: 'secbot-cmdi-marker', os: 'unix' },
  { payload: '`echo secbot-cmdi-marker`', marker: 'secbot-cmdi-marker', os: 'unix' },
  { payload: '$(echo secbot-cmdi-marker)', marker: 'secbot-cmdi-marker', os: 'unix' },
];
