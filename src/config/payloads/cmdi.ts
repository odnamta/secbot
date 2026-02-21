export const CMDI_PAYLOADS_TIMING = [
  { payload: '; sleep 5', delay: 5 },
  { payload: '| sleep 5', delay: 5 },
  { payload: '`sleep 5`', delay: 5 },
  { payload: '$(sleep 5)', delay: 5 },
  { payload: '%0asleep 5', delay: 5 },
  // Windows variants
  { payload: '& timeout /t 5', delay: 5 },
  { payload: '| timeout /t 5', delay: 5 },
];

export const CMDI_PAYLOADS_OUTPUT = [
  { payload: '; echo secbot-cmdi-marker', marker: 'secbot-cmdi-marker' },
  { payload: '| echo secbot-cmdi-marker', marker: 'secbot-cmdi-marker' },
  { payload: '`echo secbot-cmdi-marker`', marker: 'secbot-cmdi-marker' },
  { payload: '$(echo secbot-cmdi-marker)', marker: 'secbot-cmdi-marker' },
];
