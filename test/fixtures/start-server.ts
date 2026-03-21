import { createVulnerableServer } from './vulnerable-server.js';

const { server, url } = await createVulnerableServer();
console.log(`VULN_SERVER=${url}`);
console.log(`Server running at ${url}`);
// Keep alive
process.on('SIGINT', () => { server.close(); process.exit(0); });
