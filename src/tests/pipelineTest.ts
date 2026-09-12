import { LogParser } from '../services/logParser';
import { LogValidator } from '../services/logValidator';
import { DuplicateDetector } from '../services/duplicateDetector';
import { LogTypeDetector } from '../services/logTypeDetector';
import { SAMPLE_DATASETS } from '../services/sampleDatasets';

async function runVerificationTests() {
  console.log('=== RUNNING STAGE 2 INGESTION PIPELINE VERIFICATION SUITE ===\n');
  let passCount = 0;
  let testCount = 0;

  function assert(condition: boolean, testName: string, detail?: string) {
    testCount++;
    if (condition) {
      console.log(`[PASS] ${testName}`);
      passCount++;
    } else {
      console.error(`[FAIL] ${testName} - Detail: ${detail || 'Assertion failed'}`);
    }
  }

  const dupDetector = new DuplicateDetector();
  const parser = new LogParser(dupDetector);

  // 1. Suricata JSONL test
  const suricata = SAMPLE_DATASETS.suricata_network;
  const netResult = await parser.parseContent(suricata.content, { filename: suricata.filename });
  assert(netResult.format === 'JSONL', 'Format auto-detection: JSONL for Suricata stream');
  assert(netResult.detectedLogType === 'NETWORK', 'Domain auto-detection: NETWORK for Suricata EVE alerts');
  assert(netResult.events.length === 12, `Parsed 12 events from Suricata JSONL (got ${netResult.events.length})`);
  assert(netResult.validCount === 12, `All 12 Suricata events passed schema validation (got ${netResult.validCount})`);
  assert(netResult.events[0].normalizedFields?.sourceIp === '192.168.1.105', 'Normalized field extraction: sourceIp');
  assert(netResult.events[0].normalizedFields?.destinationPort === 443, 'Normalized field extraction: destinationPort');

  // 2. Sysmon CSV test
  const sysmon = SAMPLE_DATASETS.sysmon_system;
  const sysResult = await parser.parseContent(sysmon.content, { filename: sysmon.filename });
  assert(sysResult.format === 'CSV', 'Format auto-detection: CSV for Sysmon host log');
  assert(sysResult.detectedLogType === 'SYSTEM', 'Domain auto-detection: SYSTEM for Sysmon host events');
  assert(sysResult.events.length === 10, `Parsed 10 events from Sysmon CSV (got ${sysResult.events.length})`);
  assert(sysResult.events[1].normalizedFields?.processName === 'cmd.exe', 'Sysmon processName extraction');
  assert(sysResult.events[1].normalizedFields?.parentProcess === 'spoolsv.exe', 'Sysmon parentProcess extraction');

  // 3. Nginx Web Access Log test
  const nginx = SAMPLE_DATASETS.nginx_application;
  const appResult = await parser.parseContent(nginx.content, { filename: nginx.filename });
  assert(appResult.detectedLogType === 'APPLICATION', 'Domain auto-detection: APPLICATION for Web Access logs');
  assert(appResult.events.length === 11, `Parsed 11 events from Nginx access log (got ${appResult.events.length})`);
  assert(appResult.events[0].normalizedFields?.httpMethod === 'GET', 'Web access method extraction');
  assert(appResult.events[0].normalizedFields?.statusCode === 200, 'Web access statusCode extraction');

  // 4. Duplicate Detection test
  const duplicateTestEvent = netResult.events[0];
  const firstCheck = dupDetector.checkAndRecord(duplicateTestEvent);
  assert(firstCheck.isDuplicate === true, 'Duplicate detector flags identical repeated event');
  assert(firstCheck.duplicateCount >= 2, 'Duplicate detector increments occurrence counter');

  // 5. Schema Validation: Malformed / Invalid event test
  const invalidEvent = {
    ...duplicateTestEvent,
    timestamp: 'not-a-timestamp',
    normalizedFields: {
      ...duplicateTestEvent.normalizedFields,
      sourceIp: '999.999.999.999', // Invalid IP
      destinationPort: 99999 // Invalid Port
    }
  };
  const valResult = LogValidator.validate(invalidEvent);
  assert(valResult.status === 'INVALID', 'Validator identifies invalid RFC timestamp and port range');
  assert(valResult.errors.length >= 2, `Validator returns explicit diagnostic errors (got ${valResult.errors.length})`);

  // 6. Heuristic Domain Detection test
  const netDomain = LogTypeDetector.detect({ src_ip: '10.0.0.1', dst_port: 80, proto: 'TCP' });
  assert(netDomain.detectedType === 'NETWORK', 'Heuristics identify network telemetry');

  const sysDomain = LogTypeDetector.detect({ hostname: 'srv-01', pid: 1042, process_name: 'bash' });
  assert(sysDomain.detectedType === 'SYSTEM', 'Heuristics identify system telemetry');

  const appDomain = LogTypeDetector.detect({ method: 'POST', endpoint: '/api/v1/auth', status_code: 401 });
  assert(appDomain.detectedType === 'APPLICATION', 'Heuristics identify application telemetry');

  console.log(`\n=== TEST SUITE COMPLETED: ${passCount}/${testCount} TESTS PASSED ===\n`);
  if (passCount !== testCount) {
    process.exit(1);
  }
}

runVerificationTests();
