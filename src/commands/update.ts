import chalk from 'chalk';
import { reloadIOCDatabase, getIOCDatabase } from '../ioc/database.js';

export async function runUpdate(): Promise<void> {
  console.log(chalk.cyan('Reloading IOC database...'));

  reloadIOCDatabase();
  const db = getIOCDatabase();

  console.log(chalk.green('IOC database loaded:'));
  console.log(`  C2 IPs: ${db.c2Ips.length}`);
  console.log(`  Malicious domains: ${db.maliciousDomains.length}`);
  console.log(`  File hashes: ${db.fileHashes.length}`);
  console.log(`  Malicious publishers: ${db.maliciousPublishers.length}`);
  console.log(`  Malicious skill patterns: ${db.maliciousSkillPatterns.length}`);
  console.log(`  Trusted skill names: ${db.trustedSkillNames.length}`);
}
