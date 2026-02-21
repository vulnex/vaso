import chalk from 'chalk';
import { reloadIOCDatabase, getIOCDatabase, initIOCDatabase } from '../ioc/database.js';
import { fetchAndUpdateFeed } from '../ioc/updater.js';

export interface UpdateOptions {
  url?: string;
  force?: boolean;
}

export async function runUpdate(options: UpdateOptions = {}): Promise<void> {
  console.log(chalk.cyan('Updating IOC database from remote feed...'));

  const result = await fetchAndUpdateFeed({
    feedUrl: options.url,
    force: options.force ?? true, // CLI update always forces by default
  });

  if (!result.success) {
    console.log(chalk.red(`Update failed: ${result.message}`));
    console.log(chalk.yellow('Falling back to bundled IOC data.'));
    return;
  }

  console.log(chalk.green(result.message));

  if (result.newIndicators) {
    console.log(chalk.dim('  New indicators in feed:'));
    console.log(`    C2 IPs: ${result.newIndicators.c2Ips}`);
    console.log(`    Malicious domains: ${result.newIndicators.maliciousDomains}`);
    console.log(`    File hashes: ${result.newIndicators.fileHashes}`);
    console.log(`    Malicious publishers: ${result.newIndicators.maliciousPublishers}`);
    console.log(`    Malicious skill patterns: ${result.newIndicators.maliciousSkillPatterns}`);
    console.log(`    Trusted skill names: ${result.newIndicators.trustedSkillNames}`);
    console.log(`    Trusted MCP packages: ${result.newIndicators.trustedMCPPackages}`);
    console.log(`    Binary patterns: ${result.newIndicators.binaryPatterns}`);
  }

  // Reload database with merged feed data
  reloadIOCDatabase();
  await initIOCDatabase();
  const db = getIOCDatabase();

  console.log(chalk.green('\nMerged IOC database totals:'));
  console.log(`  C2 IPs: ${db.c2Ips.length}`);
  console.log(`  Malicious domains: ${db.maliciousDomains.length}`);
  console.log(`  File hashes: ${db.fileHashes.length}`);
  console.log(`  Malicious publishers: ${db.maliciousPublishers.length}`);
  console.log(`  Malicious skill patterns: ${db.maliciousSkillPatterns.length}`);
  console.log(`  Trusted skill names: ${db.trustedSkillNames.length}`);
  console.log(`  Trusted MCP packages: ${db.trustedMCPPackages.length}`);
  console.log(`  Binary patterns: ${db.binaryPatterns.length}`);
}
