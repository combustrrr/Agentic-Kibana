const policy = require('./renovate-scanners.json');
delete policy.$schema;
module.exports = {
  ...policy,
  platform: 'github',
  repositories: [process.env.GITHUB_REPOSITORY],
  onboarding: false,
  requireConfig: 'ignored',
  allowScripts: false,
  allowPlugins: false,
  allowedCommands: ['^python -m scripts\\.code_analysis\\.sync_scanner_workflows$'],
};
