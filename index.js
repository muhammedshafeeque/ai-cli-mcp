#!/usr/bin/env node

const { Command } = require('commander');
const { exec } = require('child_process');
const axios = require('axios');
const program = new Command();
const readline = require('readline');
const dotenv = require('dotenv');
const os = require('os');
const chalk = require('chalk').default;
const fs = require('fs');
const path = require('path');
dotenv.config();

// Helper: Format prompt in MCP (Model Context Protocol) style
function formatMCPPrompt(system, user) {
  return [
    { role: 'system', content: system },
    { role: 'user', content: user }
  ];
}

// Command: Send prompt to Mistral AI
program
  .command('ask <prompt>')
  .description('Send a prompt to Mistral AI using MCP format')
  .option('-s, --system <system>', 'System context', 'You are a helpful assistant.')
  .action(async (prompt, options) => {
    const apiKey = process.env.MISTRAL_API_KEY;
    if (!apiKey) {
      console.error(chalk.red('Error: Please set your MISTRAL_API_KEY environment variable.'));
      process.exit(1);
    }
    const mcpPrompt = formatMCPPrompt(options.system, prompt);
    try {
      const response = await axios.post(
        'https://api.mistral.ai/v1/chat/completions',
        {
          model: 'mistral-tiny', // Change model as needed
          messages: mcpPrompt
        },
        {
          headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json'
          }
        }
      );
      console.log(chalk.green(response.data.choices[0].message.content));
    } catch (err) {
      console.error(chalk.red('API Error:'), chalk.yellow(err.response ? JSON.stringify(err.response.data, null, 2) : err.message));
    }
  });

// Command: Run a Linux system command and use its output as context
program
  .command('sys <cmd...>')
  .description('Run a Linux system command and send its output to Mistral AI')
  .option('-s, --system <system>', 'System context', 'You are a helpful assistant.')
  .action((cmd, options) => {
    const commandStr = cmd.join(' ');
    exec(commandStr, (error, stdout, stderr) => {
      if (error) {
        console.error(chalk.red(`Error: ${stderr}`));
        process.exit(1);
      }
      // Here, you could send stdout as part of the MCP prompt to Mistral
      console.log(chalk.cyan('Command output:'), chalk.green(stdout));
      // Optionally, call the ask command logic here
    });
  });

// Command: Interactive chat with Mistral AI and system command execution
program
  .command('chat')
  .description('Start an interactive chat with Mistral AI (with system command execution)')
  .option('-s, --system <system>', 'System context', 'You are a helpful assistant. You have full access to the user\'s Linux system. If the user asks for any information or action that requires a shell command, reply with the command in a code block and I will execute it and return the output. The OS is: ' + os.type() + ' ' + os.platform() + ' ' + os.release() + '.')
  .action(async (options) => {
    const apiKey = process.env.MISTRAL_API_KEY;
    if (!apiKey) {
      console.error(chalk.red('Error: Please set your MISTRAL_API_KEY environment variable.'));
      process.exit(1);
    }
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout
    });
    let context = [
      { role: 'system', content: options.system }
    ];
    console.log(chalk.magenta('Start chatting with Mistral AI! (type "exit" to quit)'));
    const ask = () => {
      rl.question('You: ', async (input) => {
        if (input.trim().toLowerCase() === 'exit') {
          rl.close();
          return;
        }
        context.push({ role: 'user', content: input });
        try {
          const response = await axios.post(
            'https://api.mistral.ai/v1/chat/completions',
            {
              model: 'mistral-tiny',
              messages: context
            },
            {
              headers: {
                'Authorization': `Bearer ${apiKey}`,
                'Content-Type': 'application/json'
              }
            }
          );
          let reply = response.data.choices[0].message.content;
          // Check for shell command in code block
          const codeBlockMatch = reply.match(/```(?:bash|sh|zsh)?\n([\s\S]*?)```/);
          if (codeBlockMatch) {
            const commandToRun = codeBlockMatch[1].split('\n').map(l => l.trim()).filter(Boolean)[0] || '';
            // Remove explanations/comments after # or (
            if (commandToRun.includes('#')) commandToRun = commandToRun.split('#')[0].trim();
            if (commandToRun.includes('(')) commandToRun = commandToRun.split('(')[0].trim();
            console.log(`Executing command: ${commandToRun}`);
            exec(commandToRun, (error, stdout, stderr) => {
              if (error) {
                console.log(chalk.red('Command error:'), chalk.yellow(stderr || error.message));
                context.push({ role: 'assistant', content: chalk.red(`Command error: ${stderr || error.message}`) });
              } else {
                console.log(chalk.cyan('Command output:'), chalk.green(stdout));
                context.push({ role: 'assistant', content: chalk.cyan(`Command output:\n${stdout}`) });
              }
              ask();
            });
          } else {
            console.log(chalk.green('Assistant:'), chalk.green(reply));
            context.push({ role: 'assistant', content: chalk.green(reply) });
            ask();
          }
        } catch (err) {
          console.error(chalk.red('API Error:'), chalk.yellow(err.response ? JSON.stringify(err.response.data, null, 2) : err.message));
          ask();
        }
      });
    };
    ask();
  });

// Command: AGI - Convert instruction to shell command and execute
program
  .command('agi <instruction...>')
  .description('Give a natural language instruction, get it executed as a shell command')
  .option('-s, --system <system>', 'System context', 'Convert the following user instruction into a single Linux shell command. Only output the command, nothing else.')
  .action(async (instruction, options) => {
    const apiKey = process.env.MISTRAL_API_KEY;
    if (!apiKey) {
      console.error(chalk.red('Error: Please set your MISTRAL_API_KEY environment variable.'));
      process.exit(1);
    }
    const userInstruction = instruction.join(' ');
    const mcpPrompt = [
      { role: 'system', content: options.system },
      { role: 'user', content: userInstruction }
    ];
    try {
      const response = await axios.post(
        'https://api.mistral.ai/v1/chat/completions',
        {
          model: 'mistral-tiny',
          messages: mcpPrompt
        },
        {
          headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json'
          }
        }
      );
      let reply = response.data.choices[0].message.content;
      // Extract command from code block if present
      let commandToRun = '';
      const codeBlockMatch = reply.match(/```(?:bash|sh|zsh)?\n([\s\S]*?)```/);
      const isValidShellCommand = l => /^[a-zA-Z0-9_./~\-]+(\s|$)/.test(l) && !/^([Tt]o|[Tt]he|[Ii]f|[Ff]or|[Nn]ote|[Uu]se|[Ww]hen|[Yy]ou|[Aa]nd|[Oo]r|[Ss]o|[Bb]ut|[Hh]ow|[Ww]ith|[Ii]n|[Aa]s|[Tt]his|[Tt]hat|[Tt]here|[Hh]ere|[Ee]xample|[Ee]tc)/.test(l);
      if (codeBlockMatch) {
        // Take the first non-empty, valid shell command line from the code block
        commandToRun = codeBlockMatch[1].split('\n').map(l => l.trim()).filter(isValidShellCommand)[0] || '';
        // Remove explanations/comments after # or (
        if (commandToRun.includes('#')) commandToRun = commandToRun.split('#')[0].trim();
        if (commandToRun.includes('(')) commandToRun = commandToRun.split('(')[0].trim();
      } else {
        // Remove backticks and take the first non-empty, valid shell command line
        const lines = reply.replace(/`/g, '').split('\n').map(l => l.trim()).filter(isValidShellCommand);
        commandToRun = lines[0] || '';
        // Remove explanations/comments after # or (
        if (commandToRun.includes('#')) commandToRun = commandToRun.split('#')[0].trim();
        if (commandToRun.includes('(')) commandToRun = commandToRun.split('(')[0].trim();
      }
      if (!commandToRun) {
        console.log(chalk.red('No valid shell command found in the AI response.'));
        console.log(chalk.yellow('AI raw response:'), reply);
        // Fallback: try to extract a line containing a common shell command
        const fallbackCommands = [
          // File and directory operations
          'ls', 'cat', 'rm', 'touch', 'cp', 'mv', 'echo', 'pwd', 'cd', 'mkdir', 'rmdir', 'ln', 'ln -s', 'file', 'stat', 'wc', 'sort', 'uniq', 'cut', 'paste', 'join', 'split', 'tr', 'sed', 'awk',
          // Text processing
          'grep', 'egrep', 'fgrep', 'head', 'tail', 'less', 'more', 'nano', 'vim', 'vi', 'gedit', 'nano', 'emacs', 'tee', 'column', 'fmt', 'fold', 'nl', 'pr', 'rev', 'tac',
          // System information
          'ps', 'top', 'htop', 'free', 'df', 'du', 'uptime', 'who', 'whoami', 'w', 'id', 'groups', 'uname', 'hostname', 'hostnamectl', 'lscpu', 'lsmem', 'lshw', 'dmidecode', 'lspci', 'lsusb',
          // Process management
          'kill', 'killall', 'pkill', 'pgrep', 'nice', 'renice', 'nohup', 'screen', 'tmux', 'jobs', 'bg', 'fg', 'wait', 'timeout',
          // Network tools
          'curl', 'wget', 'ping', 'traceroute', 'mtr', 'netstat', 'ss', 'ip', 'ifconfig', 'route', 'arp', 'dig', 'nslookup', 'host', 'whois', 'telnet', 'nc', 'netcat', 'ssh', 'scp', 'rsync', 'ftp', 'sftp',
          // Package management
          'apt', 'apt-get', 'apt-cache', 'dpkg', 'rpm', 'yum', 'dnf', 'pacman', 'zypper', 'snap', 'flatpak', 'brew',
          // Compression and archiving
          'tar', 'zip', 'unzip', 'gzip', 'gunzip', 'bzip2', 'bunzip2', 'xz', 'unxz', '7z', 'rar', 'unrar',
          // File permissions and ownership
          'chmod', 'chown', 'chgrp', 'umask', 'su', 'sudo', 'passwd', 'useradd', 'userdel', 'usermod', 'groupadd', 'groupdel', 'groupmod',
          // Disk and filesystem
          'mount', 'umount', 'fdisk', 'parted', 'mkfs', 'fsck', 'blkid', 'lsblk', 'findmnt', 'swapon', 'swapoff',
          // System services
          'systemctl', 'service', 'init', 'systemd', 'journalctl', 'logrotate', 'cron', 'crontab', 'at', 'batch',
          // Hardware and devices
          'lspci', 'lsusb', 'lsmod', 'modprobe', 'insmod', 'rmmod', 'dmesg', 'udevadm', 'lshw', 'inxi', 'sensors', 'smartctl',
          // Text and data processing
          'awk', 'sed', 'grep', 'cut', 'paste', 'join', 'sort', 'uniq', 'comm', 'diff', 'patch', 'bc', 'dc', 'expr', 'let', 'seq',
          // Development tools
          'gcc', 'g++', 'make', 'cmake', 'git', 'svn', 'cvs', 'python', 'python3', 'node', 'npm', 'yarn', 'java', 'javac', 'mvn', 'gradle',
          // Monitoring and logging
          'top', 'htop', 'iotop', 'iftop', 'nethogs', 'iotop', 'sar', 'iostat', 'vmstat', 'mpstat', 'pidstat', 'strace', 'ltrace',
          // Security tools
          'openssl', 'gpg', 'ssh-keygen', 'ssh-copy-id', 'iptables', 'ufw', 'fail2ban', 'clamav', 'rkhunter', 'chkrootkit',
          // Backup and sync
          'rsync', 'dd', 'cpio', 'dump', 'restore', 'tar', 'dd', 'pv', 'rsync', 'scp', 'sftp', 'rclone',
          // System maintenance
          'cron', 'anacron', 'logrotate', 'tmpwatch', 'tmpreaper', 'updatedb', 'locate', 'find', 'xargs', 'parallel',
          // User environment
          'env', 'export', 'set', 'unset', 'alias', 'unalias', 'history', 'source', '.', 'exec', 'eval',
          // Shell utilities
          'basename', 'dirname', 'realpath', 'readlink', 'which', 'whereis', 'type', 'command', 'hash', 'help', 'man', 'info',
          // Date and time
          'date', 'cal', 'timedatectl', 'ntpdate', 'hwclock', 'tzselect',
          // Math and calculations
          'bc', 'dc', 'expr', 'let', 'seq', 'factor', 'primes', 'units',
          // Miscellaneous
          'clear', 'reset', 'tput', 'stty', 'script', 'watch', 'yes', 'no', 'true', 'false', 'sleep', 'usleep', 'time', 'timeout',
          // Kali Linux Security Tools
          // Information Gathering
          'nmap', 'zenmap', 'masscan', 'amass', 'subfinder', 'sublist3r', 'theharvester', 'recon-ng', 'maltego', 'spiderfoot', 'osint-spy', 'holehe', 'h8mail', 'breach-parse',
          // Vulnerability Analysis
          'openvas', 'nessus', 'nexpose', 'qualys', 'nikto', 'wpscan', 'joomscan', 'droopescan', 'plecost', 'w3af', 'zap', 'burpsuite', 'sqlmap', 'nosqlmap', 'xsstrike', 'xsser',
          // Web Application Analysis
          'burpsuite', 'zap', 'w3af', 'nikto', 'dirb', 'dirbuster', 'gobuster', 'ffuf', 'wfuzz', 'sqlmap', 'xsstrike', 'commix', 'weevely', 'webshell', 'shellshock', 'heartbleed',
          // Database Assessment
          'sqlmap', 'nosqlmap', 'sqlninja', 'bsqlbf', 'sqldict', 'mysqlmap', 'oracle-tns', 'mssqlmap', 'psqlmap', 'redis-cli', 'mongodb', 'couchdb',
          // Password Attacks
          'john', 'hashcat', 'hydra', 'medusa', 'ncrack', 'patator', 'crowbar', 'thc-pptp-bruter', 'cewl', 'crunch', 'wordlists', 'rockyou', 'hash-identifier', 'hashid',
          // Wireless Attacks
          'aircrack-ng', 'reaver', 'wash', 'bully', 'cowpatty', 'pyrit', 'kismet', 'wireshark', 'tshark', 'airodump-ng', 'aireplay-ng', 'airmon-ng', 'airtun-ng', 'packetforge-ng',
          // Exploitation Tools
          'metasploit', 'msfconsole', 'msfvenom', 'msfdb', 'armitage', 'beef-xss', 'social-engineer-toolkit', 'setoolkit', 'empire', 'cobaltstrike', 'powersploit', 'veil', 'shellter',
          // Sniffing & Spoofing
          'wireshark', 'tshark', 'tcpdump', 'ettercap', 'dsniff', 'responder', 'bettercap', 'mitmproxy', 'mitmdump', 'sslstrip', 'sslstrip2', 'dns2proxy', 'dnschef',
          // Post Exploitation
          'mimikatz', 'powersploit', 'empire', 'cobaltstrike', 'meterpreter', 'beacon', 'psexec', 'wmiexec', 'smbexec', 'pth-winexe', 'secretsdump', 'wce', 'mimipenguin',
          // Forensics
          'autopsy', 'sleuthkit', 'volatility', 'memdump', 'dd', 'dcfldd', 'dc3dd', 'guymager', 'foremost', 'scalpel', 'photorec', 'testdisk', 'extundelete', 'ext4magic',
          // Reporting Tools
          'dradis', 'faraday', 'pipal', 'magic-tree', 'keepnote', 'cherrytree', 'joplin', 'tiddlywiki', 'mediawiki', 'dokuwiki',
          // Social Engineering
          'social-engineer-toolkit', 'setoolkit', 'beef-xss', 'phishing-frenzy', 'king-phisher', 'gophish', 'evilginx2', 'credphish', 'phishery',
          // Reverse Engineering
          'ghidra', 'radare2', 'r2', 'ida', 'x64dbg', 'ollydbg', 'gdb', 'objdump', 'readelf', 'strings', 'hexdump', 'xxd', 'file', 'binwalk', 'upx', 'peid',
          // Hardware Hacking
          'arduino', 'avrdude', 'busybox', 'minicom', 'screen', 'putty', 'teraterm', 'securecrt', 'kermit', 'picocom', 'gtkterm', 'cutecom',
          // Mobile Security
          'apktool', 'dex2jar', 'jd-gui', 'jadx', 'androguard', 'androlyze', 'mobsf', 'drozer', 'objection', 'frida', 'jadx-gui', 'bytecode-viewer',
          // IoT Security
          'firmwalker', 'binwalk', 'firmware-mod-kit', 'firmware-analysis-toolkit', 'qemu', 'gdb-multiarch', 'r2', 'ghidra', 'ida', 'angr', 'unicorn',
          // Cloud Security
          'pacu', 'cloudsploit', 'scoutsuite', 'cloudmapper', 'awscli', 'gcloud', 'az', 'terraform', 'ansible', 'chef', 'puppet', 'salt',
          // Container Security
          'docker', 'docker-compose', 'kubectl', 'helm', 'rancher', 'trivy', 'clair', 'anchore', 'snyk', 'falco', 'opa', 'gatekeeper',
          // Network Security
          'snort', 'suricata', 'bro', 'zeek', 'moloch', 'arkime', 'elasticsearch', 'kibana', 'logstash', 'beats', 'graylog', 'splunk',
          // Additional Tools
          'dirsearch', 'gospider', 'hakrawler', 'waybackurls', 'gau', 'httpx', 'httprobe', 'subjack', 'subzy', 'tko-subs', 'corstest', 'corsy'
        ];
        let fallbackLine = reply.split('\n').map(l => l.trim()).find(l => fallbackCommands.some(cmd => l.startsWith(cmd + ' ')));
        // Fallback 2: look for a command inside backticks
        if (!fallbackLine) {
          const backtickMatches = reply.match(/`([^`]+)`/g);
          if (backtickMatches) {
            fallbackLine = backtickMatches.map(s => s.replace(/`/g, '').trim()).find(l => fallbackCommands.some(cmd => l.startsWith(cmd + ' ')));
          }
        }
        if (fallbackLine) {
          let fallbackCommand = fallbackLine;
          if (fallbackCommand.includes('#')) fallbackCommand = fallbackCommand.split('#')[0].trim();
          if (fallbackCommand.includes('(')) fallbackCommand = fallbackCommand.split('(')[0].trim();
          console.log(chalk.magenta('Fallback: Executing command:'), chalk.cyan(fallbackCommand));
          exec(fallbackCommand, (error, stdout, stderr) => {
            let logEntry = `\n> Instruction: ${userInstruction}\n> Command: ${fallbackCommand}\n> Output:\n${stdout || stderr || error?.message || ''}`;
            fs.appendFileSync(logPath, logEntry);
            if (error) {
              console.log(chalk.red('Command error:'), chalk.yellow(stderr || error.message));
            } else {
              console.log(chalk.cyan('Command output:'), chalk.green(stdout));
            }
          });
        }
        return;
      }
      console.log(chalk.magenta('Executing command:'), chalk.cyan(commandToRun));
      exec(commandToRun, (error, stdout, stderr) => {
        if (error) {
          console.log(chalk.red('Command error:'), chalk.yellow(stderr || error.message));
        } else {
          console.log(chalk.cyan('Command output:'), chalk.green(stdout));
        }
      });
    } catch (err) {
      console.error(chalk.red('API Error:'), chalk.yellow(err.response ? JSON.stringify(err.response.data, null, 2) : err.message));
    }
  });

// Default/fallback command: treat any unknown command as a natural language instruction
program
  .arguments('<instruction...>')
  .description('Give a natural language instruction, get it executed as a shell command')
  .action(async (instruction) => {
    const apiKey = process.env.MISTRAL_API_KEY;
    if (!apiKey) {
      console.error(chalk.red('Error: Please set your MISTRAL_API_KEY environment variable.'));
      process.exit(1);
    }
    const userInstruction = instruction.join(' ');
    const logPath = path.join(require('os').homedir(), '.ai_cli_log');
    let logContext = '';
    // Read last 30 lines from log if it exists and is not empty
    if (fs.existsSync(logPath)) {
      const logContent = fs.readFileSync(logPath, 'utf-8');
      if (logContent.trim().length > 0) {
        const lines = logContent.trim().split('\n');
        logContext = lines.slice(-30).join('\n');
      }
    }
    let systemPrompt = 'Convert the following user instruction into a single Linux shell command. Only output the command, nothing else.';
    if (logContext) {
      systemPrompt = `Here is the recent terminal log. Use it to understand references like \'the newly added file\'.\n\nLOG:\n${logContext}\n\nNow, convert the following user instruction into a single Linux shell command. Only output the command, nothing else.`;
    }
    const mcpPrompt = [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userInstruction }
    ];
    try {
      const response = await axios.post(
        'https://api.mistral.ai/v1/chat/completions',
        {
          model: 'mistral-tiny',
          messages: mcpPrompt
        },
        {
          headers: {
            'Authorization': `Bearer ${apiKey}`,
            'Content-Type': 'application/json'
          }
        }
      );
      let reply = response.data.choices[0].message.content;
      // Extract command from code block if present
      let commandToRun = '';
      const codeBlockMatch = reply.match(/```(?:bash|sh|zsh)?\n([\s\S]*?)```/);
      const isValidShellCommand = l => /^[a-zA-Z0-9_./~\-]+(\s|$)/.test(l) && !/^([Tt]o|[Tt]he|[Ii]f|[Ff]or|[Nn]ote|[Uu]se|[Ww]hen|[Yy]ou|[Aa]nd|[Oo]r|[Ss]o|[Bb]ut|[Hh]ow|[Ww]ith|[Ii]n|[Aa]s|[Tt]his|[Tt]hat|[Tt]here|[Hh]ere|[Ee]xample|[Ee]tc)/.test(l);
      if (codeBlockMatch) {
        // Take the first non-empty, valid shell command line from the code block
        commandToRun = codeBlockMatch[1].split('\n').map(l => l.trim()).filter(isValidShellCommand)[0] || '';
        // Remove explanations/comments after # or (
        if (commandToRun.includes('#')) commandToRun = commandToRun.split('#')[0].trim();
        if (commandToRun.includes('(')) commandToRun = commandToRun.split('(')[0].trim();
      } else {
        // Remove backticks and take the first non-empty, valid shell command line
        const lines = reply.replace(/`/g, '').split('\n').map(l => l.trim()).filter(isValidShellCommand);
        commandToRun = lines[0] || '';
        // Remove explanations/comments after # or (
        if (commandToRun.includes('#')) commandToRun = commandToRun.split('#')[0].trim();
        if (commandToRun.includes('(')) commandToRun = commandToRun.split('(')[0].trim();
      }
      if (!commandToRun) {
        console.log(chalk.red('No valid shell command found in the AI response.'));
        console.log(chalk.yellow('AI raw response:'), reply);
        // Fallback: try to extract a line containing a common shell command
        const fallbackCommands = [
          // File and directory operations
          'ls', 'cat', 'rm', 'touch', 'cp', 'mv', 'echo', 'pwd', 'cd', 'mkdir', 'rmdir', 'ln', 'ln -s', 'file', 'stat', 'wc', 'sort', 'uniq', 'cut', 'paste', 'join', 'split', 'tr', 'sed', 'awk',
          // Text processing
          'grep', 'egrep', 'fgrep', 'head', 'tail', 'less', 'more', 'nano', 'vim', 'vi', 'gedit', 'nano', 'emacs', 'tee', 'column', 'fmt', 'fold', 'nl', 'pr', 'rev', 'tac',
          // System information
          'ps', 'top', 'htop', 'free', 'df', 'du', 'uptime', 'who', 'whoami', 'w', 'id', 'groups', 'uname', 'hostname', 'hostnamectl', 'lscpu', 'lsmem', 'lshw', 'dmidecode', 'lspci', 'lsusb',
          // Process management
          'kill', 'killall', 'pkill', 'pgrep', 'nice', 'renice', 'nohup', 'screen', 'tmux', 'jobs', 'bg', 'fg', 'wait', 'timeout',
          // Network tools
          'curl', 'wget', 'ping', 'traceroute', 'mtr', 'netstat', 'ss', 'ip', 'ifconfig', 'route', 'arp', 'dig', 'nslookup', 'host', 'whois', 'telnet', 'nc', 'netcat', 'ssh', 'scp', 'rsync', 'ftp', 'sftp',
          // Package management
          'apt', 'apt-get', 'apt-cache', 'dpkg', 'rpm', 'yum', 'dnf', 'pacman', 'zypper', 'snap', 'flatpak', 'brew',
          // Compression and archiving
          'tar', 'zip', 'unzip', 'gzip', 'gunzip', 'bzip2', 'bunzip2', 'xz', 'unxz', '7z', 'rar', 'unrar',
          // File permissions and ownership
          'chmod', 'chown', 'chgrp', 'umask', 'su', 'sudo', 'passwd', 'useradd', 'userdel', 'usermod', 'groupadd', 'groupdel', 'groupmod',
          // Disk and filesystem
          'mount', 'umount', 'fdisk', 'parted', 'mkfs', 'fsck', 'blkid', 'lsblk', 'findmnt', 'swapon', 'swapoff',
          // System services
          'systemctl', 'service', 'init', 'systemd', 'journalctl', 'logrotate', 'cron', 'crontab', 'at', 'batch',
          // Hardware and devices
          'lspci', 'lsusb', 'lsmod', 'modprobe', 'insmod', 'rmmod', 'dmesg', 'udevadm', 'lshw', 'inxi', 'sensors', 'smartctl',
          // Text and data processing
          'awk', 'sed', 'grep', 'cut', 'paste', 'join', 'sort', 'uniq', 'comm', 'diff', 'patch', 'bc', 'dc', 'expr', 'let', 'seq',
          // Development tools
          'gcc', 'g++', 'make', 'cmake', 'git', 'svn', 'cvs', 'python', 'python3', 'node', 'npm', 'yarn', 'java', 'javac', 'mvn', 'gradle',
          // Monitoring and logging
          'top', 'htop', 'iotop', 'iftop', 'nethogs', 'iotop', 'sar', 'iostat', 'vmstat', 'mpstat', 'pidstat', 'strace', 'ltrace',
          // Security tools
          'openssl', 'gpg', 'ssh-keygen', 'ssh-copy-id', 'iptables', 'ufw', 'fail2ban', 'clamav', 'rkhunter', 'chkrootkit',
          // Backup and sync
          'rsync', 'dd', 'cpio', 'dump', 'restore', 'tar', 'dd', 'pv', 'rsync', 'scp', 'sftp', 'rclone',
          // System maintenance
          'cron', 'anacron', 'logrotate', 'tmpwatch', 'tmpreaper', 'updatedb', 'locate', 'find', 'xargs', 'parallel',
          // User environment
          'env', 'export', 'set', 'unset', 'alias', 'unalias', 'history', 'source', '.', 'exec', 'eval',
          // Shell utilities
          'basename', 'dirname', 'realpath', 'readlink', 'which', 'whereis', 'type', 'command', 'hash', 'help', 'man', 'info',
          // Date and time
          'date', 'cal', 'timedatectl', 'ntpdate', 'hwclock', 'tzselect',
          // Math and calculations
          'bc', 'dc', 'expr', 'let', 'seq', 'factor', 'primes', 'units',
          // Miscellaneous
          'clear', 'reset', 'tput', 'stty', 'script', 'watch', 'yes', 'no', 'true', 'false', 'sleep', 'usleep', 'time', 'timeout',
          // Kali Linux Security Tools
          // Information Gathering
          'nmap', 'zenmap', 'masscan', 'amass', 'subfinder', 'sublist3r', 'theharvester', 'recon-ng', 'maltego', 'spiderfoot', 'osint-spy', 'holehe', 'h8mail', 'breach-parse',
          // Vulnerability Analysis
          'openvas', 'nessus', 'nexpose', 'qualys', 'nikto', 'wpscan', 'joomscan', 'droopescan', 'plecost', 'w3af', 'zap', 'burpsuite', 'sqlmap', 'nosqlmap', 'xsstrike', 'xsser',
          // Web Application Analysis
          'burpsuite', 'zap', 'w3af', 'nikto', 'dirb', 'dirbuster', 'gobuster', 'ffuf', 'wfuzz', 'sqlmap', 'xsstrike', 'commix', 'weevely', 'webshell', 'shellshock', 'heartbleed',
          // Database Assessment
          'sqlmap', 'nosqlmap', 'sqlninja', 'bsqlbf', 'sqldict', 'mysqlmap', 'oracle-tns', 'mssqlmap', 'psqlmap', 'redis-cli', 'mongodb', 'couchdb',
          // Password Attacks
          'john', 'hashcat', 'hydra', 'medusa', 'ncrack', 'patator', 'crowbar', 'thc-pptp-bruter', 'cewl', 'crunch', 'wordlists', 'rockyou', 'hash-identifier', 'hashid',
          // Wireless Attacks
          'aircrack-ng', 'reaver', 'wash', 'bully', 'cowpatty', 'pyrit', 'kismet', 'wireshark', 'tshark', 'airodump-ng', 'aireplay-ng', 'airmon-ng', 'airtun-ng', 'packetforge-ng',
          // Exploitation Tools
          'metasploit', 'msfconsole', 'msfvenom', 'msfdb', 'armitage', 'beef-xss', 'social-engineer-toolkit', 'setoolkit', 'empire', 'cobaltstrike', 'powersploit', 'veil', 'shellter',
          // Sniffing & Spoofing
          'wireshark', 'tshark', 'tcpdump', 'ettercap', 'dsniff', 'responder', 'bettercap', 'mitmproxy', 'mitmdump', 'sslstrip', 'sslstrip2', 'dns2proxy', 'dnschef',
          // Post Exploitation
          'mimikatz', 'powersploit', 'empire', 'cobaltstrike', 'meterpreter', 'beacon', 'psexec', 'wmiexec', 'smbexec', 'pth-winexe', 'secretsdump', 'wce', 'mimipenguin',
          // Forensics
          'autopsy', 'sleuthkit', 'volatility', 'memdump', 'dd', 'dcfldd', 'dc3dd', 'guymager', 'foremost', 'scalpel', 'photorec', 'testdisk', 'extundelete', 'ext4magic',
          // Reporting Tools
          'dradis', 'faraday', 'pipal', 'magic-tree', 'keepnote', 'cherrytree', 'joplin', 'tiddlywiki', 'mediawiki', 'dokuwiki',
          // Social Engineering
          'social-engineer-toolkit', 'setoolkit', 'beef-xss', 'phishing-frenzy', 'king-phisher', 'gophish', 'evilginx2', 'credphish', 'phishery',
          // Reverse Engineering
          'ghidra', 'radare2', 'r2', 'ida', 'x64dbg', 'ollydbg', 'gdb', 'objdump', 'readelf', 'strings', 'hexdump', 'xxd', 'file', 'binwalk', 'upx', 'peid',
          // Hardware Hacking
          'arduino', 'avrdude', 'busybox', 'minicom', 'screen', 'putty', 'teraterm', 'securecrt', 'kermit', 'picocom', 'gtkterm', 'cutecom',
          // Mobile Security
          'apktool', 'dex2jar', 'jd-gui', 'jadx', 'androguard', 'androlyze', 'mobsf', 'drozer', 'objection', 'frida', 'jadx-gui', 'bytecode-viewer',
          // IoT Security
          'firmwalker', 'binwalk', 'firmware-mod-kit', 'firmware-analysis-toolkit', 'qemu', 'gdb-multiarch', 'r2', 'ghidra', 'ida', 'angr', 'unicorn',
          // Cloud Security
          'pacu', 'cloudsploit', 'scoutsuite', 'cloudmapper', 'awscli', 'gcloud', 'az', 'terraform', 'ansible', 'chef', 'puppet', 'salt',
          // Container Security
          'docker', 'docker-compose', 'kubectl', 'helm', 'rancher', 'trivy', 'clair', 'anchore', 'snyk', 'falco', 'opa', 'gatekeeper',
          // Network Security
          'snort', 'suricata', 'bro', 'zeek', 'moloch', 'arkime', 'elasticsearch', 'kibana', 'logstash', 'beats', 'graylog', 'splunk',
          // Additional Tools
          'dirsearch', 'gospider', 'hakrawler', 'waybackurls', 'gau', 'httpx', 'httprobe', 'subjack', 'subzy', 'tko-subs', 'corstest', 'corsy'
        ];
        let fallbackLine = reply.split('\n').map(l => l.trim()).find(l => fallbackCommands.some(cmd => l.startsWith(cmd + ' ')));
        // Fallback 2: look for a command inside backticks
        if (!fallbackLine) {
          const backtickMatches = reply.match(/`([^`]+)`/g);
          if (backtickMatches) {
            fallbackLine = backtickMatches.map(s => s.replace(/`/g, '').trim()).find(l => fallbackCommands.some(cmd => l.startsWith(cmd + ' ')));
          }
        }
        if (fallbackLine) {
          let fallbackCommand = fallbackLine;
          if (fallbackCommand.includes('#')) fallbackCommand = fallbackCommand.split('#')[0].trim();
          if (fallbackCommand.includes('(')) fallbackCommand = fallbackCommand.split('(')[0].trim();
          console.log(chalk.magenta('Fallback: Executing command:'), chalk.cyan(fallbackCommand));
          exec(fallbackCommand, (error, stdout, stderr) => {
            let logEntry = `\n> Instruction: ${userInstruction}\n> Command: ${fallbackCommand}\n> Output:\n${stdout || stderr || error?.message || ''}`;
            fs.appendFileSync(logPath, logEntry);
            if (error) {
              console.log(chalk.red('Command error:'), chalk.yellow(stderr || error.message));
            } else {
              console.log(chalk.cyan('Command output:'), chalk.green(stdout));
            }
          });
        }
        return;
      }
      console.log(chalk.magenta('Executing command:'), chalk.cyan(commandToRun));
      exec(commandToRun, (error, stdout, stderr) => {
        // Log the instruction, command, and output to the log file
        let logEntry = `\n> Instruction: ${userInstruction}\n> Command: ${commandToRun}\n> Output:\n${stdout || stderr || error?.message || ''}`;
        fs.appendFileSync(logPath, logEntry);
        if (error) {
          console.log(chalk.red('Command error:'), chalk.yellow(stderr || error.message));
        } else {
          console.log(chalk.cyan('Command output:'), chalk.green(stdout));
        }
      });
    } catch (err) {
      console.error(chalk.red('API Error:'), chalk.yellow(err.response ? JSON.stringify(err.response.data, null, 2) : err.message));
    }
  });

program.parse(process.argv);
