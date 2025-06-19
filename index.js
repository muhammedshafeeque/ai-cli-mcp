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

// Helper: Smart output formatting
function formatOutput(output, format = 'default') {
  switch (format) {
    case 'json':
      try {
        return JSON.stringify(JSON.parse(output), null, 2);
      } catch {
        return output;
      }
    case 'table':
      // Convert space-separated output to table format
      const lines = output.trim().split('\n');
      if (lines.length > 1) {
        const headers = lines[0].split(/\s+/);
        const data = lines.slice(1).map(line => line.split(/\s+/));
        return data.map(row => 
          headers.map((header, i) => `${header}: ${row[i] || ''}`).join(' | ')
        ).join('\n');
      }
      return output;
    case 'list':
      return output.trim().split('\n').map((line, i) => `${i + 1}. ${line}`).join('\n');
    case 'clean':
      return output.replace(/\s+/g, ' ').trim();
    default:
      return output;
  }
}

// Helper: Intelligent tool selection
function selectBestTool(task, context = '') {
  const toolMap = {
    'network_scan': ['nmap', 'arp-scan', 'netdiscover', 'masscan'],
    'port_scan': ['nmap', 'masscan', 'rustscan'],
    'web_scan': ['nikto', 'dirb', 'gobuster', 'ffuf', 'wfuzz'],
    'vulnerability_scan': ['nmap', 'nikto', 'sqlmap', 'xsstrike'],
    'password_crack': ['john', 'hashcat', 'hydra', 'medusa'],
    'file_analysis': ['file', 'strings', 'hexdump', 'binwalk'],
    'process_analysis': ['ps', 'top', 'htop', 'lsof', 'netstat'],
    'system_info': ['uname', 'lscpu', 'free', 'df', 'uptime'],
    'text_processing': ['grep', 'sed', 'awk', 'cut', 'sort', 'uniq'],
    'file_operations': ['ls', 'find', 'locate', 'which', 'whereis']
  };

  const taskLower = task.toLowerCase();
  for (const [category, tools] of Object.entries(toolMap)) {
    if (taskLower.includes(category.replace('_', ' ')) || 
        tools.some(tool => taskLower.includes(tool))) {
      return tools;
    }
  }
  return ['ls']; // default fallback
}

// Helper: Parse user intent
function parseUserIntent(instruction) {
  const intent = {
    action: '',
    target: '',
    format: 'default',
    tools: [],
    isComplex: false,
    isConversational: false
  };

  const instructionLower = instruction.toLowerCase();
  
  // Detect conversational requests that shouldn't trigger commands
  const conversationalKeywords = [
    'hello', 'hi', 'hey', 'good morning', 'good afternoon', 'good evening',
    'how are you', 'what\'s up', 'sup', 'greetings', 'salutations',
    'thanks', 'thank you', 'thx', 'appreciate it', 'thanks a lot',
    'bye', 'goodbye', 'see you', 'later', 'take care',
    'what can you do', 'help', 'help me', 'what do you do',
    'who are you', 'what are you', 'tell me about yourself'
  ];
  
  if (conversationalKeywords.some(keyword => instructionLower.includes(keyword))) {
    intent.isConversational = true;
  }
  
  // Detect format preferences
  if (instructionLower.includes('json') || instructionLower.includes('format json')) {
    intent.format = 'json';
  } else if (instructionLower.includes('table') || instructionLower.includes('formatted')) {
    intent.format = 'table';
  } else if (instructionLower.includes('list') || instructionLower.includes('numbered')) {
    intent.format = 'list';
  } else if (instructionLower.includes('clean') || instructionLower.includes('simple')) {
    intent.format = 'clean';
  }

  // Detect complex tasks
  intent.isComplex = instructionLower.includes('and') || 
                     instructionLower.includes('then') ||
                     instructionLower.includes('also') ||
                     instructionLower.includes('multiple') ||
                     instructionLower.includes('both');

  // Detect tools needed
  if (instructionLower.includes('network') || instructionLower.includes('scan')) {
    intent.tools.push('network_scan');
  }
  if (instructionLower.includes('web') || instructionLower.includes('http')) {
    intent.tools.push('web_scan');
  }
  if (instructionLower.includes('vulnerability') || instructionLower.includes('security')) {
    intent.tools.push('vulnerability_scan');
  }

  return intent;
}

// Consolidated fallback commands array
const FALLBACK_COMMANDS = [
  // File and directory operations
  'ls', 'cat', 'rm', 'touch', 'cp', 'mv', 'echo', 'pwd', 'cd', 'mkdir', 'rmdir', 'ln', 'ln -s', 'file', 'stat', 'wc', 'sort', 'uniq', 'cut', 'paste', 'join', 'split', 'tr', 'sed', 'awk',
  // Text processing
  'grep', 'egrep', 'fgrep', 'head', 'tail', 'less', 'more', 'nano', 'vim', 'vi', 'gedit', 'emacs', 'tee', 'column', 'fmt', 'fold', 'nl', 'pr', 'rev', 'tac',
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
  'top', 'htop', 'iotop', 'iftop', 'nethogs', 'sar', 'iostat', 'vmstat', 'mpstat', 'pidstat', 'strace', 'ltrace',
  // Security tools
  'openssl', 'gpg', 'ssh-keygen', 'ssh-copy-id', 'iptables', 'ufw', 'fail2ban', 'clamav', 'rkhunter', 'chkrootkit',
  // Backup and sync
  'rsync', 'dd', 'cpio', 'dump', 'restore', 'pv', 'rclone',
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
  'nmap', 'zenmap', 'masscan', 'amass', 'subfinder', 'sublist3r', 'theharvester', 'recon-ng', 'maltego', 'spiderfoot', 'osint-spy', 'holehe', 'h8mail', 'breach-parse',
  'openvas', 'nessus', 'nexpose', 'qualys', 'nikto', 'wpscan', 'joomscan', 'droopescan', 'plecost', 'w3af', 'zap', 'burpsuite', 'sqlmap', 'nosqlmap', 'xsstrike', 'xsser',
  'burpsuite', 'zap', 'w3af', 'nikto', 'dirb', 'dirbuster', 'gobuster', 'ffuf', 'wfuzz', 'sqlmap', 'xsstrike', 'commix', 'weevely', 'webshell', 'shellshock', 'heartbleed',
  'sqlmap', 'nosqlmap', 'sqlninja', 'bsqlbf', 'sqldict', 'mysqlmap', 'oracle-tns', 'mssqlmap', 'psqlmap', 'redis-cli', 'mongodb', 'couchdb',
  'john', 'hashcat', 'hydra', 'medusa', 'ncrack', 'patator', 'crowbar', 'thc-pptp-bruter', 'cewl', 'crunch', 'wordlists', 'rockyou', 'hash-identifier', 'hashid',
  'aircrack-ng', 'reaver', 'wash', 'bully', 'cowpatty', 'pyrit', 'kismet', 'wireshark', 'tshark', 'airodump-ng', 'aireplay-ng', 'airmon-ng', 'airtun-ng', 'packetforge-ng',
  'metasploit', 'msfconsole', 'msfvenom', 'msfdb', 'armitage', 'beef-xss', 'social-engineer-toolkit', 'setoolkit', 'empire', 'cobaltstrike', 'powersploit', 'veil', 'shellter',
  'wireshark', 'tshark', 'tcpdump', 'ettercap', 'dsniff', 'responder', 'bettercap', 'mitmproxy', 'mitmdump', 'sslstrip', 'sslstrip2', 'dns2proxy', 'dnschef',
  'mimikatz', 'powersploit', 'empire', 'cobaltstrike', 'meterpreter', 'beacon', 'psexec', 'wmiexec', 'smbexec', 'pth-winexe', 'secretsdump', 'wce', 'mimipenguin',
  'autopsy', 'sleuthkit', 'volatility', 'memdump', 'dd', 'dcfldd', 'dc3dd', 'guymager', 'foremost', 'scalpel', 'photorec', 'testdisk', 'extundelete', 'ext4magic',
  'dradis', 'faraday', 'pipal', 'magic-tree', 'keepnote', 'cherrytree', 'joplin', 'tiddlywiki', 'mediawiki', 'dokuwiki',
  'social-engineer-toolkit', 'setoolkit', 'beef-xss', 'phishing-frenzy', 'king-phisher', 'gophish', 'evilginx2', 'credphish', 'phishery',
  'ghidra', 'radare2', 'r2', 'ida', 'x64dbg', 'ollydbg', 'gdb', 'objdump', 'readelf', 'strings', 'hexdump', 'xxd', 'file', 'binwalk', 'upx', 'peid',
  'arduino', 'avrdude', 'busybox', 'minicom', 'screen', 'putty', 'teraterm', 'securecrt', 'kermit', 'picocom', 'gtkterm', 'cutecom',
  'apktool', 'dex2jar', 'jd-gui', 'jadx', 'androguard', 'androlyze', 'mobsf', 'drozer', 'objection', 'frida', 'jadx-gui', 'bytecode-viewer',
  'firmwalker', 'binwalk', 'firmware-mod-kit', 'firmware-analysis-toolkit', 'qemu', 'gdb-multiarch', 'r2', 'ghidra', 'ida', 'angr', 'unicorn',
  'pacu', 'cloudsploit', 'scoutsuite', 'cloudmapper', 'awscli', 'gcloud', 'az', 'terraform', 'ansible', 'chef', 'puppet', 'salt',
  'docker', 'docker-compose', 'kubectl', 'helm', 'rancher', 'trivy', 'clair', 'anchore', 'snyk', 'falco', 'opa', 'gatekeeper',
  'snort', 'suricata', 'bro', 'zeek', 'moloch', 'arkime', 'elasticsearch', 'kibana', 'logstash', 'beats', 'graylog', 'splunk',
  'dirsearch', 'gospider', 'hakrawler', 'waybackurls', 'gau', 'httpx', 'httprobe', 'subjack', 'subzy', 'tko-subs', 'corstest', 'corsy'
];

// Helper: Load recent context from log file
function loadRecentContext() {
  const logPath = path.join(require('os').homedir(), '.ai_cli_log');
  if (fs.existsSync(logPath)) {
    const logContent = fs.readFileSync(logPath, 'utf-8');
    if (logContent.trim().length > 0) {
      const lines = logContent.trim().split('\n');
      return lines.slice(-30).join('\n');
    }
  }
  return '';
}

// Main command execution
async function executeCommand(instruction, options = {}) {
  const startTime = Date.now();
  
  try {
    // Parse user intent
    const intent = parseUserIntent(instruction);
    
    // Handle conversational requests
    if (intent.isConversational) {
      console.log(chalk.cyan('🤖 AI Assistant:'));
      if (instruction.toLowerCase().includes('hello') || instruction.toLowerCase().includes('hi') || instruction.toLowerCase().includes('hey')) {
        console.log(chalk.green('Hello! I\'m your AI assistant. I can help you with:'));
        console.log(chalk.yellow('• Converting natural language to shell commands'));
        console.log(chalk.yellow('• Network scanning and security tools'));
        console.log(chalk.yellow('• System administration tasks'));
        console.log(chalk.yellow('• File and directory operations'));
        console.log(chalk.yellow('• And much more!'));
        console.log(chalk.blue('\nJust tell me what you want to do, and I\'ll help you get it done!'));
      } else if (instruction.toLowerCase().includes('help') || instruction.toLowerCase().includes('what can you do')) {
        console.log(chalk.green('I can help you with various tasks:'));
        console.log(chalk.yellow('• System commands: "show me running processes"'));
        console.log(chalk.yellow('• Network scanning: "scan my network"'));
        console.log(chalk.yellow('• File operations: "find all text files"'));
        console.log(chalk.yellow('• Security tools: "check for vulnerabilities"'));
        console.log(chalk.yellow('• And much more!'));
        console.log(chalk.blue('\nUse "ai chat" for interactive mode, or just tell me what you need!'));
      } else if (instruction.toLowerCase().includes('thank')) {
        console.log(chalk.green('You\'re welcome! Happy to help! 😊'));
      } else if (instruction.toLowerCase().includes('bye') || instruction.toLowerCase().includes('goodbye')) {
        console.log(chalk.green('Goodbye! Have a great day! 👋'));
      } else {
        console.log(chalk.green('Hello! I\'m here to help you with your tasks. What would you like to do?'));
      }
      return;
    }
    
    // Check API key
    const apiKey = process.env.MISTRAL_API_KEY;
    if (!apiKey) {
      console.error(chalk.red('Error: Please set your MISTRAL_API_KEY environment variable.'));
      process.exit(1);
    }
    // Validate API key format
    if (apiKey.length < 10) {
      console.error(chalk.red('Error: MISTRAL_API_KEY appears to be too short. Please check your API key.'));
      process.exit(1);
    }
    console.log(chalk.blue('🔑 API Key found, attempting API call...'));
    
    // Load recent context
    const recentContext = loadRecentContext();
    
    // Build system prompt
    let systemPrompt = `You are an AI assistant that converts natural language instructions into shell commands. 
    
    IMPORTANT RULES:
    1. ONLY respond with the shell command, no explanations or markdown
    2. Use simple, safe commands that work on Linux
    3. Avoid complex regex patterns that might cause shell errors
    4. For network scanning, prefer simple commands like 'nmap -sn' or 'arp-scan'
    5. If unsure, use basic commands like 'ls', 'ps', 'df', etc.
    
    Recent commands for context:
    ${recentContext}
    
    Convert this instruction to a shell command: "${instruction}"`;
    
    // Enhanced system prompt for intelligent processing
    if (intent.isComplex) {
      systemPrompt = systemPrompt.replace('single Linux shell command', 'multiple Linux shell commands separated by newlines. Each command should be on its own line. For complex tasks, break them into steps. Use command substitution $(command) or variables to pass data between commands. Consider using multiple tools if needed.');
    }
    
    // Add specific instructions for network scanning
    if (instruction.toLowerCase().includes('network') || instruction.toLowerCase().includes('scan')) {
      systemPrompt += '\n\nNETWORK SCANNING: For network scanning, use these simple commands:\n- nmap -sn 192.168.1.0/24 (ping scan)\n- arp-scan --localnet (ARP scan)\n- netdiscover -r 192.168.1.0/24 (network discovery)\n- ip neigh show (show ARP table)\n- arp -a (show ARP entries)\n\nIMPORTANT: DO NOT use complex regex patterns like grep -Eo or grep -oP. Use simple commands that work reliably.';
    }
    
    // Add specific instructions for vulnerability scanning
    if (instruction.toLowerCase().includes('vulnerability') || instruction.toLowerCase().includes('vuln')) {
      systemPrompt += '\n\nVULNERABILITY SCANNING: For vulnerability scanning, use these commands:\n- nmap -sV -p [PORT] [IP] (version detection)\n- nmap --script vuln [IP] (vulnerability scripts)\n- nikto -h [IP] (web vulnerability scanner)\n- sqlmap -u [URL] (SQL injection)\n- dirb [URL] (directory brute force)\n\nUse specific IP addresses and ports. Avoid overly specific grep patterns.';
    }
    
    // Add specific instructions for port scanning
    if (instruction.toLowerCase().includes('port') || instruction.toLowerCase().includes('ports')) {
      systemPrompt += '\n\nPORT SCANNING: For port scanning, use these commands:\n- nmap -p [PORT] [IP] (specific port)\n- nmap -p1-1000 [IP] (port range)\n- nmap -sS [IP] (SYN scan)\n- nmap -sV [IP] (version detection)\n\nUse specific IP addresses. Separate multiple commands with semicolons, not &&.';
    }
    
    // Add format instructions
    if (intent.format !== 'default') {
      systemPrompt += `\n\nIMPORTANT: Format the output as ${intent.format.toUpperCase()}. Use appropriate tools like jq for JSON, column for tables, or sed/awk for clean formatting.`;
    }
    
    // Add human-readable formatting instructions
    systemPrompt += '\n\nOUTPUT FORMATTING: Always generate commands that produce human-readable output. Use tools like:\n- column -t (for table formatting)\n- sed/awk (for clean text processing)\n- sort | uniq (for unique results)\n- head/tail (for limiting output)';
    
    // Add tool suggestions
    if (intent.tools.length > 0) {
      const suggestedTools = intent.tools.map(tool => selectBestTool(tool)).flat();
      systemPrompt += `\n\nSUGGESTED TOOLS: Consider using ${suggestedTools.join(', ')} for this task.`;
    }
    
    const mcpPrompt = [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: instruction }
    ];
    
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
    const hasIncompleteRegex = l => l.includes('grep -Eo') && !l.includes("'") || l.includes('grep -oP') && !l.includes("'") || l.includes('grep -E') && l.split("'").length % 2 === 0;
    
    if (codeBlockMatch) {
      // Take the first non-empty, valid shell command line from the code block
      commandToRun = codeBlockMatch[1].split('\n').map(l => l.trim()).filter(isValidShellCommand)[0] || '';
      // Remove explanations/comments after # or (
      if (commandToRun.includes('#')) commandToRun = commandToRun.split('#')[0].trim();
      if (commandToRun.includes('(')) commandToRun = commandToRun.split('(')[0].trim();
      // Check for incomplete regex and reject the command
      if (hasIncompleteRegex(commandToRun)) {
        commandToRun = '';
      }
    } else {
      // Remove backticks and take the first non-empty, valid shell command line
      const lines = reply.replace(/`/g, '').split('\n').map(l => l.trim()).filter(isValidShellCommand);
      commandToRun = lines[0] || '';
      // Remove explanations/comments after # or (
      if (commandToRun.includes('#')) commandToRun = commandToRun.split('#')[0].trim();
      if (commandToRun.includes('(')) commandToRun = commandToRun.split('(')[0].trim();
      // Check for incomplete regex and reject the command
      if (hasIncompleteRegex(commandToRun)) {
        commandToRun = '';
      }
    }
    
    if (!commandToRun) {
      console.log(chalk.red('No valid shell command found in the AI response.'));
      console.log(chalk.yellow('AI raw response:'), reply);
      
      // Fallback: try to extract a line containing a common shell command
      let fallbackLine = reply.split('\n').map(l => l.trim()).find(l => FALLBACK_COMMANDS.some(cmd => l.startsWith(cmd + ' ')));
      
      // Fallback 2: look for a command inside backticks
      if (!fallbackLine) {
        const backtickMatches = reply.match(/`([^`]+)`/g);
        if (backtickMatches) {
          fallbackLine = backtickMatches.map(s => s.replace(/`/g, '').trim()).find(l => FALLBACK_COMMANDS.some(cmd => l.startsWith(cmd + ' ')));
        }
      }
      
      // Fallback 3: Use specific network scanning commands if network/scan keywords detected
      if (!fallbackLine && (instruction.toLowerCase().includes('network') || instruction.toLowerCase().includes('scan') || instruction.toLowerCase().includes('ip'))) {
        const networkCommands = [
          'nmap -sn 192.168.1.0/24',
          'arp-scan --localnet',
          'netdiscover -r 192.168.1.0/24',
          'ip neigh show',
          'arp -a'
        ];
        fallbackLine = networkCommands[0]; // Use the first reliable command
        console.log(chalk.magenta('Using fallback network scan command'));
      }
      
      // Fallback 4: Use specific vulnerability scanning commands
      if (!fallbackLine && (instruction.toLowerCase().includes('vulnerability') || instruction.toLowerCase().includes('vuln'))) {
        const vulnCommands = [
          'nmap -sV 192.168.1.1',
          'nmap --script vuln 192.168.1.1',
          'nikto -h 192.168.1.1',
          'dirb http://192.168.1.1'
        ];
        fallbackLine = vulnCommands[0]; // Use the first reliable command
        console.log(chalk.magenta('Using fallback vulnerability scan command'));
      }
      
      // Fallback 5: Use specific port scanning commands
      if (!fallbackLine && (instruction.toLowerCase().includes('port') || instruction.toLowerCase().includes('ports'))) {
        const portCommands = [
          'nmap -p 21,22,23,25,53,80,110,143,443,993,995 192.168.1.1',
          'nmap -p1-1000 192.168.1.1',
          'nmap -sS 192.168.1.1'
        ];
        fallbackLine = portCommands[0]; // Use the first reliable command
        console.log(chalk.magenta('Using fallback port scan command'));
      }
      
      if (fallbackLine) {
        let fallbackCommand = fallbackLine;
        if (fallbackCommand.includes('#')) fallbackCommand = fallbackCommand.split('#')[0].trim();
        if (fallbackCommand.includes('(')) fallbackCommand = fallbackCommand.split('(')[0].trim();
        console.log(chalk.magenta('Fallback: Executing command:'), chalk.cyan(fallbackCommand));
        
        const logPath = path.join(require('os').homedir(), '.ai_cli_log');
        exec(fallbackCommand, (error, stdout, stderr) => {
          let logEntry = `\n> Instruction: ${instruction}\n> Command: ${fallbackCommand}\n> Output:\n${stdout || stderr || error?.message || ''}`;
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
    
    const logPath = path.join(require('os').homedir(), '.ai_cli_log');
    exec(commandToRun, (error, stdout, stderr) => {
      // Log the instruction, command, and output to the log file
      let logEntry = `\n> Instruction: ${instruction}\n> Command: ${commandToRun}\n> Output:\n${stdout || stderr || error?.message || ''}`;
      fs.appendFileSync(logPath, logEntry);
      
      if (error) {
        console.log(chalk.red('Command error:'), chalk.yellow(stderr || error.message));
        // Try fallback tools if available
        if (intent.tools.length > 0) {
          console.log(chalk.yellow('Trying alternative tools...'));
          const fallbackCommands = intent.tools.map(tool => selectBestTool(tool)).flat();
          // Generate fallback command using different tool
          const fallbackPrompt = `Use ${fallbackCommands[0]} instead to ${instruction}`;
          // You could implement recursive fallback here
        }
      } else {
        // Format output based on user intent
        const formattedOutput = formatOutput(stdout, intent.format);
        
        // Check if output looks like a list and format as table
        const lines = stdout.trim().split('\n').filter(line => line.trim());
        if (lines.length > 1 && (instruction.toLowerCase().includes('network') || instruction.toLowerCase().includes('scan') || instruction.toLowerCase().includes('list') || instruction.toLowerCase().includes('port'))) {
          console.log(chalk.cyan('Command output:'));
          // Check if this looks like port scan output
          const isPortScanOutput = lines.some(line => line.includes('PORT') && line.includes('STATE') && line.includes('SERVICE')) || 
                                  lines.some(line => line.includes('open') && line.includes('tcp')) ||
                                  lines.some(line => line.includes('Nmap scan report'));
          
          if (isPortScanOutput) {
            console.log(chalk.green('🔍 Port Scan Results:'));
            // Find the table header and data
            const headerIndex = lines.findIndex(line => line.includes('PORT') && line.includes('STATE'));
            if (headerIndex !== -1) {
              const header = lines[headerIndex];
              const dataLines = lines.slice(headerIndex + 1).filter(line => line.includes('/tcp') || line.includes('/udp'));
              
              if (dataLines.length > 0) {
                console.log(chalk.yellow('📊 Open Ports:'));
                dataLines.forEach((line, index) => {
                  const parts = line.trim().split(/\s+/);
                  if (parts.length >= 3) {
                    console.log(chalk.green(`${index + 1}. Port ${parts[0]} (${parts[2]}) - ${parts[1]}`));
                  }
                });
              } else {
                console.log(chalk.yellow('No open ports found'));
              }
            } else {
              // Fallback to simple list
              lines.forEach((line, index) => {
                if (line.includes('open') || line.includes('filtered')) {
                  console.log(chalk.green(`${index + 1}. ${line.trim()}`));
                }
              });
            }
          } else {
            // Try to format as table if it looks like structured data
            if (lines[0].includes(' ') && lines.length > 2) {
              try {
                const tableData = lines.map((line, index) => {
                  const parts = line.trim().split(/\s+/);
                  if (index === 0) {
                    // Header row
                    return parts.reduce((obj, part, i) => {
                      obj[`col${i}`] = part;
                      return obj;
                    }, {});
                  } else {
                    // Data row
                    return parts.reduce((obj, part, i) => {
                      obj[`col${i}`] = part;
                      return obj;
                    }, {});
                  }
                });
                console.table(tableData);
              } catch (e) {
                console.log(chalk.green(formattedOutput));
              }
            } else {
              // Simple list format
              console.log(chalk.green('📋 Results:'));
              lines.forEach((line, index) => {
                console.log(chalk.green(`${index + 1}. ${line.trim()}`));
              });
            }
          }
        } else {
          console.log(chalk.cyan('Command output:'), chalk.green(formattedOutput));
        }
        
        // Additional intelligent processing
        if (intent.format === 'json' && stdout.trim()) {
          console.log(chalk.blue('💡 Tip: Use jq for advanced JSON processing'));
        }
        if (intent.format === 'table' && stdout.includes(' ')) {
          console.log(chalk.blue('💡 Tip: Use column -t for better table formatting'));
        }
        if (lines.length > 5) {
          console.log(chalk.blue(`💡 Found ${lines.length} results. Use 'head -10' or 'tail -10' to limit output.`));
        }
      }
    });
    
  } catch (err) {
    console.error(chalk.red('API Error:'));
    if (err.response) {
      console.error(chalk.yellow(`Status: ${err.response.status}`));
      console.error(chalk.yellow(`Data: ${JSON.stringify(err.response.data, null, 2)}`));
    } else if (err.request) {
      console.error(chalk.yellow('No response received from API'));
      console.error(chalk.yellow(`Request error: ${err.message}`));
    } else {
      console.error(chalk.yellow(`Error: ${err.message}`));
    }
    console.error(chalk.blue('💡 Check your MISTRAL_API_KEY environment variable'));
  }
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
    // Validate API key format
    if (apiKey.length < 10) {
      console.error(chalk.red('Error: MISTRAL_API_KEY appears to be too short. Please check your API key.'));
      process.exit(1);
    }
    console.log(chalk.blue('🔑 API Key found, attempting API call...'));
    const mcpPrompt = formatMCPPrompt(options.system, prompt);
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
      console.log(chalk.green(response.data.choices[0].message.content));
    } catch (err) {
      console.error(chalk.red('API Error:'));
      if (err.response) {
        console.error(chalk.yellow(`Status: ${err.response.status}`));
        console.error(chalk.yellow(`Data: ${JSON.stringify(err.response.data, null, 2)}`));
      } else if (err.request) {
        console.error(chalk.yellow('No response received from API'));
        console.error(chalk.yellow(`Request error: ${err.message}`));
      } else {
        console.error(chalk.yellow(`Error: ${err.message}`));
      }
      console.error(chalk.blue('💡 Check your MISTRAL_API_KEY environment variable'));
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
      console.log(chalk.cyan('Command output:'), chalk.green(stdout));
    });
  });

// Command: Interactive chat with Mistral AI and system command execution
program
  .command('chat')
  .description('Start an interactive chat with Mistral AI (with system command execution)')
  .option('-s, --system <system>', 'System context', 'You are a helpful assistant. You have full access to the user\'s Linux system. Be conversational and friendly. Only suggest shell commands when the user explicitly asks for system information or actions. For casual conversation, just respond naturally. If you need to run a command, put it in a code block. The OS is: ' + os.type() + ' ' + os.platform() + ' ' + os.release() + '.')
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
    console.log(chalk.blue('💡 Tip: Just chat naturally! Commands will only run if you explicitly ask for system info.'));
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
            console.log(chalk.magenta(`🔧 Executing command: ${commandToRun}`));
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
            console.log(chalk.green('🤖 Assistant:'), chalk.green(reply));
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

// Default/fallback command: treat any unknown command as a natural language instruction
program
  .arguments('<instruction...>')
  .description('Give a natural language instruction, get it executed as a shell command')
  .action(async (instruction) => {
    const userInstruction = instruction.join(' ');
    
    // Parse user intent first
    const intent = parseUserIntent(userInstruction);
    
    // Handle conversational requests
    if (intent.isConversational) {
      console.log(chalk.cyan('🤖 AI Assistant:'));
      if (userInstruction.toLowerCase().includes('hello') || userInstruction.toLowerCase().includes('hi') || userInstruction.toLowerCase().includes('hey')) {
        console.log(chalk.green('Hello! I\'m your AI assistant. I can help you with:'));
        console.log(chalk.yellow('• Converting natural language to shell commands'));
        console.log(chalk.yellow('• Network scanning and security tools'));
        console.log(chalk.yellow('• System administration tasks'));
        console.log(chalk.yellow('• File and directory operations'));
        console.log(chalk.yellow('• And much more!'));
        console.log(chalk.blue('\nJust tell me what you want to do, and I\'ll help you get it done!'));
      } else if (userInstruction.toLowerCase().includes('help') || userInstruction.toLowerCase().includes('what can you do')) {
        console.log(chalk.green('I can help you with various tasks:'));
        console.log(chalk.yellow('• System commands: "show me running processes"'));
        console.log(chalk.yellow('• Network scanning: "scan my network"'));
        console.log(chalk.yellow('• File operations: "find all text files"'));
        console.log(chalk.yellow('• Security tools: "check for vulnerabilities"'));
        console.log(chalk.yellow('• And much more!'));
        console.log(chalk.blue('\nUse "ai chat" for interactive mode, or just tell me what you need!'));
      } else if (userInstruction.toLowerCase().includes('thank')) {
        console.log(chalk.green('You\'re welcome! Happy to help! 😊'));
      } else if (userInstruction.toLowerCase().includes('bye') || userInstruction.toLowerCase().includes('goodbye')) {
        console.log(chalk.green('Goodbye! Have a great day! 👋'));
      } else {
        console.log(chalk.green('Hello! I\'m here to help you with your tasks. What would you like to do?'));
      }
      return;
    }
    
    // Execute the command using the existing executeCommand function
    await executeCommand(userInstruction);
  });

program.parse(process.argv);
