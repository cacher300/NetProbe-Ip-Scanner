# IP Scanner

An IP Scanner tool that scans both local and public IP addresses, storing all the data in a SQL database. The scanner provides useful information such as:

- IP Address
- Ports Open
- Name
- Type
- Info
- MAC Address
- Status

## Features

- Scans local and public IP addresses.
- Provides detailed information for each IP.
- Stores data in a SQL database.
- Contains a built-in database of public IPs.

## Table of Contents

1. [Installation](#installation)
2. [Usage](#usage)
3. [Configuration](#configuration)
4. [Database Schema](#database-schema)
5. [License](#license)

## Installation

### Requirements

- Python 3.6+
- SQLAlchemy
- Your preferred SQL database engine (e.g., MySQL, PostgreSQL, SQLite)

### Installing

Clone the repository:

\`\`\`bash
git clone https://github.com/username/ip-scanner.git
\`\`\`

Navigate to the project directory:

\`\`\`bash
cd ip-scanner
\`\`\`

Install dependencies:

\`\`\`bash
pip install -r requirements.txt
\`\`\`

## Usage

To start the IP scanner, run:

\`\`\`bash
python ip_scanner.py
\`\`\`

You can customize the scanning parameters through the configuration file.

### Command Line Arguments

You can also use command-line arguments to control the scanning process:

\`\`\`bash
python ip_scanner.py --target TARGET --scan-type TYPE
\`\`\`

Available arguments:

- \`--target\`: Specify the target IP or range.
- \`--scan-type\`: Specify the type of scan (\`local\` or \`public\`).

## Configuration

The configuration file \`config.yaml\` allows you to customize the scanner's behavior. Key configuration options include:

- \`database_url\`: The URL of the SQL database.
- \`scan_interval\`: The interval between scans.
- \`public_ips\`: A list of public IP addresses to scan.

## Database Schema

The scanner stores its results in a SQL database with the following schema:

| Column Name    | Data Type | Description                  |
|----------------|-----------|------------------------------|
| id             | INT       | Primary key                  |
| ip_address     | VARCHAR   | The IP address               |
| ports_open     | TEXT      | List of open ports           |
| name           | VARCHAR   | Name associated with the IP  |
| type           | VARCHAR   | Type of the IP (local/public)|
| info           | TEXT      | Additional information       |
| mac_address    | VARCHAR   | The MAC address              |
| status         | VARCHAR   | Status of the IP             |

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
