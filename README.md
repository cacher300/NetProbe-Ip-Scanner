# IP Scanner

An IP Scanner tool that scans both local and public IP addresses, storing all the data in a SQL database. The scanner provides useful information such as:

- IP Address
- Ports Open
- Name
- Type
- Helpful Info
- MAC Address
- Status

## Features

- Scans local and public IP addresses.
- Provides detailed information for each IP.
- Stores data in a SQL database.
- Contains a built-in database of public IPs sorted by country.
- Web GUI

![image](https://github.com/cacher300/ip-scanner/assets/77995433/92c40bd1-3a7b-44d6-88f6-f5c93f25edf7)

![image](https://github.com/cacher300/ip-scanner/assets/77995433/68c7c1ef-d621-4f1a-af83-b14ad4efca19)

![image](https://github.com/cacher300/ip-scanner/assets/77995433/f7eaea65-e7ea-4ac4-8daa-f68b01ecd8c1)

## Table of Contents

1. [Installation](#installation)
2. [Usage](#usage)
4. [Database Schema](#database-schema)
5. [License](#license)

## Installation

### Requirements

- Python
- Windows

### Installing

Clone the repository:

```bash
git clone https://github.com/username/ip-scanner.git
```

Navigate to the project directory:

```bash
cd ip-scanner
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Usage

To start the IP scanner, run:

```bash
python main.py
```
Than open http://127.0.0.1:5000/ in your prefered browser

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
