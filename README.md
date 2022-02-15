# kommen-server
A next generation secure remote administration server.

### Architecture
The kommen architecture consists of [n] components:

   * kommen - a CLI interface to the server
   * kommen-server - a Flask server
   * handlers - a set of handlers encapsulating kommen functionality.
        * client - 
        * database - 
        * firewall - 
        * registration -

### Installation

#### Prerequisites

You will need the following packages to install the required Python modules later:

  `python3-dev`  

You need this repo and then the `kommen-shared`.


#### Database

If you want to create a fresh sqlite3 database yourself, use:
   CREATE TABLE "client" (
	"id"	INTEGER NOT NULL,
	"name"	TEXT NOT NULL UNIQUE,
	"status"	INTEGER NOT NULL,
	"sym_key"	TEXT NOT NULL UNIQUE,
	"pub_key"	TEXT NOT NULL UNIQUE,
	"priv_key"	TEXT NOT NULL UNIQUE,
	"client_id"	TEXT NOT NULL UNIQUE,
	"count"	INTEGER NOT NULL,
	PRIMARY KEY("id" AUTOINCREMENT)
);

#### Dependencies

### Usage 

#### Commands

#### Daemonize the server

1. Create a shell script
    >#!/bin/bash
    >#flask settings
    >export FLASK_APP=/kommen-server/kommen_server.py
    >export FLASK_DEBUG=0
    >
    >flask run --host=0.0.0.0 --port=80"""

2. Make the script executable with `chmod +x path/to/script.sh`

3. Create a `systemd` service in `/etc/systemd/system/` as:

    >[Unit]
    >Description = a secure remote administration server in Flask
    > 
    >[Service]
    >ExecStart = path/to/script.sh
    >
    >[Install]
    >WantedBy = multi-user.target

4. Finally, add the daemon to boot using `systemctl enable kommen_server.py`

### Testing
