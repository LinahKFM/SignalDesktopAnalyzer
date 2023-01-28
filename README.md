# Signal Desktop Analyzer

An add-on ingest module to [Autopsy Digital Forensics Platform](http://www.autopsy.com).

## Functionalities

* Decrypts Signal's SQLite database (encrypted with SQLCipher4).
* Parses the database and extracts **contacts**, **messages with attachments** and **call logs**.
* Decrypts the SQLite temporary file WAL (.sqlite-wal) and recovers **recently deleted messages**.

## Dependencies 

Autopsy 4.19.3 for Windows.

## Installation

* Download the directory **SignalDesktopAnalyzer**.

* Place it in Autopsy's python_modules folder. Further details are provided [here](http://sleuthkit.org/autopsy/docs/user-docs/4.19.3//module_install_page.html).