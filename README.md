# BFFFUF ( Burp Extension for FFUF @ffuf )

BFFFUF is an extension for Burp Suite that allows you to configure and run FFUF (Fuzz Faster U Fool) directly from Burp. This extension provides a graphical interface to set various FFUF options, save request configurations, and perform fuzzing attacks directly from the tool.

## Features

- Configure wordlists for different fuzzing markers.
- Support for fuzzing modes: Cluster Bomb, Pitchfork, and Sniper.
- Additional options such as follow redirects, silent mode, verbose mode, and more.
- Save and load configurations in TOML format.
- Execute FFUF in a terminal with specified configurations.

## Installation

1. Compile the source code and generate a JAR file.
2. In Burp Suite, go to the `Extender` tab and select `Add`.
3. Choose the generated JAR file and add the extension.

## Usage

### Configuration

1. In the `BFFFUF Config` tab, configure the wordlists for the fuzzing markers (FUZZ1, FUZZ2, FUZZ3, FUZZ4, SNIPER).
2. Set other options as needed, such as follow redirects, verbose mode, etc.
3. Click the `Save` button to save the configuration.

### Execution

1. Select the request you want to use for fuzzing.
2. Right-click to open the context menu and select `bfffuf`.
3. Choose the desired fuzzing mode: `Cluster Bomb`, `Pitchfork`, or `Sniper`.
4. The extension will save the request and run FFUF with the specified configurations.

## Dependencies

- Burp Suite
- FFUF (Fuzz Faster U Fool)
- TOML library for Java (`com.moandjiezana.toml.Toml`)

## Configuration Example

The configuration is saved at `${HOME}/.config/bffuf/bffuf.config.toml`. An example TOML configuration is:

```toml
wordlist1 = "/path/to/wordlist1.txt"
wordlist2 = "/path/to/wordlist2.txt"
wordlist3 = "/path/to/wordlist3.txt"
wordlist4 = "/path/to/wordlist4.txt"
sniperWordlist = "/path/to/sniperWordlist.txt"
