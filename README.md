# BFFUF ( Burp Extension for FFUF @ffuf )

BFFUF is an extension for Burp Suite that allows you to configure and run FFUF (Fuzz Faster U Fool) directly from Burp. This extension provides a graphical interface to set various FFUF options, save request configurations, and perform fuzzing attacks directly from the tool.


# IMPORTANT 

- BETA VERSION!
- Sniper mode only work if you choose the proto flag!!! 🚨

## Features

- Configure wordlists for different fuzzing markers.
- Support for fuzzing modes: Cluster Bomb, Pitchfork, and Sniper.
- Additional options such as follow redirects, silent mode, verbose mode, and more.
- Save and load configurations in TOML format.
- Execute FFUF in a terminal with specified configurations.

## Installation

> Requires OpenJDK >= 21

```bash
# linux users
sudo apt install openjdk-21-jdk
# OSX With Brew
brew install openjdk@21
```

1. Compile the source code and generate a JAR file.
2. In Burp Suite, go to the `Extender` tab and select `Add`.
3. Choose the generated JAR file and add the extension.

### Pocs

- Main Window
![](/static/config_main.png)

- Repeater exec
![](/static/exec_repeater.png)

- Intruder Exec
![](/static/exec_intruder.png)

- Config
![](/static/configuration_terminal_request.png)

- PRO Version ONLY 💸 ( Issue scan finished )

![](/static/image.png)


### Configuration

1. In the `BFFFUF Config` tab, configure the wordlists for the fuzzing markers (FUZZ1, FUZZ2, FUZZ3, FUZZ4, SNIPER).
2. Set other options as needed, such as follow redirects, verbose mode, etc.
3. Click the `Save` button to save the configuration.

### Execution

1. Select the request you want to use for fuzzing.
2. Right-click to open the context menu and select `bfffuf`.
3. Choose the desired fuzzing mode: `Cluster Bomb`, `Pitchfork`, or `Sniper`.
4. The extension will save the request and run FFUF with the specified configurations.

#### Usage
1. `Cluster Bomb` and `Pitchfork` you can set the FUZZ1 and FUZZ2 .. FUZZ4 wordlist write at the repeater example:

```http
GET /FUZZ1?id=FUZZ2 HTTP/1.1
Host: foo
```

2. Sniper mode, only work you if set request at the main menu and write at the request the placeholder SNIPER

```http
GET /SNIPER HTTP/1.1
Host: foo
```

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
```


## Videos

![Config](/static/config_bffuf.gif)

![Running](/static/running.gif)

![WordLists](/static/multipleWordLists.gif)
