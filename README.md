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

- Repeater exec
![](/static/exec_repeater.png)

- Intruder Exec
![](/static/exec_intruder.png)

- Config
![](/static/configuration_terminal_request.png)


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
```


## Videos

[![Config Video multi wordlists](https://i.pinimg.com/736x/96/28/28/9628288cf4023b3b5dc553421f8507cf.jpg)](https://github.com/rodnt/bffuf/raw/main/static/multipleWordLists.mov)

[![Config](https://i.pinimg.com/736x/96/28/28/9628288cf4023b3b5dc553421f8507cf.jpg)](https://github.com/rodnt/bffuf/raw/main/static/config_bffuf.mov)

[![Running video](https://i.pinimg.com/736x/96/28/28/9628288cf4023b3b5dc553421f8507cf.jpg)](https://github.com/rodnt/bffuf/blob/main/static/running.mov)
