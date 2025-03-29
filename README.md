
<div align="center">

<h3>
  <b>

  🔍 <kbd>[**Jadu**](https://github.com/Karthik-HR0/jadu)</kbd>

<kbd> V 1.0</kbd>
  </b>
</h3>

<h6>Uncover hidden secrets in JavaScript files with magical precision</h6>


<h6 align="center">
  Jadu (meaning "magic" in Hindi) is a powerful secret scanner that detects exposed credentials, API keys, and sensitive information in JavaScript files. With advanced pattern matching and concurrent scanning, Jadu helps security researchers and bug bounty hunters identify vulnerabilities before they can be exploited.
</h6>

</div>

<br>
<br>
<br>

> [!Important]
> **_Jadu is designed for security research. Always verify results manually and follow responsible disclosure practices!_**

<br>
<br>
<br>

<h1 align="center">

  <kbd> Features </kbd>

</h1>

<div align="center">

| Category              | Core Capabilities                                  | Advanced Functionality                              | Intelligent Automation                               |
|-----------------------|----------------------------------------------------|---------------------------------------------------|---------------------------------------------------|
| **Secret Detection** | • _`15+ Built-in Patterns`_ <br>• _`AWS/GitHub/Google API Keys`_ | • _`Custom Regex Support`_ <br>• _`Duplicate Filtering`_ | • _`Automatic Severity Classification`_ <br>• _`Multi-pattern Scanning`_ |
| **Performance**   | • _`Concurrent Scanning`_ <br>• _`Adjustable Thread Count`_ | • _`HTTP Client Customization`_ <br>• _`Cookie Support`_ | • _`Efficient Memory Management`_ <br>• _`Stream Processing`_ |
| **Usability**        | • _`Color-coded Output`_ <br>• _`Detailed/Silent Modes`_ | • _`Version Checking`_ <br>• _`Pattern Documentation`_ | • _`Contextual Line Numbers`_ <br>• _`Smart Pattern Highlighting`_ |
| **Extensibility**      | • _`Modular Pattern System`_ <br>• _`Go-based Architecture`_ | • _`Easy Pattern Updates`_ <br>• _`Custom User-Agents`_ | • _`Continuous Updates`_ <br>• _`Community Pattern Contributions`_ |

</div>
<br>
<br>

<h6 align="center">Installation</h6>

```bash
git clone https://github.com/Karthik-HR0/jadu
cd jadu
go build -o jadu
sudo mv jadu /usr/local/bin/
```

<br>
<br>
<details>
<summary> <h6 align="center">
  Built-in Detection Patterns :↓
</h6> </summary>
<h6 align="center">
  AVAILABLE SECRET PATTERNS 
</h6>

• AWS Access Keys • Google API Keys • GitHub Tokens • Slack Tokens • Basic Auth Credentials • Generic SHA-1 Keys • And more...

<br>
<br>
<br>

<h6 align="center">
  Example Commands
</h6>


```bash
cat urls.txt | jadu -t 100 -d
# Scan with 100 threads and detailed output
```

<div align="center">
<kbd>TO SHOW ALL PATTERNS:</kbd>
</div>

<br>

```bash
jadu -show-patterns
```

<div align="center">
<kbd>FOR HELP:</kbd>
</div>


<br>

```bash
jadu -h

```
<div align="center">
<kbd> SAMPLE OUTPUT</kbd>

``` 
[+] https://example.com/file.js [ AWS Access Key ID ] [ AKIA1234567890ABCDEF ]
[+] https://example.com/app.js [ GitHub Personal Access Token ] [ ghp_AbCdEfGhIjKlMnOpQrStUvWxYz12345678 ]
[!] https://example.com/config.js [ Google API Key ] [ AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz123456789 ]

```

<div align="center">
<kbd> SENSITIVE MODE OUTPUT</kbd>

```
jadu -sen

[!] https://example.com/keys.js [ Google API Key ] [ AIzaSyAbCdEfGhIjKlMnOpQrStUvWxYz123456789 ]
[!] https://example.com/config.json [ AWS Secret Key ] [ wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY ]

```

</div>

<br>
