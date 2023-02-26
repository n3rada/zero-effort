zero-effort
===========
```text
                                000000000                                  
                              00:::::::::00                          
                    __  __   00:::::::::::::00         _   
                  /  _|/ _| 0:::::::000:::::::0       | |  
               ___| |_| |_  0::::::0   0::::::0   _ __| |_ 
              / _ \  _|  _| 0:::::0     0:::::0  | '__| __|
             |  __/ | | |   0:::::0 000 0:::::0  | |  | |_ 
              \___|_| |_|   0:::::0     0:::::0  |_|   \__|
                     _      0:::::0     0:::::0    
                    | |     0::::::0   0::::::0   __ _  ___  _ __ 
                    | |     0:::::::000:::::::0  / _` |/ _ \| '_ \ 
                    | |      00:::::::::::::00  | (_| | (_) | | | |
                    | |____    00:::::::::00     \__, |\___/|_| |_|     
                    |______|     000000000       __/ |           
                               CVE-2020-1472    |___/ 
```

Improved version on steroids allowing to exploit [CVE-2020-1472](https://www.secura.com/uploads/whitepapers/Zerologon.pdf) vulnerability (a.k.a Zerologon) without effort. It combines the strenght of [Impacket](https://github.com/fortra/impacket) and automatically connects to the target machine through either [Evil-WinRM](https://github.com/Hackplayers/evil-winrm) or [WMI](https://learn.microsoft.com/en-us/windows/win32/wmisdk/wmi-tasks--processes) semi-interactive shell.

Mainly made to simplify the quick exploitation of this vulnerability. You are free to make a Pull Request or open an issue if you want to add something.

# Zerolo-what?
By simply sending a number of Netlogon messages in which various fields are filled with zeroes, an attacker can change the computer password of the domain controller that is stored in the AD. This can then be used to obtain domain admin credentials and then restore the original DC password. This attack has a huge impact: it basically allows any attacker on the local network (such as a malicious insider or someone who simply plugged in a device to an on-premise network port) to completely compromise the Windows domain. The attack is completely unauthenticated: the attacker does not need any user credentials

When using zerologon to perform such an attack, you can dump various types of data from the domain controller with the help of [secretsdump.py](https://github.com/fortra/impacket/blob/master/examples/secretsdump.py).

# Too much chatter, only want to run it

Once installed, you can easily run this through `proxychains`:
```shell
proxychains -f ~/proxyconfs/lab.conf zero-effort 10.10.10.5
```

## Installing the package
You can directly install the wheel from the latest version using:
```shell
python3 -m pip install zero_effort-1.0.0-py3-none-any.whl
```
And that's it. You can directly use the command line from your terminal:
```shell
zero-effort -h
```

## Poetry
Poetry is a powerful tool for managing Python dependencies and packaging projects. It provides an isolated virtual environment for each project and simplifies the process of packaging and distributing your code. With Poetry, you can easily automate the building and publishing of your Python packages to package repositories like PyPI, saving you time and reducing the risk of errors.

Once you have poetry installed to your system, you can start the project with:
```shell
poetry install
poetry run zero-effort <args>
```

# Notes
I'm using a slightly modified version of secretsdumps.py, so that I can automate the changing of options and the multiple dump. 

# Disclaimer
The tool provided in this repository is intended for educational and research purposes only. The author does not condone and is not responsible for any illegal activities performed with this tool. The user is solely responsible for any consequences of using this tool. The author makes no warranties, express or implied, regarding the tool's performance, reliability, or suitability for any particular purpose. The tool is provided "as is" without any warranty of any kind, either expressed or implied, including but not limited to the implied warranties of merchantability and fitness for a particular purpose. The author shall not be liable for any damages whatsoever arising out of the use or inability to use this tool, even if the author has been advised of the possibility of such damages.

It is important to note that using a tool like this to exploit vulnerabilities without explicit permission is illegal and unethical. It is strongly recommended that you use this tool only in a controlled environment and with the appropriate permissions.
