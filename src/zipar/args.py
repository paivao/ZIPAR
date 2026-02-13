from dataclasses import dataclass
import argparse


DESCRIPTION = """ZIPAR (Zip IPA Retriever), by Rafael Paiva.
It generate an IPA file based on installed App on jailbroken iOS device using Frida.
"""


@dataclass
class Configuration:
    host: str = ''
    port: int = 0
    device_id: str = ''
    is_remote: bool = False
    app_name: str = ''
    frontmost: bool = False
    output_file: str = ''
    list_devices: bool = False
    list_apps: bool = False
    pid: int = -1

    def remote_addr(self) -> str:
        return f'{self.host}:{self.port}'

    def should_add_remote(self) -> bool:
        return self.is_remote and self.port > 0

    def get_app_ipa_name(self, app_name: str) -> str:
        ipa_file = self.output_file or app_name
        if not ipa_file.endswith(".ipa"):
            ipa_file += '.ipa'
        return ipa_file


def cli_args() -> Configuration:
    parser = argparse.ArgumentParser(description=DESCRIPTION)
    parser.add_argument('-H', '--host', default='127.0.0.1',
                        help="Frida host to connect (remote mode)")
    parser.add_argument('-P', '--port', type=int, default=27042,
                        help="Frida port to connect (remote mode)")
    parser.add_argument('-D', '--device', dest='device_id',
                        help="Device ID to connect to.")
    parser.add_argument('-R', '--remote', action='store_true',
                        dest='is_remote',
                        help="Use remote connection (defaults to USB)")
    parser.add_argument('-o', '--output', dest='output_file',
                        help="File name (and path) to output IPA")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--list-devices', action='store_true',
                       help="List connected devices and exit.")
    group.add_argument('-l', '--list-apps', action='store_true',
                       help='List installed apps and exit.')
    group.add_argument('-F', '--frontmost', action='store_true',
                       help='Retrieves frontmost app.')
    group.add_argument('-p', '--pid', type=int,
                       help='Retrieves opened app by its PID.')
    group.add_argument('-n', '--name', dest='app_name',
                       help='''Retrieves informed app name or bundle id.
                        It will try to spawn app if it is not started yet.''')
    return parser.parse_args(namespace=Configuration())
