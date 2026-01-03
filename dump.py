#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Author: Rafael Paiva (paivao)
# Forked from https://github.com/AloneMonkey/frida-ios-dump

import sys
import frida
import threading
import os
import shutil
import argparse
import tempfile
import traceback
import paramiko
import paramiko.ssh_exception
#import re
#import subprocess
#from frida.core import CompilerOutputFormat
#from paramiko import SSHClient
from getpass import getpass
from scp import SCPClient
from tqdm import tqdm

PAYLOAD_PART = 'Payload'

DEFAULT_USER = 'root'
DEFAULT_PASS = 'alpine'
DEFAULT_HOST = 'localhost'
DEFAULT_PORT = 2222
DEFAULT_KEY_FILENAME = None

file_dict = {}

finished = threading.Event()

def get_usb_iphone(device_id: str|None):
    TYPE = 'usb'
    device_manager = frida.get_device_manager()
    changed = threading.Event()

    def on_changed():
        changed.set()

    device_manager.on('changed', on_changed)
    device_manager.enumerate_devices()

    while True:
        devices = [dev for dev in device_manager.enumerate_devices() if dev.type == TYPE]
        if len(devices) == 0:
            print('Waiting for USB device...')
            changed.wait()
        else:
            device_manager.off('changed', on_changed)
            if device_id is None:
                return devices[0]
            return next(filter(lambda d: d.id == device_id, devices))


def list_applications(device: frida.core.Device) -> None:
    applications = device.enumerate_applications()

    # Variable names are: (PID/Name/Identifier) Column With
    if len(applications) > 0:
        pcw = max(map(lambda app: len(str(app.pid)), applications))
        ncw = max(map(lambda app: len(app.name), applications))
        icw = max(map(lambda app: len(app.identifier), applications))
    else:
        pcw = 0
        ncw = 0
        icw = 0

    print(f"{'PID':>pcw} {'Name':<ncw} {'Identifier':<icw}")
    print('-'*pcw, '-'*ncw, '-'*icw)
    # For comparison, first sort by running apps (pid != 0), and then by name
    # If you ask why the comparison is inverted, it is because, with booleans, False comes before True
    for app in sorted(applications, key=lambda app: (app.pid == 0, app.name)):
        print(f"{app.pid if app.pid != 0 else '-':>pcw} {app.name:<ncw} {app.identifier:<icw}")



def load_script(session: frida.core.Session, on_message: frida.core.ScriptMessageCallback) -> frida.core.Script:
    compiler = frida.Compiler()
    script_dir = os.path.dirname(os.path.realpath(__file__))
    source = compiler.build(f"{script_dir}/agent/index.ts")
    script = session.create_script(source)
    script.on('message', on_message)
    script.load()

    return script


def open_target_app(device: frida.core.Device, name_or_bundleid: str) -> tuple[frida.core.Session, str, str]:
    print('Start the target app {}'.format(name_or_bundleid))

    pid = ''
    display_name = ''
    bundle_identifier = ''
    for application in device.enumerate_applications():
        if name_or_bundleid == application.identifier or name_or_bundleid == application.name:
            pid = application.pid
            display_name = application.name
            bundle_identifier = application.identifier

    if not pid:
        pid = device.spawn([bundle_identifier])
        session = device.attach(pid)
        device.resume(pid)
    else:
        session = device.attach(pid)

    return session, display_name, bundle_identifier

def generate_on_message(transport: paramiko.Transport, destination_dir: str) -> frida.core.ScriptMessageCallback:
    def on_message(message: frida.core.ScriptMessage, _: bytes | None) -> None:
        t = tqdm(unit='B',unit_scale=True,unit_divisor=1024,miniters=1)

        def progress(filename, size, sent):
            t.set_description(os.path.basename(filename))
            if t.total != size:
                t.reset(size)
            t.update(sent - t.n)

        if 'payload' in message:
            payload = message['payload']
            if 'dump' in payload:
                origin_path = payload['path']
                dump_path = payload['dump']

                scp_from = dump_path
                scp_to = destination_dir + '/'

                with SCPClient(transport, progress = progress, socket_timeout = 60) as scp:
                    scp.get(scp_from, scp_to)

                os.chmod(os.path.join(destination_dir, os.path.basename(dump_path)), 0o755)

                index = origin_path.find('.app/')
                file_dict[os.path.basename(dump_path)] = origin_path[index + 5:]

            if 'app' in payload:
                app_path = payload['app']

                scp_from = app_path
                scp_to = destination_dir + '/'
                with SCPClient(transport, progress = progress, socket_timeout = 60) as scp:
                    scp.get(scp_from, scp_to, recursive=True)

                os.chmod(os.path.join(destination_dir, os.path.basename(app_path)), 0o755)

                file_dict['app'] = os.path.basename(app_path)

            if 'done' in payload:
                finished.set()
        t.close()
    # End of on_message callback
    return on_message


def start_dump(session: frida.core.Session, transport: paramiko.Transport, ipa_name: str, destination_dir: str) -> None:
    script = load_script(session, generate_on_message(transport, destination_dir))
    script.post('dump')
    finished.wait()

    generate_ipa(destination_dir, ipa_name)

    if session:
        session.detach()


def generate_ipa(path: str, display_name: str) -> None:
    print(f'Generating "{display_name}.ipa"...')
    try:
        app_name = file_dict.pop('app')
        for key, value in file_dict.items():
            from_dir = os.path.join(path, key)
            to_dir = os.path.join(path, app_name, value)
            shutil.move(from_dir, to_dir)

        shutil.make_archive(display_name, 'zip', os.path.dirname(path))
        os.rename(f'{display_name}.zip', f'{display_name}.ipa')
        #target_dir = './' + path
        #zip_args = ('zip', '-qr', os.path.join(os.getcwd(), ipa_filename), target_dir)
        #subprocess.check_call(zip_args, cwd=TEMP_DIR)
        #shutil.rmtree(path)
    except Exception as e:
        print(e)
        finished.set()
    print(f'Successfully generated "{display_name}.ipa"!')


def main() -> int:
    parser = argparse.ArgumentParser(description='frida-ios-dump-2 (by Rafael Paiva). Forked from frida-ios-dump (by AloneMonkey v2.0).')
    parser.add_argument('target', nargs='?', help='Bundle identifier or display name of the target app')
    parser.add_argument('-l', '--list', dest='list_applications', action='store_true', help='List the installed apps, and exit.')
    parser.add_argument('-o', '--output', dest='output_ipa', help='Specify name of the decrypted IPA')
    parser.add_argument('-U', '--device_id', dest='device_id', type=str, default=None, help='Specify name of the decrypted IPA')
    ssh_opts = parser.add_argument_group(title="SSH parameters")
    ssh_opts.add_argument('-H', '--host', dest='ssh_host', help='Specify SSH hostname', default=DEFAULT_HOST)
    ssh_opts.add_argument('-p', '--port', dest='ssh_port', help='Specify SSH port', default=DEFAULT_PORT)
    ssh_opts.add_argument('-u', '--user', dest='ssh_user', help='Specify SSH username', default=DEFAULT_USER)
    ssh_opts.add_argument('-P', '--password', dest='ssh_pass', help='Specify SSH password', default=DEFAULT_PASS)
    ssh_opts.add_argument('-K', '--key_filename', dest='ssh_key_filename', help='Specify SSH private key file path')
    ssh_opts.add_argument('-k', '--ask', dest='ask_password', action='store_true', help='Prompt for SSH password')

    args = parser.parse_args()

    if len(sys.argv) < 2:
        parser.print_help()
        return 0

    device = get_usb_iphone(args.device_id)

    if args.list_applications:
        list_applications(device)
        return 0

    name_or_bundleid = args.target
    output_ipa = args.output_ipa
    ssh_pass = getpass() if args.ask_password else args.ssh_pass
    ssh = None
    err_code = 0
    temp_dir = None

    try:
        temp_dir = tempfile.mkdtemp()
        payload_dir = os.path.join(temp_dir, PAYLOAD_PART)
        os.mkdir(payload_dir)
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.WarningPolicy())
        ssh.connect(args.ssh_host, port=args.ssh_port, username=args.ssh_user, password=ssh_pass, key_filename=args.ssh_key_filename)

        (session, display_name, bundle_identifier) = open_target_app(device, name_or_bundleid)
        if output_ipa is None:
            output_ipa = display_name
        output_ipa = output_ipa.removesuffix(".ipa")

        if session:
            print(f'Dumping {display_name} ({bundle_identifier}) to {temp_dir}')
            transport = ssh.get_transport()
            if transport is None:
                raise Exception("could not get SSH transport")
            start_dump(session, transport, output_ipa, payload_dir)
        else:
            print(f'Unable to hook into {display_name}. Try to open it before...')
    except paramiko.ssh_exception.NoValidConnectionsError as e:
        print(f"SSH error: {e}")
        print('Try specifying -H/--hostname and/or -p/--port')
        err_code = 1
    except paramiko.AuthenticationException as e:
        print(f"SSH error: {e}")
        print('Try specifying -u/--username and/or -P/--password')
        err_code = 1
    except Exception as e:
        print(f'*** Caught exception ({e.__class__}): {e}')
        traceback.print_exc()
        err_code = 1

    if ssh:
        ssh.close()

    if temp_dir and os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)

    return err_code


if __name__ == '__main__':
    sys.exit(main())
