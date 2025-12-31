#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Author: Rafael Paiva (paivao)
# Forked from https://github.com/AloneMonkey/frida-ios-dump

import sys
import codecs
from typing import List
import frida
import threading
import os
import shutil
import time
import argparse
import tempfile
import subprocess
import re
from frida.core import CompilerOutputFormat
import paramiko
from paramiko import SSHClient
from scp import SCPClient
from tqdm import tqdm
import traceback

script_dir = os.path.dirname(os.path.realpath(__file__))

DUMP_JS = os.path.join(script_dir, 'dump.js')

DEFAULT_USER = 'root'
DEFAULT_PASS = 'alpine'
DEFAULT_HOST = 'localhost'
DEFAULT_PORT = 2222
KeyFileName = None

TEMP_DIR = tempfile.gettempdir()
PAYLOAD_DIR = 'Payload'
PAYLOAD_PATH = os.path.join(TEMP_DIR, PAYLOAD_DIR)
file_dict = {}

finished = threading.Event()

def get_usb_iphone():
    Type = 'usb'
    device_manager = frida.get_device_manager()
    changed = threading.Event()

    def on_changed():
        changed.set()

    device_manager.on('changed', on_changed)

    device = None
    while device is None:
        devices = [dev for dev in device_manager.enumerate_devices() if dev.type == Type]
        if len(devices) == 0:
            print('Waiting for USB device...')
            changed.wait()
        else:
            device = devices[0]

    device_manager.off('changed', on_changed)

    return device


def generate_ipa(path, display_name):
    ipa_filename = display_name + '.ipa'

    print('Generating "{}"'.format(ipa_filename))
    try:
        app_name = file_dict['app']

        for key, value in file_dict.items():
            from_dir = os.path.join(path, key)
            to_dir = os.path.join(path, app_name, value)
            if key != 'app':
                shutil.move(from_dir, to_dir)

        target_dir = './' + PAYLOAD_DIR
        zip_args = ('zip', '-qr', os.path.join(os.getcwd(), ipa_filename), target_dir)
        subprocess.check_call(zip_args, cwd=TEMP_DIR)
        shutil.rmtree(PAYLOAD_PATH)
    except Exception as e:
        print(e)
        finished.set()

def on_message(message, data):
    t = tqdm(unit='B',unit_scale=True,unit_divisor=1024,miniters=1)
    last_sent = [0]

    def progress(filename, size, sent):
        t.desc = os.path.basename(filename)
        t.total = size
        t.update(sent - last_sent[0])
        last_sent[0] = 0 if size == sent else sent

    if 'payload' in message:
        payload = message['payload']
        if 'dump' in payload:
            origin_path = payload['path']
            dump_path = payload['dump']

            scp_from = dump_path
            scp_to = PAYLOAD_PATH + '/'

            with SCPClient(ssh.get_transport(), progress = progress, socket_timeout = 60) as scp:
                scp.get(scp_from, scp_to)

            chmod_dir = os.path.join(PAYLOAD_PATH, os.path.basename(dump_path))
            chmod_args = ('chmod', '655', chmod_dir)
            try:
                subprocess.check_call(chmod_args)
            except subprocess.CalledProcessError as err:
                print(err)

            index = origin_path.find('.app/')
            file_dict[os.path.basename(dump_path)] = origin_path[index + 5:]

        if 'app' in payload:
            app_path = payload['app']

            scp_from = app_path
            scp_to = PAYLOAD_PATH + '/'
            with SCPClient(ssh.get_transport(), progress = progress, socket_timeout = 60) as scp:
                scp.get(scp_from, scp_to, recursive=True)

            chmod_dir = os.path.join(PAYLOAD_PATH, os.path.basename(app_path))
            chmod_args = ('chmod', '755', chmod_dir)
            try:
                subprocess.check_call(chmod_args)
            except subprocess.CalledProcessError as err:
                print(err)

            file_dict['app'] = os.path.basename(app_path)

        if 'done' in payload:
            finished.set()
    t.close()


def list_applications(device: frida._frida.Device) -> None:
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


def load_script(session):
    compiler = frida.Compiler()
    source = compiler.build(f"{script_dir}/agent/index.ts")
    script = session.create_script(source)
    script.on('message', on_message)
    script.load()

    return script


def create_dir(path):
    path = path.strip()
    path = path.rstrip('\\')
    if os.path.exists(path):
        shutil.rmtree(path)
    try:
        os.makedirs(path)
    except os.error as err:
        print(err)


def open_target_app(device: frida.core.Device, name_or_bundleid: str):
    print('Start the target app {}'.format(name_or_bundleid))

    pid = ''
    session = None
    display_name = ''
    bundle_identifier = ''
    for application in get_applications(device):
        if name_or_bundleid == application.identifier or name_or_bundleid == application.name:
            pid = application.pid
            display_name = application.name
            bundle_identifier = application.identifier

    try:
        if not pid:
            pid = device.spawn([bundle_identifier])
            session = device.attach(pid)
            device.resume(pid)
        else:
            session = device.attach(pid)
    except Exception as e:
        print(e) 

    return session, display_name, bundle_identifier


def start_dump(session, ipa_name):
    print('Dumping {} to {}'.format(display_name, TEMP_DIR))

    script = load_js_file(session, DUMP_JS)
    script.post('dump')
    finished.wait()

    generate_ipa(PAYLOAD_PATH, ipa_name)

    if session:
        session.detach()


def main() -> int:
    parser = argparse.ArgumentParser(description='frida-ios-dump (by AloneMonkey v2.0)')
    parser.add_argument('-l', '--list', dest='list_applications', action='store_true', help='List the installed apps')
    parser.add_argument('-o', '--output', dest='output_ipa', help='Specify name of the decrypted IPA')
    parser.add_argument('-H', '--host', dest='hostname', help='Specify SSH hostname', default=DEFAULT_HOST)
    parser.add_argument('-p', '--port', dest='port', help='Specify SSH port', default=DEFAULT_PORT)
    parser.add_argument('-u', '--user', dest='username', help='Specify SSH username', default=DEFAULT_USER)
    parser.add_argument('-P', '--password', dest='password', help='Specify SSH password', default=DEFAULT_PASS)
    parser.add_argument('--ask', dest='ask_password', action='store_true', help='Prompt for SSH password')
    parser.add_argument('-K', '--key_filename', dest='key_filename', help='Specify SSH private key file path')
    parser.add_argument('target', nargs='?', help='Bundle identifier or display name of the target app')

    args = parser.parse_args()

    ssh = None

    if len(sys.argv) < 2:
        parser.print_help()
        return 0

    device = get_usb_iphone()

    if args.list_applications:
        list_applications(device)
        return 0

    name_or_bundleid = args.target
    output_ipa = args.output_ipa
    # update ssh args
    if args.ssh_host:
        Host = args.ssh_host
    if args.ssh_port:
        Port = int(args.ssh_port)
    if args.ssh_user:
        User = args.ssh_user
    if args.ssh_password:
        Password = args.ssh_password
    if args.ssh_key_filename:
        KeyFileName = args.ssh_key_filename

    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(args.ssh_host, port=args.ssh_port, username=User, password=Password, key_filename=KeyFileName)

        create_dir(PAYLOAD_PATH)
        (session, display_name, bundle_identifier) = open_target_app(device, name_or_bundleid)
        if output_ipa is None:
            output_ipa = display_name
        output_ipa = re.sub('\.ipa$', '', output_ipa)
        if session:
            start_dump(session, output_ipa)
    except paramiko.ssh_exception.NoValidConnectionsError as e:
        print(e)
        print('Try specifying -H/--hostname and/or -p/--port')
        exit_code = 1
    except paramiko.AuthenticationException as e:
        print(e)
        print('Try specifying -u/--username and/or -P/--password')
        exit_code = 1
    except Exception as e:
        print('*** Caught exception: %s: %s' % (e.__class__, e))
        traceback.print_exc()
        exit_code = 1

    if ssh:
        ssh.close()

    if os.path.exists(PAYLOAD_PATH):
        shutil.rmtree(PAYLOAD_PATH)

    sys.exit(exit_code)


if __name__ == '__main__':
    sys.exit(main())
