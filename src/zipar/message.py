import os
import frida
from pathlib import Path
import threading
from tqdm import tqdm

ZERO_U32 = b'\0\0\0\0'

def receive_file_message(t: tqdm, e: threading.Event, base_path: Path, payload: dict, data):
    if dir := payload.get('directory'):
        path = base_path / dir
        path.mkdir(parents=True)
        t.set_description(f"Entering dir {dir}")
    elif file_path := payload.get('start'):
        path = base_path / file_path
        size = payload['size']
        path.touch()
        with path.open('wb') as fh:
            fh.truncate(size)
        t.set_description(f"Fetching {file_path}")
        t.reset(size)
    elif file_path := payload.get('partial'):
        path = base_path / file_path
        offset = payload['offset']
        size = payload['size']
        with path.open('r+b') as fh:
            fh.seek(offset, os.SEEK_SET)
            fh.write(data)
        t.update(size)
    elif file_path := payload.get('beginPatch'):
        path = base_path / file_path
        patchSize = payload['patchSize']
        cryptIdOffset = payload['cryptIdPos']
        with path.open('r+b') as fh:
            fh.seek(cryptIdOffset, os.SEEK_SET)
            fh.write(ZERO_U32)
        t.set_description(f"Patching {file_path}")
        t.reset(patchSize)
        print(f"Beginning pathing {path}, {cryptIdOffset}, {patchSize}")
    elif file_path := payload.get('patchPartial'):
        path = base_path / file_path
        fileOffset = payload['fileOffset']
        size = payload['size']
        with path.open('r+b') as fh:
            fh.seek(fileOffset, os.SEEK_SET)
            fh.write(data)
        t.update(size)
    elif file_path := payload.get('end'):
        t.set_description(f"Finished {file_path}")
    elif _ := payload.get('done'):
        e.set()
    elif info := payload.get('info'):
       print(f"INFO: {info}")
    else:
        raise Exception(f"unrecognized message: {payload}")
    
def receive_error_message(message: dict):
    error_msg = message.get('description', 'unknown error')
    if fileName := message.get('fileName'):
        error_msg += f', at: {fileName}'
    if line := message.get('lineNumber'):
        error_msg += f':{line}'
    if column := message.get('columnNumber'):
        error_msg += f':{column}'
    print(f"ERROR: {error_msg}")
    if stack := message.get('stack'):
        print(stack)

def generate_message_handler(base_path: Path, event: threading.Event, t: tqdm) -> frida.core.ScriptMessageCallback:
    def on_message(message: frida.core.ScriptMessage, data: bytes | None) -> None:
        # print(f"Received {message=}")
        if message['type'] == 'send':
            receive_file_message(t, event, base_path, message['payload'], data)
        elif message['type'] == 'error':
            receive_error_message(message)
    return on_message