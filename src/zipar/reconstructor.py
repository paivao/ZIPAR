import frida
import threading
from tempfile import mkdtemp
from pathlib import Path
import os
import shutil
from tqdm import tqdm


SCRIPT_FILE = (Path(__file__).parent / "agent.js")
PAYLOAD_PATH = "Payload"


def get_pay_path(p): return os.path.join(p, PAYLOAD_PATH)


def attach_script(session: frida.core.Session, on_message: frida.core.ScriptMessageCallback) -> frida.core.Script:
    if not SCRIPT_FILE.exists():
        raise Exception(f"Could nout open agent file {SCRIPT_FILE}")
    script = session.create_script(SCRIPT_FILE.read_text())
    script.on('message', on_message)
    script.load()
    return script


def generate_on_message(base_path: Path, event: threading.Event, t: tqdm) -> frida.core.ScriptMessageCallback:
    def receive_file_message(payload: dict, data):
        if dir := payload.get('directory'):
            path = base_path / dir
            path.mkdir(parents=True)
            t.set_description(f"Dumping on {dir}")
        elif file_path := payload.get('start'):
            path = base_path / file_path
            size = payload['size']
            path.touch()
            with path.open('wb') as fh:
                fh.truncate(size)
            t.set_description(f"Dumping {file_path}")
            t.reset(size)
        elif file_path := payload.get('partial'):
            path = base_path / file_path
            offset = payload['offset']
            size = payload['size']
            with path.open('r+b') as fh:
                fh.seek(offset, os.SEEK_SET)
                fh.write(data)
            t.update(size)
        elif _ := payload.get('done'):
            event.set()

    def receive_error_message(message: dict):
        error_msg = message.get('description', 'unknown error')
        if filename := message.get('filename'):
            error_msg += f', at: {filename}'
        if line := message.get('lineNumber'):
            error_msg += f':{line}'
        if column := message.get('columnNumber'):
            error_msg += f':{column}'
        print(f"ERROR: {error_msg}")
        if stack := message.get('stack'):
            print(stack)

    def on_message(message: frida.core.ScriptMessage, data: bytes | None) -> None:
        # print(f"Received {message=}")
        if message['type'] == 'send':
            receive_file_message(message['payload'], data)
        elif message['type'] == 'error':
            receive_error_message(message)
    return on_message


def create_tmp_path() -> str:
    base_path = Path(mkdtemp())
    path = base_path / PAYLOAD_PATH
    path.mkdir(parents=True)
    return path


def create_ipa(base_path: Path, output_file: str):
    path = base_path.parent
    shutil.make_archive(output_file, 'zip', path)
    os.rename(f'{output_file}.zip', output_file)
    shutil.rmtree(path)


def reconstruct(session: frida.core.Session, output_file: str):
    finished = threading.Event()
    t = tqdm(unit='B', unit_scale=True, unit_divisor=1024, miniters=1)
    base_path = create_tmp_path()
    on_message = generate_on_message(base_path, finished, t)
    script = attach_script(session, on_message)
    script.post('dump')
    finished.wait()
    t.close()
    print(f'Creating IPA file "{output_file}" now...')
    create_ipa(base_path, output_file)
