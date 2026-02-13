import frida
import threading
from tempfile import mkdtemp
from pathlib import Path
import os
import shutil
from tqdm import tqdm
from .message import generate_message_handler

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
    on_message = generate_message_handler(base_path, finished, t)
    script = attach_script(session, on_message)
    script.post('dump')
    finished.wait()
    t.close()
    print(f'Creating IPA file "{output_file}" now...')
    create_ipa(base_path, output_file)
