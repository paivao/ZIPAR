from tabulate import tabulate
from .args import cli_args
from .connection import Connection
from .reconstructor import reconstruct


BANNER = """ZIPAR
=====
"""


def main():
    print(BANNER)
    config = cli_args()
    conn = Connection(config)
    if config.list_devices:
        device_table = [("OK", "ID", "Name", "Type")]
        for dev in conn.list_devices():
            device_table.append((not dev.is_lost, dev.id, dev.name, dev.type))
        print(tabulate(device_table, headers='firstrow', tablefmt='grid'))
        return
    if config.list_apps:
        app_table = [('PID', 'Name', 'Bundle')]
        for app in conn.list_apps():
            app_table.append((app.pid, app.name, app.identifier))
        print(tabulate(app_table, headers='firstrow', tablefmt='grid'))
        return
    # The main action, to use the session to get the app
    session, app_name = conn.connect_to_app()
    print(f"Start dumping {app_name}")
    reconstruct(session, config.get_app_ipa_name(app_name))
    session.detach()


if __name__ == "__main__":
    main()
