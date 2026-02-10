from .args import cli_args
from .connection import Connection
from tabulate import tabulate


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
    session = conn.connect_to_app()
    print(session)
    session.detach()


if __name__ == "__main__":
    main()
