from .args import Configuration
import frida


class Connection:
    TIMEOUT = 60

    def __init__(self, conf: Configuration):
        self.conf = conf
        dm = frida.get_device_manager()
        self.dm = dm
        _device = None
        if conf.should_add_remote():
            _device = dm \
                .add_remote_device(conf.remote_addr(),
                                   keepalive_interval=Connection.TIMEOUT)
        if not conf.list_devices:
            if conf.device_id:
                _device = dm.get_device(conf.device_id, Connection.TIMEOUT)
            elif not conf.is_remote:
                _device = dm.get_usb_device(Connection.TIMEOUT)
            elif _device is None:
                _device = dm.get_remote_device()
        else:
            _device = None
        self.device: frida.core.Device | None = _device

    def list_devices(self) -> [frida.core.Device]:
        return self.dm.enumerate_devices()

    def list_apps(self) -> [frida._frida.Application]:
        return sorted(self.device.enumerate_applications(),
                      key=lambda a: (a.pid == 0, a.name))

    def __find_app(self):
        for app in self.list_apps():
            if self.conf.app_name == app.identifier:
                return app.pid
            if self.conf.app_name == app.name:
                return app.pid
        return -1

    def __get_app_name(self, pid: int) -> str:
        return self.device.enumerate_processes([pid])[0].name

    def connect_to_app(self) -> (frida.core.Session, str):
        pid: int = self.conf.pid
        if self.conf.frontmost:
            pid = self.device.get_frontmost_application().pid
        spawned = False
        if pid < 0:
            pid = self.__find_app()
            if pid < 0:
                pid = self.device.spawn(self.conf.app_name)
                spawned = True
        session = self.device.attach(pid)
        if spawned:
            self.device.resume(pid)
        return session, self.__get_app_name(pid)
