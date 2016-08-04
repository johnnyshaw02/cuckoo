# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import os
import logging
import random
import subprocess
import tempfile
import _winreg
import traceback

from ctypes import byref, c_ulong, create_string_buffer, c_int, sizeof
from ctypes import c_uint, c_wchar_p, create_unicode_buffer
from shutil import copy

from lib.common.constants import SHUTDOWN_MUTEX
from lib.common.defines import KERNEL32, NTDLL, SYSTEM_INFO, STILL_ACTIVE
from lib.common.defines import THREAD_ALL_ACCESS, PROCESS_ALL_ACCESS
from lib.common.defines import STARTUPINFO, PROCESS_INFORMATION
from lib.common.defines import CREATE_NEW_CONSOLE
from lib.common.errors import get_error_string
from lib.common.exceptions import CuckooError
from lib.common.results import upload_to_host
from lib.common.rand import random_string

log = logging.getLogger(__name__)

def subprocess_checkcall(args, env=None):
    return subprocess.check_call(
        args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, env=env,
    )

def subprocess_checkoutput(args, env=None):
    return subprocess.check_output(
        args, stdin=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
    )

class Process(object):
    """Windows process."""
    first_process = True
    config = None

    # Keeps track of the dump memory index for a particular process as in
    # theory, and will be useful later, we may want to dump one process
    # multiple times.
    dumpmem = {}

    def __init__(self, pid=None, tid=None, process_name=None):
        """
        @param pid: process identifier.
        @param tid: thread identifier.
        @param process_name: process name.
        """
        self.pid = pid
        self.tid = tid
        self.process_name = process_name

    @staticmethod
    def set_config(config):
        """Sets the analyzer configuration once."""
        Process.config = config

    def get_system_info(self):
        """Get system information."""
        self.system_info = SYSTEM_INFO()
        KERNEL32.GetSystemInfo(byref(self.system_info))

    def open_process(self):
        """Open a process handle."""
        return KERNEL32.OpenProcess(PROCESS_ALL_ACCESS, False, self.pid)

    def open_thread(self):
        """Open a thread handle."""
        return KERNEL32.OpenThread(THREAD_ALL_ACCESS, False, self.tid)

    def exit_code(self):
        """Get process exit code.
        @return: exit code value.
        """
        process_handle = self.open_process()

        exit_code = c_ulong(0)
        KERNEL32.GetExitCodeProcess(process_handle, byref(exit_code))
        KERNEL32.CloseHandle(process_handle)

        return exit_code.value

    def get_filepath(self):
        """Get process image file path.
        @return: decoded file path.
        """
        process_handle = self.open_process()

        NT_SUCCESS = lambda val: val >= 0

        pbi = create_string_buffer(200)
        size = c_int()

        # Set return value to signed 32bit integer.
        NTDLL.NtQueryInformationProcess.restype = c_int

        ret = NTDLL.NtQueryInformationProcess(process_handle,
                                              27,
                                              byref(pbi),
                                              sizeof(pbi),
                                              byref(size))

        KERNEL32.CloseHandle(process_handle)

        if NT_SUCCESS(ret) and size.value > 8:
            try:
                fbuf = pbi.raw[8:]
                fbuf = fbuf[:fbuf.find("\x00\x00")+1]
                return fbuf.decode("utf16", errors="ignore")
            except:
                return ""

        return ""

    def is_alive(self):
        """Process is alive?
        @return: process status.
        """
        return self.exit_code() == STILL_ACTIVE

    def get_parent_pid(self):
        """Get the Parent Process ID."""
        process_handle = self.open_process()

        NT_SUCCESS = lambda val: val >= 0

        pbi = (c_int * 6)()
        size = c_int()

        # Set return value to signed 32bit integer.
        NTDLL.NtQueryInformationProcess.restype = c_int

        ret = NTDLL.NtQueryInformationProcess(process_handle,
                                              0,
                                              byref(pbi),
                                              sizeof(pbi),
                                              byref(size))

        KERNEL32.CloseHandle(process_handle)

        if NT_SUCCESS(ret) and size.value == sizeof(pbi):
            return pbi[5]

        return None

    def shortpath(self, path):
        """Returns the shortpath for a file.

        As Python 2.7 does not support passing along unicode strings in
        subprocess.Popen() and alike this will have to do. See also:
        http://stackoverflow.com/questions/2595448/unicode-filename-to-python-subprocess-call
        """
        KERNEL32.GetShortPathNameW.restype = c_uint
        KERNEL32.GetShortPathNameW.argtypes = c_wchar_p, c_wchar_p, c_uint

        buf = create_unicode_buffer(0x8000)
        KERNEL32.GetShortPathNameW(path, buf, len(buf))
        return buf.value

    def _encode_args(self, args):
        """Convert a list of arguments to a string that can be passed along
        on the command-line.
        @param args: list of arguments
        @return: the command-line equivalent
        """
        ret = []
        for line in args:
            if " " in line:
                ret.append('"%s"' % line)
            else:
                ret.append(line)
        return " ".join(ret)

    def is32bit(self, pid=None, process_name=None, path=None):
        """Is a PE file 32-bit or does a process identifier belong to a
        32-bit process.
        @param pid: process identifier.
        @param process_name: process name.
        @param path: path to a PE file.
        @return: boolean or exception.
        """
        count = (pid is None) + (process_name is None) + (path is None)
        if count != 2:
            raise CuckooError("Invalid usage of is32bit, only one identifier "
                              "should be specified")

        is32bit_exe = os.path.join("bin", "is32bit.exe")

        if pid:
            args = [is32bit_exe, "-p", "%s" % pid]
        elif process_name:
            args = [is32bit_exe, "-n", process_name]

        # If we're running a 32-bit Python in a 64-bit Windows system and the
        # path points to System32, then we hardcode it as being a 64-bit
        # binary. (To be fair, a 64-bit Python on 64-bit Windows would also
        # make the System32 binary 64-bit).
        elif os.path.isdir("C:\\Windows\\Sysnative") and \
                path.lower().startswith("c:\\windows\\system32"):
            return False
        else:
            args = [is32bit_exe, "-f", self.shortpath(path)]

        try:
            bitsize = int(subprocess_checkoutput(args))
        except subprocess.CalledProcessError as e:
            raise CuckooError("Error returned by is32bit: %s" % e)

        return bitsize == 32

    def is64bit(self):
        aReg = _winreg.ConnectRegistry(None, _winreg.HKEY_LOCAL_MACHINE)
        try:
            hKey = _winreg.OpenKey(aReg, r'SOFTWARE\Wow6432Node')
            hKey.Close()
            return True
        except:
            return False

    def execute(self, path, args=None, dll=None, free=False, kernel_analysis=False, curdir=None,
                source=None, mode=None, maximize=False, env=None,
                trigger=None):
        """Execute sample process.
        @param path: sample path.
        @param args: process args.
        @param dll: dll path.
        @param free: do not inject our monitor.
        @param kernel_analysis: performs analysis with zer0m0n driver
        @param curdir: current working directory.
        @param source: process identifier or process name which will
                       become the parent process for the new process.
        @param mode: monitor mode - which functions to instrument.
        @param maximize: whether the GUI should be maximized.
        @param env: environment variables.
        @param trigger: trigger to indicate analysis start
        @return: operation status.
        """
        if not os.access(path, os.X_OK):
            log.error("Unable to access file at path \"%s\", "
                      "execution aborted", path)
            return False
        
        is32bit = self.is32bit(path=path)
        #is32bit = not self.is64bit()

        if not dll:
            if is32bit:
                dll = "monitor-x86.dll"
            else:
                dll = "monitor-x64.dll"

        dllpath = os.path.abspath(os.path.join("bin", dll))

        if not os.path.exists(dllpath):
            log.warning("No valid DLL specified to be injected, "
                        "injection aborted.")
            return False

        if source:
            if isinstance(source, (int, long)) or source.isdigit():
                inject_is32bit = self.is32bit(pid=int(source))
            else:
                inject_is32bit = self.is32bit(process_name=source)
        else:
            inject_is32bit = is32bit

        if inject_is32bit:
            driver_path = "zer0m0n-x86.sys"
            inject_exe = os.path.join("bin", "inject-x86.exe")
        else:
            driver_path = "zer0m0n-x64.sys"
            inject_exe = os.path.join("bin", "inject-x64.exe")

        argv = [
            inject_exe,
            "--app", self.shortpath(path),
            "--only-start",
        ]

        if args:
            argv += ["--args", self._encode_args(args)]

        if curdir:
            argv += ["--curdir", self.shortpath(curdir)]

        if source:
            if isinstance(source, (int, long)) or source.isdigit():
                argv += ["--from", "%s" % source]
            else:
                argv += ["--from-process", source]

        if maximize:
            argv += ["--maximize"]

        # Start the target program using guest account
        if "guest" in self.config.options:
            guest_user = "n00b"
            guest_pass = "Pa$$w0rd"
            argv += [ "--as-user", guest_user ]
            argv += [ "--as-password", guest_pass]
            target_file = None

            if args:
                for arg in args:
                    # The args could contain the DLL sample path if the host program is rundll32.exe
                    if ".dll" in arg:
                        dll_path = arg.split(".dll")[0]
                        dll_path += ".dll"
                        target_file = dll_path
            else:
                target_file = path

            # Change the permission of the sample file so the guest user can execute
            if guest_user:
                log.info("Changing file '%s' permission to run as user '%s'", target_file, guest_user)
                os.system("c:\windows\\system32\\icacls.exe %s /grant \"%s:F\"" % (target_file, guest_user))
            
        # Start the driver immediately before we execute the sample
        # Even though in suspended mode, we might miss some events
        if kernel_analysis:
            log.warning("kernel analysis!")
            sys_file = os.path.join("bin", driver_path)
            exe_file = os.path.join("bin", "logs_dispatcher.exe")
            if not sys_file or not exe_file or not os.path.exists(sys_file) or not os.path.exists(exe_file):
                log.warning("No valid zer0m0n files to be used, analysis aborted")
                return False

            # Automate the driver installation process
            # Driver files and logs client must be ready in cuckoo "data/monitor/latest/" path
            exe_name = random_string(6)
            service_name = random_string(6)
            driver_name = random_string(6)

            inf_data = '[Version]\r\nSignature = "$Windows NT$"\r\nClass = "ActivityMonitor"\r\nClassGuid = {b86dff51-a31e-4bac-b3cf-e8cfe75c9fc2}\r\nProvider= %Prov%\r\nCatalogFile = %DriverName%.cat\r\n[DestinationDirs]\r\nDefaultDestDir = 12\r\nMiniFilter.DriverFiles = 12\r\n[DefaultInstall]\r\nOptionDesc = %ServiceDescription%\r\nCopyFiles = MiniFilter.DriverFiles\r\n[DefaultInstall.Services]\r\nAddService = %ServiceName%,,MiniFilter.Service\r\n[DefaultUninstall]\r\nDelFiles = MiniFilter.DriverFiles\r\n[DefaultUninstall.Services]\r\nDelService = %ServiceName%,0x200\r\n[MiniFilter.Service]\r\nDisplayName= %ServiceName%\r\nDescription= %ServiceDescription%\r\nServiceBinary= %12%\\%DriverName%.sys\r\nDependencies = "FltMgr"\r\nServiceType = 2\r\nStartType = 3\r\nErrorControl = 1\r\nLoadOrderGroup = "FSFilter Activity Monitor"\r\nAddReg = MiniFilter.AddRegistry\r\n[MiniFilter.AddRegistry]\r\nHKR,,"DebugFlags",0x00010001 ,0x0\r\nHKR,"Instances","DefaultInstance",0x00000000,%DefaultInstance%\r\nHKR,"Instances\\"%Instance1.Name%,"Altitude",0x00000000,%Instance1.Altitude%\r\nHKR,"Instances\\"%Instance1.Name%,"Flags",0x00010001,%Instance1.Flags%\r\n[MiniFilter.DriverFiles]\r\n%DriverName%.sys\r\n[SourceDisksFiles]\r\n' + driver_name + '.sys = 1,,\r\n[SourceDisksNames]\r\n1 = %DiskId1%,,,\r\n[Strings]\r\n' + 'Prov = "' + random_string(
                8) + '"\r\nServiceDescription = "' + random_string(
                12) + '"\r\nServiceName = "' + service_name + '"\r\nDriverName = "' + driver_name + '"\r\nDiskId1 = "' + service_name + ' Device Installation Disk"\r\nDefaultInstance = "' + service_name + ' Instance"\r\nInstance1.Name = "' + service_name + ' Instance"\r\nInstance1.Altitude = "370050"\r\nInstance1.Flags = 0x0'

            new_inf = os.path.join("bin", "{0}.inf".format(service_name))
            new_sys = os.path.join("bin", "{0}.sys".format(driver_name))
            copy(sys_file, new_sys)
            new_exe = os.path.join("bin", "{0}.exe".format(exe_name))
            copy(exe_file, new_exe)
            log.info("[+] Driver name : "+new_sys)
            log.info("[+] Inf name : "+new_inf)
            log.info("[+] Application name : "+new_exe)
            log.info("[+] Service : "+service_name)

            fh = open(new_inf,"w")
            fh.write(inf_data)
            fh.close()

            if not is32bit:
                wow64 = c_ulong(0)
                KERNEL32.Wow64DisableWow64FsRedirection(byref(wow64))

            os.system('cmd /c "rundll32 setupapi.dll, InstallHinfSection DefaultInstall 132 ' + new_inf + '"')
            os.system("net start " + service_name)

            startup_info = STARTUPINFO()
            startup_info._cb = sizeof(startup_info)
            process_info = PROCESS_INFORMATION()
            creation_flags = CREATE_NEW_CONSOLE
            # Start log_dispatcher.exe
            ldp = KERNEL32.CreateProcessA(new_exe,
                                          None,
                                          None,
                                          None,
                                          None,
                                          creation_flags,
                                          None,
                                          os.getenv("TEMP"),
                                          byref(startup_info),
                                          byref(process_info))

            if not ldp:
                log.error("Failed starting " + exe_name + ".exe.")
                return False

        try:
            log.info("[DEBUG] HERE: %r", argv)
            output = subprocess_checkoutput(argv, env)
            self.pid, self.tid = map(int, output.split())
        except Exception:
            log.error("Failed to execute process from path %r with "
                      "arguments %r (Error: %s)", path, argv,
                      get_error_string(KERNEL32.GetLastError()))
            return False

        argv = [
            inject_exe,
            "--resume-thread",
            "--pid", "%s" % self.pid,
            "--tid", "%s" % self.tid,
        ]

        if free or kernel_analysis:
            argv += ["--free"]
        else:
            argv += ["--apc", "--dll", dllpath]

        # Needs the arguments before resuming the thread
        # Note: It must be placed after --only-start argument
        if kernel_analysis:
            argv += ["--kernel_analysis"]
            cuckoo_path = os.getcwd()
            argv += ["--cuckoo_path", unicode(cuckoo_path)]

        argv += ["--config", self.drop_config(mode=mode, trigger=trigger)]

        try:
            log.info("[DEBUG] THERE: %r", argv)
            subprocess_checkoutput(argv, env)
        except Exception:
            log.error("Failed to execute process from path %r with "
                      "arguments %r (Error: %s)", path, argv,
                      get_error_string(KERNEL32.GetLastError()))
            return False

        log.info("Successfully executed process from path %r with "
                 "arguments %r and pid %d", path, args or "", self.pid)
        return True

    def terminate(self):
        """Terminate process.
        @return: operation status.
        """
        process_handle = self.open_process()

        ret = KERNEL32.TerminateProcess(process_handle, 1)
        KERNEL32.CloseHandle(process_handle)

        if ret:
            log.info("Successfully terminated process with pid %d.", self.pid)
            return True
        else:
            log.error("Failed to terminate process with pid %d.", self.pid)
            return False

    def inject(self, dll=None, apc=False, track=True, mode=None):
        """Inject our monitor into the specified process.
        @param dll: Cuckoo DLL path.
        @param apc: Use APC injection.
        @param track: Track this process in the analyzer.
        @param mode: Monitor mode - which functions to instrument.
        """
        if not self.pid and not self.process_name:
            log.warning("No valid pid or process name specified, "
                        "injection aborted.")
            return False

        # Only check whether the process is still alive when it's identified
        # by a process identifier. Not when it's identified by a process name.
        if not self.process_name and not self.is_alive():
            log.warning("The process with pid %s is not alive, "
                        "injection aborted", self.pid)
            return False

        if self.process_name:
            is32bit = self.is32bit(process_name=self.process_name)
        elif self.pid:
            is32bit = self.is32bit(pid=self.pid)

        if not dll:
            if is32bit:
                dll = "monitor-x86.dll"
            else:
                dll = "monitor-x64.dll"

        dllpath = os.path.abspath(os.path.join("bin", dll))
        if not os.path.exists(dllpath):
            log.warning("No valid DLL specified to be injected in process "
                        "with pid %s / process name %s, injection aborted.",
                        self.pid, self.process_name)
            return False

        if is32bit:
            inject_exe = os.path.join("bin", "inject-x86.exe")
        else:
            inject_exe = os.path.join("bin", "inject-x64.exe")

        args = [
            inject_exe,
            "--dll", dllpath,
            "--config", self.drop_config(track=track, mode=mode),
        ]

        if self.pid:
            args += ["--pid", "%s" % self.pid]
        elif self.process_name:
            args += ["--process-name", self.process_name]

        if apc:
            args += ["--apc", "--tid", "%s" % self.tid]
        else:
            args += ["--crt"]

        try:
            subprocess_checkcall(args)
        except Exception:
            log.error("Failed to inject %s-bit process with pid %s and "
                      "process name %s", 32 if is32bit else 64, self.pid,
                      self.process_name)
            return False

        return True

    def drop_config(self, track=True, mode=None, trigger=None):
        """Helper function to drop the configuration for a new process."""
        fd, config_path = tempfile.mkstemp()

        # The first time we come up with a random startup-time.
        if Process.first_process:
            # This adds 1 up to 30 times of 20 minutes to the startup
            # time of the process, therefore bypassing anti-vm checks
            # which check whether the VM has only been up for <10 minutes.
            Process.startup_time = random.randint(1, 30) * 20 * 60 * 1000

        lines = {
            "pipe": self.config.pipe,
            "logpipe": self.config.logpipe,
            "analyzer": os.getcwd(),
            "first-process": "1" if Process.first_process else "0",
            "startup-time": Process.startup_time,
            "shutdown-mutex": SHUTDOWN_MUTEX,
            "force-sleepskip": self.config.options.get("force-sleepskip", "0"),
            "track": "1" if track else "0",
            "mode": mode or "",
            "disguise": self.config.options.get("disguise", "0"),
            "pipe-pid": "1",
            "trigger": trigger or "",
            "sample-pid": self.pid,
            "sample-tid": self.tid,        
        }

        for key, value in lines.items():
            os.write(fd, "%s=%s\n" % (key, value))

        os.close(fd)
        Process.first_process = False
        return config_path

    def dump_memory(self, addr=None, length=None):
        """Dump process memory, optionally target only a certain memory range.
        @return: operation status.
        """
        if not self.pid:
            log.warning("No valid pid specified, memory dump aborted")
            return False

        if not self.is_alive():
            log.warning("The process with pid %d is not alive, memory "
                        "dump aborted", self.pid)
            return False

        if self.is32bit(pid=self.pid):
            inject_exe = os.path.join("bin", "inject-x86.exe")
        else:
            inject_exe = os.path.join("bin", "inject-x64.exe")

        # Take the memory dump.
        dump_path = tempfile.mktemp()

        try:
            args = [
                inject_exe,
                "--pid", "%s" % self.pid,
                "--dump", dump_path,
            ]

            # Restrict to a certain memory block.
            if addr and length:
                args += [
                    "--dump-block",
                    "0x%x" % addr,
                    "%s" % length,
                ]

            subprocess_checkcall(args)
        except subprocess.CalledProcessError:
            log.error("Failed to dump memory of %d-bit process with pid %d.",
                      32 if self.is32bit(pid=self.pid) else 64, self.pid)
            return

        # Calculate the next index and send the process memory dump over to
        # the host. Keep in mind that one process may have multiple process
        # memory dumps in the future.
        idx = self.dumpmem[self.pid] = self.dumpmem.get(self.pid, 0) + 1

        if addr and length:
            file_name = os.path.join(
                "memory", "block-%s-0x%x-%s.dmp" % (self.pid, addr, idx)
            )
        else:
            file_name = os.path.join("memory", "%s-%s.dmp" % (self.pid, idx))

        upload_to_host(dump_path, file_name)
        os.unlink(dump_path)

        log.info("Memory dump of process with pid %d completed", self.pid)
        return True

    # The dump_memory_block functionality has been integrated with the
    # dump_memory function, this alias is just for backwards compatibility.
    dump_memory_block = dump_memory
