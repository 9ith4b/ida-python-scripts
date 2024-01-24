import signal, os
from ptrace import debugger

class Tracer:
    def __init__(self, cmd=[]):
        if isinstance(cmd, list):
            self.target = cmd[0]
            target = cmd
        else:
            self.target = cmd.split()[0]
            target = cmd.split()
        self.dbg = debugger.PtraceDebugger()
        self.pid = debugger.child.createChild(target, no_stdout=False)
        self.proc = self.dbg.addProcess(self.pid, True)
        self.vmmap = self.proc.readMappings()
        self.modules = self.get_modules()
        self.base = self.get_base()
        self.bps = {}

    def get_base(self):
        for m in self.vmmap:
            if m.pathname.endswith(os.path.basename(self.target)):
                return m.start
    
    def get_modules(self):
        modules = {}
        for m in self.vmmap:
            pathname = os.path.basename(m.pathname)
            if modules.get(pathname):
                modules[pathname].extend([m.start, m.end])
            else:
                modules[pathname] = [m.start, m.end]

        for pathname, addrs in modules.items():
            modules[pathname] = sorted(addrs)
        # print(modules)
        return modules
        
    def set_breakpoint(self, bpmap="bpmap.txt"):
        with open(bpmap) as f:
            for line in f.readlines():
                offset, delim, info = line.strip().partition(" ")
                offset = int(offset, 16)
                self.proc.createBreakpoint(self.base+offset)
                self.bps[self.base+offset] = info
    
    def tracer(self):
        running = True
        while running:
            self.proc.cont()
            event = self.dbg.waitProcessEvent()
            if isinstance(event, debugger.ProcessExit):
                self.proc.detach()
                running = False
            match (event.signum):
                case (signal.SIGTRAP):
                    # breakpoint
                    ip = self.proc.getInstrPointer()-1
                    print(f"{ip:<15x} {self.bps[ip]}")
                    self.proc.findBreakpoint(ip).desinstall()
                    self.proc.setInstrPointer(ip)
                case (signal.SIGSEGV):
                    # crash
                    crash_ip = self.proc.getInstrPointer()-1
                    print(f">> crash ip: {crash_ip:x}")
                    for pathname, addrs in self.modules.items():
                        print(f"{pathname:<30}{addrs[0]:x} - {addrs[-1]:x}")
                        if crash_ip > addrs[0] and crash_ip < addrs[-1]:
                            print(f">> crash ip: {crash_ip:x}, {pathname}")
                    self.proc.detach()
                    running = False
                case (signal.SIGINT):
                    print("stop running")
                    self.proc.detach()
                    running = False
                case (_):
                    # comment: 
                    print(event.signum)
            # end match
            

if __name__ == "__main__":
    tr = Tracer("./nc-ssl 127.0.0.1 443")
    tr.set_breakpoint()
    tr.tracer()
