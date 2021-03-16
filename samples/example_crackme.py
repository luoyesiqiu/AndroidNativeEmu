import logging
import sys
import posixpath

from unicorn import UC_HOOK_CODE
from unicorn.arm_const import *
from capstone import *
from capstone.arm_const import *
from androidemu.emulator import Emulator
from androidemu.java.java_class_def import JavaClassDef
from androidemu.java.java_method_def import java_method_def

# Configure logging
logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)7s %(name)34s | %(message)s"
)

class MainActivity(metaclass=JavaClassDef, jvm_name='com/yaotong/crackme/MainActivity'):

    def __init__(self):
        pass

    @java_method_def(name='securityCheck', signature='(Ljava/lang/String;)Z', native=True)
    def securityCheck(self, mu):
        pass

logger = logging.getLogger(__name__)

# Initialize emulator
emulator = Emulator(
    vfp_inst_set=True,
    vfs_root=posixpath.join(posixpath.dirname(__file__), "vfs")
    )
emulator.load_library("example_binaries/arm/sys/libdl.so")
emulator.load_library("example_binaries/arm/sys/libc.so")
emulator.load_library("example_binaries/arm/sys/libstdc++.so")
emulator.load_library("example_binaries/arm/sys/libm.so")
lib_module = emulator.load_library("example_binaries/arm/user/libcrackme.so", do_init=False)

# Show loaded modules.
logger.info("Loaded modules:")

for module in emulator.modules:
    logger.info("[0x%x] %s" % (module.base, module.filename))


# Add debugging.
def hook_code(mu, address, size, user_data):
    instruction = mu.mem_read(address, size)
    if len(instruction) == 2:
        cp = Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    elif len(instruction) == 4:
        cp = Cs(CS_ARCH_ARM,CS_MODE_ARM)
    
    # for ins in cp.disasm(instruction,0x1000):
    #     print('# Tracing ins at 0x%x, ins size = 0x%x, ins = %s\t%s' % (address, ins.size, ins.mnemonic, ins.op_str))


emulator.mu.hook_add(UC_HOOK_CODE, hook_code)
emulator.java_classloader.add_class(MainActivity)

try:
    emulator.call_symbol(lib_module, 'JNI_OnLoad', emulator.java_vm.address_ptr, 0x00)
    print("String length is: %i" % emulator.mu.reg_read(UC_ARM_REG_R0))
except UcError as e:
    print("Exit at %x" % emulator.mu.reg_read(UC_ARM_REG_PC))
    raise
