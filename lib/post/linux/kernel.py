
class Kernel:
	
	def aslr_enabled(self):
		""" Check if ASLR is enabled """
		aslr = self.cmd_exec('cat /proc/sys/kernel/randomize_va_space').strip()
		if aslr == '1' or aslr == '2':
			return True
		return False
	
	def exec_shield_enabled(self):
		""" Check if execshield is enabled """

		if self.cmd_exec('cat /proc/sys/kernel/exec-shield') == '1':
			return True
		return False
	
	def cpu_flags(self):
		""" Get CPU flags """
		return self.cmd_exec('cat /proc/cpuinfo | grep flags').split(':')[1].strip()

	def dmesg_restrict(self):
		""" Check if dmesg is restricted """
		if self.cmd_exec('cat /proc/sys/kernel/dmesg_restrict') == '1':
			return True
		return False

	def grsec_installed(self):
		""" Check if grsec is installed """
		if self.cmd_exec('cat /proc/sys/kernel/grsecurity/grsec_enabled') == '1':
			return True
		return False

	def kernel_arch(self):
		""" Get kernel architecture """
		return self.cmd_exec('uname -m').strip()

	def kernel_modules(self):
		""" Get kernel modules """
		return self.cmd_exec('lsmod').split('\n')	# Return a list of modules

	def kernel_name(self):
		""" Get kernel name """
		return self.cmd_exec('uname -s').strip()

	def kernel_release(self):
		""" Get kernel release """
		return self.cmd_exec('uname -r').strip()

	def kernel_version(self):
		""" Get kernel version """
		return self.cmd_exec('uname -v').strip()

	def kpti_enabled(self):
		""" Check if KPTI is enabled """
		if self.cmd_exec('cat /proc/sys/kernel/kptr_restrict') == '0':
			return True
		return False

	def mmap_min_addr(self):
		""" Get mmap_min_addr """
		return self.cmd_exec('cat /proc/sys/vm/mmap_min_addr').strip()

	def smap_enabled(self):
		""" Check if SMAP is enabled """
		if self.cmd_exec('cat /proc/sys/kernel/soft_mmu_enabled') == '1':
			return True
		return False

	def unprivileged_bpf_disabled(self):
		""" Check if unprivileged BPF is disabled """
		if self.cmd_exec('cat /proc/sys/kernel/unprivileged_bpf_disabled') == '1':
			return True
		return False


