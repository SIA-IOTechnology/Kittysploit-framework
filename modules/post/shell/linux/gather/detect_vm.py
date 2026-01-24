from kittysploit import *
from lib.post.linux.system import System

class Module(Post, System):

    __info__ = {
        "name": "Linux Virtual Machine Detection",
        "description": "Detect if the target system is running inside a virtual machine",
        "platform": Platform.LINUX,
        "author": "KittySploit Team",
        "session_type": [SessionType.SHELL, 
                        SessionType.METERPRETER,
                        SessionType.SSH],
    }

    def run(self):
        """Detect virtual machine using multiple techniques"""
        
        print_status("Detecting virtual machine environment...")
        
        vm_detected = False
        vm_type = None
        detection_methods = []
        
        # Method 1: Check DMI system information
        print_status("Checking DMI system information...")
        dmi_info = self._check_dmi_info()
        if dmi_info:
            vm_detected = True
            vm_type = dmi_info.get('type')
            detection_methods.append(f"DMI: {dmi_info.get('vendor')} - {dmi_info.get('product')}")
            print_success(f"VM detected via DMI: {vm_type}")
            print_info(f"  Vendor: {dmi_info.get('vendor')}")
            print_info(f"  Product: {dmi_info.get('product')}")
        
        # Method 2: Check loaded kernel modules
        print_status("Checking loaded kernel modules...")
        vm_modules = self._check_vm_modules()
        if vm_modules:
            vm_detected = True
            if not vm_type:
                vm_type = vm_modules[0].get('type')
            detection_methods.append(f"Kernel modules: {', '.join([m.get('module') for m in vm_modules])}")
            print_success(f"VM modules detected: {', '.join([m.get('module') for m in vm_modules])}")
            for module_info in vm_modules:
                print_info(f"  Module: {module_info.get('module')} -> {module_info.get('type')}")
        
        # Method 3: Check CPU flags and hypervisor
        print_status("Checking CPU information...")
        cpu_info = self._check_cpu_info()
        if cpu_info:
            vm_detected = True
            if not vm_type:
                vm_type = cpu_info.get('type')
            detection_methods.append(f"CPU: {cpu_info.get('method')}")
            print_success(f"VM detected via CPU: {cpu_info.get('type')}")
            print_info(f"  Method: {cpu_info.get('method')}")
        
        # Method 4: Check systemd-detect-virt (if available)
        print_status("Checking systemd-detect-virt...")
        systemd_vm = self._check_systemd_detect_virt()
        if systemd_vm:
            vm_detected = True
            if not vm_type:
                vm_type = systemd_vm
            detection_methods.append(f"systemd-detect-virt: {systemd_vm}")
            print_success(f"VM detected via systemd: {systemd_vm}")
        
        # Method 5: Check dmidecode (if available)
        print_status("Checking dmidecode...")
        dmidecode_info = self._check_dmidecode()
        if dmidecode_info:
            vm_detected = True
            if not vm_type:
                vm_type = dmidecode_info.get('type')
            detection_methods.append(f"dmidecode: {dmidecode_info.get('vendor')}")
            print_success(f"VM detected via dmidecode: {dmidecode_info.get('type')}")
            print_info(f"  Vendor: {dmidecode_info.get('vendor')}")
            print_info(f"  Product: {dmidecode_info.get('product')}")
        
        # Method 6: Check /proc/device-tree (for ARM VMs)
        print_status("Checking device tree...")
        device_tree_vm = self._check_device_tree()
        if device_tree_vm:
            vm_detected = True
            if not vm_type:
                vm_type = device_tree_vm
            detection_methods.append(f"Device tree: {device_tree_vm}")
            print_success(f"VM detected via device tree: {device_tree_vm}")
        
        # Summary
        print_status("="*60)
        if vm_detected:
            print_success(f"Virtual Machine Detected: {vm_type.upper() if vm_type else 'UNKNOWN'}")
            print_info(f"Detection methods: {len(detection_methods)}")
            for method in detection_methods:
                print_info(f"  - {method}")
        else:
            print_success("No virtual machine detected - likely running on bare metal")
        
        return True
    
    def _check_dmi_info(self):
        """Check DMI system information"""
        try:
            # Check product name
            product_name = self.cmd_exec("cat /sys/class/dmi/id/product_name 2>/dev/null").strip().lower()
            sys_vendor = self.cmd_exec("cat /sys/class/dmi/id/sys_vendor 2>/dev/null").strip().lower()
            board_vendor = self.cmd_exec("cat /sys/class/dmi/id/board_vendor 2>/dev/null").strip().lower()
            
            if not product_name and not sys_vendor:
                return None
            
            # VMware detection
            if 'vmware' in product_name or 'vmware' in sys_vendor or 'vmware' in board_vendor:
                return {
                    'type': 'VMware',
                    'vendor': sys_vendor or 'VMware',
                    'product': product_name or 'VMware Virtual Platform'
                }
            
            # VirtualBox detection
            if 'virtualbox' in product_name or 'virtualbox' in sys_vendor or 'innotek' in sys_vendor:
                return {
                    'type': 'VirtualBox',
                    'vendor': sys_vendor or 'innotek GmbH',
                    'product': product_name or 'VirtualBox'
                }
            
            # QEMU/KVM detection
            if 'qemu' in product_name or 'qemu' in sys_vendor or 'kvm' in product_name:
                return {
                    'type': 'QEMU/KVM',
                    'vendor': sys_vendor or 'QEMU',
                    'product': product_name or 'Standard PC (Q35 + ICH9)'
                }
            
            # Microsoft Hyper-V detection
            if 'microsoft' in sys_vendor or 'hyper-v' in product_name:
                return {
                    'type': 'Hyper-V',
                    'vendor': sys_vendor or 'Microsoft Corporation',
                    'product': product_name or 'Virtual Machine'
                }
            
            # Xen detection
            if 'xen' in product_name or 'xen' in sys_vendor:
                return {
                    'type': 'Xen',
                    'vendor': sys_vendor or 'Xen',
                    'product': product_name or 'HVM domU'
                }
            
            # Parallels detection
            if 'parallels' in product_name or 'parallels' in sys_vendor:
                return {
                    'type': 'Parallels',
                    'vendor': sys_vendor or 'Parallels Software International Inc.',
                    'product': product_name or 'Parallels Virtual Platform'
                }
            
            # Amazon EC2 detection
            if 'amazon' in sys_vendor or 'ec2' in product_name:
                return {
                    'type': 'Amazon EC2',
                    'vendor': sys_vendor or 'Amazon EC2',
                    'product': product_name or 'Amazon EC2'
                }
            
            # Google Cloud detection
            if 'google' in sys_vendor or 'google compute engine' in product_name:
                return {
                    'type': 'Google Cloud',
                    'vendor': sys_vendor or 'Google',
                    'product': product_name or 'Google Compute Engine'
                }
            
            # Azure detection
            if 'microsoft corporation' in sys_vendor and 'virtual machine' in product_name:
                return {
                    'type': 'Azure',
                    'vendor': sys_vendor or 'Microsoft Corporation',
                    'product': product_name or 'Virtual Machine'
                }
            
        except Exception as e:
            print_warning(f"Error checking DMI info: {e}")
        
        return None
    
    def _check_vm_modules(self):
        """Check for VM-related kernel modules"""
        vm_modules = []
        module_mapping = {
            'vmw_balloon': 'VMware',
            'vmw_vmci': 'VMware',
            'vmwgfx': 'VMware',
            'vboxguest': 'VirtualBox',
            'vboxsf': 'VirtualBox',
            'vboxvideo': 'VirtualBox',
            'virtio': 'QEMU/KVM',
            'virtio_balloon': 'QEMU/KVM',
            'virtio_net': 'QEMU/KVM',
            'virtio_blk': 'QEMU/KVM',
            'xen': 'Xen',
            'xen_blkfront': 'Xen',
            'xen_netfront': 'Xen',
            'hv_balloon': 'Hyper-V',
            'hv_netvsc': 'Hyper-V',
            'hv_storvsc': 'Hyper-V',
            'hv_utils': 'Hyper-V',
        }
        
        try:
            lsmod_output = self.cmd_exec("lsmod 2>/dev/null").lower()
            if not lsmod_output:
                return None
            
            for module, vm_type in module_mapping.items():
                if module in lsmod_output:
                    vm_modules.append({
                        'module': module,
                        'type': vm_type
                    })
        
        except Exception as e:
            print_warning(f"Error checking kernel modules: {e}")
        
        return vm_modules if vm_modules else None
    
    def _check_cpu_info(self):
        """Check CPU information for VM indicators"""
        try:
            cpuinfo = self.cmd_exec("cat /proc/cpuinfo 2>/dev/null").lower()
            if not cpuinfo:
                return None
            
            # Check for hypervisor flag
            if 'hypervisor' in cpuinfo:
                # Try to identify the hypervisor
                if 'vmware' in cpuinfo:
                    return {'type': 'VMware', 'method': 'CPU flags (hypervisor + vmware)'}
                elif 'kvm' in cpuinfo:
                    return {'type': 'QEMU/KVM', 'method': 'CPU flags (hypervisor + kvm)'}
                elif 'microsoft' in cpuinfo:
                    return {'type': 'Hyper-V', 'method': 'CPU flags (hypervisor + microsoft)'}
                else:
                    return {'type': 'Unknown Hypervisor', 'method': 'CPU flags (hypervisor flag present)'}
            
            # Check for specific VM indicators in model name
            if 'qemu' in cpuinfo or 'kvm' in cpuinfo:
                return {'type': 'QEMU/KVM', 'method': 'CPU model name'}
            elif 'vmware' in cpuinfo:
                return {'type': 'VMware', 'method': 'CPU model name'}
            elif 'virtualbox' in cpuinfo:
                return {'type': 'VirtualBox', 'method': 'CPU model name'}
        
        except Exception as e:
            print_warning(f"Error checking CPU info: {e}")
        
        return None
    
    def _check_systemd_detect_virt(self):
        """Check using systemd-detect-virt command"""
        try:
            result = self.cmd_exec("systemd-detect-virt 2>/dev/null").strip().lower()
            if result and result != 'none' and 'error' not in result:
                # Map systemd output to common VM types
                vm_mapping = {
                    'vmware': 'VMware',
                    'kvm': 'QEMU/KVM',
                    'qemu': 'QEMU/KVM',
                    'xen': 'Xen',
                    'microsoft': 'Hyper-V',
                    'oracle': 'VirtualBox',
                    'parallels': 'Parallels',
                    'amazon': 'Amazon EC2',
                    'google': 'Google Cloud',
                    'azure': 'Azure',
                    'openvz': 'OpenVZ',
                    'lxc': 'LXC',
                    'lxc-libvirt': 'LXC',
                    'systemd-nspawn': 'systemd-nspawn',
                    'docker': 'Docker',
                    'podman': 'Podman',
                    'rkt': 'rkt',
                    'bochs': 'Bochs',
                    'uml': 'User-mode Linux',
                    'chroot': 'chroot',
                }
                return vm_mapping.get(result, result.capitalize())
        except Exception as e:
            print_warning(f"Error checking systemd-detect-virt: {e}")
        
        return None
    
    def _check_dmidecode(self):
        """Check using dmidecode command"""
        try:
            # Check if dmidecode is available
            dmidecode_check = self.cmd_exec("which dmidecode 2>/dev/null").strip()
            if not dmidecode_check:
                return None
            
            # Get system information
            sys_info = self.cmd_exec("dmidecode -s system-manufacturer 2>/dev/null").strip().lower()
            product_name = self.cmd_exec("dmidecode -s system-product-name 2>/dev/null").strip().lower()
            
            if not sys_info and not product_name:
                return None
            
            # VMware
            if 'vmware' in sys_info or 'vmware' in product_name:
                return {
                    'type': 'VMware',
                    'vendor': sys_info or 'VMware',
                    'product': product_name or 'VMware Virtual Platform'
                }
            
            # VirtualBox
            if 'virtualbox' in product_name or 'innotek' in sys_info:
                return {
                    'type': 'VirtualBox',
                    'vendor': sys_info or 'innotek GmbH',
                    'product': product_name or 'VirtualBox'
                }
            
            # QEMU/KVM
            if 'qemu' in sys_info or 'qemu' in product_name or 'kvm' in product_name:
                return {
                    'type': 'QEMU/KVM',
                    'vendor': sys_info or 'QEMU',
                    'product': product_name or 'Standard PC'
                }
            
            # Microsoft Hyper-V
            if 'microsoft' in sys_info and 'virtual' in product_name:
                return {
                    'type': 'Hyper-V',
                    'vendor': sys_info or 'Microsoft Corporation',
                    'product': product_name or 'Virtual Machine'
                }
            
            # Xen
            if 'xen' in sys_info or 'xen' in product_name:
                return {
                    'type': 'Xen',
                    'vendor': sys_info or 'Xen',
                    'product': product_name or 'HVM domU'
                }
        
        except Exception as e:
            print_warning(f"Error checking dmidecode: {e}")
        
        return None
    
    def _check_device_tree(self):
        """Check device tree for ARM-based VMs"""
        try:
            # Check for device tree (common on ARM systems)
            model = self.cmd_exec("cat /proc/device-tree/model 2>/dev/null").strip().lower()
            compatible = self.cmd_exec("cat /proc/device-tree/compatible 2>/dev/null").strip().lower()
            
            if not model and not compatible:
                return None
            
            # QEMU ARM
            if 'qemu' in model or 'qemu' in compatible:
                return 'QEMU/KVM (ARM)'
            
            # KVM ARM
            if 'kvm' in model or 'kvm' in compatible:
                return 'QEMU/KVM (ARM)'
            
            # Generic virtualization
            if 'virt' in model or 'virt' in compatible:
                return 'Virtual Machine (ARM)'
        
        except Exception as e:
            print_warning(f"Error checking device tree: {e}")
        
        return None

