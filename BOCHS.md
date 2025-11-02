# Bochs configuration
## Windows users
You are the lucky guys, as you only need to download the binary and install Bochs that way. Head to [this website](https://sourceforge.net/projects/bochs/files/bochs/), and download the latest version, then check the last section of this readme.

## Linux users
Dear Linux users, now you need to make a decision: do you want to debug the MBR with the console, or with the GUI? If the answer is with the console, you can simply install bochs from your package manager, in the other case (also my case), I prefer the GUI, just so I don't have to use commands each time, we need to compile the emulator from source. While this seems a terrible task, is actually a really simple and fast one.

Rember to check the last readme section after the installation.

### Installing form the package manager
To install the emulator from the package manager you need to find the right command for your distro. In debian based one, the command is `sudo apt install bochs`. For Linux RPM I'm aware that there is a binary in [the website](https://sourceforge.net/projects/bochs/files/bochs/), but there should also be one from your package manager.

### Building from source
#### Gathering the source code
For us, we need to download the source code, from [the website](https://sourceforge.net/projects/bochs/files/bochs/) (the `tar.gz` file). The lastest version at the moment of writing this readme is `2.8`, I'll download `bochs-2.8.tar.gz`.

Now we need to extract the archive. We can do that using the following command: `tar -xvzf bochs-2.8.tar.gz`.

#### Preparing the compilation
Let's `cd` inside the extracted directory, and execute the following command:
`./configure --with-x11 --enable-debugger --enable-debugger-gui --enable-idle-hack --enable-xpm --enable-show-ips --enable-logging --enable-assert-checks --enable-cpu-level=6 --enable-fpu --enable-x86-64 --enable-vmx --enable-avx --enable-alignment-check --enable-long-phy-address --enable-a20-pin --enable-large-ramfile --enable-repeat-speedups --enable-fast-function-calls --enable-handlers-chaining --enable-cdrom --enable-iodebug --enable-pci --enable-usb`.

***Note: For AMD CPU users, change the `--enable-vmx` parameter with `--enable-svm`.***

*Note: to be able to use the debugger GUI with x11, install* ***xorg-dev*** *and* ***libgtk3-dev***

*Note: I know that all there parameters are not necessary, but just for safety I included the ones which may come handy and could be helpfull. If you know what you're doing, you can check out the [compilation page](https://bochs.sourceforge.io/doc/docbook/user/compiling.html), and use your own parameters.*

#### Compiling
We can now continue with the following command: `make`.

*Note: you can speed up the compilation of the emulator by specifying the number of **threads** your processor have with the `-j` parameter. For example, my processor has 28 threads, so I'm going to compile the emulator with the following command: `make -j 28`.*

#### Saving the compiled files on the system
Now we can just execute the following command, `sudo make install` (use sudo), and just like that, we've compiled and installed the emulator!

## Common configuration
Create a folder wherever you want: inside this folder you'll put all the files needed for the emulation. I'll refer to this folder as `emulation folder`. Inside this folder create a file called `bochsrc.bxrc`, and inside this file write the following:

```
megs: 512

# Uncomment these two lines if you're on Windows
# romimage: file="BIOS-bochs-latest"
# vgaromimage: file="VGABIOS-lgpl-latest"

boot: cdrom, disk
ata0-master: type=disk, path="whateveryouwant.img", mode=flat
mouse: enabled=0
cpu: ips=90000000

# Uncomment if you're on Linux and you're using the GUI
display_library: x, options="gui_debug"

# Uncomment if you're on Windows and you're using the GUI
# display_library: win32, options="gui_debug"
```

Uncomment the lines according to your operating system.

### Windows users
For you Windows users, you need to go inside the Bochs install folder (Usually inside `Program Files`) and copy two files inside the `emulation folder`. Those files are `BIOS-bochs-latest` and `VGABIOS-lgpl-latest`.

Also, put the bochs setup folder inside the PATH. You can do this with the `Environment Variables` menu.

### Back to the common steps
Now that we successfully installed the emulator on our system, we can prepare all the necessary files in order to run the emulation. First of all, copy the infected MBR from your infected virtual machine into a file, for example with a hex editor (I won't go into details on how to do that, there are plenty of online resources what covers that topic).

Sometimes just the MBR payload won't be enough (like in the NotPetya's case). In that case, copy all the disk sectors needed for the malware to run into the file (or simply copy as much as you think is enough, for instance I copied 128 sectors for NotPetya).

Now that you have the file, we need to create the disk image in which the payload will be executed. We'll use the `bximage` command to do so.
These are the parameters you need in order to create the image:

```
ERROR: Parameter -func missing - switching to interactive mode.

========================================================================
                                bximage
  Disk Image Creation / Conversion / Resize and Commit Tool for Bochs
                                  $Id$
========================================================================

1. Create new floppy or hard disk image
2. Convert hard disk image to other format (mode)
3. Resize hard disk image
4. Commit 'undoable' redolog to base image
5. Disk image info

0. Quit

Please choose one [0] 1

Create image

Do you want to create a floppy disk image or a hard disk image?
Please type hd or fd. [hd] hd

What kind of image should I create?
Please type flat, sparse, growing, vpc or vmware4. [flat] flat

Choose the size of hard disk sectors.
Please type 512, 1024 or 4096. [512] 512

Enter the hard disk size in megabytes, between 10 and 8257535
[10] 10

What should be the name of the image?
[c.img] whateveryouwant.img

Creating hard disk image 'whateveryouwant.img' with CHS=20/16/63 (sector size = 512)

The following line should appear in your bochsrc:
    ata0-master: type=disk, path="whateveryouwant.img", mode=flat
```

*Note: remember to adapt some parameters if you need to, like the bytes per sector, the hard disk size, and the image name...*

Now that you have the image, you can just open the image in the hex editor, and replace the image sectors with your sectors.

## Run the emulation
Now if you are using Linux, just run the following command: `bochs -q -f ./bochsrc.kxrc`. For you Windows user the command is the following: `bochsdbg.exe -q -f ./bochsrc.kxrc`

If all the steps above were done correctly, you should have a window with the Bochs debugger GUI (For those who uses the GUI of course), and a window with the Bochs emulation screen.