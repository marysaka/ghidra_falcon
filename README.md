# Nvidia Falcon plugin for Ghidra

This is pretty immature, so you'll probably need to do some development to use it, but it's likely good enough to save a bit of time over an `envydis` dead-listing.

![Screenshot](/images/screenshot1.png)

## Setup instructions

- Ensure you have the ``JAVA_HOME`` environment variable set to the path of your JDK 11 installation.
- Set the ``GHIDRA_INSTALL_DIR`` environment variable to your Ghidra install directory.
- Run ``./gradlew``
- You'll find the output zip file inside ``/dist``
- Copy the output zip to ``<Ghidra install directory>/Extensions/Ghidra``
- Start Ghidra and use the "Install Extensions" dialog to finish the installation (``File -> Install Extensions...``)

## Development

This is just how I do it:

Open up the [envytools Falcon ISA documentation](https://envytools.readthedocs.io/en/latest/hw/falcon/isa.html) to compare the semantic information with the reference pseudocode. Open Ghidra's `doc/languages/index.html` for a reference for how the Sleigh language works.

Load your test binary in Ghidra.

Use [envydis](https://github.com/envytools/envytools) on the binary you're looking at so you can quickly check the disassembly for errors if anything seems off.

In Ghidra enable PCode display by clicking the "Edit the Listing fields" icon at the top of the Listing view, right clicking "PCode" and clicking "Enable Field" (you may wish to toggle this on-and-off during reversing as it is quite verbose).

In Ghidra open the script manager ("Window" -> "Script Manager") and add key-bindings for `DebugSleighInstructionParse.java` and `ReloadSleighLangauge.java`.

`DebugSleighInstructionParse.java` will log detailed debug information about the instruciton parse for the byte under the cursor. I usually use it to find the `{line# 756} ld_b32 <reg2>, D[<reg1>]` so I know what line to go to to fix the PCode output.

`ReloadSleighLangauge.java` will reload most changes to the slaspec, including new instructions and new semantic definitions. However, if you add new registers or new `define pcodeop ...` statements, you will need to restart Ghidra to get correct output.

### Adding instructions to the decompiler

At the moment any particularly poorly implemented instruction should show up as a call to the `todo` pcodeop in the decompiler output - this is a hint that the instruction should be implemented for correct decompilation. Get the line number using `DebugSleighInstructionParse.java` on the corresponding instruction, and add the implementation to the slaspec/sinc file.

See Ghidra's `doc/languages/index.html` for more information about how to describe instructions.

Run `ReloadSleighLangauge.java`, or, if you've added a new pcodeop for the instruction, close and re-open Ghidra to see the new output.


### Adding instructions to the disassembler

If you hit undecodable instruction bytes, find the correct decoding in your `envydis` output, then search through the `envydis.sinc` file for the envydis source comment that matches. For example:

```
#	{ 0x0004003c, 0x000f003f, OP3B, N("shl"), T(sz), REG3, REG1, REG2 },
```

Try to find an implemented instruction using the same encoding/operands, for example:

```
#	{ 0x0002003c, 0x000f003f, OP3B, N("sub"), T(sz), REG3, REG1, REG2 },
:sub_b32 reg3, reg1, reg2 is op_format=0x3c & op_size=2; reg2 & reg1; subopcode3=0x2 & reg3 {
  sub(reg3, reg1, reg2);
}
```

Copy-paste and change the opcode/subopcode, mnemonic, and implementation:

```
:shl_b32 reg3, reg1, reg2 is op_format=0x3c & op_size=2; reg2 & reg1; subopcode3=0x4 & reg3 {
  todo();
}
```

Reload (with your `ReloadSleighLangauge.java` hotkey), disassembly the bytes (by pressing `D`), and check the output is correct. If it fails to disassemble, double check your code, or use `DebugSleighInstructionParse.java` to see where it goes wrong.

If you hit errors reloading, you can view the log by clicking the "Show Console" icon at the bottom Ghidra project window (the one with the file listing, not the CodeBrowser/disassembly window). The errors are only helpful some of the time, so I usually check my changes by hand first to see if I can spot what I did wrong.

## To-Do

Personally I've avoided pre-emptively adding operations that I can't test/verify easily, because I'm sure I'd even more mistakes and not realise I hadn't verified things. It should be practical to generate a huge test file covering every instruction encoding with different operand values, and automatically compare the Ghidra and envydis output to finish the instruction decoding.

Known issues:

* crypto coprocessor stuff is incorrect and messy
* separate the address spaces - this is causing weird problems
* fix mpush/mpop implementation (and variants)
* get arguments passed on the stack tested and working

## Resources

* https://envytools.readthedocs.io/en/latest/hw/falcon/index.html
* https://switchbrew.org/wiki/TSEC
