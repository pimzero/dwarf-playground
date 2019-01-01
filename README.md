Some tests/tools with DWARF debugging format.

## `debug_line`

Shows informations in the `.debug_line` section.

Flags:
 - `-l` toggles showing each couple (line, address) in file (i.e. dump each
   matrix rows). Similar to `objdump --dwarf=decodedline`
 - `-d` disassembles the opcodes in the `.debug_line` section. Smilar to
   `objdump --dwarf=line`

Sources:
 - [dwarfstd.org](http://dwarfstd.org/)
 - [Eli Bendersky's website](https://eli.thegreenplace.net/2011/02/07/how-debuggers-work-part-3-debugging-information)
 - [OSDEV](https://wiki.osdev.org/DWARF)
 - [Wikipedia - LEB128](https://en.wikipedia.org/wiki/LEB128)
