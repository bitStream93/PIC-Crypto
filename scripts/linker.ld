IMAGE_BASE = 0x140000000;
SECTIONS
{
    . = IMAGE_BASE + 0x1000;

    .text ALIGN(0x1000) :
    {
        *(.text$A);
        *(.text$B);
        *(.rdata*);
        *(.text$C);
    }
    /DISCARD/ :
    {
        *(.pdata)
        *(.xdata)
        *(.idata)
        *(.reloc)
    }
}