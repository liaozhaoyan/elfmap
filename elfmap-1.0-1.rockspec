package = "elfmap"
version = "1.0-1"
source = {
    url = "git://github.com/liaozhaoyan/elfmap",
}
description = {
    summary = "get all elf file symbols.",
    license = "MIT",
    homepage = "https://github.com/liaozhaoyan/elfmap",
    detailed = [[
get all elf file symbols.
]],
}
dependencies = {
    "lua >= 5.1",

}
external_dependencies = {
    INOTIFY = {
        header = {"elf.h", "sys/mman.h", "sys/stat.h"}
    }
}
build = {
    type = "builtin",
    modules = {
        ['elfmap'] = {
            sources = {"elfmap.c"},
        }
    },
}