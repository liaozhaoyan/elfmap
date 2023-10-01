//
// Created by 廖肇燕 on 2023/9/29.
//


#include <lua.h>
#include <lauxlib.h>

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define MT_NAME "ELFMAP_HANDLE"

#define SYMBOL_LEN  32
struct elf_symbol{
    off_t start;
    off_t end;
    char sym[SYMBOL_LEN];
};

static int handle_map_iterator(lua_State *L) {
    int val = lua_tonumber(L, lua_upvalueindex(1));
    int top = lua_tonumber(L, lua_upvalueindex(2));
    struct elf_symbol *priv = lua_touserdata(L, lua_upvalueindex(3));

    if (val < top ) {
        priv += val + 1;   // index start at 1.
        val ++;
        lua_pushnumber(L, val); /* new value */
        lua_pushvalue(L, -1); /* duplicate it */
        lua_replace(L,lua_upvalueindex(1)); /*updateupvalue*/

        lua_pushnumber(L, priv->start); /* start */
        lua_pushnumber(L, priv->end); /* end */
        lua_pushstring(L, priv->sym); /* symbol */
        return 4; /* return new value */
    }
    return 0;
}

static int maps(lua_State *L) {
    struct elf_symbol *priv = (struct elf_symbol *)luaL_checkudata(L, 1, MT_NAME);
    luaL_argcheck(L, priv != NULL, 1, "`array' expected");

    lua_pushnumber(L, 0);   // index.
    lua_pushnumber(L, priv->start);   // max index.
    lua_pushlightuserdata(L, priv);   // base point frame.
    lua_pushcclosure(L, &handle_map_iterator, 3);
    return 1;
}

static int count(lua_State *L) {
    int count;
    struct elf_symbol *priv = (struct elf_symbol *)luaL_checkudata(L, 1, MT_NAME);
    luaL_argcheck(L, priv != NULL, 1, "`array' expected");

    count = priv->start;
    lua_pushnumber(L, count);
    return 1;
}

static int query(lua_State *L) {
    struct elf_symbol *priv = (struct elf_symbol *)luaL_checkudata(L, 1, MT_NAME);
    luaL_argcheck(L, priv != NULL, 1, "`array' expected");
    off_t addr = luaL_checknumber(L, 2);
    int count = priv->start;
    priv ++;   // index start at 1. need to add one.
    int left = 0, right = count - 1, mid;

    while (left <= right) {
        struct elf_symbol *var;

        mid = (left + right) / 2;
        var = priv + mid;
        if (addr > var->end) {  // larger than end, move to right.
            left = mid + 1;
        } else if (addr < var->start) {   // lower than start, move to left.
            right = mid - 1;
        } else {
            if (addr >= var->start && addr <= var->end) {
                lua_pushstring(L, var->sym);
                lua_pushnumber(L, var->start);
                lua_pushnumber(L, var->end);
            } else {
                lua_pushstring(L, "[unknown]");
                lua_pushnumber(L, -1);
                lua_pushnumber(L, -1);
            }
            return 3;
        }
    }
    lua_pushstring(L, "[unknown]");
    lua_pushnumber(L, -1);
    lua_pushnumber(L, -1);
    return 3;
}

static int symbol(lua_State *L) {
    int i, count;
    off_t start = -1, end = -1;
    struct elf_symbol *priv = (struct elf_symbol *)luaL_checkudata(L, 1, MT_NAME);
    luaL_argcheck(L, priv != NULL, 1, "`array' expected");
    const char *sym = luaL_checkstring(L, 2);

    count = priv->start;
    priv ++;
    for (i = 0; i < count; i ++) {
        if (strncasecmp(sym, priv->sym, SYMBOL_LEN) == 0) {
            start = priv->start;
            end   = priv->end;
        }
        priv ++;
    }
    lua_pushnumber(L, start);
    lua_pushnumber(L, end);
    return 2;
}

//Function to get the size of the ELF file
static off_t get_elf_size(int elf_file_fd) {
    struct stat file_stats;
    fstat(elf_file_fd, &file_stats);
    return file_stats.st_size;
}

//Walk all symbol
static int n_symbol(char *addr, Elf64_Ehdr *ehdr, Elf64_Shdr *shdr) {
    Elf64_Sym *symtab = NULL;
    int i, j;
    int count = 0;

    for (i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type != SHT_SYMTAB)
            continue;

        symtab = (Elf64_Sym *) (addr + shdr[i].sh_offset);
        int sym_link_idx = shdr[i].sh_link;
        int num_syms = shdr[i].sh_size / sizeof(Elf64_Sym);
        char *sym_name_offset = addr + shdr[sym_link_idx].sh_offset;

        for (j = 0; j < num_syms; j++) {
            if (ELF64_ST_TYPE(symtab[j].st_info) == 2
                && symtab[j].st_size > 0) {
                count ++;
            }
        }
    }
    return count;
}

static int sort_symbol(const void *a, const void * b) {
    struct elf_symbol *sa = (struct elf_symbol *)a;
    struct elf_symbol *sb = (struct elf_symbol *)b;
    return (sa->start - sb->start);
}

//load all symbol
static void load_symbol(char *addr, Elf64_Ehdr *ehdr, Elf64_Shdr *shdr, struct elf_symbol *priv) {
    Elf64_Sym *symtab = NULL;
    int i, j;

    for (i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type != SHT_SYMTAB)
            continue;

        symtab = (Elf64_Sym *) (addr + shdr[i].sh_offset);
        int sym_link_idx = shdr[i].sh_link;
        int num_syms = shdr[i].sh_size / sizeof(Elf64_Sym);
        char *sym_name_offset = addr + shdr[sym_link_idx].sh_offset;

        for (j = 0; j < num_syms; j++) {
            if (ELF64_ST_TYPE(symtab[j].st_info) == 2
                && symtab[j].st_size > 0) {
                strncpy(priv->sym, sym_name_offset + symtab[j].st_name, SYMBOL_LEN);
                priv->start = symtab[j].st_value;
                priv->end = priv->start + symtab[j].st_size;
                priv ++;
            }
        }
    }
}

static int new(lua_State *L) {
    const char *fPath = luaL_checkstring(L, 1);
    int elf_file_fd = open(fPath, O_RDONLY);
    off_t file_size;
    char *addr;
    Elf64_Ehdr *ehdr;
    Elf64_Shdr *shdr;
    int count;
    struct elf_symbol *priv;

    if (elf_file_fd < 0) {
        luaL_error(L, "open file %s failed, errno:%d, %s\n", fPath, errno, strerror(errno));
    }
    file_size = get_elf_size(elf_file_fd);
    addr = (char *)mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, elf_file_fd, 0);
    if (addr == NULL) {
        close(elf_file_fd);
        luaL_error(L, "mmap file %s failed, errno:%d, %s\n", fPath, errno, strerror(errno));
    }
    ehdr = (Elf64_Ehdr*)addr;
    shdr = (Elf64_Shdr *)(addr + ehdr->e_shoff);

    count = n_symbol(addr, ehdr, shdr) + 1;
    priv = (struct elf_symbol *)lua_newuserdata(L, sizeof(struct elf_symbol) * count);
    priv->start = count;   // region 0 to record count of symbols.
    priv->end = 0;
    priv->sym[0] = '\0';
    load_symbol(addr, ehdr, shdr, priv + 1);
    munmap(addr, file_size);
    close(elf_file_fd);
    qsort(priv + 1, count - 1, sizeof(struct elf_symbol), sort_symbol);

    luaL_getmetatable(L, MT_NAME);
    lua_setmetatable(L, -2);
    return 1;
}

static luaL_Reg module_m[] = {
        {"maps", maps},
        {"count", count},
        {"query", query},
        {"symbol", symbol},
        {NULL, NULL}
};

static luaL_Reg module_f[] = {
        {"new", new},
        {NULL, NULL}
};

int luaopen_elfmap(lua_State *L) {
    luaL_newmetatable(L, MT_NAME);

    lua_createtable(L, 0, sizeof(module_m) / sizeof(luaL_Reg) - 1);
#if LUA_VERSION_NUM > 501
    luaL_setfuncs(L, module_m, 0);
#else
    luaL_register(L, NULL, module_m);
#endif
    lua_setfield(L, -2, "__index");
    lua_pop(L, 1);

#if LUA_VERSION_NUM > 501
    luaL_newlib(L, module_f);
#else
    luaL_register(L, "elfmap", module_f);
#endif
    return 1;
}
