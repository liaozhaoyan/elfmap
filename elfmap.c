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

struct elf_info {
    off_t bias;
    int symtabs;
    int dynsyms;
};

#define MT_NAME "ELFMAP_HANDLE"

#define SYMBOL_LEN  64
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

static int item(lua_State *L) {
    struct elf_symbol *priv = (struct elf_symbol *)luaL_checkudata(L, 1, MT_NAME);
    luaL_argcheck(L, priv != NULL, 1, "`array' expected");
    int count = priv->start;
    int i = luaL_checknumber(L, 2);

    if (i > 0 && i <=count) {
        priv += i;
        lua_pushstring(L, priv->sym);
        lua_pushnumber(L, priv->start);
        lua_pushnumber(L, priv->end);
    } else {
        lua_pushstring(L, "[unknown]");
        lua_pushnumber(L, -1);
        lua_pushnumber(L, -1);
    }
    return 3;
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

static int elf_sym_count64(char *addr, Elf64_Shdr *shdr, int index) {
    int j;
    int count = 0;
    Elf64_Sym *symtab = symtab = (Elf64_Sym *) (addr + shdr[index].sh_offset);
    int sym_link_idx = shdr[index].sh_link;
    int num_syms = shdr[index].sh_size / sizeof(Elf64_Sym);
    char *sym_name_offset = addr + shdr[sym_link_idx].sh_offset;

    for (j = 0; j < num_syms; j++) {
        if (ELF64_ST_TYPE(symtab[j].st_info) == 2  //func
            && symtab[j].st_size > 0) {
            count ++;
        }
    }
    return count;
}

static int elf_sym_count32(char *addr, Elf32_Shdr *shdr, int index) {
    int j;
    int count = 0;
    Elf32_Sym *symtab = symtab = (Elf32_Sym *) (addr + shdr[index].sh_offset);
    int sym_link_idx = shdr[index].sh_link;
    int num_syms = shdr[index].sh_size / sizeof(Elf32_Sym);
    char *sym_name_offset = addr + shdr[sym_link_idx].sh_offset;

    for (j = 0; j < num_syms; j++) {
        if (ELF32_ST_TYPE(symtab[j].st_info) == 2  //func
            && symtab[j].st_size > 0) {
            count ++;
        }
    }
    return count;
}

static Elf64_Addr elf64_bias(char* addr, Elf64_Ehdr *ehdr) {
    int i;
    Elf64_Addr bias = 0;
    Elf64_Phdr *phdr;

    phdr = (Elf64_Phdr *)(addr + ehdr->e_phoff);
    for (i = 0; i < ehdr->e_phnum; i ++) {
        if (phdr->p_type == PT_LOAD) {
            bias = phdr->p_vaddr;
            break;
        }
        phdr ++;
    }
    return bias;
}

//Walk all symbol
static int n_symbol64(char *addr, Elf64_Ehdr *ehdr, Elf64_Shdr *shdr, struct elf_info* info) {
    Elf64_Sym *symtab = NULL;
    int i, set = 0;

    for (i = 0; i < ehdr->e_shnum; i ++) {
        switch (shdr[i].sh_type) {
            case SHT_SYMTAB:
                info->symtabs = elf_sym_count64(addr, shdr, i);
                set = 1;
                break;
            case SHT_PROGBITS:
                if (set > 0 && (info->dynsyms > 0 ||info->symtabs > 0)) {
                    goto setn_symbol64;
                }
                break;
            default:
                break;
        }
    }
    setn_symbol64:
    info->bias = elf64_bias(addr, ehdr);
    return 0;
}

static Elf32_Addr elf32_bias(char* addr, Elf32_Ehdr *ehdr) {
    int i;
    Elf32_Addr bias = 0;
    Elf32_Phdr *phdr;

    phdr = (Elf32_Phdr *)(addr + ehdr->e_phoff);
    for (i = 0; i < ehdr->e_phnum; i ++) {
        if (phdr->p_type == PT_LOAD) {
            bias = phdr->p_vaddr;
            break;
        }
        phdr ++;
    }
    return bias;
}

static int n_symbol32(char *addr, Elf32_Ehdr *ehdr, Elf32_Shdr *shdr, struct elf_info* info) {
    Elf32_Sym *symtab = NULL;
    int i, set = 0;

    for (i = 0; i < ehdr->e_shnum; i ++) {
        switch (shdr[i].sh_type) {
            case SHT_SYMTAB:
                info->symtabs = elf_sym_count32(addr, shdr, i);
                set = 1;
                break;
            case SHT_PROGBITS:
                if (set > 0 && (info->dynsyms > 0 ||info->symtabs > 0)) {
                    goto setn_symbol32;
                }
                break;
            default:
                break;
        }
    }
    setn_symbol32:
    info->bias = elf32_bias(addr, ehdr);
    return 0;
}

//load all symbol
static void load_symbol64(char *addr, Elf64_Ehdr *ehdr, Elf64_Shdr *shdr,
                        struct elf_symbol *priv, struct elf_info *info) {
    Elf64_Sym *symtab = NULL;
    int i, j;
    int sh_type = info->symtabs > 0 ? SHT_SYMTAB : SHT_DYNSYM;
    off_t bias = info->symtabs > 0 ? 0 : info->bias;

    for (i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type != sh_type)
            continue;

        symtab = (Elf64_Sym *) (addr + shdr[i].sh_offset);
        int sym_link_idx = shdr[i].sh_link;
        int num_syms = shdr[i].sh_size / sizeof(Elf64_Sym);
        char *sym_name_offset = addr + shdr[sym_link_idx].sh_offset;

        for (j = 0; j < num_syms; j++) {
            if (ELF64_ST_TYPE(symtab[j].st_info) == 2
                && symtab[j].st_size > 0) {

                strncpy(priv->sym, sym_name_offset + symtab[j].st_name, SYMBOL_LEN - 1);
                priv->start = symtab[j].st_value - bias;
                priv->end = priv->start + symtab[j].st_size;
                priv ++;
            }
        }
    }
}

static void load_symbol32(char *addr, Elf32_Ehdr *ehdr, Elf32_Shdr *shdr,
                          struct elf_symbol *priv, struct elf_info *info) {
    Elf32_Sym *symtab = NULL;
    int i, j;
    int sh_type = info->symtabs > 0 ? SHT_SYMTAB : SHT_DYNSYM;
    off_t bias = info->symtabs > 0 ? 0 : info->bias;

    for (i = 0; i < ehdr->e_shnum; i++) {
        if (shdr[i].sh_type != sh_type)
            continue;

        symtab = (Elf32_Sym *) (addr + shdr[i].sh_offset);
        int sym_link_idx = shdr[i].sh_link;
        int num_syms = shdr[i].sh_size / sizeof(Elf32_Sym);
        char *sym_name_offset = addr + shdr[sym_link_idx].sh_offset;

        for (j = 0; j < num_syms; j++) {
            if (ELF32_ST_TYPE(symtab[j].st_info) == 2
                && symtab[j].st_size > 0) {
                strncpy(priv->sym, sym_name_offset + symtab[j].st_name, SYMBOL_LEN - 1);
                priv->start = symtab[j].st_value - bias;
                priv->end = priv->start + symtab[j].st_size;
                priv ++;
            }
        }
    }
}

static struct elf_symbol * elf64(lua_State *L, char *addr) {
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    Elf64_Shdr *shdr;
    int i, count;
    struct elf_symbol *priv;
    struct elf_info info = {0, 0, 0};

    ehdr = (Elf64_Ehdr*)addr;
    phdr = (Elf64_Phdr *)(addr + ehdr->e_phoff);
    shdr = (Elf64_Shdr *)(addr + ehdr->e_shoff);

    for (i = 0; i < ehdr->e_phnum; i ++) {
        if (phdr->p_type == PT_LOAD) {
            printf("PT_LOAD: 0x%lx\n", phdr->p_vaddr);
        }
        phdr ++;
    }

    n_symbol64(addr, ehdr, shdr, &info);
    count = info.symtabs > 0 ? info.symtabs : info.dynsyms;

    priv = (struct elf_symbol *)lua_newuserdata(L, sizeof(struct elf_symbol) * (count + 1));
    priv->start = count;   // region 0 to record count of symbols and offset.
    priv->end = info.bias;
    priv->sym[0] = '\0';

    load_symbol64(addr, ehdr, shdr, priv + 1, &info);
    return priv;
}

static struct elf_symbol * elf32(lua_State *L, char *addr) {
    Elf32_Ehdr *ehdr;
    Elf32_Shdr *shdr;
    int count;
    struct elf_symbol *priv;
    struct elf_info info = {0, 0, 0};

    ehdr = (Elf32_Ehdr*)addr;
    shdr = (Elf32_Shdr *)(addr + ehdr->e_shoff);

    n_symbol32(addr, ehdr, shdr, &info);
    count = info.symtabs > 0 ? info.symtabs : info.dynsyms;

    priv = (struct elf_symbol *)lua_newuserdata(L, sizeof(struct elf_symbol) * (count + 1));
    priv->start = count;   // region 0 to record count of symbols and offset.
    priv->end = info.bias;
    priv->sym[0] = '\0';

    load_symbol32(addr, ehdr, shdr, priv + 1, &info);
    return priv;
}

static int sort_symbol(const void *a, const void * b) {
    struct elf_symbol *sa = (struct elf_symbol *)a;
    struct elf_symbol *sb = (struct elf_symbol *)b;
    return (sa->start - sb->start);
}

static int new(lua_State *L) {
    const char *fPath = luaL_checkstring(L, 1);
    int elf_file_fd = open(fPath, O_RDONLY);
    off_t file_size;
    size_t syms;
    char *addr;
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

    if (memcmp(addr, ELFMAG, SELFMAG) != 0) {
        close(elf_file_fd);
        luaL_error(L, "file %s is not a elf file.\n", fPath);
    }

    switch (addr[4]) {
        case 1:
            priv = elf32(L, addr);
            break;
        case 2:
            priv = elf64(L, addr);
            break;
        default:
            close(elf_file_fd);
            luaL_error(L, "file %s is not a bad file.\n", fPath);
    }

    munmap(addr, file_size);
    close(elf_file_fd);

    syms = priv->start;
    qsort(priv + 1, syms, sizeof(struct elf_symbol), sort_symbol);

    luaL_getmetatable(L, MT_NAME);
    lua_setmetatable(L, -2);
    return 1;
}

static luaL_Reg module_m[] = {
        {"maps", maps},
        {"item", item},
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
