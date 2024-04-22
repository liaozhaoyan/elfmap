//
// Created by 廖肇燕 on 2023/9/29.
//


#include <lua.h>
#include <lauxlib.h>

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <sys/stat.h>
#include <unistd.h>
#include <assert.h>

struct elf_info {
    off_t bias;
    int symtabs;
    int dynsyms;
};

#define MT_NAME "ELFMAP_HANDLE"

#define SYMBOL_LEN  112
struct elf_symbol{
    off_t start;
    off_t end;
    char* sym;
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
        lua_replace(L, lua_upvalueindex(1)); /*updateupvalue*/

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

static int bias(lua_State *L) {
    int bias;
    struct elf_symbol *priv = (struct elf_symbol *)luaL_checkudata(L, 1, MT_NAME);
    luaL_argcheck(L, priv != NULL, 1, "`array' expected");

    bias = priv->end;
    lua_pushnumber(L, bias);
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
        if (strcasecmp(sym, priv->sym) == 0) {
            start = priv->start;
            end   = priv->end;
        }
        priv ++;
    }
    lua_pushnumber(L, start);
    lua_pushnumber(L, end);
    return 2;
}

static int elf_get_bias(Elf *elf, struct elf_info *info) {
    size_t i, n;

    if (elf_getphdrnum(elf, &n) != 0) {
        return -1;
    }

    for (i = 0; i < n; i++) {
        GElf_Phdr phdr;
        if (gelf_getphdr(elf, i, &phdr) != NULL) {
            if (phdr.p_type == PT_LOAD && (phdr.p_flags & PF_X)) {
                info->bias = phdr.p_vaddr;
                return 0;
            }
        } else {
            return -1;
        }
    }

    return -1;
}

static int elf_sym_count64(Elf *elf, Elf_Scn *scn, GElf_Shdr *shdr) {
    Elf_Data *data;
    GElf_Sym sym;
    int symbols_count, i;
    int ret = 0;

    data = elf_getdata(scn, NULL);
    symbols_count = data->d_size / sizeof(GElf_Sym);

    for (i = 0; i < symbols_count; i++) {
        gelf_getsym(data, i, &sym);

        if (ELF64_ST_TYPE(sym.st_info) == STT_FUNC && sym.st_shndx != SHN_UNDEF) {
            ret ++;
        }
    }
    return ret;
}

static int elf_sym_count32(Elf *elf, Elf_Scn *scn, GElf_Shdr *shdr) {
    Elf_Data *data;
    GElf_Sym sym;
    int symbols_count, i;
    int ret = 0;

    data = elf_getdata(scn, NULL);
    symbols_count = data->d_size / sizeof(GElf_Sym);

    for (i = 0; i < symbols_count; i++) {
        gelf_getsym(data, i, &sym);

        if (ELF32_ST_TYPE(sym.st_info) == STT_FUNC && sym.st_shndx != SHN_UNDEF) {
            ret ++;
        }
    }
    return ret;
}

//Walk all symbol
static int n_symbol64(Elf *elf, struct elf_info *info) {
    Elf_Scn *scn;
    GElf_Shdr shdr;
    size_t shnum;
    int i;

    if (elf_get_bias(elf, info) < 0) {
        return -1;
    }

    if (elf_getshdrnum(elf, &shnum) != 0) {
        return -1;
    }

    for (i = 0; i < shnum; i ++) {   // get bias
        scn = elf_getscn(elf, i);
        gelf_getshdr(scn, &shdr);

        if (shdr.sh_type == SHT_SYMTAB) {
            info->symtabs = elf_sym_count64(elf, scn, &shdr);
        } else if (shdr.sh_type == SHT_DYNSYM) {
            info->dynsyms = elf_sym_count64(elf, scn, &shdr);
        }
    }
    return 0;
}

static int n_symbol32(Elf *elf, struct elf_info *info) {
    Elf_Scn *scn;
    GElf_Shdr shdr;
    size_t shnum;
    int i;

    if (elf_get_bias(elf, info) < 0) {
        return -1;
    }

    if (elf_getshdrnum(elf, &shnum) != 0) {
        return -1;
    }

    for (i = 0; i < shnum; i ++) {   // get bias
        scn = elf_getscn(elf, i);
        gelf_getshdr(scn, &shdr);

        if (shdr.sh_type == SHT_SYMTAB) {
            info->symtabs = elf_sym_count32(elf, scn, &shdr);
        } else if (shdr.sh_type == SHT_DYNSYM) {
            info->dynsyms = elf_sym_count32(elf, scn, &shdr);
        }
    }
    return 0;
}

//load all symbol
static int load_symbol64(Elf *elf, struct elf_symbol *priv, struct elf_info *info) {
    int sh_type = info->symtabs > 0 ? SHT_SYMTAB : SHT_DYNSYM;
    GElf_Shdr shdr;
    Elf_Scn *scn = NULL;

    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr) {
            return -1;
        }
        if (shdr.sh_type == sh_type) {
            Elf_Data *data;
            GElf_Sym sym;
            int symbols_count, i;
            char *sym_name;

            data = elf_getdata(scn, NULL);
            symbols_count = data->d_size / sizeof(GElf_Sym);

            for (i = 0; i < symbols_count; i++) {
                gelf_getsym(data, i, &sym);
                if (ELF64_ST_TYPE(sym.st_info) == STT_FUNC && sym.st_shndx != SHN_UNDEF) {
                    int len;
                    char *dst;
                    sym_name = elf_strptr(elf, shdr.sh_link, sym.st_name);
                    len = strlen(sym_name) + 1;
                    dst = malloc(len);
                    assert(dst != NULL);
                    strcpy(dst, sym_name);

                    priv->sym = dst;
                    priv->start = sym.st_value;
                    priv->end = priv->start + sym.st_size;
                    priv ++;
                }
            }
        }
    }
    return 0;
}

static int load_symbol32(Elf *elf, struct elf_symbol *priv, struct elf_info *info) {
    int sh_type = info->symtabs > 0 ? SHT_SYMTAB : SHT_DYNSYM;
    GElf_Shdr shdr;
    Elf_Scn *scn = NULL;

    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        if (gelf_getshdr(scn, &shdr) != &shdr) {
            return -1;
        }
        if (shdr.sh_type == sh_type) {
            Elf_Data *data;
            GElf_Sym sym;
            int symbols_count, i;
            char *sym_name;

            data = elf_getdata(scn, NULL);
            symbols_count = data->d_size / sizeof(GElf_Sym);

            for (i = 0; i < symbols_count; i++) {
                gelf_getsym(data, i, &sym);
                if (ELF32_ST_TYPE(sym.st_info) == STT_FUNC && sym.st_shndx != SHN_UNDEF) {
                    int len;
                    char *dst;
                    sym_name = elf_strptr(elf, shdr.sh_link, sym.st_name);
                    len = strlen(sym_name) + 1;
                    dst = malloc(len);
                    assert(dst != NULL);
                    strcpy(dst, sym_name);

                    priv->sym = dst;
                    priv->start = sym.st_value;
                    priv->end = priv->start + sym.st_size;
                    priv ++;
                }
            }
            break;
        }
    }
    return 0;
}

static struct elf_symbol * elf64(lua_State *L, Elf *elf) {
    int count;
    struct elf_symbol *priv;
    struct elf_info info = {0, 0, 0};

    if (n_symbol64(elf, &info) < 0 ) {
        return NULL;
    }
    count = info.symtabs > 0 ? info.symtabs : info.dynsyms;  // symtabs first.

    priv = (struct elf_symbol *)lua_newuserdata(L, sizeof(struct elf_symbol) * (count + 1));
    priv->start = count;   // region 0 to record count of symbols and offset.
    priv->end = info.bias;
    priv->sym = NULL;

    if (load_symbol64(elf, priv + 1, &info) < 0 ) {
        return NULL;
    }
    return priv;
}

static struct elf_symbol * elf32(lua_State *L, Elf *elf) {
    int count;
    struct elf_symbol *priv;
    struct elf_info info = {0, 0, 0};

    if (n_symbol32(elf, &info) < 0 ) {
        return NULL;
    }
    count = info.symtabs > 0 ? info.symtabs : info.dynsyms;  // symtabs first.

    priv = (struct elf_symbol *)lua_newuserdata(L, sizeof(struct elf_symbol) * (count + 1));
    priv->start = count;   // region 0 to record count of symbols and offset.
    priv->end = info.bias;
    priv->sym = NULL;

    if (load_symbol32(elf, priv + 1, &info) < 0 ) {
        return NULL;
    }
    return priv;
}

static int sort_symbol(const void *a, const void * b) {
    struct elf_symbol *sa = (struct elf_symbol *)a;
    struct elf_symbol *sb = (struct elf_symbol *)b;
    return (sa->start - sb->start);
}

static int new(lua_State *L) {
    const char *fPath = luaL_checkstring(L, 1);
    Elf *elf;
    GElf_Ehdr ehdr;
    int elf_file_fd;
    int syms = 0;
    struct elf_symbol *priv = NULL;

    if (elf_version(EV_CURRENT) == EV_NONE) {
        luaL_error(L, "libelf version is too old");
    }

    elf_file_fd = open(fPath, O_RDONLY, 0);
    if (elf_file_fd < 0) {
        luaL_error(L, "open file %s failed, errno:%d, %s\n", fPath, errno, strerror(errno));
    }

    if ((elf = elf_begin(elf_file_fd, ELF_C_READ, NULL)) == NULL) {
        close(elf_file_fd);
        luaL_error(L, "elf_begin failed");
    }

    if (gelf_getehdr(elf, &ehdr) == NULL) {
        elf_end(elf);
        close(elf_file_fd);
        luaL_error(L, "gelf_getehdr failed");
    }

    if (ehdr.e_ident[EI_CLASS] == ELFCLASS32) {
        priv = elf32(L, elf);
    } else if (ehdr.e_ident[EI_CLASS] == ELFCLASS64) {
        priv = elf64(L, elf);
    } else {
        elf_end(elf);
        close(elf_file_fd);
        luaL_error(L, "not support elf class");
    }

    elf_end(elf);
    close(elf_file_fd);

    syms = priv->start;
    qsort(priv + 1, syms, sizeof(struct elf_symbol), sort_symbol);

    luaL_getmetatable(L, MT_NAME);
    lua_setmetatable(L, -2);
    return 1;
}

static int gc(lua_State *L) {
    int i, count;
    struct elf_symbol *priv = (struct elf_symbol *)luaL_checkudata(L, 1, MT_NAME);
    luaL_argcheck(L, priv != NULL, 1, "`array' expected");

    count = priv->start;
    priv ++;
    for (i = 0; i < count; i ++) {
        free(priv->sym);
        priv->sym = NULL;
        priv ++;
    }
    return 0;
}

static luaL_Reg module_m[] = {
        {"maps", maps},
        {"item", item},
        {"count", count},
        {"bias", bias},
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
    lua_pushcfunction(L, gc);
    lua_setfield(L, -2, "__gc");

    lua_pop(L, 1);

#if LUA_VERSION_NUM > 501
    luaL_newlib(L, module_f);
#else
    luaL_register(L, "elfmap", module_f);
#endif
    return 1;
}
