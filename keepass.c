#include <ctype.h>
#include <ruby.h>
#include <kpass.h>

#define MODULE_NAME "Keepass"
#define DATABASE_CLASS_NAME "Database"
#define GROUP_CLASS_NAME "Group"
#define ENTRY_CLASS_NAME "Entry"

static VALUE mKeepass;
static VALUE cDatabase;
static VALUE cGroup;
static VALUE cEntry;

static VALUE eException_KeepassException;
static VALUE eException_unknown;
static VALUE eException_kpass_decrypt_data_fail;
static VALUE eException_kpass_decrypt_db_fail;
static VALUE eException_kpass_hash_pw_fail;
static VALUE eException_kpass_prepare_key_fail;
static VALUE eException_kpass_load_decrypted_data_entry_fail;
static VALUE eException_kpass_load_decrypted_data_group_fail;
static VALUE eException_kpass_init_db_fail;
static VALUE eException_kpass_encrypt_db_fail;
static VALUE eException_kpass_encrypt_data_fail;
static VALUE eException_kpass_pack_db_fail;
static VALUE eException_kpass_verification_fail;
static VALUE eException_kpass_unsupported_flag;
static VALUE eException_kpass_not_implemented;

static void raise_kp_exception(kpass_retval result)
{
#define throw_exception(type)\
    case type:\
        rb_raise(eException_##type, kpass_error_str[type]);\
        break;

    /* it's ok, so don't do anything */
    if(result == kpass_success) {
        return;
    }
    switch(result) {
        throw_exception(kpass_decrypt_data_fail);
        throw_exception(kpass_decrypt_db_fail);
        throw_exception(kpass_hash_pw_fail);
        throw_exception(kpass_prepare_key_fail);
        throw_exception(kpass_load_decrypted_data_entry_fail);
        throw_exception(kpass_load_decrypted_data_group_fail);
        throw_exception(kpass_init_db_fail);
        throw_exception(kpass_encrypt_db_fail);
        throw_exception(kpass_encrypt_data_fail);
        throw_exception(kpass_pack_db_fail);
        throw_exception(kpass_verification_fail);
        throw_exception(kpass_unsupported_flag);
        throw_exception(kpass_not_implemented);

        default:
            rb_raise(eException_unknown, "An unknown error occurred");
    }
#undef throw_exception
}

VALUE
rb_kp_db_initialize(VALUE self, VALUE rb_file, VALUE rb_password)
{
    ID id_read;
    VALUE bytes;
    const char *c_bytes;
    long c_length;
    kpass_db *kdb = NULL;
    VALUE kdb_object;
    kpass_retval result;
    uint8_t hashed_pass[32];

    if(TYPE(rb_file) == T_STRING) {
        VALUE rb_filename = rb_file;
        ID id_new         = rb_intern("open");

        rb_file = rb_funcall(rb_cFile, id_new, 2, rb_filename,
            rb_str_new_cstr("rb"));
    }

    Check_Type(rb_file, T_FILE); /* XXX looser type check? */
    Check_Type(rb_password, T_STRING);

    id_read  = rb_intern("read");
    bytes    = rb_funcall(rb_file, id_read, 0);
    c_length = RSTRING_LEN(bytes);
    c_bytes  = RSTRING_PTR(bytes);

    kdb_object = Data_Make_Struct(cDatabase, kpass_db, 0, kpass_free_db, kdb); 

    result = kpass_init_db(kdb, c_bytes, c_length);

    if(result != kpass_success) {
        raise_kp_exception(result);
    }

    result = kpass_hash_pw(kdb, RSTRING_PTR(rb_password), hashed_pass);

    if(result != kpass_success) {
        raise_kp_exception(result);
    }

    result = kpass_decrypt_db(kdb, hashed_pass);

    if(result != kpass_success) {
        raise_kp_exception(result);
    }

    rb_ivar_set(self, rb_intern("@kdb"), kdb_object);

    return Qnil;
}

VALUE
rb_kp_db_open(VALUE klass, VALUE rb_file, VALUE rb_password)
{
    ID id_new;

    id_new = rb_intern("new");

    return rb_funcall(klass, id_new, 2, rb_file, rb_password);
}

static void
_set_time(VALUE object, const char *attr_name, uint8_t value[5])
{
    struct tm time_value;
    VALUE rb_time;

    kpass_unpack_time(value, &time_value);
    rb_time = rb_funcall(rb_cTime, rb_intern("gm"), 6,
        INT2NUM(time_value.tm_year + 1900),
        INT2NUM(time_value.tm_mon  + 1),
        INT2NUM(time_value.tm_mday),
        INT2NUM(time_value.tm_hour),
        INT2NUM(time_value.tm_min),
        INT2NUM(time_value.tm_sec)
    );

    rb_ivar_set(object, rb_intern(attr_name), rb_time);
}

static VALUE
_create_ruby_group(VALUE kdb, kpass_group *group)
{
    VALUE rb_group     = rb_funcall(cGroup, rb_intern("new"), 0);

    rb_ivar_set(rb_group, rb_intern("@kdb"), kdb);
    rb_ivar_set(rb_group, rb_intern("@id"), INT2NUM(group->id));
    rb_ivar_set(rb_group, rb_intern("@name"), rb_str_new_cstr(group->name));
    _set_time(rb_group, "@mtime", group->mtime);
    _set_time(rb_group, "@ctime", group->ctime);
    _set_time(rb_group, "@atime", group->atime);
    _set_time(rb_group, "@etime", group->etime);

    return rb_group;
}

VALUE
rb_kp_db_groups(VALUE self)
{
    VALUE kdb_object;
    kpass_db *kdb = NULL;
    VALUE groups;
    uint32_t i;

    kdb_object = rb_ivar_get(self, rb_intern("@kdb"));
    Data_Get_Struct(kdb_object, kpass_db, kdb);

    groups = rb_ary_new2(kdb->groups_len);

    for(i = 0; i < kdb->groups_len; i++) {
        VALUE rb_group = _create_ruby_group(self, kdb->groups[i]);

        rb_ary_push(groups, rb_group);
    }

    return groups;
}

static VALUE
_create_ruby_entry(kpass_entry *entry)
{
    VALUE rb_entry;

    rb_entry = rb_funcall(cEntry, rb_intern("new"), 0);

    rb_ivar_set(rb_entry, rb_intern("@name"), rb_str_new_cstr(entry->title));
    rb_ivar_set(rb_entry, rb_intern("@password"), rb_str_new_cstr(entry->password));
    _set_time(rb_entry, "@mtime", entry->mtime);
    _set_time(rb_entry, "@ctime", entry->ctime);
    _set_time(rb_entry, "@atime", entry->atime);
    _set_time(rb_entry, "@etime", entry->etime);

    return rb_entry;
}

VALUE
rb_kp_db_entries(VALUE self)
{
    VALUE kdb_object;
    kpass_db *kdb = NULL;
    VALUE entries;
    uint32_t i;

    kdb_object = rb_ivar_get(self, rb_intern("@kdb"));
    Data_Get_Struct(kdb_object, kpass_db, kdb);

    entries = rb_ary_new();

    for(i = 0; i < kdb->entries_len; i++) {
        VALUE rb_entry;
        kpass_entry *entry = kdb->entries[i];

        if(! strcmp(entry->title, "Meta-Info")) {
            continue;
        }

        rb_entry = _create_ruby_entry(entry);

        rb_ary_push(entries, rb_entry);
    }

    return entries;
}

#define gen_reader(prefix, attr_name)\
VALUE \
prefix##_##attr_name(VALUE self)\
{\
    return rb_ivar_get(self, rb_intern("@" #attr_name));\
}

gen_reader(rb_kp_grp, name);
gen_reader(rb_kp_grp, mtime);
gen_reader(rb_kp_grp, ctime);
gen_reader(rb_kp_grp, atime);
gen_reader(rb_kp_grp, etime);

gen_reader(rb_kp_entry, name);
gen_reader(rb_kp_entry, password);
gen_reader(rb_kp_entry, mtime);
gen_reader(rb_kp_entry, ctime);
gen_reader(rb_kp_entry, atime);
gen_reader(rb_kp_entry, etime);

VALUE
rb_kp_grp_entries(VALUE self)
{
    VALUE kdb_object;
    kpass_db *kdb;
    VALUE entries;
    uint32_t i;
    uint32_t group_id;

    kdb_object = rb_ivar_get(self, rb_intern("@kdb")); /* fetch the Keepass::Database */
    kdb_object = rb_ivar_get(kdb_object, rb_intern("@kdb")); /* fetch the wrapper object */
    Data_Get_Struct(kdb_object, kpass_db, kdb);

    group_id = NUM2INT(rb_ivar_get(self, rb_intern("@id")));

    entries = rb_ary_new();

    for(i = 0; i < kdb->entries_len; i++) {
        kpass_entry *entry = kdb->entries[i];
        VALUE rb_entry;

        if(entry->group_id != group_id) {
            continue;
        }

        if(! strcmp(entry->title, "Meta-Info")) {
            continue;
        }

        rb_entry = _create_ruby_entry(entry);

        rb_ary_push(entries, rb_entry);
    }

    return entries;
}

static VALUE
__define_exception(VALUE module, kpass_retval value,
    const char *value_as_str)
{
    char *copy;
    char *copy_end;
    char *p;
    VALUE klass;

    copy = strdup(value_as_str + strlen("kpass_")); /* copy and remove
                                                     * prefix */
    copy_end = copy + strlen(copy);
    copy[0]  = toupper(copy[0]); /* upper-case first character */

    p = strchr(copy, '_');
    while(p) {
        memmove(p, p + 1, copy_end - p); /* delete '_' character */
        *p = toupper(*p); /* upper-case character following '_' */
        p  = strchr(copy, '_');
    }
    klass = rb_define_class_under(module, copy, eException_KeepassException);
    free(copy);

    return klass;
}

static void
define_exception_classes(VALUE module)
{
#define define_exception(value)\
    eException_##value = __define_exception(module, value, #value)

    eException_KeepassException = rb_define_class_under(module, "Exception",
        rb_eException);

    eException_unknown = rb_define_class_under(module, "UnknownException",
        eException_KeepassException);

    define_exception(kpass_decrypt_data_fail);
    define_exception(kpass_decrypt_db_fail);
    define_exception(kpass_hash_pw_fail);
    define_exception(kpass_prepare_key_fail);
    define_exception(kpass_load_decrypted_data_entry_fail);
    define_exception(kpass_load_decrypted_data_group_fail);
    define_exception(kpass_init_db_fail);
    define_exception(kpass_encrypt_db_fail);
    define_exception(kpass_encrypt_data_fail);
    define_exception(kpass_pack_db_fail);
    define_exception(kpass_verification_fail);
    define_exception(kpass_unsupported_flag);
    define_exception(kpass_not_implemented);

#undef define_exception
}

void
Init_keepass(void)
{
    /* Module Initialization */
    mKeepass  = rb_define_module(MODULE_NAME);
    cDatabase = rb_define_class_under(mKeepass, DATABASE_CLASS_NAME,
        rb_cObject);
    cGroup = rb_define_class_under(mKeepass, GROUP_CLASS_NAME, rb_cObject);
    cEntry = rb_define_class_under(mKeepass, ENTRY_CLASS_NAME, rb_cObject);

    define_exception_classes(mKeepass);

    /* Database Methods */
    rb_define_singleton_method(cDatabase, "open", rb_kp_db_open, 2);
    rb_define_method(cDatabase, "initialize", rb_kp_db_initialize, 2);
    rb_define_method(cDatabase, "groups", rb_kp_db_groups, 0);
    rb_define_method(cDatabase, "entries", rb_kp_db_entries, 0);

    /* Group Methods */
    rb_define_method(cGroup, "name",  rb_kp_grp_name, 0);
    rb_define_method(cGroup, "mtime", rb_kp_grp_mtime, 0);
    rb_define_method(cGroup, "ctime", rb_kp_grp_ctime, 0);
    rb_define_method(cGroup, "atime", rb_kp_grp_atime, 0);
    rb_define_method(cGroup, "etime", rb_kp_grp_etime, 0);
    rb_define_method(cGroup, "entries", rb_kp_grp_entries, 0);

    /* Entry Methods */
    rb_define_method(cEntry, "name", rb_kp_entry_name, 0);
    rb_define_method(cEntry, "password", rb_kp_entry_password, 0);
    rb_define_method(cEntry, "mtime", rb_kp_entry_mtime, 0);
    rb_define_method(cEntry, "ctime", rb_kp_entry_ctime, 0);
    rb_define_method(cEntry, "atime", rb_kp_entry_atime, 0);
    rb_define_method(cEntry, "etime", rb_kp_entry_etime, 0);
}
