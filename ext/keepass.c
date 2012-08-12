#include <ctype.h>
#include <ruby.h>
#include <kpass.h>

/*
 * Document-module: Keepass
 *
 * A module containing classes related to processing
 * a Keepass database.
 *
 */
static VALUE mKeepass;

/*
 * Document-class: Keepass::Database
 *
 * A class representing a Keepass database.
 *
 */
static VALUE cDatabase;

/*
 * Document-class: Keepass::Group
 *
 * A class representing a group of entries in a Keepass
 * database.
 *
 */
static VALUE cGroup;

/*
 * Document-class: Keepass::Entry
 *
 * A class representing an entry in a Keepass
 * database.
 *
 */
static VALUE cEntry;

/*
 * Document-class: Keepass::Exception
 *
 * An exception type for exceptions that occur when accessing a Keepass
 * database.
 *
 */
static VALUE eException_KeepassException;

/*
 * Document-class: Keepass::UnknownException
 *
 * An exception type for unknown errors.
 *
 */
static VALUE eException_unknown;

/*
 * Document-class: Keepass::DecryptDataException
 *
 * An exception type for when data decryption fails.
 *
 */
static VALUE eException_kpass_decrypt_data_fail;

/*
 * Document-class: Keepass::DecryptDbException
 *
 * An exception type for when data decryption fails.
 *
 */
static VALUE eException_kpass_decrypt_db_fail;

/*
 * Document-class: Keepass::HashPwException
 *
 * An exception type for when password hashing fails.
 *
 */
static VALUE eException_kpass_hash_pw_fail;

/*
 * Document-class: Keepass::PrepareKeyException
 *
 * An exception type for when key preparation fails.
 *
 */
static VALUE eException_kpass_prepare_key_fail;

/*
 * Document-class: Keepass::LoadDecryptedDataEntryException
 *
 * An exception type for when loading an entry fails.
 *
 */
static VALUE eException_kpass_load_decrypted_data_entry_fail;

/*
 * Document-class: Keepass::LoadDecryptedDataGroupException
 *
 * An exception type for when loading a groupo fails.
 *
 */
static VALUE eException_kpass_load_decrypted_data_group_fail;

/*
 * Document-class: Keepass::InitDbException
 *
 * An exception type for when initializing a database fails.
 *
 */
static VALUE eException_kpass_init_db_fail;

/*
 * Document-class: Keepass::EncryptDbException
 *
 * An exception type for when encrypting a database fails.
 *
 */
static VALUE eException_kpass_encrypt_db_fail;

/*
 * Document-class: Keepass::EncryptDataException
 *
 * An exception type for when encrypting a database fails.
 *
 */
static VALUE eException_kpass_encrypt_data_fail;

/*
 * Document-class: Keepass::PackDbException
 *
 * An exception type for when packing a database fails.
 *
 */
static VALUE eException_kpass_pack_db_fail;

/*
 * Document-class: Keepass::VerificationException
 *
 * An exception type for when verifying a database fails.
 *
 */
static VALUE eException_kpass_verification_fail;

/*
 * Document-class: Keepass::UnsupportedFlagException
 *
 * An exception type for when an unsupported flag is used.
 *
 */
static VALUE eException_kpass_unsupported_flag;

/*
 * Document-class: Keepass::NotImplementedException
 *
 * An exception type for when unimplemented functionality is used.
 *
 */
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

/*
 * Document-method: initialize
 *
 * Opens up a Keepass database with the given filename and password.
 *
 * call-seq:
 *   Keepass::Database.new(filename, password)
 *
 */
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

/*
 * Document-method: open
 *
 * Opens up a Keepass database with the given filename and password.
 *
 * call-seq:
 *   Keepass::Database.open(filename, password)
 *
 */
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

/*
 * Document-method: groups
 *
 * Returns an Array of groups in this database.
 *
 */
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

/*
 * Document-method: entries
 *
 * Returns an Array of entries in this database.
 *
 */
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

/*
 * Document-method: name
 *
 * Returns the name of this group.
 *
 */
VALUE
rb_kp_grp_name(VALUE self)
{
    return rb_ivar_get(self, rb_intern("@name"));
}

/*
 * Document-method: mtime
 *
 * Returns the modification time of this group.
 *
 */
VALUE
rb_kp_grp_mtime(VALUE self)
{
    return rb_ivar_get(self, rb_intern("@mtime"));
}

/*
 * Document-method: ctime
 *
 * Returns the creation time of this group.
 *
 */
VALUE
rb_kp_grp_ctime(VALUE self)
{
    return rb_ivar_get(self, rb_intern("@ctime"));
}

/*
 * Document-method: atime
 *
 * Returns the last access time of this group.
 *
 */
VALUE
rb_kp_grp_atime(VALUE self)
{
    return rb_ivar_get(self, rb_intern("@atime"));
}

/*
 * Document-method: etime
 *
 * Returns the expire time of this group.
 *
 */
VALUE
rb_kp_grp_etime(VALUE self)
{
    return rb_ivar_get(self, rb_intern("@etime"));
}

/*
 * Document-method: name
 *
 * Returns the name of this entry.
 *
 */
VALUE
rb_kp_entry_name(VALUE self)
{
    return rb_ivar_get(self, rb_intern("@name"));
}

/*
 * Document-method: password
 *
 * Returns the password of this entry.
 *
 */
VALUE
rb_kp_entry_password(VALUE self)
{
    return rb_ivar_get(self, rb_intern("@password"));
}

/*
 * Document-method: mtime
 *
 * Returns the modification time of this entry.
 *
 */
VALUE
rb_kp_entry_mtime(VALUE self)
{
    return rb_ivar_get(self, rb_intern("@mtime"));
}

/*
 * Document-method: ctime
 *
 * Returns the creation time of this entry.
 *
 */
VALUE
rb_kp_entry_ctime(VALUE self)
{
    return rb_ivar_get(self, rb_intern("@ctime"));
}

/*
 * Document-method: atime
 *
 * Returns the last access time of this entry.
 *
 */
VALUE
rb_kp_entry_atime(VALUE self)
{
    return rb_ivar_get(self, rb_intern("@atime"));
}

/*
 * Document-method: etime
 *
 * Returns the expire time of this entry.
 *
 */
VALUE
rb_kp_entry_etime(VALUE self)
{
    return rb_ivar_get(self, rb_intern("@etime"));
}

/*
 * Document-method: entries
 *
 * Returns the entries contained within this group.
 *
 */
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

void
Init_keepass(void)
{
    /* Module Initialization */
    mKeepass  = rb_define_module("Keepass");
    cDatabase = rb_define_class_under(mKeepass, "Database",
        rb_cObject);
    cGroup = rb_define_class_under(mKeepass, "Group", rb_cObject);
    cEntry = rb_define_class_under(mKeepass, "Entry", rb_cObject);

    eException_KeepassException                     = rb_define_class_under(mKeepass, "Exception", rb_eStandardError);
    eException_unknown                              = rb_define_class_under(mKeepass, "UnknownException", eException_KeepassException);
    eException_kpass_decrypt_data_fail              = rb_define_class_under(mKeepass, "DecryptDataException", eException_KeepassException);
    eException_kpass_decrypt_db_fail                = rb_define_class_under(mKeepass, "DecryptDbException", eException_KeepassException);
    eException_kpass_hash_pw_fail                   = rb_define_class_under(mKeepass, "HashPwException", eException_KeepassException);
    eException_kpass_prepare_key_fail               = rb_define_class_under(mKeepass, "PrepareKeyException", eException_KeepassException);
    eException_kpass_load_decrypted_data_entry_fail = rb_define_class_under(mKeepass, "LoadDecryptedDataEntryException", eException_KeepassException);
    eException_kpass_load_decrypted_data_group_fail = rb_define_class_under(mKeepass, "LoadDecryptedDataGroupException", eException_KeepassException);
    eException_kpass_init_db_fail                   = rb_define_class_under(mKeepass, "InitDbException", eException_KeepassException);
    eException_kpass_encrypt_db_fail                = rb_define_class_under(mKeepass, "EncryptDbException", eException_KeepassException);
    eException_kpass_encrypt_data_fail              = rb_define_class_under(mKeepass, "EncryptDataException", eException_KeepassException);
    eException_kpass_pack_db_fail                   = rb_define_class_under(mKeepass, "PackDbException", eException_KeepassException);
    eException_kpass_verification_fail              = rb_define_class_under(mKeepass, "VerificationException", eException_KeepassException);
    eException_kpass_unsupported_flag               = rb_define_class_under(mKeepass, "UnsupportedFlagException", eException_KeepassException);
    eException_kpass_not_implemented                = rb_define_class_under(mKeepass, "NotImplementedException", eException_KeepassException);

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
