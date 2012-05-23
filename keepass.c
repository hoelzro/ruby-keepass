#include <ctype.h>
#include <ruby.h>
#include <kpass.h>

#define MODULE_NAME "Keepass"
#define DATABASE_CLASS_NAME "Database"
#define GROUP_CLASS_NAME "Group"
#define ENTRY_CLASS_NAME "Entry"

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
#define throw_exception(type, msg)\
    case type:\
        rb_raise(eException_##type, msg);\
        break;

    /* it's ok, so don't do anything */
    if(result == kpass_success) {
        return;
    }
    switch(result) {
        throw_exception(kpass_decrypt_data_fail, "data decryption failure");
	throw_exception(kpass_decrypt_db_fail, "database decryption failure");
	throw_exception(kpass_hash_pw_fail, "password hash failure");
	throw_exception(kpass_prepare_key_fail, "key preparation failure");
	throw_exception(kpass_load_decrypted_data_entry_fail, "entry load failure");
	throw_exception(kpass_load_decrypted_data_group_fail, "group load failure");
	throw_exception(kpass_init_db_fail, "db init failure");
	throw_exception(kpass_encrypt_db_fail, "encrypt db failure");
	throw_exception(kpass_encrypt_data_fail, "encrypt data failure");
	throw_exception(kpass_pack_db_fail, "pack db failure");
	throw_exception(kpass_verification_fail, "verification failure");
	throw_exception(kpass_unsupported_flag, "unsupported flag");
	throw_exception(kpass_not_implemented, "unimplemented");

        default:
            rb_raise(eException_unknown, "An unknown error occurred");
    }
#undef throw_exception
}

VALUE
rb_kp_db_open(VALUE self, VALUE rb_file)
{
    ID id_read;
    VALUE bytes;
    const char *c_bytes;
    long c_length;
    kpass_db *kdb = NULL;
    VALUE kdb_object;
    kpass_retval result;

    if(TYPE(rb_file) == T_STRING) {
        VALUE rb_filename = rb_file;
        ID id_new         = rb_intern("open");

        rb_file = rb_funcall(rb_cFile, id_new, 2, rb_filename,
            rb_str_new_cstr("rb"));
    }

    Check_Type(rb_file, T_FILE); /* XXX looser type check? */
    id_read  = rb_intern("read");
    bytes    = rb_funcall(rb_file, id_read, 0);
    c_length = RSTRING_LEN(bytes);
    c_bytes  = RSTRING_PTR(bytes);

    kdb_object = Data_Make_Struct(rb_cObject, kpass_db, 0, kpass_free_db, kdb); 

    result = kpass_init_db(kdb, c_bytes, c_length);

    if(result != kpass_success) {
        raise_kp_exception(result);
    }

    rb_ivar_set(self, rb_intern("@kdb"), kdb_object);

    return Qnil;
}

static void
__define_exception(VALUE module, kpass_retval value,
    const char *value_as_str)
{
    char *copy;
    char *copy_end;
    char *p;

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
    rb_define_class_under(module, copy, eException_KeepassException);
    free(copy);
}

static void
define_exception_classes(VALUE module)
{
#define define_exception(value)\
    __define_exception(module, value, #value)

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
    VALUE mKeepass;
    VALUE cDatabase;
    VALUE cGroup;
    VALUE cEntry;

    /* Module Initialization */
    mKeepass  = rb_define_module(MODULE_NAME);
    cDatabase = rb_define_class_under(mKeepass, DATABASE_CLASS_NAME,
        rb_cObject);
    cGroup = rb_define_class_under(mKeepass, GROUP_CLASS_NAME, rb_cObject);
    cEntry = rb_define_class_under(mKeepass, ENTRY_CLASS_NAME, rb_cObject);

    define_exception_classes(mKeepass);

    /* Database Methods */
    rb_define_method(cDatabase, "open", rb_kp_db_open, 1);
}
