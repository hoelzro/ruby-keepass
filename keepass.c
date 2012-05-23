#include <ruby.h>
#include <kpass.h>

#define MODULE_NAME "Keepass"
#define DATABASE_CLASS_NAME "Database"
#define GROUP_CLASS_NAME "Group"
#define ENTRY_CLASS_NAME "Entry"

static void raise_kp_exception(kpass_retval result)
{
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

    /* Database Methods */
    rb_define_method(cDatabase, "open", rb_kp_db_open, 1);
}
