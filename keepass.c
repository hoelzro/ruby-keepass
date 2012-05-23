#include <ruby.h>

#define MODULE_NAME "Keepass"
#define DATABASE_CLASS_NAME "Database"
#define GROUP_CLASS_NAME "Group"
#define ENTRY_CLASS_NAME "Entry"

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
}
