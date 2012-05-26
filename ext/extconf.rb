require 'mkmf'

return unless have_library 'kpass', 'kpass_init_db'
return unless have_header 'kpass.h'

create_makefile 'keepass'
