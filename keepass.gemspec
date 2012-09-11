Gem::Specification.new do |s|
  s.files            = ['ext/keepass.c']
  s.name             = 'keepass'
  s.require_path     = 'ext'
  s.summary          = 'Ruby bindings for libkpass'
  s.version          = '0.0.1'
  s.author           = 'Rob Hoelz'
  s.email            = 'rob@hoelz.ro'
  s.extensions       = ['ext/extconf.rb']
  s.extra_rdoc_files = ['README.rdoc']
  s.homepage         = 'https://github.com/hoelzro/ruby-keepass'
  s.license          = 'MIT'
  s.requirements     = ['libkpass']
  s.test_files       = Dir.glob('test/*.rb')
  s.description      = 'A Ruby library for accessing Keepass password databases'
end
