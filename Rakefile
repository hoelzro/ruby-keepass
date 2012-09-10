require 'rdoc/task'
require 'rake/clean'
require 'rake/testtask'

CLOBBER.include 'ext/*.so'
CLEAN.include 'ext/*.o', 'ext/mkmf.log', 'ext/Makefile'

RDoc::Task.new do |rd|
  rd.rdoc_files.include 'ext/*.c'
  rd.title    = 'keepass RDoc'
  rd.main     = 'README.rdoc'
  rd.rdoc_dir = 'doc'
end

Rake::TestTask.new do |t|
  t.libs       = ['ext']
  t.test_files = Dir.glob('test/*.rb')
end

task :default => [:compile] do
end

desc 'Compiles keepass module'
task :compile do
    cd 'ext'
    ruby 'extconf.rb'
    sh 'make'
    cd '..'
end
