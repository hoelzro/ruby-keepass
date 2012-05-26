require 'minitest/autorun'
require 'keepass'

KP_FILE            = 'test/example.kdb'
CORRECT_PASSWORD   = 'abc123'
TIME_METHODS       = [ :ctime, :mtime, :atime, :etime ]

class TestKeepass_Groups < MiniTest::Unit::TestCase
    def test_group_names
        kdb         = Keepass::Database.open KP_FILE, CORRECT_PASSWORD
        seen_groups = []

        kdb.groups.each do |group|
            seen_groups << group.name
        end

        assert_equal seen_groups, %w(Test1 Test2)
    end

    def test_time_methods
        kdb   = Keepass::Database.open KP_FILE, CORRECT_PASSWORD
        group = kdb.groups[0]

        times = TIME_METHODS.collect do |method|
            (group.send method).class
        end

        assert_equal times, [ Time ] * TIME_METHODS.length
    end

    def test_entries
        kdb     = Keepass::Database.open KP_FILE, CORRECT_PASSWORD
        group   = kdb.groups[0]
        entries = group.entries

        seen_entries = []

        entries.each do |entry|
            seen_entries << {
                :name     => entry.name,
                :password => entry.password,
            }
        end

        seen_entries.sort! do |a, b|
            a[:name] <=> b[:name]
        end

        assert_equal seen_entries, [
            { :name => 'Test1', :password => '12345' },
            { :name => 'Test2', :password => 'abcde' },
        ]
    end
end
