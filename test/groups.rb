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
end
