require 'minitest/autorun'
require 'keepass'

KP_FILE            = 'test/example.kdb'
CORRECT_PASSWORD   = 'abc123'
TIME_METHODS       = [ :ctime, :mtime, :atime, :etime ]

class TestKeepass_Entries < MiniTest::Unit::TestCase
    def test_time_methods
        kdb   = Keepass::Database.open KP_FILE, CORRECT_PASSWORD
        entry = kdb.entries[0] 

        times = TIME_METHODS.collect do |method|
            (entry.send method).class
        end

        assert_equal times, [ Time ] * TIME_METHODS.length
    end
end
