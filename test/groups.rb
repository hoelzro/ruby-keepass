require 'minitest/autorun'
require 'keepass'

KP_FILE            = 'test/example.kdb'
CORRECT_PASSWORD   = 'abc123'

class TestKeepass_Groups < MiniTest::Unit::TestCase
    def test_groups
        kdb         = Keepass::Database.open KP_FILE, CORRECT_PASSWORD
        seen_groups = []

        kdb.groups.each do |group|
            seen_groups << group.name
        end

        assert_equal seen_groups, %w(Test1 Test2)
    end
end
