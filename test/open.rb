require 'minitest/autorun'
require 'keepass'

KP_FILE = 'test/example.kdb'

class TestKeepass_Open < MiniTest::Unit::TestCase
    def assert_no_exception
        begin
            yield
            pass
        rescue Exception => e
            flunk "Unexpected exception: #{e}"
        end
    end

    def test_open_string_ok
        kdb = Keepass::Database.new

        assert_no_exception do
            kdb.open(KP_FILE)
        end
    end

    def test_open_file_ok
        kdb = Keepass::Database.new
        f   = File.open(KP_FILE, 'rb')

        assert_no_exception do
            kdb.open(f)
        end
    end
end
