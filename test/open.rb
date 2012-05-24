require 'minitest/autorun'
require 'keepass'

KP_FILE          = 'test/example.kdb'
CORRECT_PASSWORD = 'abc123'

class TestKeepass_Open < MiniTest::Unit::TestCase
    def assert_no_exception
        begin
            yield
            pass
        rescue Exception => e
            flunk "Unexpected exception: #{e}"
        end
    end

    def assert_exception ex_type
        begin
            yield
            flunk 'No exception was seen'
        rescue ex_type => e
            pass
        rescue Exception => e
            flunk "Unexpected exception: #{e}"
        end
    end

    def setup
        @kdb = Keepass::Database.new
    end

    def test_open_string_ok
        assert_no_exception do
            @kdb.open(KP_FILE, CORRECT_PASSWORD)
        end
    end

    def test_open_file_ok
        f = File.open(KP_FILE, 'rb')

        assert_no_exception do
            @kdb.open(f, CORRECT_PASSWORD)
        end
    end
end
