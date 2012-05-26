require 'minitest/autorun'
require 'keepass'

KP_FILE            = 'test/example.kdb'
CORRECT_PASSWORD   = 'abc123'
INCORRECT_PASSWORD = '123abc'
OPEN_METHODS       = [ :open, :new ]

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

    def test_open_string_ok
        OPEN_METHODS.each do |method|
            assert_no_exception do
                kdb = Keepass::Database.send method, KP_FILE, CORRECT_PASSWORD
            end
        end
    end

    def test_open_file_ok
        OPEN_METHODS.each do |method|
            f = File.open(KP_FILE, 'rb')

            assert_no_exception do
                kdb = Keepass::Database.send method, f, CORRECT_PASSWORD
            end
        end
    end

    def test_open_string_with_bad_password
        OPEN_METHODS.each do |method|
            assert_exception Keepass::DecryptDataFail do
                kdb = Keepass::Database.send method, KP_FILE, INCORRECT_PASSWORD
            end
        end
    end

    def test_open_file_with_bad_password
        OPEN_METHODS.each do |method|
            f = File.open(KP_FILE, 'rb')

            assert_exception Keepass::DecryptDataFail do
                kdb = Keepass::Database.send method, f, INCORRECT_PASSWORD
            end
        end
    end
end
