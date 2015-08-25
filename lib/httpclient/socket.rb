require 'socket'

class HTTPClient
  DELEGATED_METHODS = %w[
    close closed?
    getsockopt setsockopt
    local_address remote_address
    read_nonblock wrote_nonblock
    fileno sync= << eof?
  ]

  class SocketTimeout < SocketError; end

  class TCPSocket
    DELEGATED_METHODS.each do |method|
      class_eval(<<-EVAL, __FILE__, __LINE__)
        def #{method}(*args)
          @socket.__send__(:#{method}, *args)
        end
      EVAL
    end

    def initialize(remote_host, remote_port, local_host=nil, local_port=nil, opts = {})
      @connect_timeout = opts[:connect_timeout]
      @write_timeout = opts[:write_timeout]
      @read_timeout = opts[:read_timeout]

      address = Socket.getaddrinfo(remote_host, nil).first
      family = address[4]
      @sockaddr = Socket.pack_sockaddr_in(remote_port, address[3])

      @socket = Socket.new(family, Socket::SOCK_STREAM, 0)
      @socket.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)

      if local_host || local_port
        local_host ||= ''
        local_address = Socket.getaddrinfo(local_host, nil).find { |addr|
          addr[3] == family
        }
        local_sockaddr = Socket.pack_sockaddr_in(local_port, local_address)
        @socket.bind(local_sockaddr)
      end

      connect
    end

    def socket
      @socket
    end

    def connect
      return @socket.connect(@sockaddr) unless @connect_timeout

      begin
        @socket.connect_nonblock(@sockaddr)
      rescue Errno::EINPROGRESS
        select_timeout(:connect, @connect_timeout)
        # If there was a failure this will raise an Error
        begin
          @socket.connect_nonblock(@sockaddr)
        rescue Errno::EISCONN
          # Successfully connected
        end
      end
    end

    def write(data, timeout = nil)
      timeout ||= @write_timeout
      return @socket.write(data) unless timeout

      length = data.bytesize

      total_count = 0
      loop do
        begin
          count = @socket.write_nonblock(data)
        rescue Errno::EWOULDBLOCK
          timeout = select_timeout(:write, timeout)
          retry
        end

        total_count += count
        return total_count if total_count >= length
        data = data.byteslice(count..-1)
      end
    end

    def read(length = nil, *args)
      raise ArgumentError, 'too many arguments' if args.length > 2

      timeout = (args.length > 1) ? args.pop : @read_timeout
      return @socket.read(length, *args) unless length > 0 && timeout

      buffer = args.first || ''.force_encoding(Encoding::ASCII_8BIT)

      begin
        # Drain internal buffers
        @socket.read_nonblock(length, buffer)
        return buffer if buffer.bytesize >= length
      rescue Errno::EWOULDBLOCK
        # Internal buffers were empty
        buffer.clear
      rescue EOFError
        return nil
      end

      @chunk ||= ''.force_encoding(Encoding::ASCII_8BIT)

      loop do
        timeout = select_timeout(:read, timeout)

        begin
          @socket.read_nonblock(length, @chunk)
        rescue Errno::EWOULDBLOCK
          retry
        rescue EOFError
          return buffer.empty? ? nil : buffer
        end
        buffer << @chunk

        if length
          length -= @chunk.bytesize
          return buffer if length <= 0
        end
      end
    end

    def readpartial(length, *args)
      raise ArgumentError, 'too many arguments' if args.length > 2

      timeout = (args.length > 1) ? args.pop : @read_timeout
      return @socket.readpartial(length, *args) unless length > 0 && timeout

      begin
        @socket.read_nonblock(length, *args)
      rescue Errno::EWOULDBLOCK
        timeout = select_timeout(:read, timeout)
        retry
      end
    end

    def readbyte
      readpartial(1).ord
    end

    def gets(sep)
      buffer = ""
      until buffer.end_with?(sep)
        buffer << readpartial(1)
      end
      buffer
    rescue EOFError
      if buffer.size > 1
        buffer
      else
        nil
      end
    end

    private

    def select_timeout(type, timeout)
      if timeout >= 0
        if type == :read
          read_array = [@socket]
        else
          write_array = [@socket]
        end

        start = Time.now
        if IO.select(read_array, write_array, [@socket], timeout)
          waited = Time.now - start
          return timeout - waited
        end
      end
      raise SocketTimeout, "#{type} timeout"
    end
  end

  # Wraps up OpenSSL::SSL::SSLSocket and offers debugging features.
  class SSLSocketWrap
    def initialize(socket, context, debug_dev = nil)
      unless SSLEnabled
        raise ConfigurationError.new('Ruby/OpenSSL module is required')
      end
      @context = context
      @socket = socket
      @ssl_socket = create_openssl_socket(@socket)
      @debug_dev = debug_dev
    end

    def ssl_connect(hostname = nil)
      if hostname && @ssl_socket.respond_to?(:hostname=)
        @ssl_socket.hostname = hostname
      end
      @ssl_socket.connect
    end

    def post_connection_check(host)
      verify_mode = @context.verify_mode || OpenSSL::SSL::VERIFY_NONE
      if verify_mode == OpenSSL::SSL::VERIFY_NONE
        return
      elsif @ssl_socket.peer_cert.nil? and
        check_mask(verify_mode, OpenSSL::SSL::VERIFY_FAIL_IF_NO_PEER_CERT)
        raise OpenSSL::SSL::SSLError.new('no peer cert')
      end
      hostname = host.host
      if @ssl_socket.respond_to?(:post_connection_check) and RUBY_VERSION > "1.8.4"
        @ssl_socket.post_connection_check(hostname)
      else
        @context.post_connection_check(@ssl_socket.peer_cert, hostname)
      end
    end

    def ssl_version
      @ssl_socket.ssl_version if @ssl_socket.respond_to?(:ssl_version)
    end

    def ssl_cipher
      @ssl_socket.cipher
    end

    def ssl_state
      @ssl_socket.state
    end

    def peer_cert
      @ssl_socket.peer_cert
    end

    def close
      @ssl_socket.close
      @socket.close
    end

    def closed?
      @socket.closed?
    end

    def eof?
      @ssl_socket.eof?
    end

    def gets(*args)
      str = @ssl_socket.gets(*args)
      debug(str)
      str
    end

    def read(*args)
      str = @ssl_socket.read(*args)
      debug(str)
      str
    end

    def readpartial(*args)
      str = @ssl_socket.readpartial(*args)
      debug(str)
      str
    end

    def <<(str)
      rv = @ssl_socket.write(str)
      debug(str)
      rv
    end

    def flush
      @ssl_socket.flush
    end

    def sync
      @ssl_socket.sync
    end

    def sync=(sync)
      @ssl_socket.sync = sync
    end

  private

    def check_mask(value, mask)
      value & mask == mask
    end

    def create_openssl_socket(socket)
      ssl_socket = nil
      if OpenSSL::SSL.const_defined?("SSLContext")
        ctx = OpenSSL::SSL::SSLContext.new
        @context.set_context(ctx)
        ssl_socket = OpenSSL::SSL::SSLSocket.new(socket, ctx)
      else
        ssl_socket = OpenSSL::SSL::SSLSocket.new(socket)
        @context.set_context(ssl_socket)
      end
      ssl_socket
    end

    def debug(str)
      @debug_dev << str if @debug_dev && str
    end
  end


  # Wraps up a Socket for method interception.
  module SocketWrap
    def initialize(socket, *args)
      super(*args)
      @socket = socket
    end

    def close
      @socket.close
    end

    def closed?
      @socket.closed?
    end

    def eof?
      @socket.eof?
    end

    def gets(*args)
      @socket.gets(*args)
    end

    def read(*args)
      @socket.read(*args)
    end

    def readpartial(*args)
      # StringIO doesn't support :readpartial
      if @socket.respond_to?(:readpartial)
        @socket.readpartial(*args)
      else
        @socket.read(*args)
      end
    end

    def <<(str)
      @socket << str
    end

    def flush
      @socket.flush
    end

    def sync
      @socket.sync
    end

    def sync=(sync)
      @socket.sync = sync
    end
  end


  # Module for intercepting Socket methods and dumps in/out to given debugging
  # device.  debug_dev must respond to <<.
  module DebugSocket
    extend SocketWrap

    def debug_dev=(debug_dev)
      @debug_dev = debug_dev
    end

    def close
      super
      debug("! CONNECTION CLOSED\n")
    end

    def gets(*args)
      str = super
      debug(str)
      str
    end

    def read(*args)
      str = super
      debug(str)
      str
    end

    def readpartial(*args)
      str = super
      debug(str) if(args.first > 1)
      str
    end

    def <<(str)
      super
      debug(str)
    end

  private

    def debug(str)
      if str && @debug_dev
        if str.index("\0")
          require 'hexdump'
          str.force_encoding('BINARY') if str.respond_to?(:force_encoding)
          @debug_dev << HexDump.encode(str).join("\n")
        else
          @debug_dev << str
        end
      end
    end
  end


  # Dummy Socket for emulating loopback test.
  class LoopBackSocket
    include SocketWrap

    def initialize(host, port, response)
      super(response.is_a?(StringIO) ? response : StringIO.new(response))
      @host = host
      @port = port
    end

    def <<(str)
      # ignored
    end
  end
end
