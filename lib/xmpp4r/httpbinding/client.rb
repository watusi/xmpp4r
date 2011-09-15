# =XMPP4R - XMPP Library for Ruby
# License:: Ruby's license (see the LICENSE file) or GNU GPL, at your option.
# Website::http://home.gna.org/xmpp4r/

# TODO: eval  <body type='terminate' condition=

require 'xmpp4r/client'
require 'xmpp4r/semaphore'
require 'net/http'

module Jabber
  module HTTPBinding
    ##
    # This class implements an alternative Client
    # using HTTP Binding (JEP0124).
    #
    # This class is designed to be a drop-in replacement
    # for Jabber::Client, except for the
    # Jabber::HTTP::Client#connect method which takes an URI
    # as argument.
    #
    # HTTP requests are buffered to not exceed the negotiated
    # 'polling' and 'requests' parameters.
    #
    # Stanzas in HTTP resonses may be delayed to arrive in the
    # order defined by 'rid' parameters.
    #
    # =Debugging
    # Turning Jabber::debug to true will make debug output
    # not only spit out stanzas but HTTP request/response
    # bodies, too.
    class Client < Jabber::Client

      # Content-Type to be used for communication
      # (you can set this to "text/html")
      attr_accessor :http_content_type
      # The server should wait this value seconds if
      # there is no stanza to be received
      attr_accessor :http_wait
      # The server may hold this amount of stanzas
      # to reduce number of HTTP requests
      attr_accessor :http_hold

      ##
      # Initialize
      # jid:: [JID or String]
      # proxy:: [Net::HTTP] Proxy class (via Net::HTTP::Proxy).
      def initialize(jid, proxy=nil)
        super(jid)
        @lock = Mutex.new
        @http = proxy || Net::HTTP
        @http_wait = 20
        @http_hold = 1
        @http_content_type = 'text/xml; charset=utf-8'
        @allow_tls = false      # Shall be done at HTTP level
        initialize_for_connect  # Actually unnecessary, but nice to have these variables defined here
      end

      ##
      # Set up the stream using uri as the HTTP Binding URI
      #
      # You may optionally pass host and port parameters
      # to make use of the JEP0124 'route' feature.
      #
      # uri:: [URI::Generic or String]
      # host:: [String] Optional host to route to
      # port:: [Fixnum] Port for route feature
      # opts:: [Hash] :ssl_verify => false to defeat peer certificate verify
      #        [Fixnum] :http_inactivity => value to use for http_inactivity in
      #                 case the server does not specify.
      #        [Fixnum] :http_connect => time in seconds to wait for initial
      #                 connection.
      def connect(uri, host=nil, port=5222, opts={})

        initialize_for_connect  # Initial/default values for new connection, in case
                                # of connect/close/connect/close/connect on same object...

        uri = URI::parse(uri) unless uri.kind_of? URI::Generic
        @uri = uri

        opts = {
          :ssl_verify => true,

          # When we make the first post, we have no clue what value the server uses for
          # http_inactivity, since we haven't connected yet!
          :http_connect => 60,

          # As well, it's possible the server will NOT specify http_inactivity.
          # XEP-0124 states:
          #
          # "If the connection manager did not specify a maximum inactivity period
          # in the session creation response, then it SHOULD allow the client to be
          # inactive for as long as it chooses."
          #
          # So, we need to default this. If the server sends http_inactivity, then
          # that value will override our default.
          :http_inactivity => 60

          # In either case, if the client application has advance knowledge of the values
          # used by the server, then it should override these defaults using opts.

          }.merge(opts)

        @use_ssl = @uri.kind_of? URI::HTTPS
        @protocol_name = "HTTP#{'S' if @use_ssl}"
        @verify_mode = opts[:ssl_verify] ? OpenSSL::SSL::VERIFY_PEER : OpenSSL::SSL::VERIFY_NONE

        @http_connect = opts[:http_connect].to_i
        @http_inactivity = opts[:http_inactivity].to_i

        @http_rid = IdGenerator.generate_id.to_i
        @pending_rid = @http_rid
        @pending_rid_lock = Semaphore.new

        req_body = REXML::Element.new('body')
        req_body.attributes['rid'] = @http_rid
        req_body.attributes['content'] = @http_content_type
        req_body.attributes['hold'] = @http_hold.to_s
        req_body.attributes['wait'] = @http_wait.to_s
        req_body.attributes['to'] = @jid.domain
        req_body.attributes['ver'] = '1.8'
        if host
          req_body.attributes['route'] = "xmpp:#{host}:#{port}"
        end
        req_body.attributes['secure'] = 'true'
        req_body.attributes['xmlns'] = 'http://jabber.org/protocol/httpbind'
        req_body.attributes['xmlns:xmpp'] = 'urn:xmpp:xbosh'
        req_body.attributes['xmpp:version'] = '1.0'
        res_body = post(req_body)
        unless res_body.name == 'body'
          raise 'Response body is no <body/> element'
        end

        @streamid = res_body.attributes['authid']
        @status = CONNECTED
        @http_sid = res_body.attributes['sid']
        @http_wait = res_body.attributes['wait'].to_i if res_body.attributes['wait']
        @http_hold = res_body.attributes['hold'].to_i if res_body.attributes['hold']
        @http_inactivity = res_body.attributes['inactivity'].to_i if res_body.attributes['inactivity']
        @http_polling = res_body.attributes['polling'].to_i
        @http_polling = 5 if @http_polling == 0
        @http_requests = res_body.attributes['requests'].to_i
        @http_requests = 1 if @http_requests == 0

        receive_elements_with_rid(@http_rid, res_body.children)

        @features_sem.run
      end

      ##
      # Ensure that there is one pending request
      #
      # Will be automatically called if you've sent
      # a stanza.
      def ensure_one_pending_request
        return if is_disconnected?

        if @lock.synchronize { @pending_requests } < 1
          send_data('')
        end
      end

      ##
      # Close the session by sending
      # <presence type='unavailable'/>
      def close
        @status = DISCONNECTED
        send(Jabber::Presence.new.set_type(:unavailable))
      end

      ##
      # Send a body element with xmpp:restart set to true.
      def restart
        r = REXML::Element.new 'body'
        r.attributes['rid'] = @http_rid += 1
        r.attributes['sid'] = @http_sid
        r.attributes['to'] = @jid.domain
        r.attributes['xmlns'] = 'http://jabber.org/protocol/httpbind'
        r.attributes['xmlns:xmpp'] = 'urn:xmpp:xbosh'
        r.attributes['xmpp:restart'] = 'true'
        s = post(r)
        unless s.name == 'body'
          raise 'Response body is no <body/> element'
        end
        receive_elements_with_rid(@http_rid, s.children)
      end

      private

      # (re)initialize instances vars prior to connect()
      def initialize_for_connect
        @initial_post = true
        @http_requests = 1
        @pending_requests = 0
        @last_send = Time.at(0)
        @previous_send = Time.at(0)
        @send_buffer = ''
        @stream_mechanisms = []
        @stream_features = {}
      end

      ##
      # Receive stanzas ensuring that the 'rid' order is kept
      # result:: [REXML::Element]
      def receive_elements_with_rid(rid, elements)
        while rid > @pending_rid
          @pending_rid_lock.wait
        end
        @pending_rid = rid + 1

        elements.each { |e|
          receive(e)
        }

        @pending_rid_lock.run
      end

      ##
      # Do a POST request
      def post(body)
        body = body.to_s
        request = Net::HTTP::Post.new(@uri.path)
        request.content_length = body.size
        request.body = body
        request['Content-Type'] = @http_content_type

        # Server will disconnect @http_inactivity seconds after receiving previous client
        # response, unless it receives the post we are now sending.
        # Net::HTTP defaults to 60 seconds, which would not always be appropriate.
        # In particular, the default wouldf not work if @http_wait is > 60!
        if @initial_post == true
          read_timeout = @http_connect
          @initial_post = false
        elsif @previous_send == Time.at(0)
          read_timeout = @http_inactivity + 1
        else
          read_timeout = (Time.now - @previous_send).ceil + @http_inactivity
        end

        opts = {
          :read_timeout => read_timeout, # wait this long for a response
          :use_ssl => @use_ssl, 				 # Set SSL/no SSL
          :verify_mode => @verify_mode   # Allow caller to defeat certificate verify
        }
        Jabber::debuglog("#{@protocol_name} REQUEST (#{@pending_requests + 1}/#{@http_requests}) with timeout #{read_timeout}:\n#{request.body}")
        response = @http.start(@uri.host, @uri.port, nil, nil, nil, nil, opts ) { |http|
          http.request(request)
        }
        Jabber::debuglog("#{@protocol_name} RESPONSE (#{@pending_requests + 1}/#{@http_requests}): #{response.class}\n#{response.body}")

        unless response.kind_of? Net::HTTPSuccess
          # Unfortunately, HTTPResponses aren't exceptions
          # TODO: rescue'ing code should be able to distinguish
          raise Net::HTTPBadResponse, "#{response.class}"
        end

        body = REXML::Document.new(response.body).root
        if body.name != 'body' and body.namespace != 'http://jabber.org/protocol/httpbind'
          raise REXML::ParseException.new('Malformed body')
        end
        body
      end

      ##
      # Prepare data to POST and
      # handle the result
      def post_data(data)
        req_body = nil
        current_rid = nil

        begin
          begin
            @lock.synchronize {
              # Do not send unneeded requests
              @pending_requests += 1
              if data.size < 1 and @pending_requests > 1
                return
              end

              req_body = "<body"
              req_body += " rid='#{@http_rid += 1}'"
              req_body += " sid='#{@http_sid}'"
              req_body += " xmlns='http://jabber.org/protocol/httpbind'"
              req_body += ">"
              req_body += data
              req_body += "</body>"
              current_rid = @http_rid

              @previous_send = @last_send
              @last_send = Time.now

            }

            res_body = post(req_body)

          ensure
            @lock.synchronize { @pending_requests -= 1 }
          end

          receive_elements_with_rid(current_rid, res_body.children)
          ensure_one_pending_request

        rescue REXML::ParseException
          if @exception_block
            Thread.new do
              Thread.current.abort_on_exception = true
              close; @exception_block.call(e, self, :parser)
            end
          else
            Jabber::debuglog "Exception caught when parsing #{@protocol_name} response!"
            close
            raise
          end

        rescue StandardError => e
          Jabber::debuglog("POST error (will retry): #{e.class}: #{e}")
          receive_elements_with_rid(current_rid, [])
          # It's not good to resend on *any* exception,
          # but there are too many cases (Timeout, 404, 502)
          # where resending is appropriate
          # TODO: recognize these conditions and act appropriate
          send_data(data)
        end
      end

      ##
      # Send data,
      # buffered and obeying 'polling' and 'requests' limits
      def send_data(data)
        @lock.synchronize do

          @send_buffer += data
          limited_by_polling = (@last_send + @http_polling >= Time.now)
          limited_by_requests = (@pending_requests + 1 > @http_requests)

          # Can we send?
          if !limited_by_polling and !limited_by_requests
            data = @send_buffer
            @send_buffer = ''

            Thread.new do
              Thread.current.abort_on_exception = true
              post_data(data)
            end

          elsif !limited_by_requests
            Thread.new do
              Thread.current.abort_on_exception = true
              # Defer until @http_polling has expired
              wait = @last_send + @http_polling - Time.now
              sleep(wait) if wait > 0
              # Ignore locking, it's already threaded ;-)
              send_data('')
            end
          end

        end
      end
    end
  end
end
