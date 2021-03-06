require 'json'
require 'time'

class VtAPI
  class Response
    def self.parse(response_body)
      json = JSON.parse(response_body)
      if json.is_a? Array
        return json.map{|e| Response.new(e) }
      else
        return Response.new(json)
      end
    end

    def initialize(json)
      @json = json
      @json.keys.each do |key|
        Response.class_eval {
          define_method key.to_s do |*args|
            @json[key]
          end
        }
      end
      @json['scan_date'] = Time.parse(@json['scan_date'] + "UTC") if @json.has_key? 'scan_date'
    end

    def keys
      @json.keys
    end

    def positive_threats
      Hash[@json.fetch('scans', {}).select{|k,v| v['detected'] }.map{|k,v| [k, v['result']] }]
    end

    def positive_brands
      @json.fetch('scans', {}).select{|k,v| v['detected'] }.keys
    end

    def scan_results
      Hash[@json.fetch('scans', {}).map{|k,v| [k, v['result']] }]
    end

    def [](key)
      @json.fetch(key.to_s) # raise KeyError when key doesn't exist.
    end

    def to_s
      @json.to_json
    end
  end
end
