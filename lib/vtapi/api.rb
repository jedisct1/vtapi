require 'rest-client'
require 'tempfile'
require 'json'

class VtAPI
  # base URL of the VirusTotal Public API v2.0 
  BASE_URL = 'https://www.virustotal.com/vtapi/v2/'

  attr_reader :apikey

  def initialize(apikey)
    @apikey = apikey
  end

  def file_scan(data)
    # TODO: set filename or file path
    tmp = Tempfile.open('tmp')
    tmp.write data
    def tmp.content_type
      'application/octet-stream'
    end
    tmp.pos=0
    http_post('file/scan', file: tmp, multipart: true)
  end

  def file_rescan(resource)
    if resource.is_a? Array
      raise 'limit is up to 25 items' if resource.size > 25
      resource = resource.join(', ')
    end
    http_post('file/rescan', resource: resource)
  end

  def file_report(resource)
    if resource.is_a? Array
      raise 'limit is up to 4 items' if resource.size > 4
      resource = resource.join(', ')
    end
    http_post('file/report', resource: resource)
  end

  def url_scan(url)
    if url.is_a? Array
      raise 'limit is up to 4 items' if url.size > 4
      url = url.join("\n")
    end
    http_post('url/scan', url: url)
  end

  def url_report(url)
    if url.is_a? Array
      raise 'limit is up to 4 items' if url.size > 4
      url = url.join(", ")
    end
    http_post('url/report', resource: url)
  end

  def url_distribution()
    http_get('url/distribution')
  end

  def ip_report(ip)
    raise 'only one IP address can be scanned at a time' if ip.is_a? Array
    http_get('ip-address/report', ip: ip)
  end

  def domain_report(domain)
    raise 'only one domain can be scanned at a time' if domain.is_a? Array
    http_get('domain/report', domain: domain)
  end

  def http_query(verb, path, params = { })
    uri = BASE_URL + path
    params['apikey'] = @apikey
    params =
      case verb
      when :get
        { params: params }
      when :post
        params
      else
        raise "Unsupported verb: #{verb}"
      end
    resp = RestClient.send(verb, uri, params) do |resp, req, result, &block|
      case resp.code
      when 204
        raise ExceedAPILimit, "you exceed the public API request rate limit: key[#{@apikey}]"
      when 403
        raise AuthError, "you do not have the required priviledges: key[#{@apikey}]"
      else
        resp.return!(req, result, &block)
      end
    end
    Response.parse(resp.body)
  end

  def http_get(path, params = {})
    http_query(:get, path, params)
  end

  def http_post(path, params = {})
    http_query(:post, path, params)
  end
end
