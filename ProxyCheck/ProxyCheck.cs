/*
 * This is free and unencumbered software released into the public domain.
 * 
 * Anyone is free to copy, modify, publish, use, compile, sell, or
 * distribute this software, either in source code form or as a compiled
 * binary, for any purpose, commercial or non-commercial, and by any
 * means.
 * 
 * In jurisdictions that recognize copyright laws, the author or authors
 * of this software dedicate any and all copyright interest in the
 * software to the public domain. We make this dedication for the benefit
 * of the public at large and to the detriment of our heirs and
 * successors. We intend this dedication to be an overt act of
 * relinquishment in perpetuity of all present and future rights to this
 * software under copyright law.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 * 
 * For more information, please refer to <https://unlicense.org>
*/

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace ProxyCheckUtil
{
    [PublicAPI]
    public class ProxyCheck
    {
        /// <summary>
        /// Creates the ProxyCheck object with optional API key and cache provider
        /// </summary>
        /// <param name="apiKey">API key to use</param>
        /// <param name="cacheProvider">Cache provider to use</param>
        public ProxyCheck(string apiKey = "", IProxyChceckCacheProvider cacheProvider = null)
        {
            if (apiKey == null)
                apiKey = string.Empty;

            ApiKey = apiKey;
            CacheProvider = cacheProvider;
        }

        public ProxyCheck(IProxyChceckCacheProvider cacheProvider)
        {
            CacheProvider = cacheProvider;
        }

        private const string PROXYCHECKURL = "proxycheck.io/v2";
        
        private ProxyCheckRequestOptions _options = new ProxyCheckRequestOptions();


        public IProxyChceckCacheProvider CacheProvider { get; set; }

        /// <summary>
        /// The API key to use with the query
        /// (Default: String.Empty)
        /// </summary>
        public string ApiKey { get; set; }

        #region Request options kept here for legacy reasons

        /// <summary>
        /// Including checking for VPN
        /// (Default: false)
        /// </summary>
        public bool IncludeVPN
        {
            get => _options.IncludeVPN;
            set => _options.IncludeVPN = value;
        }

        /// <summary>
        /// Use HTTPS when checking IP address (slower)
        /// (Default: false)
        /// </summary>
        public bool UseTLS
        {
            get => _options.UseTLS;
            set => _options.UseTLS = value;
        }

        /// <summary>
        /// Enables viewing the ASN of the network the IP address belongs to
        /// (Default: false)
        /// </summary>
        public bool IncludeASN
        {
            get => _options.IncludeASN;
            set => _options.IncludeASN = value;
        }


        /// <summary>
        /// Use the real-time inference engine
        /// (Default: true)
        /// </summary>
        public bool UseInference
        {
            get => _options.UseInference;
            set => _options.UseInference = value;
        }

        /// <summary>
        /// Includes port number the IP was last seen operating a proxy server on
        /// (Default: false)
        /// </summary>
        public bool IncludePort
        {
            get => _options.IncludePort;
            set => _options.IncludePort = value;
        }

        /// <summary>
        /// Includes the last time the IP address was seen acting as a proxy server
        /// (Default: false)
        /// </summary>
        public bool IncludeLastSeen
        {
            get => _options.IncludeLastSeen;
            set => _options.IncludeLastSeen = value;
        }


        #endregion

        /// <summary>
        /// Includes the answering node in the reply
        /// (Default: false)
        /// </summary>
        public bool IncludeNode { get; set; }

        /// <summary>
        /// Includes the time it took for query
        /// (Default: false)
        /// </summary>
        public bool IncludeTime { get; set; }

        /// <summary>
        /// Restircts the proxy results between now and amount specifed days ago.
        /// (Default: 7)
        /// </summary>
        public int DayLimit { get; set; } = 7;




        /// <summary>
        /// Checks to see if the given IP address is a proxy
        /// </summary>
        /// <param name="ipAddress">The IP address to check</param>
        /// <param name="tag">Optional tag</param>
        /// <exception cref="ProxyCheckException">An error has occured</exception>
        /// <returns>Object describing the result.</returns>
        public async Task<ProxyCheckResult> QueryAsync(string ipAddress, string tag = "")
        {
            if (ipAddress == null)
                throw new ArgumentNullException(nameof(ipAddress));

            if (!IPAddress.TryParse(ipAddress, out IPAddress ip))
                throw new ArgumentException("Must be a valid IP", nameof(ipAddress));

            return await QueryAsync(ip, tag);
        }

        /// <summary>
        /// Checks to see if the given IP address is a proxy
        /// </summary>
        /// <param name="ipAddress">The IP address to check</param>
        /// <param name="tag">Optional tag</param>
        /// <exception cref="ProxyCheckException">An error has occured</exception>
        /// <returns>Object describing the result.</returns>
        public async Task<ProxyCheckResult> QueryAsync(IPAddress ipAddress, string tag = "")
        {
            return await QueryAsync(new[] {ipAddress}, tag);
        }

        /// <summary>
        /// Checks to see if the given IP address is a proxy
        /// </summary>
        /// <param name="ipAddresses">The IP addresses to check</param>
        /// <param name="tag">Optional tag</param>
        /// <exception cref="ProxyCheckException">An error has occured</exception>
        /// <returns>Object describing the result.</returns>
        public async Task<ProxyCheckResult> QueryAsync(string[] ipAddresses, string tag = "")
        {
            if (ipAddresses == null)
                throw new ArgumentNullException(nameof(ipAddresses));

            if (ipAddresses.Length == 0)
                throw new ArgumentException("Must have at least 1 IP address", nameof(ipAddresses));

            List<IPAddress> ips = new List<IPAddress>(ipAddresses.Length);
            foreach (var ipString in ipAddresses)
            {
                if (!IPAddress.TryParse(ipString, out IPAddress ip))
                    throw new ArgumentException($"Invalid IP address provided. `{ipString}` is not a valid IP");

                ips.Add(ip);
            }

            return await QueryAsync(ips.ToArray(), tag);
        }

        /// <summary>
        /// Checks to see if the given IP address is a proxy
        /// </summary>
        /// <param name="ipAddresses">The IP addresses to check</param>
        /// <param name="tag">Optional tag</param>
        /// <exception cref="ProxyCheckException">An error has occured</exception>
        /// <returns>Object describing the result.</returns>
        public async Task<ProxyCheckResult> QueryAsync(IPAddress[] ipAddresses, string tag = "")
        {
            // We use this for if the cache is used and query is 100% cache hits
            Stopwatch sw = new Stopwatch();
            
            if (!ipAddresses.Any())
                throw new ArgumentException("Must contain at least 1 IP Address", nameof(ipAddresses));

            IDictionary<IPAddress, ProxyCheckResult.IpResult> ipResults = null;
            if (CacheProvider != null)
            {
                sw.Start();

                ipResults = CacheProvider.GetCacheRecords(ipAddresses, _options);

                // Ensure all the results are marked that they are cache hits

                foreach (var item in ipResults)
                    item.Value.IsCacheHit = true;

                // We need to weed out the cache hits to pass the misses to the api
                var ipList = ipAddresses.ToList();
                ipList.RemoveAll(c => ipResults.ContainsKey(c));
                ipAddresses = ipList.ToArray();

                // Not 100% cache hits dont need stop watch anymore
                if(ipAddresses.Any())
                    sw.Stop();
            }


            if (ipAddresses.Length == 0 && ipResults != null) // All cache hits
            {

                ProxyCheckResult result = new ProxyCheckResult
                {
                    Results = new Dictionary<IPAddress, ProxyCheckResult.IpResult>(ipResults),
                    Status = StatusResult.OK,
                    Node = IncludeNode ? "CACHE" : null
                };

                // 100% cache hits let's stop now
                sw.Stop();
                result.QueryTime = sw.Elapsed;

                return result;
            }

            var url = new StringBuilder()
                .Append($"{(UseTLS ? "https://" : "http://")}{PROXYCHECKURL}/")
                .Append(!string.IsNullOrWhiteSpace(ApiKey) ? $"&key={ApiKey}" : "")
                .Append($"&vpn={Convert.ToInt32(IncludeVPN)}")
                .Append($"&asn={Convert.ToInt32(IncludeASN)}")
                .Append($"&node={Convert.ToInt32(IncludeNode)}")
                .Append($"&time={Convert.ToInt32(IncludeTime)}")
                .Append($"&inf={Convert.ToInt32(UseInference)}")
                .Append($"&port={Convert.ToInt32(IncludePort)}")
                .Append($"&seen={Convert.ToInt32(IncludeLastSeen)}")
                .Append($"&days={Convert.ToInt32(DayLimit)}");

            using (var client = new HttpClient())
            {
                Dictionary<string, string> postData = new Dictionary<string, string>();

                string ipList = string.Join(",", ipAddresses.Select(c => c.ToString()));
                postData.Add("ips", ipList);

                if (!string.IsNullOrWhiteSpace(tag))
                    postData.Add("tag", tag);

                FormUrlEncodedContent content = new FormUrlEncodedContent(postData);

                try
                {
                    var response = await client.PostAsync(url.ToString(), content);

                    string json = await response.Content.ReadAsStringAsync();

                    ProxyCheckResult result = ParseJson(json);

                    // We want to update the cache now
                    CacheProvider?.SetCacheRecord(result.Results, _options);

                    if (ipResults == null || !ipResults.Any()) // Return current results as none were cache hits
                        return result;

                    foreach (var item in ipResults)
                    {
                        if(result.Results.ContainsKey(item.Key))
                            continue; // We don't want to include a cache hit from an IP that was somehow gotten from API too.

                        result.Results.Add(item.Key, item.Value);
                    }

                    return result;

                }
                catch (ArgumentNullException e)
                {
                    throw new ProxyCheckException("URL should not be NULL", e);
                }
                catch (JsonReaderException e)
                {
                    throw new ProxyCheckException("Bad JSON from server", e);
                }
                catch (Exception e)
                {
                    throw new ProxyCheckException("Unknown state please check the inner exception.", e);
                }
            }

        }

        /// <summary>
        /// Parses the servers JSON response
        /// </summary>
        /// <param name="json">JSON to Parse</param>
        /// <returns>The parsed JSON</returns>
        private ProxyCheckResult ParseJson(string json)
        {
            ProxyCheckResult res = new ProxyCheckResult();

            JObject obj = JObject.Parse(json);

            foreach (var token in obj)
            {
                switch (token.Key)
                {
                    case "status":
                        if (Enum.TryParse((string) token.Value, true, out StatusResult statusResult))
                        {
                            res.Status = statusResult;
                        }

                        break;

                    case "node":
                        res.Node = (string) token.Value;
                        break;

                    case "query time":
                        double secs = Convert.ToDouble(((string) token.Value).Substring(0, ((string) token.Value).Length - 1));
                        TimeSpan ts = TimeSpan.FromSeconds(secs);
                        res.QueryTime = ts;
                        break;

                    default:
                        if (IPAddress.TryParse(token.Key, out IPAddress ip))
                        {
                            ProxyCheckResult.IpResult ipResult = new ProxyCheckResult.IpResult();

                            foreach (var innerToken in (JObject) token.Value)
                            {
                                switch (innerToken.Key)
                                {
                                    case "asn":
                                        ipResult.ASN = (string) innerToken.Value;
                                        break;

                                    case "provider":
                                        ipResult.Provider = (string) innerToken.Value;
                                        break;

                                    case "country":
                                        ipResult.Country = (string) innerToken.Value;
                                        break;

                                    case "latitude":
                                        ipResult.Latitude = Convert.ToDouble((string) innerToken.Value);
                                        break;

                                    case "longitude":
                                        ipResult.Longitude = Convert.ToDouble((string) innerToken.Value);
                                        break;

                                    case "isocode":
                                        ipResult.ISOCode = (string) innerToken.Value;
                                        break;

                                    case "city":
                                        ipResult.City = (string) innerToken.Value;
                                        break;

                                    case "proxy":
                                        string isProxy = (string) innerToken.Value;
                                        ipResult.IsProxy = isProxy.Equals("yes", StringComparison.OrdinalIgnoreCase);
                                        break;

                                    case "type":
                                        ipResult.ProxyType = (string)innerToken.Value;
                                        break;

                                    case "port":
                                        ipResult.Port = Convert.ToInt32((string) innerToken.Value);
                                        break;

                                    case "last seen human":
                                        ipResult.LastSeenHuman = (string) innerToken.Value;
                                        break;

                                    case "last seen unix":
                                        ipResult.LastSeenUnix = Convert.ToInt64((string) innerToken.Value);
                                        break;

                                    case "error":
                                        ipResult.ErrorMessage = (string) innerToken.Value;
                                        break;

                                    default:
                                        Debug.WriteLine(
                                            $"Unknown item present Key: {innerToken.Key}, Value:{innerToken.Value}");
                                        break;
                                }
                            }

                            res.Results.Add(ip, ipResult);
                        }

                        break;
                }
            }

            return res;
        }
    }
}

