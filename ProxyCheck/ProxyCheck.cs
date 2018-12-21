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
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using static ProxyCheckUtil.ProxyCheckResult;

namespace ProxyCheckUtil
{
    public enum StatusResult
    {
        OK,
        Warning,
        Denied,
        Error,
    }

    public class ProxyCheckResult
    {
        /// <summary>
        /// API status result
        /// </summary>
        public StatusResult Status { get; set; }

        /// <summary>
        /// Answering node
        /// </summary>
        public string Node { get; set; }

        /// <summary>
        /// Dictionary of results for the IP address(es) provided
        /// </summary>
        public Dictionary<IPAddress, IpResult> Results { get; } = new Dictionary<IPAddress, IpResult>();
     
        /// <summary>
        /// The amount of time the query took on the server
        /// </summary>
        public TimeSpan? QueryTime { get; set; }

        public class IpResult
        {
            /// <summary>
            /// The ASN the IP address belongs to
            /// </summary>
            public string ASN { get; set; }

            /// <summary>
            /// The provider the IP address belongs to
            /// </summary>
            public string Provider { get; set; }

            /// <summary>
            /// The country the IP address is in.
            /// </summary>
            public string Country { get; set; }

            /// <summary>
            /// The latitude of the IP address
            /// </summary>
            /// <remarks>
            /// This is not the exact location of the IP address
            /// </remarks>
            public double? Latitude { get; set; }
            /// <summary>
            /// The longitude of the IP address
            /// </summary>
            /// <remarks>
            /// This is not the exact location of the IP address
            /// </remarks>
            public double? Longitude { get; set; }
            /// <summary>
            /// The city the of the IP address
            /// </summary>
            /// <remarks>
            /// This may not be the exact city
            /// </remarks>
            public string City { get; set; }

            /// <summary>
            /// ISO Country code of the IP address country
            /// </summary>
            public string ISOCode { get; set; }

            /// <summary>
            /// True if the IP is detected as proxy
            /// False otherwise
            /// </summary>
            public bool IsProxy { get; set; }

            /// <summary>
            /// The type of proxy detected
            /// </summary>
            public string ProxyType { get; set; }

            /// <summary>
            /// The port the proxy server is operating on
            /// </summary>
            public int? Port { get; set; }

            /// <summary>
            /// The last time the proxy server was seen in human readable format.
            /// </summary>
            public string LastSeenHuman { get; set; }

            /// <summary>
            /// The last time the proxy server was seen in Unix time stamp
            /// </summary>
            public long? LastSeenUnix { get; set; }

            /// <summary>
            /// The last time the proxy server was seen
            /// </summary>
            public DateTimeOffset? LastSeen
            {
                get
                {
                    if (LastSeenUnix == null)
                        return null;

                    return DateTimeOffset.FromUnixTimeSeconds(LastSeenUnix.Value);
                }

            }

            /// <summary>
            /// If not `null` the description of the error that occured
            /// </summary>
            public string ErrorMessage { get; set; }
        }
    }

    public class ProxyCheck
    {
        private const string PROXYCHECKURL = "proxycheck.io/v2";

        /// <summary>
        /// The API key to use with the query
        /// (Default: String.Empty)
        /// </summary>
        public string ApiKey { get; set; } = "";

        /// <summary>
        /// Including checking for VPN
        /// (Default: false)
        /// </summary>
        public bool IncludeVPN { get; set; } = false;

        /// <summary>
        /// Use HTTPS when checking IP address (slower)
        /// (Default: false)
        /// </summary>
        public bool UseTLS { get; set; } = false;

        /// <summary>
        /// Enables viewing the ASN of the network the IP address belongs to
        /// (Default: false)
        /// </summary>
        public bool IncludeASN { get; set; } = false;

        /// <summary>
        /// Includes the answering node in the reply
        /// (Default: false)
        /// </summary>
        public bool IncludeNode { get; set; } = false;

        /// <summary>
        /// Includes the time it took for query
        /// (Default: false)
        /// </summary>
        public bool IncludeTime { get; set; } = false;

        /// <summary>
        /// Use the real-time inference engine
        /// (Default: true)
        /// </summary>
        public bool UseInference { get; set; } = true;

        /// <summary>
        /// Includes port number the IP was last seen operating a proxy server on
        /// (Default: false)
        /// </summary>
        public bool IncludePort { get; set; } = false;

        /// <summary>
        /// Includes the last time the IP address was seen acting as a proxy server
        /// (Default: false)
        /// </summary>
        public bool IncludeLastSeen { get; set; } = false;

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
        /// <returns>Object describing the result.</returns>
        public async Task<ProxyCheckResult> QueryAsync(IPAddress ipAddress, string tag = "")
        {
            return await QueryAsync(new IPAddress[] {ipAddress}, tag);
        }

        /// <summary>
        /// Checks to see if the given IP address is a proxy
        /// </summary>
        /// <param name="ipAddresses">The IP addresses to check</param>
        /// <param name="tag">Optional tag</param>
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
        /// <returns>Object describing the result.</returns>
        public async Task<ProxyCheckResult> QueryAsync(IPAddress[] ipAddresses, string tag = "")
        {
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

                if (!ipAddresses.Any())
                    throw new ArgumentException("Must contain at least 1 IP Address", nameof(ipAddresses));

                string ipList = string.Join(",", ipAddresses.Select(c => c.ToString()));
                postData.Add("ips", ipList);

                if (!string.IsNullOrWhiteSpace(tag))
                    postData.Add("tag", tag);

                FormUrlEncodedContent content = new FormUrlEncodedContent(postData);

                try
                {
                    HttpResponseMessage response = null;

                    response = await client.PostAsync(url.ToString(), content);

                    string json = await response.Content.ReadAsStringAsync();

                    return ParseJson(json);

                }
                catch (Exception e)
                {
                    // Should do something here just rethrowing
                    throw;
                }
            }

        }

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
                            IpResult ipResult = new IpResult();

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

