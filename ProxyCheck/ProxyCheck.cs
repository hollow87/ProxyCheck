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
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;

namespace ProxyCheck
{
    public class ProxyCheck
    {
        public class ProxyCheckResposne
        {
            [JsonProperty(PropertyName = "node")]
            public string Node { get; internal set; }

            [JsonProperty(PropertyName = "asn")]
            public string ASN { get; internal set; }

            [JsonProperty(PropertyName = "provider")]
            public string Provider { get; internal set; }

            [JsonProperty(PropertyName = "country")]
            public string Country { get; internal set; }

            [JsonProperty(PropertyName = "ip")]
            public string IP { get; internal set; }

            public IPAddress IPAddress => IPAddress.Parse(IP);

            [JsonProperty(PropertyName = "proxy")]
            public string Proxy { get; internal set; }

            public bool IsProxy => Proxy.ToLower() == "yes";

            [JsonProperty(PropertyName = "type")]
            public string Type { get; internal set; }

            [JsonProperty(PropertyName = "query time")]
            public string QueryTime { get; internal set; }

            [JsonProperty(PropertyName = "error")]
            public string Error { get; internal set; }
        }

        private const string PROXYCHECKURL = "proxycheck.io/v1";

        /// <summary>
        /// The API key to use with the query
        /// </summary>
        public string ApiKey { get; set; } = "";

        /// <summary>
        /// Including checking for VPN
        /// </summary>
        public bool IncludeVPN { get; set; }

        /// <summary>
        /// Use HTTPS when checking IP address (slower)
        /// </summary>
        public bool UseTLS { get; set; }

        /// <summary>
        /// Enables viewing the ASN of the network the IP address belongs to
        /// </summary>
        public bool IncludeASN { get; set; }

        /// <summary>
        /// Includes the answering node in the reply
        /// </summary>
        public bool IncludeNode { get; set; }

        /// <summary>
        /// Includes the time it took for query
        /// </summary>
        public bool IncludeTime { get; set; }

        public async Task<bool> IsProxyAsync(IPAddress ipAddress, string tag = "")
        {
            try
            {
                var response = await QueryAsync(ipAddress, tag);

                if (!string.IsNullOrWhiteSpace(response.Error))
                    throw new Exception(response.Error);

                return response.IsProxy;
            }
            catch(Exception e)
            {
                // Just rethrowing the exception
                throw;
            }
        }

        public async Task<ProxyCheckResposne> QueryAsync(IPAddress ipAddress, string tag = "")
        {
            var url = new StringBuilder()
                .Append($"{(UseTLS ? "https://" : "http://")}{PROXYCHECKURL}/{ipAddress}")
                .Append(!string.IsNullOrWhiteSpace(ApiKey) ? $"&key={ApiKey}" : "")
                .Append($"{(IncludeVPN ? "&vpn=1" : "")}")
                .Append($"{(IncludeASN ? "&asn=1" : "")}")
                .Append($"{(IncludeNode ? "&node=1" : "")}")
                .Append($"{(IncludeTime ? "&time=1" : "")}");

            using (var client = new HttpClient())
            {
                FormUrlEncodedContent content = null;
                
                if (!string.IsNullOrWhiteSpace(tag))
                {
                    content = new FormUrlEncodedContent(new Dictionary<string, string>
                    {
                        {"tag", tag}
                    });
                }

                try
                {
                    HttpResponseMessage response = null;
                    if (content != null)
                        response = await client.PostAsync(url.ToString(), content);
                    else
                        response = await client.GetAsync(url.ToString());

                    string json = await response.Content.ReadAsStringAsync();

                    ProxyCheckResposne result = JsonConvert.DeserializeObject<ProxyCheckResposne>(json);

                    return result;
                }
                catch(Exception e)
                {
                    // Should do something here just rethrowing
                    throw;
                }
            }

        }
    }
}
