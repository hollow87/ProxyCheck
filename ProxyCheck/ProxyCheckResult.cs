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
using JetBrains.Annotations;

namespace ProxyCheckUtil
{
    [PublicAPI]
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
        public Dictionary<IPAddress, IpResult> Results { get; internal set; } = new Dictionary<IPAddress, IpResult>();

        /// <summary>
        /// The amount of time the query took on the server
        /// </summary>
        public TimeSpan? QueryTime { get; set; }

        [PublicAPI]
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

            /// <summary>
            /// True if this item was retrieved from cache
            /// </summary>
            public bool IsCacheHit { get; set; }
        }
    }
}
