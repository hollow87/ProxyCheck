using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;

namespace ProxyCheckUtil
{
    public class SimpleInMemoryCache : IProxyCheckCacheProvider
    {
        private List<CacheItem> _cacheItems = new List<CacheItem>();
        private TimeSpan _maxCacheAge = TimeSpan.FromHours(1);

        private class CacheItem
        {
            public IPAddress IPAddress { get; set; }
            public ProxyCheckRequestOptions Options { get; set; }

            public ProxyCheckResult.IpResult Result { get; set; }

            public DateTimeOffset Time { get; set; }

        }

        public SimpleInMemoryCache()
        {

        }

        public SimpleInMemoryCache(TimeSpan maxCacheAge)
        {
            _maxCacheAge = maxCacheAge;
        }

        public ProxyCheckResult.IpResult GetCacheRecord(IPAddress ip, ProxyCheckRequestOptions options)
        {
            var results = GetCacheRecords(new[] {ip}, options);

            if (results != null && results.ContainsKey(ip))
                return results[ip];

            return null;
        }

        public IDictionary<IPAddress, ProxyCheckResult.IpResult> GetCacheRecords(IPAddress[] ipAddress, ProxyCheckRequestOptions options)
        {
            // Let's clean the cache first
            CleanCache();

            var cacheHits =
                _cacheItems.Where(c => ipAddress.Any(ip => ip.Equals(c.IPAddress)) && c.Options.Equals(options)).ToArray();

            var results = new Dictionary<IPAddress, ProxyCheckResult.IpResult>(cacheHits.Length);

            foreach (var item in cacheHits)
            {
                results.Add(item.IPAddress, item.Result);
            }

            return results;
        }

        public void SetCacheRecord(IDictionary<IPAddress, ProxyCheckResult.IpResult> results, ProxyCheckRequestOptions options)
        {
            // Let's clean the cache first
            CleanCache();

            // We are not going to bother with removing existing exact matches as cleaning them upon a request/store will remove them.
            foreach (var item in results)
            {
                CacheItem cItem = new CacheItem
                {
                    IPAddress = item.Key,
                    Options = options,
                    Result = item.Value,
                    Time = DateTimeOffset.UtcNow
                };

                _cacheItems.Add(cItem);
            }
        }

        private void CleanCache()
        {
            _cacheItems.RemoveAll(c => c.Time + _maxCacheAge <= DateTimeOffset.UtcNow);
        }
    }
}