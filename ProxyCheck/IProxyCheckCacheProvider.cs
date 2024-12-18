using System.Collections.Generic;
using System.Net;

namespace ProxyCheckUtil
{
    public interface IProxyCheckCacheProvider
    {
        ProxyCheckResult.IpResult GetCacheRecord(IPAddress ip, ProxyCheckRequestOptions options);

        IDictionary<IPAddress, ProxyCheckResult.IpResult> GetCacheRecords(IPAddress[] ipAddress, ProxyCheckRequestOptions options);

        void SetCacheRecord(IDictionary<IPAddress, ProxyCheckResult.IpResult> results,
            ProxyCheckRequestOptions options);
    }
}