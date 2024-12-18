using JetBrains.Annotations;

namespace ProxyCheckUtil
{
    [PublicAPI]
    public class ProxyCheckRequestOptions
    {
        /// <summary>
        /// Including checking for VPN
        /// (Default: false)
        /// </summary>
        public bool IncludeVPN { get; set; }

        /// <summary>
        /// Use HTTPS when checking IP address (slower)
        /// (Default: false)
        /// </summary>
        public bool UseTLS { get; set; }

        /// <summary>
        /// Enables viewing the ASN of the network the IP address belongs to
        /// (Default: false)
        /// </summary>
        public bool IncludeASN { get; set; }

        /// <summary>
        /// Use the real-time inference engine
        /// (Default: true)
        /// </summary>
        public bool UseInference { get; set; } = true;

        /// <summary>
        /// Includes port number the IP was last seen operating a proxy server on
        /// (Default: false)
        /// </summary>
        public bool IncludePort { get; set; }

        /// <summary>
        /// Includes the last time the IP address was seen acting as a proxy server
        /// (Default: false)
        /// </summary>
        public bool IncludeLastSeen { get; set; }

        /// <summary>
        /// Determines whether you will receive a risk score with the result. If enabled, a risk score will be included
        /// with your response.<br/>
        /// (Default: <see cref="RiskLevel.Disabled"/>) 
        /// </summary>
        public RiskLevel? RiskLevel { get; set; }

        public override bool Equals(object obj)
        {
            if (!(obj is ProxyCheckRequestOptions o))
                return false;

            if (IncludeVPN != o.IncludeVPN)
                return false;

            if (UseTLS != o.UseTLS)
                return false;

            if (IncludeASN != o.IncludeASN)
                return false;

            if (UseInference != o.UseInference)
                return false;

            if (IncludePort != o.IncludePort)
                return false;

            if (RiskLevel != o.RiskLevel)
                return false;

            return IncludeLastSeen == o.IncludeLastSeen;
        }
    }
}