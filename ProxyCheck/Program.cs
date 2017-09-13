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
using System.Text;

namespace ProxyCheck
{
    class Program
    {
        static void Main(string[] args)
        {
            ProxyCheck check = new ProxyCheck
            {
                ApiKey = "v5w179-tee693-636ri1-r4f211",
                IncludeVPN = true,
                IncludeASN = true,
                IncludeNode = true,
                IncludeTime = true,
                UseTLS = false
            };

            // Without tag
            // var resp = check.QueryAsync(IPAddress.Parse("37.60.48.2")).Result;

            // With Tag
            var resp = check.QueryAsync(IPAddress.Parse("37.60.48.2"), "test").Result;

            Console.WriteLine($"Node: {resp.Node}");
            Console.WriteLine($"ASN: {resp.ASN}");
            Console.WriteLine($"Provider: {resp.Provider}");
            Console.WriteLine($"Country: {resp.Country}");
            Console.WriteLine($"IP Address: {resp.IPAddress}");
            Console.WriteLine($"IP: {resp.IP}");
            Console.WriteLine($"Proxy: {resp.Proxy}");
            Console.WriteLine($"ISProxy: {resp.IsProxy}");
            Console.WriteLine($"Type: {resp.Type}");
            Console.WriteLine($"Query Time: {resp.QueryTime}");
            Console.WriteLine($"Error: {resp.Error}");

            Console.WriteLine();
            Console.WriteLine("----------------------");
            Console.WriteLine();

            var isProxy = check.IsProxyAsync(IPAddress.Parse("37.60.48.2"), "test").Result;

            Console.WriteLine($"Is Proxy: {isProxy}");

            Console.WriteLine();
            Console.WriteLine("----------------------");
            Console.WriteLine();
            
            Console.WriteLine("Press any key to exit");
            Console.ReadKey(true);
        }
    }
}
