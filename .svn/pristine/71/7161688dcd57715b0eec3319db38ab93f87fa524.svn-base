using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using Thinktecture.IdentityServer.Models;

namespace Thinktecture.IdentityServer.Helper
{
    public static class SFHelper
    {
        public static void WrapSWT(NameValueCollection collection, SFSimpleWebToken token, bool deflate)
        {
            var rawToken = token.RawToken;
            if (deflate)
            {
                var zipped = ZipStr(rawToken);
                rawToken = Convert.ToBase64String(zipped);
                collection["wrap_deflated"] = "true";
            }
            collection["wrap_access_token"] = HttpUtility.UrlEncode(rawToken);
            var seconds = Convert.ToInt32((token.ValidTo - token.ValidFrom).TotalSeconds);
            collection["wrap_access_token_expires_in"] = seconds.ToString();
        }

        public static string ToQueryString(NameValueCollection collection, bool startWithQuestionMark = true)
        {
            if (collection == null || !collection.HasKeys())
                return String.Empty;

            var sb = new StringBuilder();
            if (startWithQuestionMark)
                sb.Append("?");

            var j = 0;
            var keys = collection.Keys;
            foreach (string key in keys)
            {
                var i = 0;
                var values = collection.GetValues(key);
                foreach (var value in values)
                {
                    sb.Append(key)
                        .Append("=")
                        .Append(value);

                    if (++i < values.Length)
                        sb.Append("&");
                }
                if (++j < keys.Count)
                    sb.Append("&");
            }
            return sb.ToString();
        }

        private static byte[] ZipStr(String str)
        {
            using (MemoryStream output = new MemoryStream())
            {
                using (DeflateStream gzip = new DeflateStream(output, CompressionMode.Compress))
                {
                    using (StreamWriter writer = new StreamWriter(gzip, System.Text.Encoding.UTF8))
                    {
                        writer.Write(str);
                    }
                }

                return output.ToArray();
            }
        }

        public static byte[] HexToByte(string hexString)
        {
            byte[] returnBytes = new byte[hexString.Length / 2];
            for (int i = 0; i < returnBytes.Length; i++)
                returnBytes[i] = Convert.ToByte(hexString.Substring(i * 2, 2), 16);
            return returnBytes;
        }
    }
}
