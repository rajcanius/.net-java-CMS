using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Net.Sockets;

namespace CMSTest
{
    class Program
    {
        private const String data = "Hello from client!";
        private const String PATH_TO_CERTIFICATE = "";
        private const String KEYSTORE_PASSWORD = ""; 

        static void Main(string[] args)
        {
            TcpClient client = new TcpClient("localhost", 5555);

            //notice flags at certificate loading. These are necessary to correctly obtain private key 
            X509Certificate2 cert = new X509Certificate2(PATH_TO_CERTIFICATE, KEYSTORE_PASSWORD, X509KeyStorageFlags.Exportable | X509KeyStorageFlags.PersistKeySet);

            
            byte[] dataBuffer = new byte[2000];
            NetworkStream receiveChannel = client.GetStream();
            receiveChannel.Read(dataBuffer, 0, 2000);

            
            SignedCms envelopeDecode = new SignedCms();

            envelopeDecode.Decode(dataBuffer);
            //should be validated only signature or certificate chain also?
            envelopeDecode.CheckSignature(false);

            ContentInfo ci = envelopeDecode.ContentInfo;
            byte[] content = ci.Content;

            Console.WriteLine(Encoding.ASCII.GetString(content));

            byte[] response = sign(cert);
            receiveChannel.Write(response, 0, response.Length);

            Console.Read();

        }

        private static byte[] sign(X509Certificate2 cert)
        {
            ContentInfo content = new ContentInfo(Encoding.ASCII.GetBytes(data));
            SignedCms envelope = new SignedCms(content);
            CmsSigner cmsSigner = new CmsSigner(cert);
            envelope.ComputeSignature(cmsSigner);
            return envelope.Encode();
        }
    }
}
