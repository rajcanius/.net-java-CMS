# .net-java-CMS
Simple sources for Java and .NET communicator using CMS for signature (and certificate chain) validation

For Java CMS, You need to download:
  Bouncycastle provider JDK - bcprov
  Bouncycastle PKIX/CMS/... JDK - bcpkix
All sources can be found at https://www.bouncycastle.org/latest_releases.html

.NET CMS is supported directly in .NET API

Examples don't expect messages longer that 2000 Bytes to be transfered (hardcoded 2000 B receive buffer).
Code should be example how to sign and validate data exchanged betwen Java server and .NET client.

