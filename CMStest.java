package main.java;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

/**
 * Created by Rajcanius on 27. 6. 2016.
 */
public class CMStest {
    private static final String KEYSTORE_INSTANCE = "JKS";
    private static final String KEYSTORE_FILE = "";
    private static final String KEYSTORE_ALIAS = "";
    private static final String KEYSTORE_PWD = "";

    private static final String data = "Hello from server!";

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());

        try {
            ServerSocket serverSocket = new ServerSocket(5555);
            Socket server = serverSocket.accept();
            System.out.println("Connection accepted.");

            signatureScheme(server);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void signatureScheme(Socket server) {
        try {
            KeyStore ks = KeyStore.getInstance(KEYSTORE_INSTANCE);

            ks.load(new FileInputStream(KEYSTORE_FILE), KEYSTORE_PWD.toCharArray());
            Key key = ks.getKey(KEYSTORE_ALIAS, KEYSTORE_PWD.toCharArray());
            X509Certificate cert = (X509Certificate) ks.getCertificate(KEYSTORE_ALIAS);

            List certList = new ArrayList();
            CMSTypedData msg = new CMSProcessableByteArray(data.getBytes());
            certList.add(cert);

            Store certs = new JcaCertStore(certList);
            CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
            ContentSigner sha256Signer = new JcaContentSignerBuilder("SHA256withRSA").setProvider("BC").build((PrivateKey) key);
            gen.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").build()).build(sha256Signer, cert));

            gen.addCertificates(certs);
            CMSSignedData sigData = gen.generate(msg, true);

            DataOutputStream output = new DataOutputStream(server.getOutputStream());
            output.write(sigData.getEncoded());

            DataInputStream input = new DataInputStream(server.getInputStream());
            byte[] dataBuffer = new byte[2000];
            input.read(dataBuffer);

            System.out.println(verify(dataBuffer));
        } catch (OperatorCreationException | NoSuchAlgorithmException | CertificateException | KeyStoreException | UnrecoverableKeyException | CMSException | IOException e) {
            e.printStackTrace();
        }
    }

    private static boolean verify(byte[] envelopedData) {
        boolean res = false;
        try {
            CMSSignedData cms = new CMSSignedData(envelopedData);

            byte[] array = (byte[]) cms.getSignedContent().getContent();
            System.out.println(new String(array));

            Store store = cms.getCertificates();
            SignerInformationStore signers = cms.getSignerInfos();
            Collection c = signers.getSigners();
            Iterator it = c.iterator();
            while (it.hasNext()) {
                SignerInformation signer = (SignerInformation) it.next();
                Collection certCollection = store.getMatches(signer.getSID());
                Iterator certIt = certCollection.iterator();

                X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
                X509Certificate cert = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);

                if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert))) {
                    res = true;
                }
            }
        } catch (CertificateException | OperatorCreationException | CMSException e) {
            e.printStackTrace();
        }
        return res;
    }
}
