import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class VerifyCertificate {

    private static final String CERTIFICATE_TYPE = "X.509";

    public static void main(String[] args) {
        if(args.length == 2) {
            try {
                var certCA = getCertificate(args[0]);
                var certUser = getCertificate(args[1]);
                PrintDistinguishedName(certCA, certUser);
                VerifyCertificates(certCA, certUser);
                System.out.println("Pass");
            } catch (Exception e) {
                System.out.println("Fail");
                System.out.println(e.getMessage());
            }
        }
        else System.out.println("Not enough arguments provided.");
    }

    private static X509Certificate getCertificate(String filePath) throws CertificateException, FileNotFoundException {
        var fileInputStream = new FileInputStream(filePath);
        var bufferedInputStream = new BufferedInputStream(fileInputStream);
        var factory = CertificateFactory.getInstance(CERTIFICATE_TYPE);
        return (X509Certificate) factory.generateCertificate(bufferedInputStream);
    }

    private static void PrintDistinguishedName(X509Certificate certCA, X509Certificate certUser) {
        System.out.println("CA: " + certCA.getSubjectDN());
        System.out.println("User: " + certUser.getSubjectDN());
    }

    public static void VerifyCertificates(X509Certificate caCertificate, X509Certificate userCertificate)
            throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException,
            SignatureException {
        caCertificate.checkValidity();
        caCertificate.verify(caCertificate.getPublicKey());
        userCertificate.checkValidity();
        userCertificate.verify(caCertificate.getPublicKey());
    }

}
