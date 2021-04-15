import pytest

class TestEspresso:

    @staticmethod
    @pytest.mark.parametrize("cert_path, printcert", 
    [
        ( 'samples/ca.pem', 'Owner: CN=ca, OU=ca, O=ca, L=ca, ST=ca, C=CA\nIssuer: CN=root, OU=root, O=root, L=root, ST=root, C=CA\nSerial number: 5f822698\nValid from: Wed Apr 14 13:40:13 EDT 2021 until: Tue Jul 13 13:40:13 EDT 2021\nCertificate fingerprints:\n\t SHA1: 59:7C:A0:72:5D:98:9F:61:B9:9F:29:20:C8:73:60:9C:0E:02:EB:DF\n\t SHA256: AE:56:E7:5E:49:F2:1B:4B:FF:7A:76:12:6E:72:84:1C:6B:D3:E7:FA:D9:84:43:53:C7:24:A9:2F:3E:12:63:7F\nSignature algorithm name: SHA256withDSA\nSubject Public Key Algorithm: 2048-bit DSA key\nVersion: 3\n\nExtensions: \n\n#1: ObjectId: 2.5.29.35 Criticality=false\nAuthorityKeyIdentifier [\nKeyIdentifier [\n0000: 9D 76 79 BA 97 17 06 07   75 A6 5C E1 E6 98 09 F0  .vy.....u.\\.....\n0010: D8 42 F6 C1                                        .B..\n]\n]\n\n#2: ObjectId: 2.5.29.19 Criticality=false\nBasicConstraints:[\n  CA:true\n  PathLen:0\n]\n\n#3: ObjectId: 2.5.29.14 Criticality=false\nSubjectKeyIdentifier [\nKeyIdentifier [\n0000: C2 BF E5 BF 85 2B ED 82   D2 F1 49 89 06 5B 5E 90  .....+....I..[^.\n0010: 64 FC C3 16                                        d...\n]\n]\n\n' ),
        ( 'samples/server.pem', 'Certificate[1]:\nOwner: CN=server, OU=server, O=server, L=server, ST=server, C=CA\nIssuer: CN=ca, OU=ca, O=ca, L=ca, ST=ca, C=CA\nSerial number: 4e2d045a\nValid from: Wed Apr 14 13:42:22 EDT 2021 until: Tue Jul 13 13:42:22 EDT 2021\nCertificate fingerprints:\n\t SHA1: 0B:BE:A7:40:20:F4:F0:DE:D1:C8:99:26:32:A8:33:7A:EB:E8:87:70\n\t SHA256: 83:C1:8D:49:A4:98:3F:73:66:97:63:78:4C:E5:70:BF:0C:A2:71:4A:58:CE:B0:4E:65:87:39:F0:06:1F:7F:2C\nSignature algorithm name: SHA256withDSA\nSubject Public Key Algorithm: 2048-bit DSA key\nVersion: 3\n\nExtensions: \n\n#1: ObjectId: 2.5.29.35 Criticality=false\nAuthorityKeyIdentifier [\nKeyIdentifier [\n0000: C2 BF E5 BF 85 2B ED 82   D2 F1 49 89 06 5B 5E 90  .....+....I..[^.\n0010: 64 FC C3 16                                        d...\n]\n]\n\n#2: ObjectId: 2.5.29.15 Criticality=true\nKeyUsage [\n  DigitalSignature\n  Key_Encipherment\n]\n\n#3: ObjectId: 2.5.29.14 Criticality=false\nSubjectKeyIdentifier [\nKeyIdentifier [\n0000: 9B 06 D8 13 2E 6F 2F 62   85 66 42 A9 AC 86 2E A8  .....o/b.fB.....\n0010: 25 89 AB FC                                        %...\n]\n]\n\n\nCertificate[2]:\nOwner: CN=ca, OU=ca, O=ca, L=ca, ST=ca, C=CA\nIssuer: CN=root, OU=root, O=root, L=root, ST=root, C=CA\nSerial number: 5f822698\nValid from: Wed Apr 14 13:40:13 EDT 2021 until: Tue Jul 13 13:40:13 EDT 2021\nCertificate fingerprints:\n\t SHA1: 59:7C:A0:72:5D:98:9F:61:B9:9F:29:20:C8:73:60:9C:0E:02:EB:DF\n\t SHA256: AE:56:E7:5E:49:F2:1B:4B:FF:7A:76:12:6E:72:84:1C:6B:D3:E7:FA:D9:84:43:53:C7:24:A9:2F:3E:12:63:7F\nSignature algorithm name: SHA256withDSA\nSubject Public Key Algorithm: 2048-bit DSA key\nVersion: 3\n\nExtensions: \n\n#1: ObjectId: 2.5.29.35 Criticality=false\nAuthorityKeyIdentifier [\nKeyIdentifier [\n0000: 9D 76 79 BA 97 17 06 07   75 A6 5C E1 E6 98 09 F0  .vy.....u.\\.....\n0010: D8 42 F6 C1                                        .B..\n]\n]\n\n#2: ObjectId: 2.5.29.19 Criticality=false\nBasicConstraints:[\n  CA:true\n  PathLen:0\n]\n\n#3: ObjectId: 2.5.29.14 Criticality=false\nSubjectKeyIdentifier [\nKeyIdentifier [\n0000: C2 BF E5 BF 85 2B ED 82   D2 F1 49 89 06 5B 5E 90  .....+....I..[^.\n0010: 64 FC C3 16                                        d...\n]\n]\n\n' ),
        ( 'samples/not_a_cert.txt', None ),
        ( 'sample/not_exist.pem', None )
    ])
    def test_keytool_printcert(cert_path, printcert):
        """
        keytool_printcert is tested here instead of assemblyline_v4_service because keytool is 
        installed on a per service basis.

        The test certificates (ca.pem and server.pem) were created for this test by following the
        steps in the 'Generate Certificates for an SSL Server' section of the keytool docs: 
        https://docs.oracle.com/javase/8/docs/technotes/tools/windows/keytool.html
        """
        from assemblyline_v4_service.common.keytool_parse import keytool_printcert

        cert = keytool_printcert(cert_path)
        assert cert == printcert

    @staticmethod
    @pytest.mark.parametrize("jar", 
    [
        ''
    ])
    def test_execute(jar):
        pass

